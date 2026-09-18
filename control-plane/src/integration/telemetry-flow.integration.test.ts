import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { calculateEventHash, signingBytes } from "@/lib/telemetry/cryptography";
import type { TelemetryEvent } from "@/lib/telemetry/schema";
import { verifyBackupRecovery } from "./recovery";

vi.mock("server-only", () => ({}));

const tenantKey = `integration-${randomUUID()}-${randomUUID()}`;
const organizationId = randomUUID();
const eventOneId = randomUUID();
const eventTwoId = randomUUID();
  const dpoCredentialId = randomUUID();
  const loginSourceHash = "d".repeat(64);
const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const keyId = createHash("sha256")
  .update(publicKey.export({ type: "spki", format: "der" }))
  .digest("hex");
let databaseConnected = false;
let organizationCreated = false;
let createdReportSigningKeyId: string | null = null;

function signedEvent(eventId: string, timestamp: string, previousHash: string, inputTokens: number, signer: KeyObject) {
  const event: TelemetryEvent = {
    event_id: eventId,
    timestamp,
    client_id_hash: "a".repeat(64),
    application_id: "integration-test",
    routing: { provider: "test-provider", model: "gpt-enterprise" },
    compliance_flags: { pii_detected: true, pii_redacted: true, policy_passed: true },
    metrics: { input_tokens: inputTokens, output_tokens: 5 },
    cryptography: {
      hash_algorithm: "SHA-256",
      request_response_hash: "b".repeat(64),
      previous_event_hash: previousHash,
      event_hash: "",
      signature_algorithm: "ECDSA_P256_SHA256_ASN1",
      key_id: keyId,
      signature: "",
    },
  };
  event.cryptography.event_hash = calculateEventHash(event);
  event.cryptography.signature = sign("sha256", signingBytes(event), {
    key: signer,
    dsaEncoding: "der",
  }).toString("base64").replace(/=+$/, "");
  return event;
}

describe("telemetry control-plane flow", () => {
  beforeAll(async () => {
    await client.connect();
    databaseConnected = true;
    await client.query(`CREATE TABLE IF NOT EXISTS control_plane_migrations (
      filename text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )`);
    const migrations = (await readdir(resolve("db/migrations"))).filter((name) => name.endsWith(".sql")).sort();
    for (const migration of migrations) {
      await client.query(await readFile(resolve("db/migrations", migration), "utf8"));
      await client.query(`INSERT INTO control_plane_migrations(filename) VALUES ($1) ON CONFLICT DO NOTHING`, [migration]);
    }
    await client.query(
      `INSERT INTO organizations (id, name, tenant_key) VALUES ($1, $2, $3)`,
      [organizationId, "Integration Test Organization", createHash("sha256").update(tenantKey).digest("hex")],
    );
    organizationCreated = true;
    await client.query(
      `INSERT INTO tenant_access_keys (organization_id, key_hash, label) VALUES ($1,$2,$3)`,
      [organizationId, createHash("sha256").update(tenantKey).digest("hex"), "Integration data plane"],
    );
    await client.query(
      `INSERT INTO telemetry_public_keys (organization_id, key_id, public_key_pem, label)
       VALUES ($1, $2, $3, $4)`,
      [organizationId, keyId, publicKeyPem, "integration-test"],
    );
    await client.query(
      `INSERT INTO dpo_access_keys (id, organization_id, key_hash, label, role) VALUES ($1,$2,$3,$4,$5)`,
      [dpoCredentialId, organizationId, "c".repeat(64), "Integration DPO", "DPO"],
    );
  });

  afterAll(async () => {
    if (!databaseConnected) return;
    if (!organizationCreated) {
      await client.end();
      return;
    }
    await client.query(`DELETE FROM dashboard_login_attempts WHERE source_hash = $1`, [loginSourceHash]);
    await client.query(`DELETE FROM ai_systems WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM compliance_reports WHERE organization_id = $1`, [organizationId]);
    if (createdReportSigningKeyId) await client.query(`DELETE FROM report_signing_keys WHERE key_id = $1`, [createdReportSigningKeyId]);
    await client.query(`DELETE FROM telemetry_merkle_checkpoints WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM telemetry_events WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM telemetry_buffer WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM telemetry_chain_heads WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM telemetry_public_keys WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM telemetry_event_ids WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM dpo_access_keys WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM tenant_access_keys WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM security_audit_checkpoints WHERE organization_id = $1`, [organizationId]);
    await client.query(`SELECT set_config('aiproxy.audit_maintenance', 'on', false)`);
    await client.query(`DELETE FROM telemetry_tombstones WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM security_audit_events WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM security_audit_heads WHERE organization_id = $1`, [organizationId]);
    await client.query(`SELECT set_config('aiproxy.audit_maintenance', 'off', false)`);
    await client.query(`DELETE FROM organization_retention_policies WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM organizations WHERE id = $1`, [organizationId]);
    await client.end();
  });

  it("preserves an out-of-order signed chain through ingest, worker, and dashboard", async () => {
    const first = signedEvent(eventOneId, "2026-09-15T08:00:00.000Z", "", 10, privateKey);
    const second = signedEvent(eventTwoId, "2026-09-15T08:00:01.000Z", first.cryptography.event_hash, 20, privateKey);
    const { POST } = await import("@/app/api/telemetry/ingest/route");

    for (const event of [second, first]) {
      const response = await POST(new Request("http://localhost/api/telemetry/ingest", {
        method: "POST",
        headers: { authorization: `Bearer ${tenantKey}`, "content-type": "application/json" },
        body: JSON.stringify(event),
      }));
      expect(response.status).toBe(202);
      expect(await response.json()).toMatchObject({ status: "BUFFERED", accepted: 1, duplicates: 0 });
    }

    const { processBufferedTelemetry } = await import("@/lib/telemetry/worker");
    expect(await processBufferedTelemetry(new Date("2026-09-15T08:01:00.000Z"))).toMatchObject({
      chains: 1, verified: 2, compromised: 0, invalid: 0, deferred: 0,
    });

    const rows = await client.query(
      `SELECT event_id, status, chain_sequence FROM telemetry_events
       WHERE organization_id = $1 ORDER BY chain_sequence`,
      [organizationId],
    );
    expect(rows.rows).toEqual([
      { event_id: eventOneId, status: "VERIFIED", chain_sequence: "1" },
      { event_id: eventTwoId, status: "VERIFIED", chain_sequence: "2" },
    ]);

    const { createMerkleCheckpoints } = await import("@/lib/telemetry/checkpoint");
    expect(await createMerkleCheckpoints()).toMatchObject({ created: 1 });
    expect(await createMerkleCheckpoints()).toMatchObject({ created: 0 });

    const anchorKeys = generateKeyPairSync("ed25519");
    const reportKeys = generateKeyPairSync("ed25519");
    vi.stubEnv("DASHBOARD_SESSION_SECRET", "s".repeat(32));
    vi.stubEnv("CRON_SECRET", "c".repeat(32));
    vi.stubEnv("MERKLE_ANCHOR_URL", "http://independent-anchor.test/v1/checkpoints");
    vi.stubEnv("MERKLE_ANCHOR_TOKEN", "a".repeat(32));
    vi.stubEnv("MERKLE_ANCHOR_PUBLIC_KEY", anchorKeys.publicKey.export({ type: "spki", format: "pem" }).toString());
    vi.stubEnv("REPORT_SIGNING_PRIVATE_KEY", reportKeys.privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    const { anchorPendingCheckpoints, anchorReceiptSigningBytes } = await import("@/lib/telemetry/anchor");
    const anchorFetcher = async (_input: string | URL | Request, init?: RequestInit) => {
      const request = JSON.parse(String(init?.body)) as { checkpoint_id: string; root_hash: string };
      const receipt = {
        anchor_id: "integration-ledger-1",
        checkpoint_id: request.checkpoint_id,
        root_hash: request.root_hash,
        anchored_at: new Date().toISOString(),
        signature_algorithm: "Ed25519" as const,
        signature: "placeholder-signature-value-long-enough",
      };
      receipt.signature = sign(null, anchorReceiptSigningBytes(receipt), anchorKeys.privateKey).toString("base64");
      return Response.json(receipt);
    };
    const anchorResult = await anchorPendingCheckpoints(anchorFetcher);
    expect(anchorResult).toEqual({ configured: true, attempted: 1, anchored: 1, failed: 0 });

    await client.query(
      `INSERT INTO ai_systems (
         organization_id, application_id, model, name, provider, intended_purpose,
         risk_class, system_owner, legal_basis, human_oversight
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [organizationId, "integration-test", "gpt-enterprise", "Legal assistant", "test-provider",
        "Assist legal reviewers", "HIGH", "Legal Operations", "Legitimate interest", "Mandatory reviewer approval"],
    );

    const { getDashboardData } = await import("@/lib/dashboard");
    const dashboard = await getDashboardData(organizationId);
    expect(dashboard?.summary).toMatchObject({
      totalEvents: 2,
      totalTokens: 40,
      piiPrevented: 2,
      verifiedEvents: 2,
      compromisedEvents: 0,
      invalidSignatures: 0,
      chainStatus: "INTACT",
      unclassifiedSystems: 0,
    });
    expect(dashboard?.models).toHaveLength(1);
    expect(dashboard?.checkpoint).toMatchObject({
      leafCount: 1, anchorStatus: "ANCHORED", anchorId: "integration-ledger-1",
    });
    expect(dashboard?.checkpoint?.rootHash).toMatch(/^[a-f0-9]{64}$/);

    const { checkControlPlaneReadiness } = await import("@/lib/readiness");
    expect(await checkControlPlaneReadiness()).toBe(true);
    const { clearLoginFailures, getLoginThrottle, recordLoginFailure } = await import("@/lib/login-throttle");
    const throttleNow = new Date("2026-09-15T12:00:00.000Z");
    expect((await getLoginThrottle(loginSourceHash, throttleNow)).allowed).toBe(true);
    for (let attempt = 0; attempt < 5; attempt += 1) await recordLoginFailure(loginSourceHash, throttleNow);
    expect(await getLoginThrottle(loginSourceHash, throttleNow)).toMatchObject({ allowed: false, retryAfterSeconds: 900 });
    await clearLoginFailures(loginSourceHash);
    expect((await getLoginThrottle(loginSourceHash, throttleNow)).allowed).toBe(true);
    expect(dashboard?.models[0]).toMatchObject({
      applicationId: "integration-test", model: "gpt-enterprise", eventCount: 2,
      totalTokens: 40, piiIncidents: 2, governance: { riskClass: "HIGH", systemOwner: "Legal Operations" },
    });

    const { sealComplianceReport, getSealedReport, getReportVerificationKey, listSealedReports, verifySealedReport } = await import("@/lib/compliance-report");
    const reportId = await sealComplianceReport({ credentialId: dpoCredentialId, organizationId });
    const sealedReport = await getSealedReport(reportId, organizationId);
    expect(sealedReport).not.toBeNull();
    expect(sealedReport!.payload).toMatchObject({
      evidence: { administrative_audit: { status: "NO_EVIDENCE", eventCount: 0, latestSequence: "0", latestEventHash: "" } },
    });
    createdReportSigningKeyId = sealedReport!.signing_key_id;
    expect(verifySealedReport(sealedReport!, reportKeys.publicKey.export({ type: "spki", format: "pem" }).toString())).toBe(true);
    expect(await getReportVerificationKey(sealedReport!.signing_key_id, organizationId)).toBe(
      reportKeys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    );
    expect(await listSealedReports(organizationId)).toMatchObject([{
      id: reportId,
      generatedByLabel: "Integration DPO",
      generatedByRole: "DPO",
      payloadHash: sealedReport!.payload_hash,
    }]);
    const { getSecurityAuditLedger } = await import("@/lib/security-audit");
    const audit = await getSecurityAuditLedger(organizationId);
    expect(audit.valid).toBe(true);
    expect(audit.events).toHaveLength(1);
    expect(audit.events[0].eventData).toMatchObject({
      actor_type: "DPO_CREDENTIAL", actor_id: dpoCredentialId,
      action: "COMPLIANCE_REPORT_SEALED", resource_id: reportId,
    });
    const { appendSecurityAuditEvent } = await import("@/lib/security-audit");
    await appendSecurityAuditEvent({
      organizationId, actorId: dpoCredentialId, action: "COMPLIANCE_REPORT_DOWNLOADED",
      resourceType: "COMPLIANCE_REPORT", resourceId: reportId,
    });
    const { createSecurityAuditCheckpoints } = await import("@/lib/security-audit-checkpoint");
    expect(await createSecurityAuditCheckpoints()).toMatchObject({ created: 1, invalid: 0 });
    expect(await createSecurityAuditCheckpoints()).toMatchObject({ created: 0, invalid: 0 });
    expect(await anchorPendingCheckpoints(anchorFetcher)).toEqual({ configured: true, attempted: 1, anchored: 1, failed: 0 });
    const anchoredAudit = await getSecurityAuditLedger(organizationId);
    expect(anchoredAudit.events).toHaveLength(2);
    expect(anchoredAudit.evidence.anchor).toMatchObject({ status: "ANCHORED", anchorId: "integration-ledger-1" });
    if (process.env.TEST_BACKUP_RECOVERY === "1") await verifyBackupRecovery(client, organizationId);
    const originalAuditHash = await client.query<{ event_hash: string }>(
      `SELECT event_hash FROM security_audit_events WHERE organization_id = $1 AND sequence = 1`, [organizationId],
    );
    await client.query(`ALTER TABLE security_audit_events DISABLE TRIGGER security_audit_events_immutable`);
    await client.query(`UPDATE security_audit_events SET event_hash = $2 WHERE organization_id = $1 AND sequence = 1`, [organizationId, "b".repeat(64)]);
    await client.query(`ALTER TABLE security_audit_events ENABLE TRIGGER security_audit_events_immutable`);
    expect(await createSecurityAuditCheckpoints()).toMatchObject({ created: 0, invalid: 1 });
    await client.query(`ALTER TABLE security_audit_events DISABLE TRIGGER security_audit_events_immutable`);
    await client.query(`UPDATE security_audit_events SET event_hash = $2 WHERE organization_id = $1 AND sequence = 1`, [organizationId, originalAuditHash.rows[0].event_hash]);
    await client.query(`ALTER TABLE security_audit_events ENABLE TRIGGER security_audit_events_immutable`);
    const { getControlPlaneMetrics } = await import("@/lib/operations");
    expect((await getControlPlaneMetrics()).brokenSecurityAuditChains).toBe(0);
    await expect(client.query(
      `UPDATE security_audit_events SET event_data = '{}'::jsonb WHERE organization_id = $1`,
      [organizationId],
    )).rejects.toThrow(/append-only/);

    await client.query(`DELETE FROM ai_systems WHERE organization_id = $1`, [organizationId]);
    const unclassified = await getDashboardData(organizationId);
    expect(unclassified?.summary.unclassifiedSystems).toBe(1);
    expect(unclassified?.models[0].governance).toBeNull();

    await client.query(`UPDATE tenant_access_keys SET revoked_at=now() WHERE organization_id=$1`, [organizationId]);
    const rejected = await POST(new Request("http://localhost/api/telemetry/ingest", {
      method: "POST",
      headers: { authorization: `Bearer ${tenantKey}`, "content-type": "application/json" },
      body: JSON.stringify(first),
    }));
    expect(rejected.status).toBe(401);

    await client.query(
      `INSERT INTO organization_retention_policies
       (organization_id, telemetry_retention_days, legal_hold, legal_hold_reason, legal_hold_set_at)
       VALUES ($1, 30, true, 'CASE-2026-17', now())`, [organizationId],
    );
    const { enforceRetentionPolicies } = await import("@/lib/retention");
    const retentionNow = new Date("2026-10-20T12:00:00.000Z");
    expect(await enforceRetentionPolicies(retentionNow)).toEqual({ organizations: 1, held: 1, purged: 0 });
    await client.query(
      `UPDATE organization_retention_policies SET legal_hold=false, legal_hold_reason=NULL, legal_hold_set_at=NULL WHERE organization_id=$1`,
      [organizationId],
    );
    // Pause the worker after policy discovery, then commit a policy change.
    // The worker must re-read it inside the purge transaction.
    for (const change of ["hold", "extend"] as const) {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", ["retention:" + organizationId]);
      const pending = enforceRetentionPolicies(retentionNow);
      try {
        await vi.waitFor(async () => {
          await client.query("SELECT pg_stat_clear_snapshot()");
          const waiting = await client.query(`SELECT 1 FROM pg_stat_activity
            WHERE datname=current_database() AND pid <> pg_backend_pid()
              AND wait_event='advisory' AND query LIKE '%pg_advisory_xact_lock%'`);
          expect(waiting.rowCount).toBeGreaterThan(0);
        }, { timeout: 5000, interval: 20 });
        await client.query(change === "hold"
          ? `UPDATE organization_retention_policies SET legal_hold=true, legal_hold_reason='CONCURRENT-HOLD', legal_hold_set_at=now() WHERE organization_id=$1`
          : `UPDATE organization_retention_policies SET telemetry_retention_days=3650 WHERE organization_id=$1`, [organizationId]);
        await client.query("COMMIT");
        expect(await pending).toEqual({ organizations: 1, held: change === "hold" ? 1 : 0, purged: 0 });
      } finally {
        await client.query("ROLLBACK");
        await pending;
      }
      await client.query(`UPDATE organization_retention_policies SET legal_hold=false,
        legal_hold_reason=NULL, legal_hold_set_at=NULL, telemetry_retention_days=30 WHERE organization_id=$1`, [organizationId]);
    }
    expect(await enforceRetentionPolicies(retentionNow)).toEqual({ organizations: 1, held: 0, purged: 2 });
    const retainedEvidence = await getDashboardData(organizationId);
    expect(retainedEvidence?.retention).toMatchObject({ telemetryRetentionDays: 30, legalHold: false, tombstoneCount: 2 });
    expect(retainedEvidence?.models).toHaveLength(0);
    expect(retainedEvidence?.summary.chainStatus).toBe("INTACT");
    if (process.env.TEST_BACKUP_RECOVERY === "1") await verifyBackupRecovery(client, organizationId);
    await expect(client.query(
      `UPDATE telemetry_tombstones SET event_hash=$2 WHERE organization_id=$1`, [organizationId, "c".repeat(64)],
    )).rejects.toThrow(/append-only/);

    const { saveAISystem, listAISystems } = await import("@/lib/ai-systems");
    const profile = { application_id: "integration-test", model: "gpt-enterprise", name: "Governed system",
      provider: "test-provider", intended_purpose: "Review documents", risk_class: "HIGH" as const,
      system_owner: "Legal", legal_basis: "Assessment 12", human_oversight: "Mandatory review",
      data_categories: ["business records"], deployment_regions: ["EU"], status: "ACTIVE" as const };
    const identity = { organizationId, credentialId: dpoCredentialId };
    const systemId = await saveAISystem(identity, profile);
    expect(await listAISystems(randomUUID())).toEqual([]);
    expect(await saveAISystem(identity, { ...profile, name: "Updated system" })).toBe(systemId);
    expect(await listAISystems(organizationId)).toMatchObject([{ id: systemId, name: "Updated system" }]);
    const profileAudit = await getSecurityAuditLedger(organizationId);
    expect(profileAudit.valid).toBe(true);
    expect(profileAudit.events.some((event) => event.eventData.action === "AI_SYSTEM_PROFILE_UPSERTED")).toBe(true);
    const { updateRetentionPolicy, RetentionConflictError } = await import("@/lib/retention-admin");
    const { getRetentionPolicy } = await import("@/lib/retention");
    await updateRetentionPolicy(identity, { command: "set", days: 365 });
    await updateRetentionPolicy(identity, { command: "hold", reason: "CASE-18" });
    await updateRetentionPolicy(identity, { command: "set", days: 730 });
    expect(await getRetentionPolicy(organizationId)).toMatchObject({ telemetryRetentionDays: 730, legalHold: true });
    expect(await getRetentionPolicy(randomUUID())).toBeNull();
    await client.query(`ALTER TABLE security_audit_events ADD CONSTRAINT reject_retention_test
      CHECK (event_data->>'action' NOT IN ('LEGAL_HOLD_RELEASED', 'RETENTION_POLICY_UPDATED')) NOT VALID`);
    try {
      await expect(updateRetentionPolicy(identity, { command: "release", reason: "closed" })).rejects.toThrow();
      await expect(updateRetentionPolicy(identity, { command: "set", days: 30 })).rejects.toThrow();
      expect(await getRetentionPolicy(organizationId)).toMatchObject({ telemetryRetentionDays: 730, legalHold: true });
    } finally {
      await client.query(`ALTER TABLE security_audit_events DROP CONSTRAINT reject_retention_test`);
    }
    await updateRetentionPolicy(identity, { command: "release", reason: "CASE-18 closed" });
    expect(await getRetentionPolicy(organizationId)).toMatchObject({ legalHold: false, legalHoldReason: null });
    await expect(updateRetentionPolicy(identity, { command: "release", reason: "again" })).rejects.toBeInstanceOf(RetentionConflictError);
    const retentionAudit = await getSecurityAuditLedger(organizationId);
    expect(retentionAudit.valid).toBe(true);
    for (const action of ["RETENTION_POLICY_UPDATED", "LEGAL_HOLD_ENABLED", "LEGAL_HOLD_RELEASED"]) {
      expect(retentionAudit.events.some((event) => event.eventData.action === action && event.eventData.actor_id === dpoCredentialId)).toBe(true);
    }
    // A rejected audit insert must roll back the profile change, too.
    await client.query(`ALTER TABLE security_audit_events ADD CONSTRAINT reject_profile_test
      CHECK (event_data->>'action' <> 'AI_SYSTEM_PROFILE_UPSERTED') NOT VALID`);
    try {
      await expect(saveAISystem(identity, { ...profile, name: "Must roll back" })).rejects.toThrow();
      expect(await listAISystems(organizationId)).toMatchObject([{ id: systemId, name: "Updated system" }]);
    } finally {
      await client.query(`ALTER TABLE security_audit_events DROP CONSTRAINT reject_profile_test`);
    }
    // More than one page, including a new append between page requests.
    await client.query(`SELECT append_security_audit_event($1::uuid, 'SYSTEM', 'pagination-test',
      'PAGINATION_TEST', 'TEST', n::text, '{}'::jsonb) FROM generate_series(1, 201) n`, [organizationId]);
    const firstPage = await getSecurityAuditLedger(organizationId);
    expect(firstPage.events).toHaveLength(200);
    expect(firstPage.nextCursor).not.toBeNull();
    await appendSecurityAuditEvent({ organizationId, actorId: dpoCredentialId,
      action: "PAGINATION_NEW_EVENT", resourceType: "TEST", resourceId: "new" });
    const secondPage = await getSecurityAuditLedger(organizationId, BigInt(firstPage.nextCursor!));
    expect(secondPage.nextCursor).toBeNull();
    const sequences = [...firstPage.events, ...secondPage.events].map((event) => event.sequence.toString());
    expect(new Set(sequences).size).toBe(firstPage.evidence.eventCount);
    expect(sequences).toHaveLength(firstPage.evidence.eventCount);
    expect(secondPage.events.every((event) => event.sequence < BigInt(firstPage.nextCursor!))).toBe(true);
    expect(secondPage.evidence.eventCount).toBe(firstPage.evidence.eventCount + 1);
    const otherTenant = await getSecurityAuditLedger(randomUUID(), BigInt(firstPage.nextCursor!));
    expect(otherTenant.events).toEqual([]);
    expect(otherTenant.evidence.status).toBe("NO_EVIDENCE");
    expect(otherTenant.nextCursor).toBeNull();
  }, 120_000);
});
