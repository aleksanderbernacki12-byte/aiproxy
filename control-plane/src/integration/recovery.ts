import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import assert from "node:assert/strict";
import pg from "pg";
import { verifySealedReport } from "@/lib/compliance-report";

const quote = (name: string) => `"${name.replaceAll('"', '""')}"`;

// Test fixtures only: no persistent dump files or customer data are used.
function postgresTool(tool: string, databaseUrl: URL, args: string[], input?: Buffer) {
  const container = process.env.TEST_POSTGRES_CONTAINER;
  const env = {
    ...process.env,
    PGHOST: container ? "127.0.0.1" : databaseUrl.hostname,
    PGPORT: container ? "5432" : databaseUrl.port || "5432",
    PGUSER: decodeURIComponent(databaseUrl.username),
    PGPASSWORD: decodeURIComponent(databaseUrl.password),
    PGDATABASE: decodeURIComponent(databaseUrl.pathname.slice(1)),
    PGSSLMODE: "disable",
  };
  const command = container ? "docker" : tool;
  const commandArgs = container
    ? ["exec", "-i", ...["PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGSSLMODE"].flatMap((key) => ["--env", key]), container, tool, ...args]
    : args;
  const result = spawnSync(command, commandArgs, { env, input, timeout: 60_000, maxBuffer: 16 << 20 });
  // Do not print process errors: they can contain connection details or data.
  assert.equal(result.status, 0, `${tool} failed; check PostgreSQL client version, availability, and test database permissions`);
  return result.stdout;
}

async function fingerprint(client: pg.Client) {
  const hash = createHash("sha256");
  const tables = await client.query<{ tablename: string }>(
    "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename",
  );
  for (const { tablename } of tables.rows) {
    hash.update(tablename);
    const data = await client.query(`SELECT to_jsonb(t)::text AS row FROM public.${quote(tablename)} t ORDER BY to_jsonb(t)::text COLLATE "C"`);
    hash.update(JSON.stringify(data.rows));
  }
  const sequences = await client.query<{ sequencename: string }>(
    "SELECT sequencename FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename",
  );
  for (const { sequencename } of sequences.rows) {
    hash.update(sequencename);
    hash.update(JSON.stringify((await client.query(`SELECT last_value, is_called FROM public.${quote(sequencename)}`)).rows));
  }
  return hash.digest("hex");
}

export async function verifyBackupRecovery(source: pg.Client, organizationId: string) {
  const sourceUrl = new URL(process.env.TEST_DATABASE_URL!);
  assert.ok(["localhost", "127.0.0.1", "[::1]"].includes(sourceUrl.hostname), "Recovery rehearsal requires a local disposable database");
  const databaseName = `aiproxy_recovery_${randomUUID().replaceAll("-", "")}`;
  const restoredUrl = new URL(sourceUrl);
  restoredUrl.pathname = `/${databaseName}`;
  const restored = new pg.Client({ connectionString: restoredUrl.toString() });
  let created = false;
  try {
    const expected = await fingerprint(source);
    const backup = postgresTool("pg_dump", sourceUrl, ["--format=custom", "--no-owner", "--no-acl"]);
    await source.query(`CREATE DATABASE ${quote(databaseName)} TEMPLATE template0`);
    created = true;
    try {
      postgresTool("pg_restore", restoredUrl, ["--dbname", databaseName, "--no-owner", "--no-acl", "--exit-on-error", "--single-transaction"], backup);
    } finally {
      backup.fill(0);
    }
    await restored.connect();
    assert.equal(await fingerprint(restored), expected, "Restored tables or sequence state differ from backup source");
    const chain = await restored.query("SELECT verify_security_audit_chain($1::uuid) AS valid", [organizationId]);
    assert.equal(chain.rows[0].valid, true, "Restored audit chain is invalid");
    const reports = await restored.query(`SELECT r.*, k.public_key_pem FROM compliance_reports r
      JOIN report_signing_keys k ON k.key_id=r.signing_key_id WHERE r.organization_id=$1`, [organizationId]);
    assert.ok(reports.rows.length > 0, "Recovery fixture must contain a sealed report");
    for (const report of reports.rows) {
      assert.equal(verifySealedReport({
        report_id: report.id, payload: report.payload, payload_hash: report.payload_hash,
        signature_algorithm: "Ed25519", signing_key_id: report.signing_key_id,
        signature: report.signature, created_at: report.created_at.toISOString(),
      }, report.public_key_pem), true, "Restored report signature is invalid");
    }
    await assert.rejects(restored.query(
      "UPDATE security_audit_events SET event_hash=repeat('0',64) WHERE organization_id=$1", [organizationId],
    ), /append-only/);
    const tombstones = await restored.query("SELECT count(*)::int AS count FROM telemetry_tombstones WHERE organization_id=$1", [organizationId]);
    if (tombstones.rows[0].count > 0) {
      await assert.rejects(restored.query(
        "DELETE FROM telemetry_tombstones WHERE organization_id=$1", [organizationId],
      ), /append-only/);
    }
    // Prove restored audit functions and sequence state support new writes.
    await restored.query("SELECT append_security_audit_event($1::uuid, 'OPERATOR', 'recovery-test', 'RECOVERY_VERIFIED', 'TEST', 'recovery-test', '{}'::jsonb)", [organizationId]);
    assert.equal((await restored.query("SELECT verify_security_audit_chain($1::uuid) AS valid", [organizationId])).rows[0].valid, true);
  } finally {
    try {
      await restored.end();
    } finally {
      if (created) await source.query(`DROP DATABASE ${quote(databaseName)}`);
    }
  }
}
