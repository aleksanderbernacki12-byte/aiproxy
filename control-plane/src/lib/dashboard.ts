import "server-only";

import { and, asc, desc, eq, sql } from "drizzle-orm";
import { aiSystems, organizations, telemetryEvents, telemetryMerkleCheckpoints } from "@/db/schema";
import { getDatabase } from "@/db/client";

export type ChainStatus = "INTACT" | "ATTENTION_REQUIRED" | "NO_EVIDENCE";

export type ModelInventoryRow = {
  applicationId: string;
  model: string;
  observedProvider: string;
  eventCount: number;
  totalTokens: number;
  policyViolations: number;
  piiIncidents: number;
  lastSeenAt: Date;
  governance: {
    name: string;
    provider: string | null;
    intendedPurpose: string;
    riskClass: "UNCLASSIFIED" | "MINIMAL" | "LIMITED" | "HIGH" | "PROHIBITED";
    systemOwner: string;
    legalBasis: string;
    humanOversight: string;
    dataCategories: string[];
    deploymentRegions: string[];
    status: "ACTIVE" | "SUSPENDED" | "RETIRED";
  } | null;
};

export type DashboardData = {
  organization: { id: string; name: string };
  models: ModelInventoryRow[];
  checkpoint: {
    rootHash: string;
    leafCount: number;
    createdAt: Date;
    anchorStatus: "PENDING" | "ANCHORED";
    anchorId: string | null;
    anchoredAt: Date | null;
  } | null;
  retention: {
    telemetryRetentionDays: number;
    legalHold: boolean;
    legalHoldReason: string | null;
    legalHoldSetAt: Date | null;
    tombstoneCount: number;
  } | null;
  summary: {
    totalEvents: number;
    totalTokens: number;
    piiPrevented: number;
    policyViolations: number;
    verifiedEvents: number;
    compromisedEvents: number;
    invalidSignatures: number;
    firstEventAt: Date | null;
    lastEventAt: Date | null;
    chainStatus: ChainStatus;
    unclassifiedSystems: number;
  };
};

const modelExpression = sql<string>`coalesce(nullif(${telemetryEvents.routing}->>'model', ''), 'Okänd modell')`;
const providerExpression = sql<string>`coalesce(nullif(${telemetryEvents.routing}->>'provider', ''), 'Okänd leverantör')`;
const tokenExpression = sql<number>`(
  case
    when jsonb_typeof(${telemetryEvents.metrics}->'total_tokens') = 'number'
      then (${telemetryEvents.metrics}->>'total_tokens')::numeric
    else
      case when jsonb_typeof(${telemetryEvents.metrics}->'input_tokens') = 'number'
        then (${telemetryEvents.metrics}->>'input_tokens')::numeric else 0 end
      + case when jsonb_typeof(${telemetryEvents.metrics}->'output_tokens') = 'number'
        then (${telemetryEvents.metrics}->>'output_tokens')::numeric else 0 end
  end
)`;
const piiIncidentExpression = sql<boolean>`coalesce((${telemetryEvents.complianceFlags}->>'pii_detected')::boolean, false)`;
const policyViolationExpression = sql<boolean>`exists (
  select 1
  from jsonb_each(${telemetryEvents.complianceFlags}) as flag(key, value)
  where flag.value = 'true'::jsonb
    and flag.key ~ '(_violation|_breach|_blocked|_failed)$'
)`;

export function chainStatusFor(
  totalEvents: number,
  compromisedEvents: number,
  invalidSignatures: number,
): ChainStatus {
  if (totalEvents === 0) return "NO_EVIDENCE";
  if (compromisedEvents > 0 || invalidSignatures > 0) return "ATTENTION_REQUIRED";
  return "INTACT";
}

export async function getDashboardData(organizationId: string): Promise<DashboardData | null> {
  const database = getDatabase();
  const [organization] = await database
    .select({ id: organizations.id, name: organizations.name })
    .from(organizations)
    .where(eq(organizations.id, organizationId))
    .limit(1);
  if (!organization) return null;

  const [models, [summary], [checkpoint], retentionResult] = await Promise.all([
    database
      .select({
        applicationId: telemetryEvents.applicationId,
        model: modelExpression.as("model"),
        observedProvider: providerExpression.as("observed_provider"),
        eventCount: sql<number>`count(*)::integer`.mapWith(Number),
        totalTokens: sql<number>`coalesce(sum(${tokenExpression}), 0)::bigint`.mapWith(Number),
        policyViolations:
          sql<number>`count(*) filter (where ${policyViolationExpression})::integer`.mapWith(Number),
        piiIncidents:
          sql<number>`count(*) filter (where ${piiIncidentExpression})::integer`.mapWith(Number),
        lastSeenAt: sql<Date>`max(${telemetryEvents.eventTimestamp})`.mapWith(
          telemetryEvents.eventTimestamp,
        ),
        governanceName: aiSystems.name,
        governanceProvider: aiSystems.provider,
        intendedPurpose: aiSystems.intendedPurpose,
        riskClass: aiSystems.riskClass,
        systemOwner: aiSystems.systemOwner,
        legalBasis: aiSystems.legalBasis,
        humanOversight: aiSystems.humanOversight,
        dataCategories: aiSystems.dataCategories,
        deploymentRegions: aiSystems.deploymentRegions,
        systemStatus: aiSystems.status,
      })
      .from(telemetryEvents)
      .leftJoin(aiSystems, and(
        eq(aiSystems.organizationId, telemetryEvents.organizationId),
        eq(aiSystems.applicationId, telemetryEvents.applicationId),
        eq(aiSystems.model, modelExpression),
      ))
      .where(eq(telemetryEvents.organizationId, organizationId))
      .groupBy(
        telemetryEvents.applicationId, modelExpression, providerExpression, aiSystems.id,
      )
      .orderBy(asc(telemetryEvents.applicationId), asc(modelExpression)),
    database
      .select({
        totalEvents: sql<number>`count(*)::integer`.mapWith(Number),
        totalTokens: sql<number>`coalesce(sum(${tokenExpression}), 0)::bigint`.mapWith(Number),
        piiPrevented:
          sql<number>`count(*) filter (where ${piiIncidentExpression} and coalesce((${telemetryEvents.complianceFlags}->>'pii_redacted')::boolean, false))::integer`.mapWith(
            Number,
          ),
        policyViolations:
          sql<number>`count(*) filter (where ${policyViolationExpression})::integer`.mapWith(Number),
        verifiedEvents:
          sql<number>`count(*) filter (where ${telemetryEvents.status} = 'VERIFIED')::integer`.mapWith(
            Number,
          ),
        compromisedEvents:
          sql<number>`count(*) filter (where ${telemetryEvents.status} = 'COMPROMISED_CHAIN')::integer`.mapWith(
            Number,
          ),
        invalidSignatures:
          sql<number>`count(*) filter (where ${telemetryEvents.status} = 'INVALID_SIGNATURE')::integer`.mapWith(
            Number,
          ),
        firstEventAt: sql<Date | null>`min(${telemetryEvents.eventTimestamp})`,
        lastEventAt: sql<Date | null>`max(${telemetryEvents.eventTimestamp})`,
      })
      .from(telemetryEvents)
      .where(eq(telemetryEvents.organizationId, organizationId)),
    database.select({
      rootHash: telemetryMerkleCheckpoints.rootHash,
      leafCount: telemetryMerkleCheckpoints.leafCount,
      createdAt: telemetryMerkleCheckpoints.createdAt,
      anchorStatus: telemetryMerkleCheckpoints.anchorStatus,
      anchorId: telemetryMerkleCheckpoints.anchorId,
      anchoredAt: telemetryMerkleCheckpoints.anchoredAt,
    }).from(telemetryMerkleCheckpoints)
      .where(eq(telemetryMerkleCheckpoints.organizationId, organizationId))
      .orderBy(desc(telemetryMerkleCheckpoints.createdAt), desc(telemetryMerkleCheckpoints.id)).limit(1),
    database.execute<{
      telemetry_retention_days: number | null; legal_hold: boolean | null;
      legal_hold_reason: string | null; legal_hold_set_at: Date | null; tombstone_count: number;
    }>(sql`
      SELECT policy.telemetry_retention_days, policy.legal_hold,
        policy.legal_hold_reason, policy.legal_hold_set_at,
        (SELECT count(*)::integer FROM telemetry_tombstones WHERE organization_id = ${organizationId}::uuid) AS tombstone_count
      FROM organizations organization
      LEFT JOIN organization_retention_policies policy ON policy.organization_id = organization.id
      WHERE organization.id = ${organizationId}::uuid
    `),
  ]);

  const normalizedSummary = summary ?? {
    totalEvents: 0,
    totalTokens: 0,
    piiPrevented: 0,
    policyViolations: 0,
    verifiedEvents: 0,
    compromisedEvents: 0,
    invalidSignatures: 0,
    firstEventAt: null,
    lastEventAt: null,
  };
  const inventory = models.map((model) => ({
    applicationId: model.applicationId,
    model: model.model,
    observedProvider: model.observedProvider,
    eventCount: model.eventCount,
    totalTokens: model.totalTokens,
    policyViolations: model.policyViolations,
    piiIncidents: model.piiIncidents,
    lastSeenAt: model.lastSeenAt,
    governance: model.governanceName && model.intendedPurpose && model.riskClass && model.systemOwner && model.legalBasis && model.humanOversight && model.systemStatus
      ? {
          name: model.governanceName, provider: model.governanceProvider,
          intendedPurpose: model.intendedPurpose, riskClass: model.riskClass,
          systemOwner: model.systemOwner, legalBasis: model.legalBasis,
          humanOversight: model.humanOversight, dataCategories: model.dataCategories ?? [],
          deploymentRegions: model.deploymentRegions ?? [], status: model.systemStatus,
        }
      : null,
  }));
  const retention = retentionResult.rows[0];
  return {
    organization,
    models: inventory,
    checkpoint: checkpoint ?? null,
    retention: retention?.telemetry_retention_days != null && retention.legal_hold != null ? {
      telemetryRetentionDays: retention.telemetry_retention_days,
      legalHold: retention.legal_hold,
      legalHoldReason: retention.legal_hold_reason,
      legalHoldSetAt: retention.legal_hold_set_at,
      tombstoneCount: retention.tombstone_count,
    } : null,
    summary: {
      ...normalizedSummary,
      chainStatus: chainStatusFor(
        normalizedSummary.totalEvents + (retention?.tombstone_count ?? 0),
        normalizedSummary.compromisedEvents,
        normalizedSummary.invalidSignatures,
      ),
      unclassifiedSystems: inventory.filter((model) => !model.governance || model.governance.riskClass === "UNCLASSIFIED").length,
    },
  };
}
