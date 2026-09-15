import "server-only";

import { asc, desc, eq, sql } from "drizzle-orm";
import { organizations, telemetryEvents, telemetryMerkleCheckpoints } from "@/db/schema";
import { getDatabase } from "@/db/client";

export type ChainStatus = "INTACT" | "ATTENTION_REQUIRED" | "NO_EVIDENCE";

export type ModelInventoryRow = {
  model: string;
  eventCount: number;
  totalTokens: number;
  policyViolations: number;
  piiIncidents: number;
  lastSeenAt: Date;
};

export type DashboardData = {
  organization: { id: string; name: string };
  models: ModelInventoryRow[];
  checkpoint: { rootHash: string; leafCount: number; createdAt: Date } | null;
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
  };
};

const modelExpression = sql<string>`coalesce(nullif(${telemetryEvents.routing}->>'model', ''), 'Okänd modell')`;
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

  const [models, [summary], [checkpoint]] = await Promise.all([
    database
      .select({
        model: modelExpression.as("model"),
        eventCount: sql<number>`count(*)::integer`.mapWith(Number),
        totalTokens: sql<number>`coalesce(sum(${tokenExpression}), 0)::bigint`.mapWith(Number),
        policyViolations:
          sql<number>`count(*) filter (where ${policyViolationExpression})::integer`.mapWith(Number),
        piiIncidents:
          sql<number>`count(*) filter (where ${piiIncidentExpression})::integer`.mapWith(Number),
        lastSeenAt: sql<Date>`max(${telemetryEvents.eventTimestamp})`.mapWith(
          telemetryEvents.eventTimestamp,
        ),
      })
      .from(telemetryEvents)
      .where(eq(telemetryEvents.organizationId, organizationId))
      .groupBy(modelExpression)
      .orderBy(asc(modelExpression)),
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
    }).from(telemetryMerkleCheckpoints)
      .where(eq(telemetryMerkleCheckpoints.organizationId, organizationId))
      .orderBy(desc(telemetryMerkleCheckpoints.createdAt), desc(telemetryMerkleCheckpoints.id)).limit(1),
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
  return {
    organization,
    models,
    checkpoint: checkpoint ?? null,
    summary: {
      ...normalizedSummary,
      chainStatus: chainStatusFor(
        normalizedSummary.totalEvents,
        normalizedSummary.compromisedEvents,
        normalizedSummary.invalidSignatures,
      ),
    },
  };
}
