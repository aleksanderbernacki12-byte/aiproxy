import "server-only";

import { sql } from "drizzle-orm";
import { getDatabase } from "@/db/client";
import { telemetryBuffer, telemetryEvents, telemetryMerkleCheckpoints } from "@/db/schema";

export type ControlPlaneMetrics = {
  bufferPending: number;
  oldestBufferedSeconds: number;
  verifiedEvents: number;
  compromisedEvents: number;
  invalidSignatureEvents: number;
  pendingAnchors: number;
  oldestPendingAnchorSeconds: number;
  brokenSecurityAuditChains: number;
};

export async function getControlPlaneMetrics(now = new Date()): Promise<ControlPlaneMetrics> {
  const database = getDatabase();
  const [[buffer], [events], [anchors], auditChains] = await Promise.all([
    database.select({
      pending: sql<number>`count(*)::integer`.mapWith(Number),
      oldest: sql<Date | null>`min(${telemetryBuffer.receivedAt})`,
    }).from(telemetryBuffer),
    database.select({
      verified: sql<number>`count(*) filter (where ${telemetryEvents.status} = 'VERIFIED')::integer`.mapWith(Number),
      compromised: sql<number>`count(*) filter (where ${telemetryEvents.status} = 'COMPROMISED_CHAIN')::integer`.mapWith(Number),
      invalidSignature: sql<number>`count(*) filter (where ${telemetryEvents.status} = 'INVALID_SIGNATURE')::integer`.mapWith(Number),
    }).from(telemetryEvents),
    database.select({
      pending: sql<number>`count(*) filter (where ${telemetryMerkleCheckpoints.anchorStatus} = 'PENDING')::integer`.mapWith(Number),
      oldest: sql<Date | null>`min(${telemetryMerkleCheckpoints.createdAt}) filter (where ${telemetryMerkleCheckpoints.anchorStatus} = 'PENDING')`,
    }).from(telemetryMerkleCheckpoints),
    database.execute<{ broken: number }>(sql`
      SELECT count(*) filter (where not verify_security_audit_chain(organization_id))::integer AS broken
      FROM security_audit_heads
    `),
  ]);
  const oldest = buffer?.oldest ? new Date(buffer.oldest) : null;
  const oldestAnchor = anchors?.oldest ? new Date(anchors.oldest) : null;
  return {
    bufferPending: buffer?.pending ?? 0,
    oldestBufferedSeconds: oldest ? Math.max(0, Math.floor((now.getTime() - oldest.getTime()) / 1000)) : 0,
    verifiedEvents: events?.verified ?? 0,
    compromisedEvents: events?.compromised ?? 0,
    invalidSignatureEvents: events?.invalidSignature ?? 0,
    pendingAnchors: anchors?.pending ?? 0,
    oldestPendingAnchorSeconds: oldestAnchor ? Math.max(0, Math.floor((now.getTime() - oldestAnchor.getTime()) / 1000)) : 0,
    brokenSecurityAuditChains: auditChains.rows[0]?.broken ?? 0,
  };
}

export function formatControlPlaneMetrics(metrics: ControlPlaneMetrics) {
  return [
    "# HELP aiproxy_control_plane_buffer_pending Telemetry events currently waiting for ordered verification.",
    "# TYPE aiproxy_control_plane_buffer_pending gauge",
    `aiproxy_control_plane_buffer_pending ${metrics.bufferPending}`,
    "# HELP aiproxy_control_plane_oldest_buffered_seconds Age in seconds of the oldest buffered telemetry event.",
    "# TYPE aiproxy_control_plane_oldest_buffered_seconds gauge",
    `aiproxy_control_plane_oldest_buffered_seconds ${metrics.oldestBufferedSeconds}`,
    "# HELP aiproxy_control_plane_verified_events_total Telemetry events accepted into verified chains.",
    "# TYPE aiproxy_control_plane_verified_events_total counter",
    `aiproxy_control_plane_verified_events_total ${metrics.verifiedEvents}`,
    "# HELP aiproxy_control_plane_compromised_events_total Telemetry events classified as compromised chain links.",
    "# TYPE aiproxy_control_plane_compromised_events_total counter",
    `aiproxy_control_plane_compromised_events_total ${metrics.compromisedEvents}`,
    "# HELP aiproxy_control_plane_invalid_signature_events_total Telemetry events rejected for invalid cryptographic evidence.",
    "# TYPE aiproxy_control_plane_invalid_signature_events_total counter",
    `aiproxy_control_plane_invalid_signature_events_total ${metrics.invalidSignatureEvents}`,
    "# HELP aiproxy_control_plane_pending_merkle_anchors Merkle checkpoints awaiting a verified external receipt.",
    "# TYPE aiproxy_control_plane_pending_merkle_anchors gauge",
    `aiproxy_control_plane_pending_merkle_anchors ${metrics.pendingAnchors}`,
    "# HELP aiproxy_control_plane_oldest_pending_anchor_seconds Age in seconds of the oldest checkpoint awaiting external anchoring.",
    "# TYPE aiproxy_control_plane_oldest_pending_anchor_seconds gauge",
    `aiproxy_control_plane_oldest_pending_anchor_seconds ${metrics.oldestPendingAnchorSeconds}`,
    "# HELP aiproxy_control_plane_broken_security_audit_chains Administrative audit chains that fail complete verification.",
    "# TYPE aiproxy_control_plane_broken_security_audit_chains gauge",
    `aiproxy_control_plane_broken_security_audit_chains ${metrics.brokenSecurityAuditChains}`,
    "",
  ].join("\n");
}
