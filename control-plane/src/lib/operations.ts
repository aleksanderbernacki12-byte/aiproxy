import "server-only";

import { sql } from "drizzle-orm";
import { getDatabase } from "@/db/client";
import { telemetryBuffer, telemetryEvents } from "@/db/schema";

export type ControlPlaneMetrics = {
  bufferPending: number;
  oldestBufferedSeconds: number;
  verifiedEvents: number;
  compromisedEvents: number;
  invalidSignatureEvents: number;
};

export async function getControlPlaneMetrics(now = new Date()): Promise<ControlPlaneMetrics> {
  const database = getDatabase();
  const [[buffer], [events]] = await Promise.all([
    database.select({
      pending: sql<number>`count(*)::integer`.mapWith(Number),
      oldest: sql<Date | null>`min(${telemetryBuffer.receivedAt})`,
    }).from(telemetryBuffer),
    database.select({
      verified: sql<number>`count(*) filter (where ${telemetryEvents.status} = 'VERIFIED')::integer`.mapWith(Number),
      compromised: sql<number>`count(*) filter (where ${telemetryEvents.status} = 'COMPROMISED_CHAIN')::integer`.mapWith(Number),
      invalidSignature: sql<number>`count(*) filter (where ${telemetryEvents.status} = 'INVALID_SIGNATURE')::integer`.mapWith(Number),
    }).from(telemetryEvents),
  ]);
  const oldest = buffer?.oldest ? new Date(buffer.oldest) : null;
  return {
    bufferPending: buffer?.pending ?? 0,
    oldestBufferedSeconds: oldest ? Math.max(0, Math.floor((now.getTime() - oldest.getTime()) / 1000)) : 0,
    verifiedEvents: events?.verified ?? 0,
    compromisedEvents: events?.compromised ?? 0,
    invalidSignatureEvents: events?.invalidSignature ?? 0,
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
    "",
  ].join("\n");
}
