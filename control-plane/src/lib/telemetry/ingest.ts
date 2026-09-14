import { telemetryBuffer, telemetryEventIds } from "@/db/schema";
import { getDatabase } from "@/db/client";
import type { TelemetryEvent } from "./schema";

export async function bufferTelemetryEvents(events: TelemetryEvent[]) {
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const newIds = await transaction
      .insert(telemetryEventIds)
      .values(events.map((event) => ({ eventId: event.event_id })))
      .onConflictDoNothing()
      .returning({ eventId: telemetryEventIds.eventId });
    const acceptedIds = new Set(newIds.map(({ eventId }) => eventId));
    const accepted = events.filter((event) => acceptedIds.has(event.event_id));
    if (accepted.length > 0) {
      await transaction.insert(telemetryBuffer).values(
        accepted.map((event) => ({
          eventId: event.event_id,
          eventTimestamp: new Date(event.timestamp),
          keyId: event.cryptography.key_id,
          payload: event,
        })),
      );
    }
    return {
      accepted: accepted.length,
      duplicates: events.length - accepted.length,
    };
  });
}
