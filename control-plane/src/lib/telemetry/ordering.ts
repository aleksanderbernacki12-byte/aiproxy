import type { TelemetryEvent } from "./schema";

export function findExtendingEventIndex(
  rows: Array<{ payload: Pick<TelemetryEvent, "cryptography"> }>,
  latestEventHash: string,
) {
  return rows.findIndex(
    ({ payload }) => payload.cryptography.previous_event_hash === latestEventHash,
  );
}
