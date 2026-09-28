# Telemetry chain recovery after a gap

Date: 2026-09-28
Status: approved direction (owner chose "flag the gap, continue", 2026-09-28)

## Purpose

Closes finding 1 of `docs/reviews/2026-09-28-control-plane-review.md`. The
worker only advances a chain head on `VERIFIED` events, so after the first
gap every later correctly signed event for that key is classified
`COMPROMISED_CHAIN` forever, and retention (which only purges events with a
chain sequence) stops for that key. A lost data-plane queue database with a
persisted signing key restarts the chain at genesis and triggers this.

## Design

All changes are in `processKeyChain` (`control-plane/src/lib/telemetry/worker.ts`)
and the retention query. No migration, no new status.

1. **Discontinuity event joins the chain.** When no buffered event extends the
   head and the oldest one is past the reorder window, and its signature and
   key validity check out, it is classified `COMPROMISED_CHAIN` as today, but
   it now receives the next `chain_sequence` and becomes the new head
   (`latestEventHash`, `sequence`, `lastEventTimestamp`). Events that extend it
   are `VERIFIED` again. One gap therefore produces exactly one
   `COMPROMISED_CHAIN` event, and "Kedjebrott" on the dashboard and in the
   report counts gaps, not every event after the first one.

2. **Gap kind in `status_reason`.** A discontinuity whose
   `previous_event_hash` is empty while the head is not is recorded as
   `chain restarted at genesis (expected <head>)`; any other as
   `previous_event_hash <x> does not match chain head <head>` (today's text).

3. **Late stragglers do not fork the chain.** A past-window event whose
   signed timestamp is not after the head's `lastEventTimestamp` is an event
   that arrived after the chain had already moved on. It is classified
   `COMPROMISED_CHAIN` with reason `arrived after the chain continued past it`,
   gets no sequence, and does not move the head.

4. **Invalid events never move the head** (unchanged): signature or key
   validity failures stay `INVALID_SIGNATURE` without a sequence.

5. **Retention.** Purge candidates are events with a `chain_sequence` (the
   `status = 'VERIFIED'` condition is dropped), still only when an anchored
   checkpoint covers the sequence. Discontinuity events are part of the
   anchored chain and age out with it; unsequenced events are unaffected.

Offline verification stays possible: walking a key's events and tombstones by
sequence, each `previous_event_hash` equals the prior event's hash except at a
`COMPROMISED_CHAIN` event, which marks a declared gap.

Existing deployments: events already stuck as `COMPROMISED_CHAIN` without a
sequence stay as they are; the first new event after deploy is one more
discontinuity and the chain recovers from there.

Out of scope: data-plane changes (the control plane now handles a genesis
restart), purging unsequenced events, and immutability of stored events
(finding 2).

## Testing

Integration tests against PostgreSQL (`telemetry-flow.integration.test.ts`
pattern), with the reorder window at 0:

- Gap: events 1, 2, then 4, 5 (3 never sent) → 1, 2 `VERIFIED`; 4
  `COMPROMISED_CHAIN` with sequence 3; 5 `VERIFIED` with sequence 4; head at 5.
- Genesis restart: after 1, 2 a new chain starting with `previous_event_hash
  = ""` → its first event is `COMPROMISED_CHAIN` with the genesis reason, the
  next is `VERIFIED`.
- Late straggler: after the gap above, event 3 arrives → `COMPROMISED_CHAIN`,
  no sequence, head still at 5.
- Invalid signature on the would-be discontinuity event → `INVALID_SIGNATURE`,
  head unchanged, the next valid event becomes the discontinuity.
- Retention purges an anchored discontinuity event and its `VERIFIED`
  successors.
