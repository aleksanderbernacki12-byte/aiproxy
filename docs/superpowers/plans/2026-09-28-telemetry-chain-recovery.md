# Telemetry Chain Recovery — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A gap in a telemetry chain is flagged once, and verification and retention continue after it.

**Architecture:** `processKeyChain` (`control-plane/src/lib/telemetry/worker.ts`) gives a past-window discontinuity event the next sequence and makes it the head, classifies late stragglers without moving the head, and names genesis restarts in `status_reason`. Retention selects events by `chain_sequence` instead of `status = 'VERIFIED'`.

**Tech Stack:** Next.js route handlers, Drizzle, PostgreSQL, Vitest. Spec: `docs/superpowers/specs/2026-09-28-telemetry-chain-recovery-design.md`. Branch: `fix/telemetry-chain-recovery`.

Local PostgreSQL for integration tests:

```sh
docker run -d --rm --name aiproxy-cp-test -e POSTGRES_USER=aiproxy -e POSTGRES_PASSWORD=test -e POSTGRES_DB=aiproxy_test -p 55432:5432 postgres:17-alpine
export TEST_DATABASE_URL=postgresql://aiproxy:test@localhost:55432/aiproxy_test
```

Verification before each commit (in `control-plane/`): `npm run lint && npm test && npm run typecheck && npm run test:integration`.

---

### Task 1: Failing integration tests

**Files:** create `control-plane/src/integration/chain-recovery.integration.test.ts`.

- [ ] Own organization and signing key (same setup/teardown pattern as `telemetry-flow.integration.test.ts`: apply migrations, insert organization, `telemetry_public_keys` row; delete everything for the org in `afterAll`, tombstones under `aiproxy.audit_maintenance`).
- [ ] Helper `signedEvent(timestamp, previousHash)` returning a signed `TelemetryEvent` with a random `event_id`; helper `ingest(events)` inserting through `bufferTelemetryEvents(organizationId, events)`; helper `process()` calling `processBufferedTelemetry(new Date(Date.now() + 3_600_000))` so every buffered row is past the reorder window.
- [ ] Test "gap": ingest e1, e2 (chained), process; ingest e4 (previous = hash of an e3 that is never sent), e5 (previous = e4); process. Expect statuses/sequences e1 VERIFIED 1, e2 VERIFIED 2, e4 COMPROMISED_CHAIN 3 with reason matching `/does not match chain head/`, e5 VERIFIED 4; `telemetry_chain_heads.latest_event_hash` = e5 hash, sequence 4.
- [ ] Test "late straggler" (continues the chain above): ingest e3 (previous = e2, timestamp between e2 and e4); process. Expect e3 COMPROMISED_CHAIN, `chain_sequence` null, reason `/arrived after the chain continued/`; head unchanged.
- [ ] Test "genesis restart" (new key, own chain): g1, g2 processed; then r1 (previous = "") and r2 (previous = r1), later timestamps; process. Expect r1 COMPROMISED_CHAIN sequence 3, reason `/chain restarted at genesis/`; r2 VERIFIED 4.
- [ ] Test "invalid discontinuity": new key; k1 processed; then x (previous = unknown hash, signed by a different private key, earliest timestamp) and y (previous = unknown hash, valid); process. Expect x INVALID_SIGNATURE no sequence, y COMPROMISED_CHAIN sequence 2.
- [ ] Test "retention": for the gap key, insert an `ANCHORED` `telemetry_merkle_checkpoints` row whose `chain_heads` covers sequence 4, a retention policy of 30 days, and run `enforceRetentionPolicies` with `now` 60 days after the events. Expect e1, e2, e4, e5 purged (tombstones exist), e3 (unsequenced) kept.
- [ ] Run `npm run test:integration`: the new tests fail (e5 is COMPROMISED_CHAIN; e4 has no sequence; retention keeps e4).
- [ ] Commit: `test(control-plane): cover telemetry chain gaps` — together with Task 2 if the repo requires green commits; otherwise alone.

### Task 2: Worker recovery

**Files:** `control-plane/src/lib/telemetry/worker.ts`.

- [ ] In the `rowIndex < 0` past-window branch, after verification succeeds:
  - if `lastEventTimestamp` is set and `new Date(payload.timestamp) <= lastEventTimestamp`: status `COMPROMISED_CHAIN`, reason `arrived after the chain continued past it (head ${latestEventHash})`, no sequence, head unchanged;
  - otherwise: status `COMPROMISED_CHAIN`, reason `chain restarted at genesis (expected ${latestEventHash})` when `previous_event_hash === ""` and `latestEventHash !== ""`, else the existing mismatch text; `sequence += 1n`, `eventSequence = sequence`, `latestEventHash = event_hash`, `lastEventTimestamp = payload timestamp`.
- [ ] Persist the head when any event got a sequence (today: only when `verified > 0`): track `headMoved` and use it in the final upsert condition.
- [ ] `npm run test:integration`: gap, straggler, genesis, invalid tests pass.
- [ ] Commit: `fix(control-plane): recover the telemetry chain after a gap`.

### Task 3: Retention

**Files:** `control-plane/src/lib/retention.ts`.

- [ ] Replace `AND event.status = 'VERIFIED' AND event.chain_sequence IS NOT NULL` with `AND event.chain_sequence IS NOT NULL`.
- [ ] `npm run test:integration`: retention test passes; existing retention test in `telemetry-flow` still passes.
- [ ] Commit: `fix(control-plane): age out chain discontinuity events with their chain`.

### Task 4: Docs and verification

- [ ] `control-plane/README.md`: where it describes `TELEMETRY_REORDER_WINDOW_SECONDS`/compromised classification, state that a gap is flagged once on the first event after it and the chain continues; late events are flagged without sequence.
- [ ] Mark finding 1 as addressed in `docs/reviews/2026-09-28-control-plane-review.md` (one line under the finding).
- [ ] Full verification command above green; `git status` clean.
- [ ] Commit: `docs: describe telemetry chain recovery`.
