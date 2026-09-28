# Control Plane review, P3 findings

Date: 2026-09-28
Status: approved (owner, 2026-09-28)

Findings 6–9 of `docs/reviews/2026-09-28-control-plane-review.md`. Each ships
as its own commit.

## 9. Ingest JSON nesting depth

`jsonValueSchema` recurses without a depth limit, so deeply nested JSON inside
the 1 MiB body can overflow the stack during validation and answer 500. The
ingest route rejects a body nested deeper than 32 levels with 400 before
schema validation, using an iterative depth check exported from
`lib/telemetry/schema.ts`. Test: 10 000 nested arrays inside `metrics` → 400,
nothing buffered.

## 7. Anchor queue head-of-line

`anchorPendingCheckpoints` always takes the five oldest pending checkpoints,
so five that fail permanently block every newer one, and retention (which
requires `ANCHORED`) stops. Pending checkpoints are now ordered by
`anchor_attempts`, then age: a failing checkpoint moves behind fresh ones
while still being retried. Test: five pending checkpoints with high attempt
counts and one new one → the new one is attempted.

## 6. Server-side logout

The session is a signed cookie valid for eight hours; logout only clears it
in the browser. `dpo_access_keys` gains `session_version integer NOT NULL
DEFAULT 0` (migration 0018). A session carries the version it was issued
with (tokens without one count as 0); `validateDPOIdentity` also requires the
current version. Logout with a valid session increments the version inside
the organization's context and records `DASHBOARD_SESSION_ENDED` in the audit
ledger, then clears the cookie. This ends every session of that access key,
the same as revoking and reissuing it but without a new key. Tests: a session
stops validating after logout; logout without a valid cookie still clears it.

## 8. Data plane: permanent rejections

The Go sender retries every non-2xx response, so one event the control plane
rejects with 400 blocks the queue forever. Now a 400, 413 or 422 response for
a batch re-sends it one event at a time in queue order (simpler than bisecting
and keeps chain order; rejections are rare); a single event that is still
rejected is moved to a `telemetry_rejected` table (payload, status,
time) and removed from the queue, and a `rejected` counter is exposed next to
the existing delivery counters. Other statuses (401, 403, 408, 429, 5xx) are
retried as today. The control plane classifies the resulting gap in the chain
as a declared gap. Test: a batch of three where the server rejects any batch
containing event 2 → events 1 and 3 delivered, event 2 in
`telemetry_rejected`, queue empty.
