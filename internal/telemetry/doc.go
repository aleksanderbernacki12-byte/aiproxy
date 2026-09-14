// Package telemetry pseudonymizes client identifiers with a rotating local
// salt and asynchronously delivers signed compliance events to the control
// plane.
//
// A single sequencer commits each event and the instance's current hash-chain
// head to SQLite in one transaction. A separate sender retries ordered batches,
// keeping control-plane availability outside the LLM request path.
package telemetry
