# Compliance pipeline alert runbook

These alerts monitor evidence delivery. LLM traffic remains fail-open during
compliance subsystem failures, so an alert requires operational follow-up even
when the proxy itself is serving requests normally.

## Telemetry dropped or persistence failed

Check free disk space, ownership and permissions for the telemetry SQLite path,
then inspect local Aiproxy error logs. Preserve the SQLite file and signing key.
Do not restart repeatedly or delete queue files while investigating. A dropped
event was never admitted to the durable chain and must be recorded as an
evidence gap.

## Telemetry delivery backlog

Check connectivity, TLS and DNS to the Control Plane, then verify
`AIPROXY_TENANT_KEY`. HTTP 401 responses indicate an invalid or rotated tenant
credential. Confirm that pending events decrease after connectivity returns;
the sender retains order and retries automatically.

## Secure Vault backlog or upload failure

Check AWS credential resolution, KMS permissions, S3 permissions, region, and
whether Object Lock is enabled on the bucket. Keep
`AIPROXY_SECUREVAULT_SPOOL_KEY` unchanged while spool entries exist. Confirm
that `spool_pending` decreases after AWS recovers.

## Secure Vault local failure or quarantine

Check disk capacity and permissions on the spool directory. Preserve all
`.work`, `.retry`, and `.corrupt` files. A quarantined entry could not be
authenticated or decoded with the configured spool key; investigate key
rotation or file corruption before attempting recovery.

## Control Plane buffer delay

Verify that the scheduled worker calls `/api/internal/telemetry/process` with
the configured `CRON_SECRET`. Check Postgres connectivity, worker logs, public
key registration, and whether a chain predecessor is still within the reorder
window.

## Compromised chain or invalid signature

Treat the event as evidence requiring investigation. Identify the organization
and data-plane `key_id` in the database, preserve the affected rows and logs,
and compare the registered public key with the customer instance. Do not alter
the chain head or reclassify the event before the investigation is documented.

## External Merkle anchoring delay

Check HTTPS and DNS connectivity to `MERKLE_ANCHOR_URL`, then verify the
dedicated bearer credential and Ed25519 public receipt key. Inspect
`anchor_last_error` without deleting pending checkpoints. After recovery,
invoke `/api/internal/telemetry/anchor` with `CRON_SECRET` and confirm both the
pending count and oldest age decrease. Preserve rejected receipts and anchor
provider logs if the root, checkpoint ID, or signature did not verify.

## Installation

Load `deploy/prometheus/aiproxy-alerts.yml` through Prometheus `rule_files` and
route `severity: critical` to the compliance/security on-call path. Tune only
the backlog thresholds to measured traffic volume; alerts for dropped events,
local persistence failures, quarantine, compromised chains, and invalid
signatures should remain zero-tolerance.
