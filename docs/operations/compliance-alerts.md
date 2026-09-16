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

## Telemetry storage budget

Compare `aiproxy_telemetry_database_used_bytes` with
`aiproxy_telemetry_database_limit_bytes`, and check actual free disk space.
The default SQLite budget is 256 MiB; configure `--telemetry-max-db-bytes`
to increase it, allowing additional disk space for the rollback journal
(at least twice the budget plus filesystem overhead). Restart with the same
database and signing key after changing the budget.

Restore delivery to release pages occupied by queued payloads. The file can
remain large because free pages are reused; use the used-bytes metric for the
capacity alert. The permanent deduplication ledger also consumes the budget
and is never automatically purged. Do not delete it or discard queued evidence.
When storage is full, new events are lost before joining the durable hash
chain; document the evidence gap even when later deliveries succeed. Storage
failure counters reset on restart, so retain the monitoring history.

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

## PII redaction spike

Confirm whether the affected route recently changed its clients, prompt
templates, or workload. Compare the aggregate model and application inventory
in the Control Plane with the deployment timeline. Do not add prompt contents,
matched values, or long-lived client identifiers to metrics or alert labels.
If the increase is expected, tune both the minimum event count and percentage
threshold for that environment; retaining both conditions prevents low-volume
routes from alerting on a single redaction.

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

## Administrative audit chain broken

Treat this as a possible Control Plane integrity incident. Restrict database
write access, preserve database and application logs, and take a consistent
backup before investigating. Compare the affected organization's event hashes,
sequence links, and stored chain head with its latest independently retained
sealed compliance report. Do not enable `aiproxy.audit_maintenance` or repair
rows until the original evidence and incident timeline have been preserved.

## Installation

Load `deploy/prometheus/aiproxy-alerts.yml` through Prometheus `rule_files` and
route `severity: critical` to the compliance/security on-call path. Tune only
the backlog and PII-spike thresholds to measured traffic volume; alerts for
dropped events, local persistence failures, quarantine, compromised chains,
and invalid signatures should remain zero-tolerance. Administrative
audit-chain failures must also remain zero-tolerance.
