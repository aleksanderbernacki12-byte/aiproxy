# Control Plane backup and recovery

## Automated recovery rehearsal

Run against a **disposable local PostgreSQL 17 database**, with a database role
that can create databases and apply the migrations. Use PostgreSQL 17
`pg_dump` and `pg_restore` on PATH:

```sh
cd control-plane
TEST_DATABASE_URL=postgresql://aiproxy@127.0.0.1:5432/aiproxy_test npm run test:recovery
```

This runs the signed telemetry integration fixture and takes two custom-format
backups: before retention and after verified events become tombstones. Each
backup is restored into a uniquely named new database. The test compares all
public table data and sequence state, verifies the administrative audit chain
and sealed report signatures using restored public keys, checks append-only
triggers, and appends a new audit event to the restored chain. It drops only
the temporary databases it created, including on failure. A killed process may
leave an `aiproxy_recovery_*` database for the test-environment owner to remove.

Backups remain in memory, capped at 16 MiB for these synthetic fixtures. This
is a test harness, not a production backup utility. The base integration test
creates and cleans up fixture records in the supplied source database; never
point it at a customer database.

CI runs the same rehearsal using the PostgreSQL service container's own tools
through `TEST_POSTGRES_CONTAINER`, avoiding server/client version mismatches.
No cloud credentials or external anchor are used. Anchor receipts in this test
come from an in-process signed test fixture.

## Production recovery procedure

1. Schedule encrypted backups with retention and monitoring outside the
   database host. Use `pg_dump --format=custom` with a client version compatible
   with the server. Keep credentials in a protected passfile or secret manager,
   and use private filesystem permissions for dump files. Database backups
   contain tenant metadata, credential hashes, and signed evidence.
2. Back up runtime configuration and report-signing keys separately through
   the secret manager. Public report keys are archived in PostgreSQL; private
   signing keys and session, scheduler, and anchor secrets are not. Back up
   PostgreSQL roles and permissions separately if needed: a database dump alone
   does not preserve cluster-level role definitions.
3. Restore into a **new, isolated database**, keeping the damaged database and
   logs for investigation. Use `pg_restore --exit-on-error --single-transaction`
   with an explicit destination. Do not run migrations before a full restore.
   If using `--no-owner --no-acl`, provision and verify the intended production
   ownership and access permissions separately.
4. Keep application traffic, ingestion, and scheduled workers stopped during
   validation. Check migration records, counts, chain heads, checkpoint and
   anchor receipts, sealed report signatures, retention settings, legal holds,
   and append-only triggers. Compare hashes and receipts against evidence kept
   independently of the restored database. Verify the readiness endpoint after
   restoring configuration. Apply later migrations only if intentionally
   upgrading from the backup's application version.
5. Resolve events received **after the backup** before admitting new traffic.
   Data-plane queues remove acknowledged events, so they may no longer contain
   records missing from an older backup. A later event can therefore reference
   a missing predecessor. Use an established point-in-time recovery or evidence
   recovery procedure; do not silently reset chain heads or discard the gap.
6. Record the recovery point, downtime, validation results, missing evidence,
   and approval to switch the application to the restored database. Resume
   workers and ingestion while monitoring backlog and chain alerts.

This rehearsal does not test production volume, point-in-time recovery, role
restoration, AWS KMS/S3 Object Lock, or a real independent anchor. Those require
a separate staging environment and an agreed recovery-point/recovery-time target.
