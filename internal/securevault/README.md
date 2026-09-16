# Secure vault

`securevault` archives complete, unredacted HTTP exchanges inside the customer's
data plane. It does not depend on the proxy, routing, or cache packages.
When used through the compliance coordinator, reusable credentials and cookies
in HTTP headers are replaced with `[REDACTED_SECRET]` before capture. Request
and response bodies remain original for authorized investigations.

## Storage flow

1. `StoreAsync` validates the UUID and places the request and response in a
   bounded channel without waiting for AWS or disk I/O.
2. A worker captures both bodies and writes an AES-256-GCM-encrypted spool file
   before attempting any AWS operation.
3. AWS KMS `GenerateDataKey` returns an AES-256 plaintext data key and an
   encrypted copy. The plaintext key encrypts the archive in memory and is then
   cleared on a best-effort basis.
4. The encrypted archive and encrypted data key are uploaded to S3. The final
   path is `<prefix>/<event_id>` and every upload requests `COMPLIANCE` Object
   Lock for five calendar years from the successful attempt.
5. Failed KMS or S3 attempts remain in the encrypted spool and retry with capped
   exponential backoff. Spool files survive process restarts.

The customer must supply the KMS key, S3 bucket, AWS credentials, and a stable
32-byte `SpoolKey`. The spool key belongs in the customer's secret manager. It
must not be sent to the control plane or regenerated while retry files exist.

The S3 bucket must have Object Lock and versioning enabled. The data-plane IAM
identity needs `kms:GenerateDataKey`, `s3:PutObject`, and
`s3:PutObjectRetention` for the configured resources.

## CLI configuration

`aiproxy start` enables the vault when both `-secure-vault-kms-key-id` and
`-secure-vault-s3-bucket` are set. AWS credentials and the default region use
the AWS SDK credential/configuration chain; `-secure-vault-aws-region` can
override the resolved region. The encrypted retry queue defaults to
`.aiproxy_securevault` and can be moved with `-secure-vault-spool-dir`.

The stable spool key must be supplied as a base64-encoded 32-byte value in
`AIPROXY_SECUREVAULT_SPOOL_KEY`. It is deliberately not available as a CLI
flag. Generate and retain it in the customer's secret manager, for example:

```sh
openssl rand -base64 32
```

`-secure-vault-s3-prefix` optionally places evidence below a customer-selected
object prefix. KMS/S3 failures remain on the encrypted local queue and never
block or fail the LLM response.

## Call contract

Call `StoreAsync` only after the HTTP response has been delivered. A successful
return transfers ownership of both bodies to the vault; the caller must not
read or close them concurrently. A `false` return means that the record was not
accepted, most commonly because the bounded queue is full or shutdown has
started. The caller should turn this into a local operational alert without
delaying the LLM response.

`Shutdown` stops new submissions and drains accepted in-memory work to S3 or the
encrypted disk spool. Pass a bounded context during graceful process shutdown.

Delivery is at least once. If S3 stores an object but the client cannot observe
the success response, the retry may create another Object-Locked version with
the same event ID. Consumers should use the event ID as the logical identity.

`Vault.Snapshot()` exposes non-blocking aggregate health: accepted and dropped
submissions, memory queue depth, encrypted spool backlog, quarantined entries,
local and AWS upload failures, completed uploads, and latest outcome times.
Through the compliance recorder these values appear under
`compliance.secure_vault` in `GET /_aiproxy/stats`; raw evidence and secrets
are never included.

## Investigation export

`aiproxy vault-export` retrieves one event from the customer bucket, asks the
customer KMS to decrypt its DEK with the stored encryption context, verifies
the AES-GCM tag and archive identity, and writes the raw JSON to a new `0600` (Unix)
file. It refuses to overwrite an existing file. Run this only inside the
customer-controlled investigation environment:

```sh
aiproxy vault-export -event-id <uuid> -s3-bucket <bucket> \
  -s3-prefix <prefix> -aws-region eu-north-1 -output ./evidence.json
```
