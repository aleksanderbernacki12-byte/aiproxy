# Demo anchor

A stand-in for the independent append-only anchor that the Control Plane
requires (`MERKLE_ANCHOR_URL`). It implements the receipt protocol described in
[control-plane/README.md](../../control-plane/README.md#merkle-checkpoints) and
signs each checkpoint with its own Ed25519 key.

It stores nothing and runs under the same operator as the demo Control Plane, so
it demonstrates the protocol, not independence. Production needs a separately
operated append-only ledger.

Deploy as its own Vercel project with root directory `demo/anchor`. The endpoint
is `https://<deployment>/api/checkpoints`. Environment:

- `ANCHOR_TOKEN`: at least 32 random characters; the Control Plane's
  `MERKLE_ANCHOR_TOKEN`.
- `ANCHOR_PRIVATE_KEY`: PEM-encoded Ed25519 private key (`\n` escapes allowed).
  Its public key is the Control Plane's `MERKLE_ANCHOR_PUBLIC_KEY`.

`control-plane/src/lib/telemetry/demo-anchor.test.ts` checks that its receipts
pass the Control Plane's verification.
