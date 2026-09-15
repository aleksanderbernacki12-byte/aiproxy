import "server-only";

import { createPublicKey, verify } from "node:crypto";
import canonicalize from "canonicalize";
import { asc, eq, sql } from "drizzle-orm";
import { z } from "zod";
import { getDatabase } from "@/db/client";
import { telemetryMerkleCheckpoints } from "@/db/schema";

const MAX_BATCH = 5;
const RECEIPT_DOMAIN = Buffer.from("aiproxy-merkle-anchor-receipt-v1\0");
const receiptSchema = z.object({
  anchor_id: z.string().min(1).max(240),
  checkpoint_id: z.string().regex(/^[1-9][0-9]*$/),
  root_hash: z.string().regex(/^[a-f0-9]{64}$/),
  anchored_at: z.iso.datetime({ offset: true }),
  signature_algorithm: z.literal("Ed25519"),
  signature: z.string().min(40).max(256).regex(/^[A-Za-z0-9+/]+={0,2}$/),
}).strict();

export type AnchorReceipt = z.infer<typeof receiptSchema>;

export function anchorReceiptSigningBytes(receipt: AnchorReceipt) {
  const canonical = canonicalize({ ...receipt, signature: "" });
  if (!canonical) throw new Error("Anchor receipt cannot be canonicalized");
  return Buffer.concat([RECEIPT_DOMAIN, Buffer.from(canonical)]);
}

export function verifyAnchorReceipt(input: unknown, publicKeyPem: string, checkpointId: string, rootHash: string) {
  const parsed = receiptSchema.safeParse(input);
  if (!parsed.success) return { ok: false as const, reason: "Anchor returned an invalid receipt" };
  const receipt = parsed.data;
  if (receipt.checkpoint_id !== checkpointId || receipt.root_hash !== rootHash) {
    return { ok: false as const, reason: "Anchor receipt does not match the checkpoint" };
  }
  try {
    const key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== "ed25519") return { ok: false as const, reason: "Anchor receipt key must be Ed25519" };
    const valid = verify(null, anchorReceiptSigningBytes(receipt), key, Buffer.from(receipt.signature, "base64"));
    return valid ? { ok: true as const, receipt } : { ok: false as const, reason: "Anchor receipt signature is invalid" };
  } catch {
    return { ok: false as const, reason: "Anchor receipt verification failed" };
  }
}

function anchorConfig() {
  const endpoint = process.env.MERKLE_ANCHOR_URL;
  const token = process.env.MERKLE_ANCHOR_TOKEN;
  const publicKey = process.env.MERKLE_ANCHOR_PUBLIC_KEY;
  if (!endpoint || !token || !publicKey) return null;
  const url = new URL(endpoint);
  if (url.protocol !== "https:" && process.env.NODE_ENV === "production") throw new Error("MERKLE_ANCHOR_URL must use HTTPS");
  return { url, token, publicKey: publicKey.replaceAll("\\n", "\n") };
}

export async function anchorPendingCheckpoints(fetcher: typeof fetch = fetch) {
  const config = anchorConfig();
  if (!config) return { configured: false, attempted: 0, anchored: 0, failed: 0 };
  const database = getDatabase();
  const checkpoints = await database.select({
    id: telemetryMerkleCheckpoints.id,
    rootHash: telemetryMerkleCheckpoints.rootHash,
    leafCount: telemetryMerkleCheckpoints.leafCount,
    createdAt: telemetryMerkleCheckpoints.createdAt,
  }).from(telemetryMerkleCheckpoints)
    .where(eq(telemetryMerkleCheckpoints.anchorStatus, "PENDING"))
    .orderBy(asc(telemetryMerkleCheckpoints.createdAt), asc(telemetryMerkleCheckpoints.id)).limit(MAX_BATCH);
  let anchored = 0;
  let failed = 0;
  for (const checkpoint of checkpoints) {
    const checkpointId = checkpoint.id.toString();
    const outcome = await database.transaction(async (transaction) => {
      const lock = await transaction.execute<{ anchor_status: string }>(sql`
        SELECT anchor_status FROM telemetry_merkle_checkpoints
        WHERE id = ${checkpoint.id} FOR UPDATE
      `);
      if (lock.rows[0]?.anchor_status !== "PENDING") return "skipped" as const;
      try {
        const response = await fetcher(config.url, {
          method: "POST",
          headers: { authorization: `Bearer ${config.token}`, "content-type": "application/json", "idempotency-key": `aiproxy-checkpoint-${checkpointId}` },
          body: JSON.stringify({
            checkpoint_id: checkpointId,
            root_hash: checkpoint.rootHash,
            hash_algorithm: "SHA-256",
            leaf_count: checkpoint.leafCount,
            created_at: checkpoint.createdAt.toISOString(),
          }),
          signal: AbortSignal.timeout(5_000),
        });
        if (!response.ok) throw new Error(`Anchor returned HTTP ${response.status}`);
        const verification = verifyAnchorReceipt(await response.json(), config.publicKey, checkpointId, checkpoint.rootHash);
        if (!verification.ok) throw new Error(verification.reason);
        const anchoredAt = new Date(verification.receipt.anchored_at);
        if (anchoredAt < checkpoint.createdAt || anchoredAt.getTime() > Date.now() + 5 * 60_000) {
          throw new Error("Anchor receipt timestamp is outside the accepted interval");
        }
        await transaction.update(telemetryMerkleCheckpoints).set({
          anchorStatus: "ANCHORED",
          anchorAttempts: sql`${telemetryMerkleCheckpoints.anchorAttempts} + 1`,
          anchorLastError: null,
          anchorId: verification.receipt.anchor_id,
          anchoredAt,
          anchorReceipt: verification.receipt,
        }).where(eq(telemetryMerkleCheckpoints.id, checkpoint.id));
        return "anchored" as const;
      } catch (error) {
        await transaction.update(telemetryMerkleCheckpoints).set({
          anchorAttempts: sql`${telemetryMerkleCheckpoints.anchorAttempts} + 1`,
          anchorLastError: error instanceof Error ? error.message.slice(0, 500) : "External anchoring failed",
        }).where(eq(telemetryMerkleCheckpoints.id, checkpoint.id));
        return "failed" as const;
      }
    });
    if (outcome === "anchored") anchored += 1;
    if (outcome === "failed") failed += 1;
  }
  return { configured: true, attempted: checkpoints.length, anchored, failed };
}
