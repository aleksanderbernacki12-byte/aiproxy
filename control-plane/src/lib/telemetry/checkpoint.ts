import "server-only";

import { createHash } from "node:crypto";
import { asc, desc, eq, sql } from "drizzle-orm";
import { getDatabase } from "@/db/client";
import { telemetryChainHeads, telemetryMerkleCheckpoints, type MerkleCheckpointHead } from "@/db/schema";

const LEAF_DOMAIN = Buffer.from("aiproxy-merkle-leaf-v1\0");
const NODE_DOMAIN = Buffer.from("aiproxy-merkle-node-v1\0");

function digest(...parts: Uint8Array[]): Uint8Array {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
}

export function calculateMerkleRoot(organizationId: string, input: MerkleCheckpointHead[]) {
  if (input.length === 0) throw new Error("A Merkle checkpoint requires at least one chain head");
  const heads = [...input].sort((a, b) => a.key_id.localeCompare(b.key_id));
  let level = heads.map((head) => digest(
    LEAF_DOMAIN,
    Buffer.from(organizationId, "utf8"),
    Buffer.from(head.key_id, "hex"),
    Buffer.from(head.event_hash, "hex"),
    Buffer.from(head.sequence, "utf8"),
  ));
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      const right = level[index + 1] ?? left;
      next.push(digest(NODE_DOMAIN, left, right));
    }
    level = next;
  }
  return { rootHash: Buffer.from(level[0]).toString("hex"), heads };
}

async function checkpointOrganization(organizationId: string) {
  return getDatabase().transaction(async (transaction) => {
    await transaction.execute(sql`SELECT pg_advisory_xact_lock(hashtextextended(${"merkle:" + organizationId}, 0))`);
    const rows = await transaction.select({
      keyId: telemetryChainHeads.keyId,
      eventHash: telemetryChainHeads.latestEventHash,
      sequence: telemetryChainHeads.sequence,
    }).from(telemetryChainHeads)
      .where(eq(telemetryChainHeads.organizationId, organizationId))
      .orderBy(asc(telemetryChainHeads.keyId));
    if (rows.length === 0) return false;
    const checkpoint = calculateMerkleRoot(organizationId, rows.map((row) => ({
      key_id: row.keyId, event_hash: row.eventHash, sequence: row.sequence.toString(),
    })));
    const [latest] = await transaction.select({ rootHash: telemetryMerkleCheckpoints.rootHash })
      .from(telemetryMerkleCheckpoints)
      .where(eq(telemetryMerkleCheckpoints.organizationId, organizationId))
      .orderBy(desc(telemetryMerkleCheckpoints.createdAt), desc(telemetryMerkleCheckpoints.id)).limit(1);
    if (latest?.rootHash === checkpoint.rootHash) return false;
    await transaction.insert(telemetryMerkleCheckpoints).values({
      organizationId, rootHash: checkpoint.rootHash, leafCount: checkpoint.heads.length, chainHeads: checkpoint.heads,
    }).onConflictDoNothing();
    return true;
  });
}

export async function createMerkleCheckpoints() {
  const organizations = await getDatabase().selectDistinct({ organizationId: telemetryChainHeads.organizationId }).from(telemetryChainHeads);
  let created = 0;
  for (const { organizationId } of organizations) if (await checkpointOrganization(organizationId)) created += 1;
  return { organizations: organizations.length, created };
}
