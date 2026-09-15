import { describe, expect, it, vi } from "vitest";
import { calculateMerkleRoot } from "./checkpoint";

vi.mock("server-only", () => ({}));

const organizationId = "11111111-1111-1111-1111-111111111111";
const a = { key_id: "a".repeat(64), event_hash: "1".repeat(64), sequence: "3" };
const b = { key_id: "b".repeat(64), event_hash: "2".repeat(64), sequence: "7" };

describe("Merkle checkpoints", () => {
  it("is deterministic regardless of input order", () => {
    expect(calculateMerkleRoot(organizationId, [a, b])).toEqual(calculateMerkleRoot(organizationId, [b, a]));
  });

  it("binds the root to tenant, chain head, and sequence", () => {
    const root = calculateMerkleRoot(organizationId, [a]).rootHash;
    expect(root).toMatch(/^[a-f0-9]{64}$/);
    expect(calculateMerkleRoot("22222222-2222-2222-2222-222222222222", [a]).rootHash).not.toBe(root);
    expect(calculateMerkleRoot(organizationId, [{ ...a, sequence: "4" }]).rootHash).not.toBe(root);
  });

  it("rejects an empty checkpoint", () => {
    expect(() => calculateMerkleRoot(organizationId, [])).toThrow(/at least one chain head/);
  });
});
