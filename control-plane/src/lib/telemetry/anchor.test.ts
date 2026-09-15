import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { anchorReceiptSigningBytes, verifyAnchorReceipt, type AnchorReceipt } from "./anchor";

vi.mock("server-only", () => ({}));

function signedReceipt() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const receipt: AnchorReceipt = {
    anchor_id: "independent-ledger-42",
    checkpoint_id: "42",
    root_hash: "a".repeat(64),
    anchored_at: "2026-09-15T18:00:00.000Z",
    signature_algorithm: "Ed25519",
    signature: "placeholder-signature-value-long-enough",
  };
  receipt.signature = sign(null, anchorReceiptSigningBytes(receipt), privateKey).toString("base64");
  return { receipt, publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
}

describe("external Merkle anchor receipts", () => {
  it("verifies a matching Ed25519 receipt", () => {
    const { receipt, publicKeyPem } = signedReceipt();
    expect(verifyAnchorReceipt(receipt, publicKeyPem, "42", "a".repeat(64))).toMatchObject({ ok: true });
  });

  it("rejects a mismatched checkpoint and tampered receipt", () => {
    const { receipt, publicKeyPem } = signedReceipt();
    expect(verifyAnchorReceipt(receipt, publicKeyPem, "43", receipt.root_hash).ok).toBe(false);
    expect(verifyAnchorReceipt({ ...receipt, anchored_at: "2026-09-16T18:00:00.000Z" }, publicKeyPem, "42", receipt.root_hash).ok).toBe(false);
  });

  it("rejects malformed receipts and non-Ed25519 keys", () => {
    const { receipt } = signedReceipt();
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    expect(verifyAnchorReceipt({}, "invalid", "42", receipt.root_hash).ok).toBe(false);
    expect(verifyAnchorReceipt(receipt, publicKey.export({ type: "spki", format: "pem" }).toString(), "42", receipt.root_hash).ok).toBe(false);
  });
});
