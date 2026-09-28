import { generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { POST, signReceipt } from "../../../../demo/anchor/api/checkpoints.mjs";

vi.mock("server-only", () => ({}));
import { verifyAnchorReceipt } from "./anchor";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const checkpoint = { checkpoint_id: "42", root_hash: "a".repeat(64), hash_algorithm: "SHA-256", leaf_count: 1, created_at: new Date().toISOString() };
const token = "t".repeat(32);

function anchorRequest(body: unknown, authorization = `Bearer ${token}`) {
  return new Request("https://anchor.test/api/checkpoints", {
    method: "POST", headers: { authorization, "content-type": "application/json" }, body: JSON.stringify(body),
  });
}

describe("demo anchor", () => {
  afterEach(() => vi.unstubAllEnvs());

  it("signs receipts the control plane accepts", () => {
    const receipt = signReceipt(checkpoint, privatePem);
    expect(verifyAnchorReceipt(receipt, publicPem, "42", "a".repeat(64)).ok).toBe(true);
    expect(signReceipt(checkpoint, privatePem).anchor_id).toBe(receipt.anchor_id);
  });

  it("answers an authorized request with a verifiable receipt", async () => {
    vi.stubEnv("ANCHOR_TOKEN", token);
    vi.stubEnv("ANCHOR_PRIVATE_KEY", privatePem.replaceAll("\n", "\\n"));
    const response = await POST(anchorRequest(checkpoint));
    expect(response.status).toBe(200);
    expect(verifyAnchorReceipt(await response.json(), publicPem, "42", "a".repeat(64)).ok).toBe(true);
  });

  it("rejects a wrong token and a malformed checkpoint", async () => {
    vi.stubEnv("ANCHOR_TOKEN", token);
    vi.stubEnv("ANCHOR_PRIVATE_KEY", privatePem);
    expect((await POST(anchorRequest(checkpoint, `Bearer ${"x".repeat(32)}`))).status).toBe(401);
    expect((await POST(anchorRequest({ ...checkpoint, root_hash: "not-hex" }))).status).toBe(400);
  });

  it("refuses to run without configuration", async () => {
    vi.stubEnv("ANCHOR_TOKEN", "");
    expect((await POST(anchorRequest(checkpoint))).status).toBe(503);
  });
});
