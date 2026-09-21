import { createHash, generateKeyPairSync, sign } from "node:crypto";
import canonicalize from "canonicalize";
import { describe, expect, it, vi } from "vitest";
import { verifySealedReport, type SealedReport } from "./compliance-report";

vi.mock("server-only", () => ({}));
vi.mock("@/db/client", () => ({ getDatabase: vi.fn() }));

describe("sealed compliance reports", () => {
  it("verifies the payload hash, key fingerprint, and Ed25519 signature", () => {
    const keys = generateKeyPairSync("ed25519");
    const payload = { schema_version: "aiproxy-compliance-report-v1", total_events: 2 };
    const canonical = Buffer.from(canonicalize(payload)!);
    const report: SealedReport = {
      report_id: "11111111-1111-1111-1111-111111111111",
      payload,
      payload_hash: createHash("sha256").update(canonical).digest("hex"),
      signature_algorithm: "Ed25519",
      signing_key_id: createHash("sha256").update(keys.publicKey.export({ type: "spki", format: "der" })).digest("hex"),
      signature: sign(null, Buffer.concat([Buffer.from("aiproxy-compliance-report-v1\0"), canonical]), keys.privateKey).toString("base64"),
      created_at: "2026-09-15T20:00:00.000Z",
    };
    const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(verifySealedReport(report, publicKey)).toBe(true);
    expect(verifySealedReport({ ...report, payload: { ...payload, total_events: 3 } }, publicKey)).toBe(false);
  });
});
