import { describe, expect, it } from "vitest";
import {
  calculateEventHash,
  signingBytes,
  verifyTelemetryCryptography,
} from "./cryptography";
import { createSignedFixture } from "./test-fixture";

describe("Go telemetry cryptography contract", () => {
  it("verifies an RFC 8785 event hash and ECDSA P-256 DER signature", () => {
    const { event, publicKeyPem } = createSignedFixture();
    expect(calculateEventHash(event)).toBe(event.cryptography.event_hash);
    expect(verifyTelemetryCryptography(event, publicKeyPem)).toEqual({ ok: true });
  });

  it("canonicalizes object keys independently of insertion order", () => {
    const { event } = createSignedFixture();
    const reordered = {
      ...event,
      routing: { model: "gpt-enterprise", provider: "customer-azure" },
      metrics: { input_tokens: 12, latency_ms: 42 },
    };
    expect(signingBytes(reordered)).toEqual(signingBytes(event));
  });

  it("rejects metadata tampering and the wrong public key", () => {
    const { event, publicKeyPem } = createSignedFixture();
    const tampered = { ...event, application_id: "attacker-modified" };
    expect(verifyTelemetryCryptography(tampered, publicKeyPem)).toMatchObject({
      ok: false,
    });
    const other = createSignedFixture();
    expect(verifyTelemetryCryptography(event, other.publicKeyPem)).toMatchObject({
      ok: false,
    });
  });
});
