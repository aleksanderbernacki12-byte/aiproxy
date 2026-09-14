import {
  createHash,
  generateKeyPairSync,
  sign,
} from "node:crypto";
import { calculateEventHash, signingBytes } from "./cryptography";
import type { TelemetryEvent } from "./schema";

export function createSignedFixture(previousEventHash = "") {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const keyId = createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
  const event: TelemetryEvent = {
    event_id: "550e8400-e29b-41d4-a716-446655440000",
    timestamp: "2026-09-13T12:00:00.000Z",
    client_id_hash: "a".repeat(64),
    application_id: "legal-assistant",
    routing: { provider: "customer-azure", model: "gpt-enterprise" },
    compliance_flags: ["pii_redacted", "policy_passed"],
    metrics: { latency_ms: 42, input_tokens: 12 },
    cryptography: {
      hash_algorithm: "SHA-256",
      request_response_hash: "b".repeat(64),
      previous_event_hash: previousEventHash,
      event_hash: "",
      signature_algorithm: "ECDSA_P256_SHA256_ASN1",
      key_id: keyId,
      signature: "",
    },
  };
  event.cryptography.event_hash = calculateEventHash(event);
  event.cryptography.signature = sign("sha256", signingBytes(event), {
    key: privateKey,
    dsaEncoding: "der",
  })
    .toString("base64")
    .replace(/=+$/, "");
  return { event, privateKey, publicKeyPem };
}
