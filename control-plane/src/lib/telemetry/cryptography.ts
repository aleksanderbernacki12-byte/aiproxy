import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from "node:crypto";
import canonicalize from "canonicalize";
import type { TelemetryEvent } from "./schema";

const EVENT_HASH_DOMAIN = Buffer.from("aiproxy-telemetry-event-v1\0", "utf8");

function canonicalBytes(event: TelemetryEvent) {
  const canonical = canonicalize(event);
  if (canonical === undefined) {
    throw new Error("Payload is not valid RFC 8785 JSON");
  }
  return Buffer.from(canonical, "utf8");
}

export function signingBytes(event: TelemetryEvent) {
  return canonicalBytes({
    ...event,
    cryptography: { ...event.cryptography, signature: "" },
  });
}

export function calculateEventHash(event: TelemetryEvent) {
  const draft = canonicalBytes({
    ...event,
    cryptography: {
      ...event.cryptography,
      event_hash: "",
      signature: "",
    },
  });
  return createHash("sha256").update(EVENT_HASH_DOMAIN).update(draft).digest("hex");
}

export type CryptographicVerification =
  | { ok: true }
  | { ok: false; reason: string };

export function verifyTelemetryCryptography(
  event: TelemetryEvent,
  publicKeyPem: string,
): CryptographicVerification {
  const calculatedHash = calculateEventHash(event);
  if (calculatedHash !== event.cryptography.event_hash) {
    return { ok: false, reason: "event_hash does not match the canonical payload" };
  }

  try {
    const publicKey = createPublicKey(publicKeyPem);
    if (
      publicKey.asymmetricKeyType !== "ec" ||
      publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1"
    ) {
      return { ok: false, reason: "registered key is not ECDSA P-256" };
    }
    const fingerprint = createHash("sha256")
      .update(publicKey.export({ type: "spki", format: "der" }))
      .digest("hex");
    if (fingerprint !== event.cryptography.key_id) {
      return { ok: false, reason: "key_id does not match the registered public key" };
    }
    const signature = Buffer.from(event.cryptography.signature, "base64");
    const valid = verifySignature(
      "sha256",
      signingBytes(event),
      { key: publicKey, dsaEncoding: "der" },
      signature,
    );
    return valid
      ? { ok: true }
      : { ok: false, reason: "ECDSA signature verification failed" };
  } catch (error) {
    return {
      ok: false,
      reason: error instanceof Error ? error.message : "ECDSA verification failed",
    };
  }
}
