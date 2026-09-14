import { describe, expect, it } from "vitest";
import { telemetryBatchSchema, telemetryEventSchema } from "./schema";
import { createSignedFixture } from "./test-fixture";

describe("telemetry schema", () => {
  it("accepts both one exact event and an ordered Go batch", () => {
    const { event } = createSignedFixture();
    expect(telemetryBatchSchema.parse(event)).toEqual([event]);
    expect(telemetryBatchSchema.parse([event])).toEqual([event]);
  });

  it("rejects unknown top-level and cryptography fields", () => {
    const { event } = createSignedFixture();
    expect(
      telemetryEventSchema.safeParse({ ...event, prompt: "must never arrive" }).success,
    ).toBe(false);
    expect(
      telemetryEventSchema.safeParse({
        ...event,
        cryptography: { ...event.cryptography, private_key: "forbidden" },
      }).success,
    ).toBe(false);
  });

  it("rejects malformed hashes, algorithms, timestamps, and duplicate IDs", () => {
    const { event } = createSignedFixture();
    expect(
      telemetryEventSchema.safeParse({ ...event, client_id_hash: "raw-customer-id" })
        .success,
    ).toBe(false);
    expect(
      telemetryEventSchema.safeParse({
        ...event,
        cryptography: { ...event.cryptography, hash_algorithm: "MD5" },
      }).success,
    ).toBe(false);
    expect(telemetryEventSchema.safeParse({ ...event, timestamp: "yesterday" }).success).toBe(
      false,
    );
    expect(telemetryBatchSchema.safeParse([event, event]).success).toBe(false);
  });
});
