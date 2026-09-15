import { describe, expect, it, vi } from "vitest";
import { telemetryKeyValidity } from "./worker";

vi.mock("server-only", () => ({}));

const eventTime = new Date("2026-09-15T12:00:00Z");

describe("telemetry key lifecycle", () => {
  it("accepts an event within an active key interval", () => {
    expect(telemetryKeyValidity({
      validFrom: new Date("2026-09-15T11:00:00Z"),
      validUntil: new Date("2026-09-15T13:00:00Z"),
      revokedAt: null,
    }, eventTime)).toEqual({ ok: true });
  });

  it("rejects events outside the key interval", () => {
    expect(telemetryKeyValidity({ validFrom: new Date("2026-09-15T12:00:01Z"), validUntil: null, revokedAt: null }, eventTime).ok).toBe(false);
    expect(telemetryKeyValidity({ validFrom: null, validUntil: eventTime, revokedAt: null }, eventTime).ok).toBe(false);
  });

  it("rejects a revoked key regardless of its validity interval", () => {
    expect(telemetryKeyValidity({ validFrom: null, validUntil: null, revokedAt: new Date() }, eventTime)).toEqual({
      ok: false,
      reason: "The registered public key is revoked",
    });
  });
});
