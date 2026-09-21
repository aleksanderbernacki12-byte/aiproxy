import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
import { createDashboardSession, verifyDashboardSession } from "./dashboard-session";

const identity = { credentialId: "key-1", organizationId: "org-1", role: "DPO" as const };

describe("dashboard session", () => {
  it("round-trips a signed organization scope", () => {
    const token = createDashboardSession(identity, "secret", 1_000_000);
    expect(verifyDashboardSession(token, "secret", 1_001_000)).toEqual({ ...identity, expiresAt: 29800 });
  });

  it("rejects tampering, expiry, and the wrong secret", () => {
    const token = createDashboardSession(identity, "secret", 1_000_000);
    expect(verifyDashboardSession(`${token}x`, "secret", 1_001_000)).toBeNull();
    expect(verifyDashboardSession(token, "wrong", 1_001_000)).toBeNull();
    expect(verifyDashboardSession(token, "secret", 30_000_000)).toBeNull();
  });

});
