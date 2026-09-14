import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
import { accessKeyMatches, createDashboardSession, verifyDashboardSession } from "./dashboard-session";

describe("dashboard session", () => {
  it("round-trips a signed organization scope", () => {
    const token = createDashboardSession("org-1", "secret", 1_000_000);
    expect(verifyDashboardSession(token, "secret", 1_001_000)).toEqual({ organizationId: "org-1", expiresAt: 29800 });
  });

  it("rejects tampering, expiry, and the wrong secret", () => {
    const token = createDashboardSession("org-1", "secret", 1_000_000);
    expect(verifyDashboardSession(`${token}x`, "secret", 1_001_000)).toBeNull();
    expect(verifyDashboardSession(token, "wrong", 1_001_000)).toBeNull();
    expect(verifyDashboardSession(token, "secret", 30_000_000)).toBeNull();
  });

  it("compares access keys exactly", () => {
    expect(accessKeyMatches("correct", "correct")).toBe(true);
    expect(accessKeyMatches("wrong", "correct")).toBe(false);
    expect(accessKeyMatches("", undefined)).toBe(false);
  });
});
