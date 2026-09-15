import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ authenticateDPOAccessKey: vi.fn(), appendSecurityAuditEvent: vi.fn() }));
vi.mock("@/lib/dpo-auth", () => mocks);
vi.mock("@/lib/security-audit", () => ({ appendSecurityAuditEvent: mocks.appendSecurityAuditEvent }));
vi.mock("server-only", () => ({}));

import { POST } from "./route";

function request(key = "x".repeat(32)) {
  const body = new URLSearchParams({ access_key: key });
  return new Request("https://control.example/api/dashboard/session", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
}

describe("POST /api/dashboard/session", () => {
  beforeEach(() => {
    vi.stubEnv("DASHBOARD_SESSION_SECRET", "s".repeat(32));
    mocks.authenticateDPOAccessKey.mockResolvedValue({ credentialId: "key-1", organizationId: "org-1", role: "DPO", label: "Primary DPO" });
  });
  afterEach(() => { vi.clearAllMocks(); vi.unstubAllEnvs(); });

  it("creates an HttpOnly tenant-scoped session for an active credential", async () => {
    const response = await POST(request());
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("https://control.example/dashboard");
    const cookie = response.headers.get("set-cookie") ?? "";
    expect(cookie).toContain("aiproxy_dpo_session=");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=strict");
    expect(mocks.appendSecurityAuditEvent).toHaveBeenCalledWith(expect.objectContaining({
      organizationId: "org-1", actorId: "key-1", action: "DASHBOARD_SESSION_CREATED",
    }));
  });

  it("rejects invalid credentials without creating a session", async () => {
    mocks.authenticateDPOAccessKey.mockResolvedValueOnce(null);
    const response = await POST(request("wrong"));
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toContain("/login?error=invalid");
    expect(response.headers.get("set-cookie")).toBeNull();
  });

  it("fails closed when session config or Postgres is unavailable", async () => {
    vi.stubEnv("DASHBOARD_SESSION_SECRET", "short");
    expect((await POST(request())).status).toBe(503);
    vi.stubEnv("DASHBOARD_SESSION_SECRET", "s".repeat(32));
    mocks.authenticateDPOAccessKey.mockRejectedValueOnce(new Error("offline"));
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    expect((await POST(request())).status).toBe(503);
    errorSpy.mockRestore();
  });

  it("does not create a session when the security event cannot be recorded", async () => {
    mocks.appendSecurityAuditEvent.mockRejectedValueOnce(new Error("offline"));
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const response = await POST(request());
    expect(response.status).toBe(503);
    expect(response.headers.get("set-cookie")).toBeNull();
    errorSpy.mockRestore();
  });
});
