import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
const mocks = vi.hoisted(() => ({ endDPOSessions: vi.fn(), validateDPOIdentity: vi.fn() }));
vi.mock("@/lib/dpo-auth", () => mocks);
import { createDashboardSession } from "@/lib/dashboard-session";
import { POST } from "./route";

const secret = "s".repeat(32);
const identity = { credentialId: "key-1", organizationId: "org-1", role: "DPO" as const, sessionVersion: 2 };

function request(origin?: string, cookie?: string) {
  const headers: Record<string, string> = {};
  if (origin) headers.origin = origin;
  if (cookie) headers.cookie = `aiproxy_dpo_session=${cookie}`;
  return new Request("https://control.example/api/dashboard/logout", { method: "POST", headers });
}

describe("POST /api/dashboard/logout", () => {
  beforeEach(() => {
    vi.stubEnv("DASHBOARD_SESSION_SECRET", secret);
    mocks.validateDPOIdentity.mockResolvedValue(true);
    mocks.endDPOSessions.mockResolvedValue(undefined);
  });
  afterEach(() => { vi.clearAllMocks(); vi.unstubAllEnvs(); });

  it("clears the session cookie for same-origin submissions", async () => {
    const response = await POST(request("https://control.example"));
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("https://control.example/login");
    expect(response.headers.get("set-cookie")).toContain("aiproxy_dpo_session=;");
    expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
    expect(mocks.endDPOSessions).not.toHaveBeenCalled();
  });

  it("ends the key's sessions on the server for a valid session", async () => {
    const response = await POST(request("https://control.example", createDashboardSession(identity, secret)));
    expect(response.status).toBe(303);
    expect(mocks.endDPOSessions).toHaveBeenCalledWith(expect.objectContaining(identity));
  });

  it("rejects missing and cross-origin submissions", async () => {
    expect((await POST(request())).status).toBe(403);
    expect((await POST(request("https://attacker.example"))).status).toBe(403);
  });
});
