import { describe, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { POST } from "./route";

function request(origin?: string) {
  return new Request("https://control.example/api/dashboard/logout", {
    method: "POST", headers: origin ? { origin } : {},
  });
}

describe("POST /api/dashboard/logout", () => {
  it("clears the session cookie for same-origin submissions", async () => {
    const response = await POST(request("https://control.example"));
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("https://control.example/login");
    expect(response.headers.get("set-cookie")).toContain("aiproxy_dpo_session=;");
    expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
  });

  it("rejects missing and cross-origin submissions", async () => {
    expect((await POST(request())).status).toBe(403);
    expect((await POST(request("https://attacker.example"))).status).toBe(403);
  });
});
