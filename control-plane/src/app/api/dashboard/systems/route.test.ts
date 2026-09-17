import { beforeEach, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({ requireDashboardIdentity: vi.fn(), saveAISystem: vi.fn() }));
vi.mock("@/lib/dashboard-auth", () => ({ requireDashboardIdentity: mocks.requireDashboardIdentity }));
vi.mock("@/lib/ai-systems", () => ({ saveAISystem: mocks.saveAISystem }));
import { POST } from "./route";

const profile = { application_id: "legal", model: "model-a", name: "Legal assistant", provider: "",
  intended_purpose: "Draft review", risk_class: "LIMITED", system_owner: "Legal",
  legal_basis: "Assessment 12", human_oversight: "Mandatory review", data_categories: ["business records"], deployment_regions: ["EU"], status: "ACTIVE" };
function request(body: unknown = profile, origin = "https://control.example", contentType = "application/json") {
  return new Request("https://control.example/api/dashboard/systems", { method: "POST",
    headers: { origin, "content-type": contentType }, body: JSON.stringify(body) });
}
beforeEach(() => {
  vi.resetAllMocks();
  mocks.requireDashboardIdentity.mockResolvedValue({ organizationId: "tenant-a", credentialId: "key-a", role: "DPO" });
  mocks.saveAISystem.mockResolvedValue("profile-id");
});
it.each(["DPO", "ADMIN"])("saves for %s using only session tenant identity", async (role) => {
  const identity = { organizationId: "tenant-a", credentialId: "key-a", role };
  mocks.requireDashboardIdentity.mockResolvedValue(identity);
  expect((await POST(request())).status).toBe(200);
  expect(mocks.saveAISystem).toHaveBeenCalledWith(identity, profile);
});
it.each(["AUDITOR", "unknown"])("denies %s without writing", async (role) => {
  mocks.requireDashboardIdentity.mockResolvedValue({ organizationId: "tenant-a", credentialId: "key-a", role });
  expect((await POST(request())).status).toBe(403);
  expect(mocks.saveAISystem).not.toHaveBeenCalled();
});
it.each(["https://evil.example", ""])("rejects invalid origin %s", async (origin) => {
  expect((await POST(request(profile, origin))).status).toBe(403);
  expect(mocks.saveAISystem).not.toHaveBeenCalled();
});
it.each([
  { ...profile, organization_id: "tenant-b" }, { ...profile, name: " " },
  { ...profile, risk_class: "SAFE" }, { ...profile, data_categories: [""] },
  { ...profile, provider: "x".repeat(161) }, { ...profile, status: "DELETED" },
])("rejects invalid or tenant-selecting payloads", async (body) => {
  expect((await POST(request(body))).status).toBe(400);
  expect(mocks.saveAISystem).not.toHaveBeenCalled();
});
it("rejects oversized and incorrectly typed bodies before writing", async () => {
  expect((await POST(request({ ...profile, name: "x".repeat(65536) }))).status).toBe(413);
  expect((await POST(request(profile, "https://control.example", "text/plain"))).status).toBe(415);
  expect(mocks.saveAISystem).not.toHaveBeenCalled();
});
it("reports unavailable persistence without leaking database errors", async () => {
  mocks.saveAISystem.mockRejectedValue(new Error("private database details"));
  const response = await POST(request());
  expect(response.status).toBe(503);
  expect(await response.text()).not.toContain("private database details");
});
