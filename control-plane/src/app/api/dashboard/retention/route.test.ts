import { beforeEach, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({ requireDashboardIdentity: vi.fn(), updateRetentionPolicy: vi.fn() }));
vi.mock("@/lib/dashboard-auth", () => ({ requireDashboardIdentity: mocks.requireDashboardIdentity }));
vi.mock("@/lib/retention-admin", () => ({ updateRetentionPolicy: mocks.updateRetentionPolicy, RetentionConflictError: class extends Error {} }));
import { POST } from "./route";
import { RetentionConflictError } from "@/lib/retention-admin";

const policyCommand = { command: "set", days: 365 };
function request(body: unknown = policyCommand, origin = "https://control.example", contentType = "application/json") {
  return new Request("https://control.example/api/dashboard/retention", { method: "POST",
    headers: { origin, "content-type": contentType }, body: JSON.stringify(body) });
}
beforeEach(() => {
  vi.resetAllMocks();
  mocks.requireDashboardIdentity.mockResolvedValue({ organizationId: "tenant-a", credentialId: "key-a", role: "DPO" });
  mocks.updateRetentionPolicy.mockResolvedValue(undefined);
});
it.each(["DPO", "ADMIN"])("saves for %s using only session tenant identity", async (role) => {
  const identity = { organizationId: "tenant-a", credentialId: "key-a", role };
  mocks.requireDashboardIdentity.mockResolvedValue(identity);
  expect((await POST(request())).status).toBe(200);
  expect(mocks.updateRetentionPolicy).toHaveBeenCalledWith(identity, policyCommand);
});
it.each(["AUDITOR", "unknown"])("denies %s without writing", async (role) => {
  mocks.requireDashboardIdentity.mockResolvedValue({ organizationId: "tenant-a", credentialId: "key-a", role });
  expect((await POST(request())).status).toBe(403);
  expect(mocks.updateRetentionPolicy).not.toHaveBeenCalled();
});
it.each(["https://evil.example", ""])("rejects invalid origin %s", async (origin) => {
  expect((await POST(request(policyCommand, origin))).status).toBe(403);
  expect(mocks.updateRetentionPolicy).not.toHaveBeenCalled();
});
it.each([
  { ...policyCommand, organization_id: "tenant-b" }, { command: "set", days: 29 },
  { command: "set", days: 3651 }, { command: "set", days: 30.5 },
  { command: "set", days: "365" }, { command: "hold", reason: " " },
  { command: "release", reason: "x".repeat(501) }, { command: "delete" },
])("rejects invalid or tenant-selecting payloads", async (body) => {
  expect((await POST(request(body))).status).toBe(400);
  expect(mocks.updateRetentionPolicy).not.toHaveBeenCalled();
});
it("rejects oversized and incorrectly typed bodies before writing", async () => {
  expect((await POST(request({ ...policyCommand, name: "x".repeat(65536) }))).status).toBe(413);
  expect((await POST(request(policyCommand, "https://control.example", "text/plain"))).status).toBe(415);
  expect(mocks.updateRetentionPolicy).not.toHaveBeenCalled();
});
it("reports unavailable persistence without leaking database errors", async () => {
  mocks.updateRetentionPolicy.mockRejectedValue(new Error("private database details"));
  const response = await POST(request());
  expect(response.status).toBe(503);
  expect(await response.text()).not.toContain("private database details");
});

it.each(["hold", "release"])("accepts %s with a case reference", async (command) => {
  const body = { command, reason: "CASE-17" };
  expect((await POST(request(body))).status).toBe(200);
  expect(mocks.updateRetentionPolicy).toHaveBeenCalledWith(expect.objectContaining({ organizationId: "tenant-a" }), body);
});

it("returns a conflict for an absent policy or inactive hold", async () => {
  mocks.updateRetentionPolicy.mockRejectedValue(new RetentionConflictError());
  expect((await POST(request({ command: "release", reason: "closed" }))).status).toBe(409);
});
it("rejects malformed JSON without writing", async () => {
  const malformed = new Request("https://control.example/api/dashboard/retention", {
    method: "POST", headers: { origin: "https://control.example", "content-type": "application/json" }, body: "{",
  });
  expect((await POST(malformed)).status).toBe(400);
  expect(mocks.updateRetentionPolicy).not.toHaveBeenCalled();
});
