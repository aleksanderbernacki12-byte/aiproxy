import { beforeEach, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({ requireDashboardIdentity: vi.fn(), changeAccessCredential: vi.fn() }));
vi.mock("@/lib/dashboard-auth", () => ({ requireDashboardIdentity: mocks.requireDashboardIdentity }));
vi.mock("@/lib/access-admin", () => ({ changeAccessCredential: mocks.changeAccessCredential, AccessConflictError: class extends Error {}, AccessDeniedError: class extends Error {} }));
import { POST } from "./route";
import { AccessConflictError, AccessDeniedError } from "@/lib/access-admin";

const policyCommand = { command: "create", label: "Audit team", role: "AUDITOR", expires_in_days: 90 };
function request(body: unknown = policyCommand, origin = "https://control.example", contentType = "application/json") {
  return new Request("https://control.example/api/dashboard/access", { method: "POST",
    headers: { origin, "content-type": contentType }, body: JSON.stringify(body) });
}
beforeEach(() => {
  vi.resetAllMocks();
  mocks.requireDashboardIdentity.mockResolvedValue({ organizationId: "tenant-a", credentialId: "key-a", role: "ADMIN" });
  mocks.changeAccessCredential.mockResolvedValue({ id: "key-id", access_key: "one-time-secret" });
});
it.each(["ADMIN"])("saves for %s using only session tenant identity", async (role) => {
  const identity = { organizationId: "tenant-a", credentialId: "key-a", role };
  mocks.requireDashboardIdentity.mockResolvedValue(identity);
  expect((await POST(request())).status).toBe(200);
  expect(mocks.changeAccessCredential).toHaveBeenCalledWith(identity, policyCommand);
});
it.each(["DPO", "AUDITOR", "unknown"])("denies %s without writing", async (role) => {
  mocks.requireDashboardIdentity.mockResolvedValue({ organizationId: "tenant-a", credentialId: "key-a", role });
  expect((await POST(request())).status).toBe(403);
  expect(mocks.changeAccessCredential).not.toHaveBeenCalled();
});
it.each(["https://evil.example", ""])("rejects invalid origin %s", async (origin) => {
  expect((await POST(request(policyCommand, origin))).status).toBe(403);
  expect(mocks.changeAccessCredential).not.toHaveBeenCalled();
});
it.each([
  { ...policyCommand, organization_id: "tenant-b" }, { ...policyCommand, expires_in_days: 0 },
  { ...policyCommand, expires_in_days: 366 }, { ...policyCommand, expires_in_days: 1.5 },
  { ...policyCommand, expires_in_days: "90" }, { ...policyCommand, role: "OWNER" },
  { ...policyCommand, label: " " }, { ...policyCommand, label: "x".repeat(161) },
  { command: "revoke", credential_id: "invalid" },
])("rejects invalid or tenant-selecting payloads", async (body) => {
  expect((await POST(request(body))).status).toBe(400);
  expect(mocks.changeAccessCredential).not.toHaveBeenCalled();
});
it("rejects oversized and incorrectly typed bodies before writing", async () => {
  expect((await POST(request({ ...policyCommand, name: "x".repeat(65536) }))).status).toBe(413);
  expect((await POST(request(policyCommand, "https://control.example", "text/plain"))).status).toBe(415);
  expect(mocks.changeAccessCredential).not.toHaveBeenCalled();
});
it("reports unavailable persistence without leaking database errors", async () => {
  mocks.changeAccessCredential.mockRejectedValue(new Error("private database details"));
  const response = await POST(request());
  expect(response.status).toBe(503);
  expect(await response.text()).not.toContain("private database details");
});

it("returns conflict for protected or unavailable keys", async () => {
  mocks.changeAccessCredential.mockRejectedValue(new AccessConflictError());
  expect((await POST(request({ command: "revoke", credential_id: "11111111-1111-4111-8111-111111111111" }))).status).toBe(409);
});
it("prevents caching of the one-time secret", async () => {
  const response = await POST(request());
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(await response.json()).toEqual({ id: "key-id", access_key: "one-time-secret" });
});
it("rejects malformed JSON without writing", async () => {
  const malformed = new Request("https://control.example/api/dashboard/access", {
    method: "POST", headers: { origin: "https://control.example", "content-type": "application/json" }, body: "{",
  });
  expect((await POST(malformed)).status).toBe(400);
  expect(mocks.changeAccessCredential).not.toHaveBeenCalled();
});

it("rejects an administrator revoked since session validation", async () => {
  mocks.changeAccessCredential.mockRejectedValue(new AccessDeniedError());
  expect((await POST(request())).status).toBe(403);
});
