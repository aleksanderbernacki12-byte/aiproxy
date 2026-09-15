import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ requireDashboardIdentity: vi.fn(), sealComplianceReport: vi.fn() }));
vi.mock("@/lib/dashboard-auth", () => ({ requireDashboardIdentity: mocks.requireDashboardIdentity }));
vi.mock("@/lib/compliance-report", () => ({ sealComplianceReport: mocks.sealComplianceReport }));
import { POST } from "./route";

function request(origin = "https://control.example") {
  return new Request("https://control.example/api/dashboard/reports", { method: "POST", headers: { origin } });
}

describe("POST /api/dashboard/reports", () => {
  beforeEach(() => {
    mocks.requireDashboardIdentity.mockResolvedValue({ credentialId: "key-1", organizationId: "org-1", role: "DPO" });
    mocks.sealComplianceReport.mockResolvedValue("11111111-1111-1111-1111-111111111111");
  });
  afterEach(() => vi.clearAllMocks());

  it("seals same-origin reports for a DPO", async () => {
    const response = await POST(request());
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toContain("/api/dashboard/reports/11111111");
  });

  it("forbids auditors and cross-origin submissions", async () => {
    mocks.requireDashboardIdentity.mockResolvedValueOnce({ credentialId: "key-1", organizationId: "org-1", role: "AUDITOR" });
    expect((await POST(request())).status).toBe(403);
    expect((await POST(request("https://evil.example"))).status).toBe(403);
    expect(mocks.sealComplianceReport).not.toHaveBeenCalled();
  });
});
