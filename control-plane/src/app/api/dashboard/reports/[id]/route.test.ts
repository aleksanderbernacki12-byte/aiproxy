import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  requireDashboardIdentity: vi.fn(), getSealedReport: vi.fn(), appendSecurityAuditEvent: vi.fn(),
}));
vi.mock("@/lib/dashboard-auth", () => ({ requireDashboardIdentity: mocks.requireDashboardIdentity }));
vi.mock("@/lib/compliance-report", () => ({ getSealedReport: mocks.getSealedReport }));
vi.mock("@/lib/security-audit", () => ({ appendSecurityAuditEvent: mocks.appendSecurityAuditEvent }));
import { GET } from "./route";

const reportId = "11111111-1111-4111-8111-111111111111";
const context = (id: string) => ({ params: Promise.resolve({ id }) });

describe("GET /api/dashboard/reports/[id]", () => {
  beforeEach(() => mocks.requireDashboardIdentity.mockResolvedValue({ organizationId: "org-1", credentialId: "dpo-1" }));
  afterEach(() => vi.clearAllMocks());

  it("records tenant-authorized evidence downloads", async () => {
    mocks.getSealedReport.mockResolvedValue({ report_id: reportId, payload: {}, payload_hash: "a".repeat(64) });
    const response = await GET(new Request("https://control.example"), context(reportId));
    expect(response.status).toBe(200);
    expect(mocks.getSealedReport).toHaveBeenCalledWith(reportId, "org-1");
    expect(mocks.appendSecurityAuditEvent).toHaveBeenCalledWith(expect.objectContaining({
      organizationId: "org-1", actorId: "dpo-1", action: "COMPLIANCE_REPORT_DOWNLOADED", resourceId: reportId,
    }));
  });

  it("does not record malformed or unavailable report IDs", async () => {
    expect((await GET(new Request("https://control.example"), context("bad"))).status).toBe(404);
    expect(mocks.appendSecurityAuditEvent).not.toHaveBeenCalled();
    mocks.getSealedReport.mockResolvedValue(null);
    expect((await GET(new Request("https://control.example"), context(reportId))).status).toBe(404);
    expect(mocks.appendSecurityAuditEvent).not.toHaveBeenCalled();
  });

  it("fails closed when evidence access cannot be recorded", async () => {
    mocks.getSealedReport.mockResolvedValue({ report_id: reportId, payload: {} });
    mocks.appendSecurityAuditEvent.mockRejectedValueOnce(new Error("offline"));
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    expect((await GET(new Request("https://control.example"), context(reportId))).status).toBe(503);
    errorSpy.mockRestore();
  });
});
