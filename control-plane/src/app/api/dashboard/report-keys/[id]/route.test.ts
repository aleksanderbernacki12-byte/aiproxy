import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ requireDashboardIdentity: vi.fn(), getReportVerificationKey: vi.fn() }));
vi.mock("@/lib/dashboard-auth", () => ({ requireDashboardIdentity: mocks.requireDashboardIdentity }));
vi.mock("@/lib/compliance-report", () => ({ getReportVerificationKey: mocks.getReportVerificationKey }));
import { GET } from "./route";

const keyId = "a".repeat(64);
const context = (id: string) => ({ params: Promise.resolve({ id }) });

describe("GET /api/dashboard/report-keys/[id]", () => {
  beforeEach(() => mocks.requireDashboardIdentity.mockResolvedValue({ organizationId: "org-1" }));
  afterEach(() => vi.clearAllMocks());

  it("returns a tenant-authorized public verification key", async () => {
    mocks.getReportVerificationKey.mockResolvedValue("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n");
    const response = await GET(new Request("https://control.example"), context(keyId));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-disposition")).toContain(keyId);
    expect(mocks.getReportVerificationKey).toHaveBeenCalledWith(keyId, "org-1");
  });

  it("does not query malformed or unavailable key IDs", async () => {
    expect((await GET(new Request("https://control.example"), context("bad"))).status).toBe(404);
    expect(mocks.getReportVerificationKey).not.toHaveBeenCalled();
    mocks.getReportVerificationKey.mockResolvedValue(null);
    expect((await GET(new Request("https://control.example"), context(keyId))).status).toBe(404);
  });
});
