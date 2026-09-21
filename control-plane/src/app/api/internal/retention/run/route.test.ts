import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ enforceRetentionPolicies: vi.fn() }));
vi.mock("@/lib/retention", () => mocks);
import { GET } from "./route";

function request(token?: string) {
  return new Request("https://control.example/api/internal/retention/run", {
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
}

describe("GET /api/internal/retention/run", () => {
  beforeEach(() => {
    vi.stubEnv("CRON_SECRET", "retention-secret");
    mocks.enforceRetentionPolicies.mockResolvedValue({ organizations: 2, held: 1, purged: 12 });
  });
  afterEach(() => { vi.clearAllMocks(); vi.unstubAllEnvs(); });

  it("requires the cron credential", async () => {
    expect((await GET(request())).status).toBe(401);
    expect(mocks.enforceRetentionPolicies).not.toHaveBeenCalled();
  });

  it("runs configured retention policies", async () => {
    const response = await GET(request("retention-secret"));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: "RETENTION_ENFORCED", organizations: 2, held: 1, purged: 12 });
  });
});
