import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ anchorPendingCheckpoints: vi.fn() }));
vi.mock("@/lib/telemetry/anchor", () => mocks);
import { GET } from "./route";

function request(token?: string) {
  return new Request("https://control.example/api/internal/telemetry/anchor", {
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
}

describe("GET /api/internal/telemetry/anchor", () => {
  beforeEach(() => vi.stubEnv("CRON_SECRET", "anchor-secret"));
  afterEach(() => { vi.clearAllMocks(); vi.unstubAllEnvs(); });

  it("requires the cron credential", async () => {
    expect((await GET(request())).status).toBe(401);
    expect(mocks.anchorPendingCheckpoints).not.toHaveBeenCalled();
  });

  it("reports disabled anchoring without losing checkpoints", async () => {
    mocks.anchorPendingCheckpoints.mockResolvedValue({ configured: false, attempted: 0, anchored: 0, failed: 0 });
    expect((await GET(request("anchor-secret"))).status).toBe(503);
  });

  it("processes configured anchors", async () => {
    mocks.anchorPendingCheckpoints.mockResolvedValue({ configured: true, attempted: 2, anchored: 1, failed: 1 });
    const response = await GET(request("anchor-secret"));
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ status: "ANCHORED", anchored: 1, failed: 1 });
  });
});
