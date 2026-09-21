import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getControlPlaneMetrics: vi.fn(),
  formatControlPlaneMetrics: vi.fn(),
}));

vi.mock("@/lib/operations", () => mocks);

import { GET } from "./route";

function request(token?: string) {
  return new Request("https://control.example/api/internal/metrics", {
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
}

describe("GET /api/internal/metrics", () => {
  beforeEach(() => {
    vi.stubEnv("CRON_SECRET", "metrics-secret");
    mocks.getControlPlaneMetrics.mockResolvedValue({ bufferPending: 0 });
    mocks.formatControlPlaneMetrics.mockReturnValue("metric 1\n");
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.unstubAllEnvs();
  });

  it("rejects missing or invalid credentials before querying Postgres", async () => {
    expect((await GET(request())).status).toBe(401);
    expect((await GET(request("wrong"))).status).toBe(401);
    expect(mocks.getControlPlaneMetrics).not.toHaveBeenCalled();
  });

  it("returns 503 when the endpoint secret is not configured", async () => {
    vi.stubEnv("CRON_SECRET", "");
    expect((await GET(request())).status).toBe(503);
  });

  it("serves authenticated Prometheus output without caching", async () => {
    const response = await GET(request("metrics-secret"));
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("metric 1\n");
    expect(response.headers.get("content-type")).toContain("text/plain");
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
});
