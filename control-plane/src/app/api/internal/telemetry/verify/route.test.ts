import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ verifyStoredTelemetry: vi.fn() }));
vi.mock("@/lib/telemetry/verification", () => mocks);
import { GET } from "./route";

function request(token?: string) {
  return new Request("https://control.example/api/internal/telemetry/verify", {
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
}

describe("GET /api/internal/telemetry/verify", () => {
  beforeEach(() => {
    vi.stubEnv("CRON_SECRET", "verify-secret");
    mocks.verifyStoredTelemetry.mockResolvedValue({ organizations: 2, eventsChecked: 10, failures: 0, incomplete: 0 });
  });
  afterEach(() => { vi.clearAllMocks(); vi.unstubAllEnvs(); });

  it("is unavailable without a configured cron credential", async () => {
    vi.stubEnv("CRON_SECRET", "");
    expect((await GET(request("verify-secret"))).status).toBe(503);
  });

  it("rejects requests without the cron credential", async () => {
    expect((await GET(request())).status).toBe(401);
    expect(mocks.verifyStoredTelemetry).not.toHaveBeenCalled();
  });

  it("re-verifies stored telemetry for authenticated requests", async () => {
    const response = await GET(request("verify-secret"));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      status: "VERIFIED_STORED_TELEMETRY", organizations: 2, eventsChecked: 10, failures: 0, incomplete: 0,
    });
  });
});
