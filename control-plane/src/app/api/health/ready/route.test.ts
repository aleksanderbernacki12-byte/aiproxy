import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ checkControlPlaneReadiness: vi.fn() }));
vi.mock("@/lib/readiness", () => mocks);
import { GET } from "./route";

afterEach(() => vi.clearAllMocks());

describe("GET /api/health/ready", () => {
  it("reports readiness only after database migrations", async () => {
    mocks.checkControlPlaneReadiness.mockResolvedValueOnce(true).mockResolvedValueOnce(false);
    expect((await GET()).status).toBe(200);
    expect((await GET()).status).toBe(503);
  });

  it("fails closed when PostgreSQL is unavailable", async () => {
    mocks.checkControlPlaneReadiness.mockRejectedValue(new Error("offline"));
    expect((await GET()).status).toBe(503);
  });
});
