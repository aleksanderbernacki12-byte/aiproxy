import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ createMerkleCheckpoints: vi.fn(), createSecurityAuditCheckpoints: vi.fn() }));
vi.mock("@/lib/telemetry/checkpoint", () => mocks);
vi.mock("@/lib/security-audit-checkpoint", () => ({ createSecurityAuditCheckpoints: mocks.createSecurityAuditCheckpoints }));
import { GET } from "./route";

function request(token?: string) {
  return new Request("https://control.example/api/internal/telemetry/checkpoint", {
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
}

describe("GET /api/internal/telemetry/checkpoint", () => {
  beforeEach(() => {
    vi.stubEnv("CRON_SECRET", "checkpoint-secret");
    mocks.createMerkleCheckpoints.mockResolvedValue({ organizations: 2, created: 1 });
    mocks.createSecurityAuditCheckpoints.mockResolvedValue({ organizations: 1, created: 1, invalid: 0 });
  });
  afterEach(() => { vi.clearAllMocks(); vi.unstubAllEnvs(); });

  it("rejects requests without the cron credential", async () => {
    expect((await GET(request())).status).toBe(401);
    expect(mocks.createMerkleCheckpoints).not.toHaveBeenCalled();
  });

  it("creates authenticated checkpoints", async () => {
    const response = await GET(request("checkpoint-secret"));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      status: "CHECKPOINTED",
      telemetry: { organizations: 2, created: 1 },
      security_audit: { organizations: 1, created: 1, invalid: 0 },
    });
  });
});
