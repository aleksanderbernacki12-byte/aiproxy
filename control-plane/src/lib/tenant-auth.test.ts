import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getDatabase: vi.fn(),
}));

vi.mock("server-only", () => ({}));
vi.mock("@/db/client", () => ({ getDatabase: mocks.getDatabase }));

import { authenticateTenant, digestTenantKey, extractBearerToken } from "./tenant-auth";

describe("tenant authentication", () => {
  it("extracts exactly one well-formed Bearer credential", () => {
    const request = (authorization?: string) =>
      new Request("https://control.example/api/telemetry/ingest", {
        headers: authorization ? { authorization } : {},
      });
    expect(extractBearerToken(request("Bearer tenant-key"))).toBe("tenant-key");
    expect(extractBearerToken(request("bearer tenant-key"))).toBeNull();
    expect(extractBearerToken(request("Bearer tenant key"))).toBeNull();
    expect(extractBearerToken(request())).toBeNull();
  });

  it("creates the lookup digest without retaining the plaintext shape", () => {
    const tenantKey = "customer-secret-with-at-least-32-characters";
    expect(digestTenantKey(tenantKey)).toBe(
      createHash("sha256").update(tenantKey).digest("hex"),
    );
    expect(digestTenantKey(tenantKey)).toMatch(/^[0-9a-f]{64}$/);
    expect(digestTenantKey(tenantKey)).not.toContain(tenantKey);
  });

  it("returns the organization selected by the tenant-key digest", async () => {
    const limit = vi
      .fn()
      .mockResolvedValue([{ id: "11111111-1111-1111-1111-111111111111", name: "Acme" }]);
    const where = vi.fn(() => ({ limit }));
    const innerJoin = vi.fn(() => ({ where }));
    const from = vi.fn(() => ({ innerJoin }));
    const select = vi.fn(() => ({ from }));
    mocks.getDatabase.mockReturnValue({ select });
    const request = new Request("https://control.example/api/telemetry/ingest", {
      headers: { authorization: `Bearer ${"customer-secret".padEnd(32, "x")}` },
    });

    await expect(authenticateTenant(request)).resolves.toEqual({
      id: "11111111-1111-1111-1111-111111111111",
      name: "Acme",
    });
    expect(select).toHaveBeenCalledOnce();
    expect(where).toHaveBeenCalledOnce();
    expect(innerJoin).toHaveBeenCalledOnce();
    expect(limit).toHaveBeenCalledWith(1);
  });

  it("rejects a missing credential without querying Postgres", async () => {
    mocks.getDatabase.mockClear();
    const request = new Request("https://control.example/api/telemetry/ingest");
    await expect(authenticateTenant(request)).resolves.toBeNull();
    expect(mocks.getDatabase).not.toHaveBeenCalled();
  });

  it("rejects undersized credentials without querying Postgres", async () => {
    mocks.getDatabase.mockClear();
    const request = new Request("https://control.example/api/telemetry/ingest", {
      headers: { authorization: "Bearer short" },
    });
    await expect(authenticateTenant(request)).resolves.toBeNull();
    expect(mocks.getDatabase).not.toHaveBeenCalled();
  });
});
