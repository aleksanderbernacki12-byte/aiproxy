import { afterEach, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
const mocks = vi.hoisted(() => ({ pool: vi.fn(), connect: [] as Array<(connection: { query: (text: string) => unknown }) => void>, drizzle: vi.fn() }));
vi.mock("pg", () => ({
  Pool: class {
    constructor(options: unknown) { mocks.pool(options); }
    on(event: string, handler: (connection: { query: (text: string) => unknown }) => void) {
      if (event === "connect") mocks.connect.push(handler);
    }
  },
}));
vi.mock("drizzle-orm/node-postgres", () => ({ drizzle: mocks.drizzle }));
import { getCrossTenantDatabase, getDatabase } from "./client";
const state = globalThis as typeof globalThis & { aiproxyPool?: unknown; aiproxyCrossTenantPool?: unknown };
afterEach(() => {
  delete state.aiproxyPool; delete state.aiproxyCrossTenantPool;
  mocks.connect.length = 0; vi.unstubAllEnvs(); vi.clearAllMocks();
});

function connectQuery(index: number) {
  const query = vi.fn();
  mocks.connect[index]({ query });
  return query.mock.calls[0][0];
}

it("reuses one bounded pool across production database calls", () => {
  vi.stubEnv("NODE_ENV", "production");
  vi.stubEnv("DATABASE_URL", "postgresql://localhost/test");
  getDatabase(); getDatabase();
  expect(mocks.pool).toHaveBeenCalledTimes(1);
  expect(mocks.pool).toHaveBeenCalledWith(expect.objectContaining({ max: 10 }));
  expect(mocks.drizzle.mock.calls[0][0]).toBe(mocks.drizzle.mock.calls[1][0]);
});

it("drops every connection to the row-level-security role", () => {
  vi.stubEnv("DATABASE_URL", "postgresql://localhost/test");
  getDatabase();
  getCrossTenantDatabase();
  expect(mocks.pool).toHaveBeenCalledTimes(2);
  expect(connectQuery(0)).toBe("SET ROLE aiproxy_app");
  expect(connectQuery(1)).toBe("SET ROLE aiproxy_app; SET aiproxy.cross_tenant = 'on'");
});
