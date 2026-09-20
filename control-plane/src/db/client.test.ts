import { afterEach, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
const mocks = vi.hoisted(() => ({ pool: vi.fn(), drizzle: vi.fn() }));
vi.mock("pg", () => ({ Pool: class { constructor(options: unknown) { mocks.pool(options); } } }));
vi.mock("drizzle-orm/node-postgres", () => ({ drizzle: mocks.drizzle }));
import { getDatabase } from "./client";
const state = globalThis as typeof globalThis & { aiproxyPool?: unknown };
afterEach(() => { delete state.aiproxyPool; vi.unstubAllEnvs(); vi.clearAllMocks(); });
it("reuses one bounded pool across production database calls", () => {
  delete state.aiproxyPool;
  vi.stubEnv("NODE_ENV", "production");
  vi.stubEnv("DATABASE_URL", "postgresql://localhost/test");
  getDatabase(); getDatabase();
  expect(mocks.pool).toHaveBeenCalledTimes(1);
  expect(mocks.pool).toHaveBeenCalledWith(expect.objectContaining({ max: 10 }));
  expect(mocks.drizzle.mock.calls[0][0]).toBe(mocks.drizzle.mock.calls[1][0]);
});
