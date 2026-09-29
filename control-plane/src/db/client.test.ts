import { PgDialect } from "drizzle-orm/pg-core";
import { afterEach, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
const mocks = vi.hoisted(() => ({ pool: vi.fn(), on: vi.fn(), execute: vi.fn(), drizzle: vi.fn() }));
vi.mock("pg", () => ({
  Pool: class {
    constructor(options: unknown) { mocks.pool(options); }
    on(...args: unknown[]) { mocks.on(...args); }
  },
}));
vi.mock("drizzle-orm/node-postgres", () => ({ drizzle: mocks.drizzle }));
import { withCrossTenant, withOrganization, withoutTenant } from "./client";
const state = globalThis as typeof globalThis & { aiproxyPool?: unknown };
const transaction = { execute: mocks.execute };
mocks.drizzle.mockReturnValue({ transaction: (work: (tx: typeof transaction) => unknown) => work(transaction) });
afterEach(() => {
  delete state.aiproxyPool;
  vi.unstubAllEnvs(); mocks.pool.mockClear(); mocks.on.mockClear(); mocks.execute.mockClear();
});

function contextQuery() {
  return new PgDialect().sqlToQuery(mocks.execute.mock.calls[0][0]);
}
const context = "SELECT set_config('role', 'aiproxy_app_' || left(md5(current_database()), 12), true),\n      set_config('aiproxy.cross_tenant', $1, true),\n      set_config('aiproxy.organization_id', $2, true)";

it("reuses one bounded pool and sets nothing for the session", async () => {
  vi.stubEnv("DATABASE_URL", "postgresql://localhost/test");
  await withoutTenant(async () => undefined);
  await withCrossTenant(async () => undefined);
  expect(mocks.pool).toHaveBeenCalledTimes(1);
  expect(mocks.pool).toHaveBeenCalledWith(expect.objectContaining({ max: 10 }));
  expect(mocks.on).not.toHaveBeenCalled();
});

it("sets the role and tenant context for the transaction only", async () => {
  vi.stubEnv("DATABASE_URL", "postgresql://localhost/test");
  expect(await withOrganization("org-1", async (tx) => { expect(tx).toBe(transaction); return "done"; })).toBe("done");
  expect(contextQuery()).toMatchObject({ sql: context, params: ["off", "org-1"] });
  mocks.execute.mockClear();
  await withCrossTenant(async () => undefined);
  expect(contextQuery()).toMatchObject({ sql: context, params: ["on", ""] });
  mocks.execute.mockClear();
  await withoutTenant(async () => undefined);
  expect(contextQuery()).toMatchObject({ sql: context, params: ["off", ""] });
});
