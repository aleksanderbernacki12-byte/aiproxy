import "server-only";

import { sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from "./schema";

const globalDatabase = globalThis as typeof globalThis & {
  aiproxyPool?: Pool;
  aiproxyCrossTenantPool?: Pool;
};

function createPool(max: number, crossTenant: boolean) {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error("DATABASE_URL is required");
  }
  const pool = new Pool({
    connectionString,
    max,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
  });
  // Row-level security (0017) does not apply to superusers, and the
  // deployment may connect as one, so every connection drops to the
  // restricted role first.
  pool.on("connect", (connection) => {
    void connection.query(crossTenant
      ? "SET ROLE aiproxy_app; SET aiproxy.cross_tenant = 'on'"
      : "SET ROLE aiproxy_app");
  });
  return pool;
}

// The default pool has no tenant context: tenant tables return no rows and
// reject writes. Use withOrganization for tenant data.
export function getDatabase() {
  // Reuse the bounded pool in production too; creating one per query exhausts PostgreSQL.
  globalDatabase.aiproxyPool ??= createPool(10, false);
  return drizzle(globalDatabase.aiproxyPool, { schema });
}

// Only for work that is cross-tenant by nature: looking up a credential
// before its organization is known, and the internal jobs.
export function getCrossTenantDatabase() {
  globalDatabase.aiproxyCrossTenantPool ??= createPool(5, true);
  return drizzle(globalDatabase.aiproxyCrossTenantPool, { schema });
}

export type Database = ReturnType<typeof getDatabase>;
export type Transaction = Parameters<Parameters<Database["transaction"]>[0]>[0];

// Runs work in a transaction that can only see and write organizationId's
// rows. The role is set again for the transaction because a transaction-mode
// connection pooler (pgbouncer) does not keep the session-level SET ROLE.
export async function withOrganization<T>(organizationId: string, work: (transaction: Transaction) => Promise<T>) {
  return getDatabase().transaction(async (transaction) => {
    await transaction.execute(sql`SELECT set_config('role', 'aiproxy_app', true),
      set_config('aiproxy.organization_id', ${organizationId}, true)`);
    return work(transaction);
  });
}
