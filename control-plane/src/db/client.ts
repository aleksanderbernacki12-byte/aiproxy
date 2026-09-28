import "server-only";

import { sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from "./schema";

const globalDatabase = globalThis as typeof globalThis & {
  aiproxyPool?: Pool;
  aiproxyCrossTenantPool?: Pool;
};

// The role 0019 created for this database.
function selectAppRole(local: boolean) {
  return `set_config('role', 'aiproxy_app_' || left(md5(current_database()), 12), ${local})`;
}

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
  // restricted per-database role (0019) first.
  pool.on("connect", (connection) => {
    // A failure here leaves the connection on the deployment's own user;
    // readiness (applicationRoleActive) turns that into NOT_READY.
    connection.query(crossTenant
      ? `SELECT ${selectAppRole(false)}, set_config('aiproxy.cross_tenant', 'on', false)`
      : `SELECT ${selectAppRole(false)}`)
      .catch((error: unknown) => console.error("Could not switch to the application database role", error));
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
    await transaction.execute(sql`SELECT ${sql.raw(selectAppRole(true))},
      set_config('aiproxy.organization_id', ${organizationId}, true)`);
    return work(transaction);
  });
}
