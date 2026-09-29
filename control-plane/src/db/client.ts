import "server-only";

import { sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from "./schema";

const globalDatabase = globalThis as typeof globalThis & {
  aiproxyPool?: Pool;
};

function getDatabase() {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error("DATABASE_URL is required");
  }
  // Reuse the bounded pool in production too; creating one per query exhausts PostgreSQL.
  globalDatabase.aiproxyPool ??= new Pool({
    connectionString,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
  });
  return drizzle(globalDatabase.aiproxyPool, { schema });
}

export type Database = ReturnType<typeof getDatabase>;
export type Transaction = Parameters<Parameters<Database["transaction"]>[0]>[0];

// Every query runs in a transaction that switches to the per-database role
// (0019; row-level security from 0017 does not apply to the owner) and sets
// its whole tenant context with transaction-local set_config. Nothing is set
// for the session: behind a transaction-mode pooler such as pgbouncer,
// session state stays on the server connection and reaches other clients,
// so both values are also set explicitly to override any state left there.
async function inContext<T>(crossTenant: boolean, organizationId: string, work: (transaction: Transaction) => Promise<T>) {
  return getDatabase().transaction(async (transaction) => {
    await transaction.execute(sql`SELECT set_config('role', 'aiproxy_app_' || left(md5(current_database()), 12), true),
      set_config('aiproxy.cross_tenant', ${crossTenant ? "on" : "off"}, true),
      set_config('aiproxy.organization_id', ${organizationId}, true)`);
    return work(transaction);
  });
}

// Can only see and write organizationId's rows.
export function withOrganization<T>(organizationId: string, work: (transaction: Transaction) => Promise<T>) {
  return inContext(false, organizationId, work);
}

// Sees every organization. Only for work that is cross-tenant by nature:
// looking up a credential before its organization is known, and the
// internal jobs.
export function withCrossTenant<T>(work: (transaction: Transaction) => Promise<T>) {
  return inContext(true, "", work);
}

// No tenant context: tenant tables return no rows and reject writes.
export function withoutTenant<T>(work: (transaction: Transaction) => Promise<T>) {
  return inContext(false, "", work);
}
