import "server-only";

import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from "./schema";

const globalDatabase = globalThis as typeof globalThis & {
  aiproxyPool?: Pool;
};

export function getDatabase() {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error("DATABASE_URL is required");
  }
  const pool =
    globalDatabase.aiproxyPool ??
    new Pool({
      connectionString,
      max: 10,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
    });
  // Reuse the bounded pool in production too; creating one per query exhausts PostgreSQL.
  globalDatabase.aiproxyPool = pool;
  return drizzle(pool, { schema });
}
