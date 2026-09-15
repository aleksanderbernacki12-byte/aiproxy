import "server-only";

import { sql } from "drizzle-orm";
import { getDatabase } from "@/db/client";

export const expectedMigration = "0014_retention_and_legal_hold.sql";

export async function checkControlPlaneReadiness() {
  const result = await getDatabase().execute<{ migration_ready: boolean }>(sql`
    SELECT EXISTS (
      SELECT 1 FROM control_plane_migrations WHERE filename = ${expectedMigration}
    ) AS migration_ready
  `);
  return result.rows[0]?.migration_ready === true;
}
