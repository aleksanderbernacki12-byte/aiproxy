import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import process from "node:process";
import pg from "pg";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  throw new Error("DATABASE_URL is required");
}

const client = new pg.Client({ connectionString: databaseUrl });

try {
  await client.connect();
  await client.query(`CREATE TABLE IF NOT EXISTS control_plane_migrations (
    filename text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
  )`);
  const directory = resolve("db/migrations");
  const filenames = (await readdir(directory))
    .filter((filename) => filename.endsWith(".sql"))
    .sort();
  for (const filename of filenames) {
    const existing = await client.query(
      "SELECT 1 FROM control_plane_migrations WHERE filename = $1",
      [filename],
    );
    if (existing.rowCount) continue;
    const migration = await readFile(resolve(directory, filename), "utf8");
    try {
      await client.query("BEGIN");
      await client.query(migration);
      await client.query(
        "INSERT INTO control_plane_migrations(filename) VALUES ($1)",
        [filename],
      );
      await client.query("COMMIT");
      console.log(`Applied db/migrations/${filename}`);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    }
  }
} finally {
  await client.end();
}
