import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import pg from "pg";

// Managed PostgreSQL gives each database a non-superuser owner, and several
// databases often share one cluster. Roles are cluster-wide, so migrations
// that pass as a superuser can still fail for the second owner (v0.77.0).
const source = new URL(process.env.TEST_DATABASE_URL ?? "");
if (!["localhost", "127.0.0.1", "[::1]"].includes(source.hostname)) throw new Error("Shared-cluster tests require a local disposable PostgreSQL service");
const admin = new pg.Client({ connectionString: source.toString() });
const suffix = randomUUID().replaceAll("-", "").slice(0, 12);
const owners = ["a", "b"].map((label) => ({
  role: `aiproxy_owner_${label}_${suffix}`,
  password: randomUUID(),
  database: `aiproxy_shared_${label}_${suffix}`,
}));

async function run(args, databaseUrl) {
  const child = spawn(process.execPath, args, { env: { ...process.env, DATABASE_URL: databaseUrl,
    APP_DATABASE_PASSWORD: randomUUID().replaceAll("-", "") }, stdio: "inherit" });
  const code = await new Promise((resolve, reject) => { child.on("error", reject); child.on("exit", resolve); });
  if (code !== 0) throw new Error(`Shared-cluster command failed (${code})`);
}

await admin.connect();
try {
  for (const owner of owners) {
    await admin.query(`CREATE ROLE "${owner.role}" LOGIN NOSUPERUSER CREATEROLE PASSWORD '${owner.password}'`);
    await admin.query(`CREATE DATABASE "${owner.database}" OWNER "${owner.role}"`);
  }
  for (const owner of owners) {
    const target = new URL(source);
    target.username = owner.role;
    target.password = owner.password;
    target.pathname = `/${owner.database}`;
    console.log(`Migrating and testing ${owner.database} as ${owner.role}`);
    await run(["scripts/migrate.mjs"], target.toString());
    await run(["./node_modules/vitest/vitest.mjs", "run", "--config", "vitest.integration.config.ts"], target.toString());
  }
} finally {
  for (const owner of owners) {
    await admin.query(`DROP DATABASE IF EXISTS "${owner.database}" WITH (FORCE)`);
    const { rows: [{ role }] } = await admin.query(`SELECT 'aiproxy_app_' || left(md5($1::text), 12) AS role`, [owner.database]);
    await admin.query(`DROP ROLE IF EXISTS "${owner.database}_login"`);
    await admin.query(`DROP ROLE IF EXISTS "${role}"`);
    await admin.query(`DROP ROLE IF EXISTS "${owner.role}"`);
  }
  await admin.end();
}
