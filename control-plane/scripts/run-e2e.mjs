import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import pg from "pg";
import { cp } from "node:fs/promises";

const source = new URL(process.env.TEST_DATABASE_URL ?? "");
if (!["localhost", "127.0.0.1", "[::1]"].includes(source.hostname)) throw new Error("E2E requires a local disposable PostgreSQL service");
const name = `aiproxy_e2e_${randomUUID().replaceAll("-", "")}`;
const admin = new pg.Client({ connectionString: source.toString() });
const target = new URL(source); target.pathname = `/${name}`;
// The application runs as the login role, as in production; seeding uses the owner.
const loginPassword = randomUUID().replaceAll("-", "");
const login = new URL(target); login.username = `${name}_login`; login.password = loginPassword;
const env = { ...process.env, DATABASE_URL: target.toString(), E2E_DATABASE_URL: target.toString(),
  E2E_APP_DATABASE_URL: login.toString(), APP_DATABASE_PASSWORD: loginPassword,
  DASHBOARD_SESSION_SECRET: `e2e-only-${randomUUID()}-${randomUUID()}` };
async function run(args) {
  const child = spawn(process.execPath, args, { env, stdio: "inherit" });
  const code = await new Promise((resolve, reject) => { child.on("error", reject); child.on("exit", resolve); });
  if (code !== 0) throw new Error(`E2E command failed (${code})`);
}
await admin.connect();
try {
  await admin.query(`CREATE DATABASE "${name}"`);
  await run(["scripts/migrate.mjs"]);
  await cp(".next/static", ".next/standalone/.next/static", { recursive: true });
  await cp("public", ".next/standalone/public", { recursive: true });
  await run(["node_modules/@playwright/test/cli.js", "test"]);
} finally {
  await admin.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
  // Migration 0019 and the migrate script created cluster-wide roles for the throwaway database.
  const { rows: [{ role }] } = await admin.query(`SELECT 'aiproxy_app_' || left(md5($1::text), 12) AS role`, [name]);
  await admin.query(`DROP ROLE IF EXISTS "${name}_login"`);
  await admin.query(`DROP ROLE IF EXISTS "${role}"`);
  await admin.end();
}
