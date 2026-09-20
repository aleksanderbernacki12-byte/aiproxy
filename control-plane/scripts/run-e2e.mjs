import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import pg from "pg";
import { cp } from "node:fs/promises";

const source = new URL(process.env.TEST_DATABASE_URL ?? "");
if (!["localhost", "127.0.0.1", "[::1]"].includes(source.hostname)) throw new Error("E2E requires a local disposable PostgreSQL service");
const name = `aiproxy_e2e_${randomUUID().replaceAll("-", "")}`;
const admin = new pg.Client({ connectionString: source.toString() });
const target = new URL(source); target.pathname = `/${name}`;
const env = { ...process.env, DATABASE_URL: target.toString(), E2E_DATABASE_URL: target.toString(),
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
  await admin.end();
}
