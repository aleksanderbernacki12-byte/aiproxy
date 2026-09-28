import { execFileSync, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pg from "pg";

// A migration can pass on an empty database and still fail on one that holds
// the previous release's schema and rows. Upgrade from the latest release tag
// that is not this commit, as a non-superuser owner like managed PostgreSQL.
const source = new URL(process.env.TEST_DATABASE_URL ?? "");
if (!["localhost", "127.0.0.1", "[::1]"].includes(source.hostname)) throw new Error("Upgrade tests require a local disposable PostgreSQL service");

function git(...args) {
  return execFileSync("git", args, { encoding: "utf8" }).trim();
}
const head = git("rev-parse", "HEAD");
// UPGRADE_FROM_RELEASE checks an upgrade from an older release by hand.
const release = process.env.UPGRADE_FROM_RELEASE ?? git("tag", "--list", "v*", "--sort=-v:refname").split("\n")
  .find((tag) => tag && git("rev-list", "-n", "1", tag) !== head);
if (!release) throw new Error("No earlier release tag; fetch tags first (git fetch --tags)");

const previous = await mkdtemp(join(tmpdir(), "aiproxy-upgrade-"));
await mkdir(join(previous, "db", "migrations"), { recursive: true });
const migrations = git("ls-tree", "--full-tree", "--name-only", `${release}:control-plane/db/migrations`).split("\n").filter((name) => name.endsWith(".sql"));
if (migrations.length === 0) throw new Error(`${release} has no control-plane migrations`);
for (const name of migrations) {
  await writeFile(join(previous, "db", "migrations", name), git("show", `${release}:control-plane/db/migrations/${name}`));
}

const suffix = randomUUID().replaceAll("-", "").slice(0, 12);
const owner = { role: `aiproxy_upgrade_owner_${suffix}`, password: randomUUID(), database: `aiproxy_upgrade_${suffix}` };
const target = new URL(source);
target.username = owner.role;
target.password = owner.password;
target.pathname = `/${owner.database}`;
const organizationId = randomUUID();

async function run(args, { cwd, environment = {} } = {}) {
  const child = spawn(process.execPath, args, { cwd, stdio: "inherit",
    env: { ...process.env, DATABASE_URL: target.toString(), ...environment } });
  const code = await new Promise((resolve, reject) => { child.on("error", reject); child.on("exit", resolve); });
  if (code !== 0) throw new Error(`Upgrade command failed (${code})`);
}

const admin = new pg.Client({ connectionString: source.toString() });
await admin.connect();
try {
  await admin.query(`CREATE ROLE "${owner.role}" LOGIN NOSUPERUSER CREATEROLE PASSWORD '${owner.password}'`);
  await admin.query(`CREATE DATABASE "${owner.database}" OWNER "${owner.role}"`);
  console.log(`Migrating ${owner.database} to ${release}`);
  await run([join(process.cwd(), "scripts/migrate.mjs")], { cwd: previous });

  const client = new pg.Client({ connectionString: target.toString() });
  await client.connect();
  try {
    await client.query(`INSERT INTO organizations (id, name, tenant_key) VALUES ($1, 'Upgrade Organization', $2)`,
      [organizationId, createHash("sha256").update(randomUUID()).digest("hex")]);
    await client.query(
      `INSERT INTO ai_systems (organization_id, application_id, model, name, provider, intended_purpose,
         risk_class, system_owner, legal_basis, human_oversight)
       VALUES ($1, 'upgrade', 'm', 'Upgrade system', 'p', 'Testing upgrades', 'MINIMAL', 'Owner', 'Legitimate interest', 'Reviewer')`,
      [organizationId]);
  } finally {
    await client.end();
  }

  console.log(`Upgrading ${owner.database} from ${release} to this commit`);
  await run(["scripts/migrate.mjs"], { environment: { APP_DATABASE_PASSWORD: randomUUID().replaceAll("-", "") } });
  const upgraded = new pg.Client({ connectionString: target.toString() });
  await upgraded.connect();
  try {
    const { rows: [{ count }] } = await upgraded.query(`SELECT count(*)::int AS count FROM ai_systems WHERE organization_id = $1`, [organizationId]);
    if (count !== 1) throw new Error(`Upgrade lost the previous release's rows (found ${count})`);
  } finally {
    await upgraded.end();
  }
  await run(["./node_modules/vitest/vitest.mjs", "run", "--config", "vitest.integration.config.ts"]);
} finally {
  await admin.query(`DROP DATABASE IF EXISTS "${owner.database}" WITH (FORCE)`);
  const { rows: [{ role }] } = await admin.query(`SELECT 'aiproxy_app_' || left(md5($1::text), 12) AS role`, [owner.database]);
  await admin.query(`DROP ROLE IF EXISTS "${owner.database}_login"`);
  await admin.query(`DROP ROLE IF EXISTS "${role}"`);
  await admin.query(`DROP ROLE IF EXISTS "${owner.role}"`);
  await admin.end();
  await rm(previous, { recursive: true, force: true });
}
