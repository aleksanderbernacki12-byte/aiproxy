import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import pg from "pg";

// Neon's pooled endpoint and most managed poolers run pgbouncer in
// transaction mode: server connections, and any session state on them, pass
// between clients. Run the integration suite through one, after leaving
// cross-tenant mode switched on for the session of a pooled server connection.
const image = "edoburu/pgbouncer@sha256:4c1ca296ef525f108f5d3552cc337c0c09587cf8dae7f0067fd93349e47dc1cd";
const source = new URL(process.env.TEST_DATABASE_URL ?? "");
const postgresContainer = process.env.TEST_POSTGRES_CONTAINER;
if (!["localhost", "127.0.0.1", "[::1]"].includes(source.hostname) || !postgresContainer) {
  throw new Error("pgbouncer tests require TEST_DATABASE_URL on a local disposable PostgreSQL and TEST_POSTGRES_CONTAINER");
}

function docker(...args) {
  return execFileSync("docker", args, { encoding: "utf8" }).trim();
}
const [networkName, network] = Object.entries(JSON.parse(docker("inspect", postgresContainer))[0].NetworkSettings.Networks)[0];
const name = `aiproxy-pgbouncer-${randomUUID().slice(0, 8)}`;
const user = decodeURIComponent(source.username);
docker("run", "-d", "--name", name, "--network", networkName, "-p", "127.0.0.1::5432",
  "-e", `DB_HOST=${network.IPAddress}`, "-e", "DB_PORT=5432",
  "-e", `DB_USER=${user}`, "-e", `DB_PASSWORD=${decodeURIComponent(source.password)}`,
  // Looks up every other role (the application login role) through the superuser.
  "-e", `AUTH_USER=${user}`, "-e", "AUTH_TYPE=scram-sha-256",
  "-e", "POOL_MODE=transaction", "-e", "DEFAULT_POOL_SIZE=2", "-e", "MAX_CLIENT_CONN=200", image);

try {
  const target = new URL(source);
  target.hostname = "127.0.0.1";
  target.port = docker("port", name, "5432/tcp").split(":").at(-1);
  for (let attempt = 1; ; attempt += 1) {
    const client = new pg.Client({ connectionString: target.toString() });
    try {
      await client.connect();
      await client.query("SELECT set_config('aiproxy.cross_tenant', 'on', false)");
      await client.end();
      break;
    } catch (error) {
      await client.end().catch(() => undefined);
      if (attempt === 30) throw error;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
  console.log(`Running the integration suite through pgbouncer (transaction mode) at ${target.host}`);
  const child = spawn(process.execPath, ["./node_modules/vitest/vitest.mjs", "run", "--config", "vitest.integration.config.ts"],
    { env: { ...process.env, DATABASE_URL: target.toString() }, stdio: "inherit" });
  const code = await new Promise((resolve, reject) => { child.on("error", reject); child.on("exit", resolve); });
  process.exitCode = code ?? 1;
} finally {
  docker("rm", "-f", name);
}
