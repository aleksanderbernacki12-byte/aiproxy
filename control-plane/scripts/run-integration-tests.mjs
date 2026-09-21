import { spawnSync } from "node:child_process";
import process from "node:process";

const databaseUrl = process.env.TEST_DATABASE_URL;
if (!databaseUrl) {
  throw new Error("TEST_DATABASE_URL is required and must point to a disposable PostgreSQL database");
}

const result = spawnSync(
  process.execPath,
  ["./node_modules/vitest/vitest.mjs", "run", "--config", "vitest.integration.config.ts"],
  {
    cwd: process.cwd(),
    env: { ...process.env, DATABASE_URL: databaseUrl,
      TEST_BACKUP_RECOVERY: process.argv.includes("--recovery") ? "1" : "0" },
    stdio: "inherit",
  },
);

process.exitCode = result.status ?? 1;
