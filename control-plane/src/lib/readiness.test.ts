import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { configurationFailures } from "./readiness";

function validEnvironment() {
  const anchor = generateKeyPairSync("ed25519");
  const report = generateKeyPairSync("ed25519");
  return {
    NODE_ENV: "production",
    DASHBOARD_SESSION_SECRET: "s".repeat(32),
    CRON_SECRET: "c".repeat(32),
    MERKLE_ANCHOR_TOKEN: "a".repeat(32),
    MERKLE_ANCHOR_URL: "https://anchor.example/v1/checkpoints",
    MERKLE_ANCHOR_PUBLIC_KEY: anchor.publicKey.export({ type: "spki", format: "pem" }).toString(),
    REPORT_SIGNING_PRIVATE_KEY: report.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    TELEMETRY_REORDER_WINDOW_SECONDS: "30",
  };
}

describe("Control Plane readiness configuration", () => {
  it("accepts complete independent production cryptography", () => {
    expect(configurationFailures(validEnvironment())).toEqual([]);
  });

  it("rejects missing, reused, malformed, and insecure production settings", () => {
    const environment = validEnvironment();
    environment.CRON_SECRET = environment.DASHBOARD_SESSION_SECRET;
    environment.MERKLE_ANCHOR_URL = "http://anchor.example";
    environment.MERKLE_ANCHOR_PUBLIC_KEY = "invalid";
    environment.REPORT_SIGNING_PRIVATE_KEY = "invalid";
    environment.TELEMETRY_REORDER_WINDOW_SECONDS = "0";
    expect(configurationFailures(environment)).toEqual(expect.arrayContaining([
      "secret_reuse", "anchor_https", "anchor_public_key", "report_private_key", "reorder_window",
    ]));
  });
});
