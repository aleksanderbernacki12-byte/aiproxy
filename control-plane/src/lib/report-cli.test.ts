import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import canonicalize from "canonicalize";
import { expect, it } from "vitest";

it("generates owner-only report keys and verifies sealed artifacts offline", async () => {
  const directory = await mkdtemp(join(tmpdir(), "aiproxy-report-cli-"));
  try {
    const privatePath = join(directory, "report-private.pem");
    const publicPath = join(directory, "report-public.pem");
    const keygen = spawnSync(process.execPath, ["scripts/generate-report-signing-key.mjs", privatePath, publicPath], {
      cwd: process.cwd(), encoding: "utf8",
    });
    expect(keygen.status, keygen.stderr).toBe(0);
    expect((await stat(privatePath)).mode & 0o777).toBe(0o600);
    const privateKey = createPrivateKey(await readFile(privatePath, "utf8"));
    const publicKey = createPublicKey(await readFile(publicPath, "utf8"));
    const payload = { schema_version: "aiproxy-compliance-report-v1", evidence: { total_events: 7 } };
    const canonical = Buffer.from(canonicalize(payload)!);
    const report = {
      report_id: "11111111-1111-4111-8111-111111111111",
      payload,
      payload_hash: createHash("sha256").update(canonical).digest("hex"),
      signature_algorithm: "Ed25519",
      signing_key_id: createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex"),
      signature: sign(null, Buffer.concat([Buffer.from("aiproxy-compliance-report-v1\0"), canonical]), privateKey).toString("base64"),
      created_at: "2026-09-15T20:00:00.000Z",
    };
    const reportPath = join(directory, "report.json");
    await writeFile(reportPath, JSON.stringify(report));
    const verified = spawnSync(process.execPath, ["scripts/verify-compliance-report.mjs", reportPath, publicPath], {
      cwd: process.cwd(), encoding: "utf8",
    });
    expect(verified.status, verified.stderr).toBe(0);
    expect(verified.stdout).toContain("VERIFIED report 11111111");

    await writeFile(reportPath, JSON.stringify({ ...report, payload: { ...payload, evidence: { total_events: 8 } } }));
    const tampered = spawnSync(process.execPath, ["scripts/verify-compliance-report.mjs", reportPath, publicPath], {
      cwd: process.cwd(), encoding: "utf8",
    });
    expect(tampered.status).not.toBe(0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
