import process from "node:process";
import { internalBaseUrl, requestTimeout } from "./scheduler-config.mjs";

const secret = process.env.CRON_SECRET;
if (!secret || secret.length < 32) throw new Error("CRON_SECRET must contain at least 32 characters");

const baseUrl = internalBaseUrl(process.env.CONTROL_PLANE_INTERNAL_URL ?? "http://app:3000");
const timeoutMs = requestTimeout(process.env.SCHEDULER_REQUEST_TIMEOUT_MS);

const running = new Set();
async function invoke(path) {
  const response = await fetch(new URL(path, baseUrl), {
    headers: { authorization: `Bearer ${secret}` },
    signal: AbortSignal.timeout(timeoutMs),
  });
  try {
    if (!response.ok) throw new Error(`${path} returned HTTP ${response.status}`);
  } finally {
    await response.body?.cancel();
  }
}

async function run(path) {
  if (running.has(path)) return;
  running.add(path);
  try { await invoke(path); }
  catch (error) { console.error("Control Plane scheduled task failed", error); }
  finally { running.delete(path); }
}

async function checkpointAndAnchor() {
  await run("/api/internal/telemetry/checkpoint");
  await run("/api/internal/telemetry/anchor");
}

await run("/api/internal/telemetry/process");
await run("/api/internal/retention/run");
setInterval(() => void run("/api/internal/telemetry/process"), 60_000);
setInterval(() => void checkpointAndAnchor(), 5 * 60_000);
setInterval(() => void run("/api/internal/retention/run"), 24 * 60 * 60_000);
