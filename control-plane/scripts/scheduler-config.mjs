export function internalBaseUrl(value) {
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("CONTROL_PLANE_INTERNAL_URL must use HTTP or HTTPS");
  if (url.username || url.password || url.search || url.hash) throw new Error("CONTROL_PLANE_INTERNAL_URL must not contain credentials, query, or fragment");
  return url;
}

export function requestTimeout(value) {
  if (value === undefined || value === "") return 70_000;
  if (!/^[0-9]+$/.test(value)) throw new Error("SCHEDULER_REQUEST_TIMEOUT_MS must be an integer");
  const milliseconds = Number(value);
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 5_000 || milliseconds > 300_000) {
    throw new Error("SCHEDULER_REQUEST_TIMEOUT_MS must be between 5000 and 300000");
  }
  return milliseconds;
}
