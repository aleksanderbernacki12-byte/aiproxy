import { timingSafeEqual } from "node:crypto";

export function hasBearerToken(request: Request, expected: string | undefined) {
  if (!expected) {
    return false;
  }
  const actual = request.headers.get("authorization") ?? "";
  const wanted = `Bearer ${expected}`;
  const actualBytes = Buffer.from(actual);
  const wantedBytes = Buffer.from(wanted);
  return (
    actualBytes.length === wantedBytes.length &&
    timingSafeEqual(actualBytes, wantedBytes)
  );
}

export function hasSameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}
