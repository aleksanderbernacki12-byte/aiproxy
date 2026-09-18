// PostgreSQL bigint cursors remain strings until validated to avoid precision loss.
export function parseAuditCursor(value: string | string[] | undefined): bigint | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !/^[1-9][0-9]{0,18}$/.test(value)) throw new Error("Invalid audit cursor");
  const cursor = BigInt(value);
  if (cursor > 9223372036854775807n) throw new Error("Invalid audit cursor");
  return cursor;
}
