import { expect, it } from "vitest";
import { parseAuditCursor } from "./audit-pagination";

it("preserves bigint precision and accepts the first page", () => {
  expect(parseAuditCursor(undefined)).toBeUndefined();
  expect(parseAuditCursor("1")).toBe(1n);
  expect(parseAuditCursor("9223372036854775807")).toBe(9223372036854775807n);
});
it.each(["", "0", "-1", "01", "1.5", "1e3", " 1", "9223372036854775808", "1".repeat(100), ["1", "2"]])("rejects invalid cursors %s", (value) => {
  expect(() => parseAuditCursor(value)).toThrow("Invalid audit cursor");
});
