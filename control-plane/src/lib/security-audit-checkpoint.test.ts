import { describe, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { calculateSecurityAuditAnchorRoot } from "./security-audit-checkpoint";

describe("security audit anchor roots", () => {
  it("binds the checkpoint to tenant, sequence, and audit head", () => {
    const hash = "a".repeat(64);
    const root = calculateSecurityAuditAnchorRoot("11111111-1111-4111-8111-111111111111", "7", hash);
    expect(root).toMatch(/^[a-f0-9]{64}$/);
    expect(calculateSecurityAuditAnchorRoot("22222222-2222-4222-8222-222222222222", "7", hash)).not.toBe(root);
    expect(calculateSecurityAuditAnchorRoot("11111111-1111-4111-8111-111111111111", "8", hash)).not.toBe(root);
    expect(() => calculateSecurityAuditAnchorRoot("org", "0", hash)).toThrow(/invalid/);
  });
});
