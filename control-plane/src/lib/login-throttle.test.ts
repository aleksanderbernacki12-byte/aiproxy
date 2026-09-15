import { describe, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { hashLoginSource } from "./login-throttle";

describe("dashboard login source pseudonymization", () => {
  it("creates stable, secret-bound hashes without retaining the source address", () => {
    const request = new Request("https://control.example/login", { headers: { "x-forwarded-for": "192.0.2.15, 10.0.0.1" } });
    const first = hashLoginSource(request, "a".repeat(32));
    expect(first).toMatch(/^[a-f0-9]{64}$/);
    expect(first).not.toContain("192.0.2.15");
    expect(hashLoginSource(request, "a".repeat(32))).toBe(first);
    expect(hashLoginSource(request, "b".repeat(32))).not.toBe(first);
  });
});
