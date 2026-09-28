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

  const secret = "a".repeat(32);
  const withForwardedFor = (value: string) => new Request("https://control.example/login", { headers: { "x-forwarded-for": value } });

  it("uses the address the trusted proxy appended, not one the client supplied", () => {
    const direct = hashLoginSource(withForwardedFor("203.0.113.7"), secret, 1);
    expect(hashLoginSource(withForwardedFor("198.51.100.1, 203.0.113.7"), secret, 1)).toBe(direct);
    expect(hashLoginSource(withForwardedFor("198.51.100.2, 203.0.113.7"), secret, 1)).toBe(direct);
  });

  it("skips one address per additional trusted proxy", () => {
    const client = hashLoginSource(withForwardedFor("203.0.113.7"), secret, 1);
    expect(hashLoginSource(withForwardedFor("198.51.100.1, 203.0.113.7, 10.0.0.2"), secret, 2)).toBe(client);
    expect(hashLoginSource(withForwardedFor("203.0.113.7"), secret, 2)).toBe(client);
  });
});
