import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("@/db/client", () => ({ getDatabase: vi.fn() }));

import { hashDPOAccessKey } from "./dpo-auth";

describe("DPO access key hashing", () => {
  it("produces a stable SHA-256 digest without retaining the credential", () => {
    expect(hashDPOAccessKey("dpo-secret")).toBe("215548b0e6f95dfd94fd735c31f2840413901aa6afe7f314ea3b4aa30dd1a5f1");
  });
});
