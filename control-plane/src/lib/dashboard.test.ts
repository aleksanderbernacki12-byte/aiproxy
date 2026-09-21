import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("@/db/client", () => ({ getDatabase: vi.fn() }));

import { chainStatusFor } from "./dashboard";

describe("dashboard data policy", () => {
  it("classifies audit-chain evidence conservatively", () => {
    expect(chainStatusFor(0, 0, 0)).toBe("NO_EVIDENCE");
    expect(chainStatusFor(10, 0, 0)).toBe("INTACT");
    expect(chainStatusFor(10, 1, 0)).toBe("ATTENTION_REQUIRED");
    expect(chainStatusFor(10, 0, 1)).toBe("ATTENTION_REQUIRED");
  });

});
