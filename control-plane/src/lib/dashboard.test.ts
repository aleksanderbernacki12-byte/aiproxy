import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("@/db/client", () => ({ withOrganization: vi.fn() }));

import { chainStatusFor } from "./dashboard";

describe("dashboard data policy", () => {
  const now = new Date("2026-09-28T12:00:00.000Z");
  const cleanRun = { completedAt: new Date("2026-09-28T11:00:00.000Z"), complete: true, failures: 0 };

  it("classifies audit-chain evidence conservatively", () => {
    expect(chainStatusFor(0, 0, 0, null, now)).toBe("NO_EVIDENCE");
    expect(chainStatusFor(10, 0, 0, cleanRun, now)).toBe("INTACT");
    expect(chainStatusFor(10, 1, 0, cleanRun, now)).toBe("ATTENTION_REQUIRED");
    expect(chainStatusFor(10, 0, 1, cleanRun, now)).toBe("ATTENTION_REQUIRED");
  });

  it("requires a recent, complete, clean re-verification run", () => {
    expect(chainStatusFor(10, 0, 0, null, now)).toBe("ATTENTION_REQUIRED");
    expect(chainStatusFor(10, 0, 0, { ...cleanRun, failures: 1 }, now)).toBe("ATTENTION_REQUIRED");
    expect(chainStatusFor(10, 0, 0, { ...cleanRun, complete: false }, now)).toBe("ATTENTION_REQUIRED");
    expect(chainStatusFor(10, 0, 0, { ...cleanRun, completedAt: new Date("2026-09-26T11:59:00.000Z") }, now))
      .toBe("ATTENTION_REQUIRED");
    expect(chainStatusFor(10, 0, 0, { ...cleanRun, completedAt: new Date("2026-09-26T12:01:00.000Z") }, now))
      .toBe("INTACT");
  });

});
