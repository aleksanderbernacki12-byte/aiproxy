import { describe, expect, it } from "vitest";
import { findExtendingEventIndex } from "./ordering";
import { createSignedFixture } from "./test-fixture";

describe("buffer ordering", () => {
  it("selects the event linked to the current head even when it arrived later", () => {
    const currentHead = "c".repeat(64);
    const missingPredecessor = createSignedFixture("d".repeat(64)).event;
    const extendingEvent = createSignedFixture(currentHead).event;
    const rows = [{ payload: missingPredecessor }, { payload: extendingEvent }];
    expect(findExtendingEventIndex(rows, currentHead)).toBe(1);
  });

  it("returns no candidate when the predecessor has not arrived", () => {
    const event = createSignedFixture("d".repeat(64)).event;
    expect(findExtendingEventIndex([{ payload: event }], "c".repeat(64))).toBe(-1);
  });
});
