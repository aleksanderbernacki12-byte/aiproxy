import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createSignedFixture } from "@/lib/telemetry/test-fixture";

const mocks = vi.hoisted(() => ({
  bufferTelemetryEvents: vi.fn(),
  authenticateTenant: vi.fn(),
}));

vi.mock("@/lib/telemetry/ingest", () => ({
  bufferTelemetryEvents: mocks.bufferTelemetryEvents,
}));
vi.mock("@/lib/tenant-auth", () => ({
  authenticateTenant: mocks.authenticateTenant,
}));

import { POST } from "./route";

function request(body: unknown, token = "tenant-secret") {
  return new Request("https://control.example/api/telemetry/ingest", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

describe("POST /api/telemetry/ingest", () => {
  beforeEach(() => {
    mocks.authenticateTenant.mockImplementation(async (incoming: Request) =>
      incoming.headers.get("authorization") === "Bearer tenant-secret"
        ? { id: "11111111-1111-1111-1111-111111111111", name: "Acme" }
        : null,
    );
    mocks.bufferTelemetryEvents.mockResolvedValue({ accepted: 1, duplicates: 0 });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("authenticates, validates, buffers, and returns 202", async () => {
    const { event } = createSignedFixture();
    const response = await POST(request([event]));
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({
      status: "BUFFERED",
      accepted: 1,
      duplicates: 0,
    });
    expect(mocks.bufferTelemetryEvents).toHaveBeenCalledWith(
      "11111111-1111-1111-1111-111111111111",
      [event],
    );
  });

  it("returns 503 when tenant lookup is unavailable", async () => {
    const { event } = createSignedFixture();
    mocks.authenticateTenant.mockRejectedValueOnce(new Error("database offline"));
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const response = await POST(request(event));
    expect(response.status).toBe(503);
    expect(mocks.bufferTelemetryEvents).not.toHaveBeenCalled();
    errorSpy.mockRestore();
  });

  it("rejects unauthorized and structurally invalid payloads", async () => {
    const { event } = createSignedFixture();
    expect((await POST(request(event, "wrong"))).status).toBe(401);
    expect((await POST(request({ ...event, prompt: "plaintext" }))).status).toBe(400);
    expect(mocks.bufferTelemetryEvents).not.toHaveBeenCalled();
  });

  it("returns 503 without acknowledging an event when Postgres is unavailable", async () => {
    const { event } = createSignedFixture();
    mocks.bufferTelemetryEvents.mockRejectedValueOnce(new Error("database offline"));
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const response = await POST(request(event));
    expect(response.status).toBe(503);
    expect(errorSpy).toHaveBeenCalledOnce();
    errorSpy.mockRestore();
  });
});
