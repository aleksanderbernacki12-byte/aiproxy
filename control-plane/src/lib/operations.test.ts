import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("@/db/client", () => ({ getDatabase: vi.fn() }));

import { formatControlPlaneMetrics } from "./operations";

describe("Control Plane Prometheus metrics", () => {
  it("formats backlog and verification outcomes without tenant labels", () => {
    const output = formatControlPlaneMetrics({
      bufferPending: 4,
      oldestBufferedSeconds: 75,
      verifiedEvents: 20,
      compromisedEvents: 2,
      invalidSignatureEvents: 1,
      pendingAnchors: 3,
      oldestPendingAnchorSeconds: 900,
    });
    for (const line of [
      "aiproxy_control_plane_buffer_pending 4",
      "aiproxy_control_plane_oldest_buffered_seconds 75",
      "aiproxy_control_plane_verified_events_total 20",
      "aiproxy_control_plane_compromised_events_total 2",
      "aiproxy_control_plane_invalid_signature_events_total 1",
      "aiproxy_control_plane_pending_merkle_anchors 3",
      "aiproxy_control_plane_oldest_pending_anchor_seconds 900",
    ]) expect(output).toContain(line);
    expect(output).not.toContain("organization");
  });
});
