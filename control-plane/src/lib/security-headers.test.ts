import { describe, expect, it } from "vitest";
import nextConfig, { securityHeaders } from "../../next.config";

describe("Control Plane security headers", () => {
  it("applies restrictive browser policies to every route", async () => {
    const configured = Object.fromEntries(securityHeaders.map(({ key, value }) => [key, value]));
    expect(configured["Content-Security-Policy"]).toContain("frame-ancestors 'none'");
    expect(configured["Content-Security-Policy"]).toContain("form-action 'self'");
    expect(configured["Content-Security-Policy"]).toContain("object-src 'none'");
    expect(configured["X-Content-Type-Options"]).toBe("nosniff");
    expect(configured["X-Frame-Options"]).toBe("DENY");
    expect(configured["Referrer-Policy"]).toBe("same-origin");

    const routes = await nextConfig.headers?.();
    expect(routes).toEqual([{ source: "/(.*)", headers: [...securityHeaders] }]);
  });
});
