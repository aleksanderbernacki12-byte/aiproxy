import type { NextConfig } from "next";

export const securityHeaders = [
	{
		key: "Content-Security-Policy",
		value: [
			"default-src 'self'",
			"base-uri 'self'",
			"connect-src 'self'",
			"font-src 'self'",
			"form-action 'self'",
			"frame-ancestors 'none'",
			"img-src 'self' data:",
			"object-src 'none'",
			"script-src 'self' 'unsafe-inline'",
			"style-src 'self' 'unsafe-inline'",
		].join("; "),
	},
	{ key: "Cross-Origin-Opener-Policy", value: "same-origin" },
	{ key: "Cross-Origin-Resource-Policy", value: "same-origin" },
	{ key: "Permissions-Policy", value: "camera=(), geolocation=(), microphone=(), payment=(), usb=()" },
	{ key: "Referrer-Policy", value: "same-origin" },
	{ key: "Strict-Transport-Security", value: "max-age=31536000" },
	{ key: "X-Content-Type-Options", value: "nosniff" },
	{ key: "X-Frame-Options", value: "DENY" },
] as const;

const nextConfig: NextConfig = {
	output: "standalone",
	async headers() {
		return [{ source: "/(.*)", headers: [...securityHeaders] }];
	},
};

export default nextConfig;
