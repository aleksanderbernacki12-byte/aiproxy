import { defineConfig, devices } from "@playwright/test";

if (!process.env.E2E_DATABASE_URL) throw new Error("Run npm run test:e2e to use an isolated database");
export default defineConfig({
  testDir: "./e2e", fullyParallel: false, workers: 1,
  forbidOnly: !!process.env.CI, retries: 0, timeout: 45_000,
  reporter: [["list"], ["html", { open: "never" }]],
  use: { baseURL: "http://localhost:32187", trace: "retain-on-failure", screenshot: "only-on-failure" },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile-chromium", use: { ...devices["Pixel 7"] } },
  ],
  webServer: { command: "node .next/standalone/server.js",
    url: "http://localhost:32187/login", reuseExistingServer: false, timeout: 60_000,
    env: { DATABASE_URL: process.env.E2E_DATABASE_URL, HOSTNAME: "localhost", PORT: "32187" } },
});
