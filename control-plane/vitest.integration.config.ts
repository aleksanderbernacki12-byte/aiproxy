import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  test: {
    environment: "node",
    include: ["src/integration/**/*.integration.test.ts"],
    // Every file applies the migrations to the same database; running them
    // concurrently races the DDL.
    fileParallelism: false,
  },
});
