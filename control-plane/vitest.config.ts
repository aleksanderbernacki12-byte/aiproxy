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
    exclude: ["e2e/**", "src/integration/**", "**/node_modules/**", "**/.git/**"],
    coverage: { reporter: ["text"] },
  },
});
