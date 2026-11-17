import { defineConfig } from "vitest/config";

// Tauri expects a fixed dev port and its own output on screen, so do not clear it.
export default defineConfig({
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**"] },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: ["chrome105", "safari15"],
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
