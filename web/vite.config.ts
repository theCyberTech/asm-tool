import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const rootDir = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [
    react(),
    {
      name: "strip-crossorigin",
      transformIndexHtml: {
        order: "post",
        handler(html) {
          return html.replace(/ crossorigin(="[^"]*")?/g, "");
        },
      },
    },
  ],
  base: "/",
  build: {
    outDir: resolve(rootDir, "../asm-go/internal/dashboard/webdist"),
    emptyOutDir: false,
    sourcemap: false,
    modulePreload: false,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8080",
      "/health": "http://127.0.0.1:8080",
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts",
    restoreMocks: true,
  },
});
