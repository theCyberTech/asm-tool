import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const rootDir = dirname(fileURLToPath(import.meta.url));

function classicDashboardBundle() {
  return {
    name: "classic-dashboard-bundle",
    transformIndexHtml: {
      order: "post" as const,
      handler(html: string) {
        let out = html.replace(/ crossorigin(="[^"]*")?/g, "").replace(/\s+type="module"/g, "");
        const match = out.match(/<script src="(\/assets\/[^"]+\.js)"><\/script>/);
        if (match) {
          out = out.replace(match[0], "");
          out = out.replace("</body>", `    <script defer src="${match[1]}"></script>\n  </body>`);
        }
        return out;
      },
    },
  };
}

export default defineConfig({
  plugins: [react(), classicDashboardBundle()],
  base: "/",
  build: {
    outDir: resolve(rootDir, "../asm-go/internal/dashboard/webdist"),
    emptyOutDir: false,
    sourcemap: false,
    modulePreload: false,
    rollupOptions: {
      output: {
        format: "iife",
        name: "ASMDashboard",
        inlineDynamicImports: true,
        entryFileNames: "assets/index.js",
      },
    },
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
