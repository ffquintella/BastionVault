import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const host = process.env.TAURI_DEV_HOST;

export default defineConfig(async () => ({
  plugins: [react(), tailwindcss()],
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
  clearScreen: false,
  build: {
    rolldownOptions: {
      // Two pages: the vault UI, and the web session toolbar the desktop
      // host loads in its own webview above a web session's remote content
      // (features/web-application-connect.md Phase 5). The toolbar is a
      // separate entry so that webview loads none of the vault UI.
      input: {
        main: fileURLToPath(new URL("./index.html", import.meta.url)),
        webChrome: fileURLToPath(new URL("./web-chrome.html", import.meta.url)),
      },
    },
  },
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
}));
