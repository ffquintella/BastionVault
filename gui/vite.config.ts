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
      // Three pages: the vault UI; the web session toolbar the desktop host
      // loads in its own webview above a web session's remote content
      // (features/web-application-connect.md Phase 5); and the session
      // windows — a session's own window, the Session Workspace and
      // recording replays (features/session-workspace.md, T110). The last
      // two are separate entries so those webviews load none of the vault
      // UI. The host's URLs name these files (`session/workspace.rs`).
      input: {
        main: fileURLToPath(new URL("./index.html", import.meta.url)),
        webChrome: fileURLToPath(new URL("./web-chrome.html", import.meta.url)),
        session: fileURLToPath(new URL("./session.html", import.meta.url)),
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
