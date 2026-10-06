/**
 * Entry point of the web session toolbar page (`web-chrome.html`), loaded
 * by the host in the `webchrome-<token>` webview of a web session window
 * (features/web-application-connect.md Phase 5, T96). Deliberately not the
 * vault UI: no router, no stores, no vault API — three host commands.
 */
import { invoke } from "@tauri-apps/api/core";
import { mountChrome } from "./chrome";
import "./webChrome.css";

const root = document.getElementById("web-chrome");
if (root) {
  mountChrome(root, { invoke: (cmd) => invoke(cmd) });
}
