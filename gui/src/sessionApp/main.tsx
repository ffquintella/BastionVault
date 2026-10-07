/**
 * Entry point of `session.html`, the session-only bundle (T110). See
 * `SessionApp.tsx` for what it mounts and why.
 */
import React from "react";
import ReactDOM from "react-dom/client";
import { SessionApp } from "./SessionApp";
import "../index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <SessionApp />
  </React.StrictMode>,
);
