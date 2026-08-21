import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";
import "./styles/theme.css";

function mountDashboard() {
  const root = document.getElementById("root");
  if (!root) {
    throw new Error("ASM dashboard root element is missing");
  }
  if (root.dataset.mounted === "true") {
    return;
  }
  root.dataset.mounted = "true";
  createRoot(root).render(
    <StrictMode>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </StrictMode>,
  );
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", mountDashboard);
} else {
  mountDashboard();
}
