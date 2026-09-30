import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { initAnalytics, trackPage } from "./analytics/tracker";
import "./index.css";

// First-party, cookieless analytics (see veklom.com/privacy).
initAnalytics({ host: "vlink" });
trackPage(window.location.pathname);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
