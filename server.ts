import path from "node:path";
import dotenv from "dotenv";
import express from "express";
import { createServer as createViteServer } from "vite";
import { createApp } from "./src/server/app";
import { FileBackedVLinkRegistry } from "./src/server/fileBackedRegistry";
import { createLeaseSealer } from "./src/server/leaseSealer";
import { installFailoverSupport } from "./src/server/failoverSupport";
import { installReceiptSupport } from "./src/server/receiptSupport";
import { disabledOptionalFeatures, missingProductionConfig } from "./src/server/startupConfig";

dotenv.config();

const PORT = Number(process.env.PORT || 3000);
const production = process.env.NODE_ENV === "production";
if (production) {
  // Fail closed: report every missing required setting at once so one restart fixes them all.
  const missing = missingProductionConfig(process.env);
  if (missing.length) throw new Error(`VLink refuses to start in production:\n- ${missing.join("\n- ")}`);
}
const statePath = process.env.VLINK_STATE_PATH?.trim();
const lockerPhycerBaseUrl = process.env.VLINK_LOCKERPHYCER_URL?.trim() || process.env.LOCKERPHYCER_URL?.trim();
const leaseSealer = createLeaseSealer();
for (const line of disabledOptionalFeatures(process.env)) console.log(`[vlink] ${line}`);
const registry = statePath ? new FileBackedVLinkRegistry({ statePath, leaseSealer }) : undefined;
const { app, registry: activeRegistry } = createApp({
  registry,
  leaseSealer,
  lockerPhycerBaseUrl,
  publicOrigin: process.env.VLINK_PUBLIC_ORIGIN,
  pairingOrigin: process.env.VLINK_PAIRING_ORIGIN,
});
installReceiptSupport(app, activeRegistry, { privateKeyPem: process.env.VLINK_RECEIPT_PRIVATE_KEY_PEM });
installFailoverSupport(app, activeRegistry, { timeoutMs: Number(process.env.VLINK_FAILOVER_TIMEOUT_MS ?? 4_000) });

if (process.env.NODE_ENV !== "production") {
  const vite = await createViteServer({ server: { middlewareMode: true }, appType: "spa" });
  app.use(vite.middlewares);
} else {
  const clientPath = path.join(process.cwd(), "dist", "client");
  app.use(express.static(clientPath));
  // The client is built with base "/vlink/connect/" (veklom.com proxies that prefix here, stripped).
  // Served directly on vlink.veklom.com the prefix arrives intact, so serve assets under it too.
  app.use("/vlink/connect", express.static(clientPath));
  app.get("*", (_req, res) => res.sendFile(path.join(clientPath, "index.html")));
}

app.listen(PORT, "0.0.0.0", () => {
  console.log(`VLink listening on http://0.0.0.0:${PORT}`);
});
