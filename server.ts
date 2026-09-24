import path from "node:path";
import dotenv from "dotenv";
import express from "express";
import { createServer as createViteServer } from "vite";
import { createApp } from "./src/server/app";
import { FileBackedVLinkRegistry } from "./src/server/fileBackedRegistry";
import { createLeaseSealer } from "./src/server/leaseSealer";
import { installFailoverSupport } from "./src/server/failoverSupport";
import { installReceiptSupport } from "./src/server/receiptSupport";

dotenv.config();

const PORT = Number(process.env.PORT || 3000);
const production = process.env.NODE_ENV === "production";
const statePath = process.env.VLINK_STATE_PATH?.trim();
if (production && !statePath) {
  throw new Error("VLINK_STATE_PATH is required in production so VLink identity and access state survive process restarts");
}
const lockerPhycerBaseUrl = process.env.VLINK_LOCKERPHYCER_URL?.trim() || process.env.LOCKERPHYCER_URL?.trim();
if (production && !lockerPhycerBaseUrl) {
  throw new Error("VLINK_LOCKERPHYCER_URL (or LOCKERPHYCER_URL) is required in production for workspace identity and approval");
}
const leaseSealer = createLeaseSealer();
if (production && !leaseSealer) {
  throw new Error("VLINK_LEASE_SEALING_KEY must be a valid 32-byte base64 or 64-character hex key in production for recoverable device exchange");
}
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
  app.get("*", (_req, res) => res.sendFile(path.join(clientPath, "index.html")));
}

app.listen(PORT, "0.0.0.0", () => {
  console.log(`VLink listening on http://0.0.0.0:${PORT}`);
});
