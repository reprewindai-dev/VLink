import path from "node:path";
import dotenv from "dotenv";
import express from "express";
import { createServer as createViteServer } from "vite";
import { createApp } from "./src/server/app";
import { installFailoverSupport } from "./src/server/failoverSupport";
import { installReceiptSupport } from "./src/server/receiptSupport";

dotenv.config();

const PORT = Number(process.env.PORT || 3000);
const { app, registry } = createApp({ publicOrigin: process.env.VLINK_PUBLIC_ORIGIN });
installReceiptSupport(app, registry, { privateKeyPem: process.env.VLINK_RECEIPT_PRIVATE_KEY_PEM });
installFailoverSupport(app, registry, { timeoutMs: Number(process.env.VLINK_FAILOVER_TIMEOUT_MS ?? 4_000) });

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
