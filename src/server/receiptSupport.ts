import type { Express, Request, Response } from "express";
import type { VLinkRegistry } from "./vlinkRegistry";
import type { VLinkSignedReceipt } from "../types/vlink";
import { VLinkReceiptSigner, verifyVLinkReceipt } from "./receiptSigner";

export interface ReceiptSupportOptions {
  privateKeyPem?: string;
}

const bearerToken = (req: Request) => {
  const authorization = req.header("authorization")?.trim();
  if (!authorization) return undefined;
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  return match?.[1]?.trim() || undefined;
};

export const installReceiptSupport = (
  app: Express,
  registry: VLinkRegistry,
  options: ReceiptSupportOptions = {},
) => {
  const signer = new VLinkReceiptSigner(options.privateKeyPem ?? process.env.VLINK_RECEIPT_PRIVATE_KEY_PEM);
  const receiptsById = new Map<string, VLinkSignedReceipt>();
  const receiptIdsByVLink = new Map<string, string[]>();
  const originalAddActivity = registry.addActivity.bind(registry);

  registry.addActivity = ((event, now) => {
    const activity = originalAddActivity(event, now);
    const receipt = signer.signEvent(activity, now ?? new Date());
    receiptsById.set(receipt.receiptId, receipt);
    const ids = receiptIdsByVLink.get(receipt.vlinkId) ?? [];
    ids.unshift(receipt.receiptId);
    receiptIdsByVLink.set(receipt.vlinkId, ids.slice(0, 100));
    return activity;
  }) as VLinkRegistry["addActivity"];

  const requireReceiptAccess = (req: Request, res: Response, vlinkId: string) => {
    const token = bearerToken(req);
    if (!token || !token.startsWith("vlt_")) {
      res.setHeader("WWW-Authenticate", 'Bearer realm="VLink receipts"');
      res.status(401).json({ error: "vlink_access_token_required" });
      return false;
    }
    if (!registry.authenticate(vlinkId, token)) {
      res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
      res.status(401).json({ error: "invalid_or_expired_vlink_access_token" });
      return false;
    }
    return true;
  };

  app.get("/.well-known/vlink-receipt-key.json", (_req, res) => {
    res.setHeader("Cache-Control", "public, max-age=300");
    res.json(signer.keyDescriptor());
  });

  app.get("/receipts/vlinks/:vlinkId", (req, res) => {
    if (!registry.get(req.params.vlinkId)) return res.status(404).json({ error: "vlink_not_found" });
    if (!requireReceiptAccess(req, res, req.params.vlinkId)) return;
    const receipts = (receiptIdsByVLink.get(req.params.vlinkId) ?? [])
      .map((id) => receiptsById.get(id))
      .filter((receipt): receipt is VLinkSignedReceipt => Boolean(receipt))
      .map((receipt) => structuredClone(receipt));
    res.json({ vlinkId: req.params.vlinkId, keyId: signer.keyDescriptor().keyId, receipts });
  });

  app.get("/receipts/:receiptId", (req, res) => {
    const receipt = receiptsById.get(req.params.receiptId);
    if (!receipt) return res.status(404).json({ error: "receipt_not_found" });
    if (!requireReceiptAccess(req, res, receipt.vlinkId)) return;
    res.json({ receipt: structuredClone(receipt) });
  });

  app.post("/receipts/verify", (req, res) => {
    const receipt = req.body?.receipt as VLinkSignedReceipt | undefined;
    if (!receipt) return res.status(400).json({ error: "receipt_required" });
    const expectedKeyId = typeof req.body?.expectedKeyId === "string" ? req.body.expectedKeyId : undefined;
    res.json(verifyVLinkReceipt(receipt, expectedKeyId));
  });

  return {
    keyDescriptor: () => signer.keyDescriptor(),
    receipt: (receiptId: string) => {
      const receipt = receiptsById.get(receiptId);
      return receipt ? structuredClone(receipt) : undefined;
    },
    receipts: (vlinkId: string) =>
      (receiptIdsByVLink.get(vlinkId) ?? [])
        .map((id) => receiptsById.get(id))
        .filter((receipt): receipt is VLinkSignedReceipt => Boolean(receipt))
        .map((receipt) => structuredClone(receipt)),
  };
};
