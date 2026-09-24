import { createHash } from "node:crypto";
import type { Request, Response } from "express";
import type { VLinkRegistry } from "./vlinkRegistry";
import type { DeviceRequestProof } from "./pairingProof";

type RequestWithVLinkBodyHash = Request & { vlinkBodyHash?: string };

const sha256 = (value: Buffer | string) => createHash("sha256").update(value).digest("hex");

export const captureVLinkRequestBodyHash = (request: Request, _response: Response, body: Buffer) => {
  (request as RequestWithVLinkBodyHash).vlinkBodyHash = sha256(body);
};

const parseDeviceRequestProof = (value: string | undefined): Pick<DeviceRequestProof, "timestampMs" | "nonce" | "signature"> | undefined => {
  if (!value || value.length > 2_048 || !/^[A-Za-z0-9_-]+$/.test(value)) return undefined;
  try {
    const parsed: unknown = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return undefined;
    const proof = parsed as Record<string, unknown>;
    if (
      Object.keys(proof).length !== 3 ||
      !Object.hasOwn(proof, "timestampMs") ||
      !Object.hasOwn(proof, "nonce") ||
      !Object.hasOwn(proof, "signature") ||
      typeof proof.timestampMs !== "number" ||
      !Number.isSafeInteger(proof.timestampMs) ||
      typeof proof.nonce !== "string" ||
      typeof proof.signature !== "string"
    ) return undefined;
    return { timestampMs: proof.timestampMs, nonce: proof.nonce, signature: proof.signature };
  } catch {
    return undefined;
  }
};

export const authenticateVLinkRequest = (
  registry: VLinkRegistry,
  req: Request,
  vlinkId: string,
  token: string,
  now = new Date(),
) => {
  const suppliedProof = parseDeviceRequestProof(req.header("x-vlink-device-proof"));
  const proof = suppliedProof
    ? {
        ...suppliedProof,
        method: req.method.toUpperCase(),
        target: req.originalUrl,
        host: (req.get("host") ?? "").toLowerCase(),
        bodyHash: (req as RequestWithVLinkBodyHash).vlinkBodyHash ?? sha256(Buffer.alloc(0)),
      }
    : undefined;
  return registry.authenticate(vlinkId, token, now, proof);
};

export const makeDeviceRequestProofHeader = (input: {
  timestampMs: number;
  nonce: string;
  signature: string;
}) => Buffer.from(JSON.stringify(input), "utf8").toString("base64url");
