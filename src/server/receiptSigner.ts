import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as ed25519Sign,
  verify as ed25519Verify,
  type KeyObject,
} from "node:crypto";
import type {
  VLinkActivityEvent,
  VLinkReceiptKeyDescriptor,
  VLinkReceiptPublicKeyJwk,
  VLinkReceiptVerification,
  VLinkSignedReceipt,
} from "../types/vlink";
import { VLINK_RECEIPT_VERSION } from "../types/vlink";

const sha256 = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");

export const canonicalizeVLinkJson = (value: unknown): string => {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Non-finite numbers cannot be canonicalized");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalizeVLinkJson(entry === undefined ? null : entry)).join(",")}]`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${canonicalizeVLinkJson(entry)}`).join(",")}}`;
  }
  throw new Error(`Unsupported canonical JSON value: ${typeof value}`);
};

const publicJwk = (publicKey: KeyObject): VLinkReceiptPublicKeyJwk => {
  const jwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    throw new Error("Receipt signer did not produce an Ed25519 public key");
  }
  return { kty: "OKP", crv: "Ed25519", x: jwk.x };
};

const keyIdFromPublicKey = (publicKey: KeyObject) => {
  const spki = publicKey.export({ type: "spki", format: "der" });
  return `vkey_sha256_${sha256(spki)}`;
};

const keyIdFromJwk = (jwk: VLinkReceiptPublicKeyJwk) => {
  const key = createPublicKey({ key: jwk as never, format: "jwk" });
  return keyIdFromPublicKey(key);
};

const payloadHash = (payload: VLinkActivityEvent) => `sha256:${sha256(canonicalizeVLinkJson(payload))}`;

export class VLinkReceiptSigner {
  private readonly privateKey: KeyObject;
  private readonly publicKey: KeyObject;
  private readonly descriptor: VLinkReceiptKeyDescriptor;

  constructor(privateKeyPem?: string) {
    if (privateKeyPem?.trim()) {
      this.privateKey = createPrivateKey(privateKeyPem.replace(/\\n/g, "\n"));
      this.publicKey = createPublicKey(this.privateKey);
      this.descriptor = {
        keyId: keyIdFromPublicKey(this.publicKey),
        algorithm: "Ed25519",
        publicKeyJwk: publicJwk(this.publicKey),
        persistence: "configured",
        trustNote:
          "This key is configured by the VLink operator. Signature verification proves integrity under this key; external key pinning or anchoring is still required for stronger non-repudiation claims.",
      };
    } else {
      const pair = generateKeyPairSync("ed25519");
      this.privateKey = pair.privateKey;
      this.publicKey = pair.publicKey;
      this.descriptor = {
        keyId: keyIdFromPublicKey(this.publicKey),
        algorithm: "Ed25519",
        publicKeyJwk: publicJwk(this.publicKey),
        persistence: "ephemeral",
        trustNote:
          "This process generated an ephemeral signing key. Receipts remain mathematically verifiable with their embedded public key, but stable operator identity requires a configured and externally pinned/anchored key.",
      };
    }
  }

  keyDescriptor(): VLinkReceiptKeyDescriptor {
    return structuredClone(this.descriptor);
  }

  signEvent(event: VLinkActivityEvent, now = new Date()): VLinkSignedReceipt {
    const unsigned: Omit<VLinkSignedReceipt, "signature"> = {
      version: VLINK_RECEIPT_VERSION,
      receiptId: `vrcpt_${randomBytes(12).toString("hex")}`,
      eventId: event.eventId,
      vlinkId: event.vlinkId,
      issuedAt: now.toISOString(),
      algorithm: "Ed25519",
      digestAlgorithm: "SHA-256",
      canonicalization: "vlink-canonical-json/v1",
      keyId: this.descriptor.keyId,
      publicKeyJwk: structuredClone(this.descriptor.publicKeyJwk),
      payloadHash: payloadHash(event),
      payload: structuredClone(event),
    };
    const signature = ed25519Sign(null, Buffer.from(canonicalizeVLinkJson(unsigned)), this.privateKey).toString("base64url");
    return { ...unsigned, signature };
  }
}

export const verifyVLinkReceipt = (
  receipt: VLinkSignedReceipt,
  expectedKeyId?: string,
): VLinkReceiptVerification => {
  try {
    const publicKey = createPublicKey({ key: receipt.publicKeyJwk as never, format: "jwk" });
    const computedKeyId = keyIdFromJwk(receipt.publicKeyJwk);
    const keyIdValid = computedKeyId === receipt.keyId;
    const payloadHashValid = payloadHash(receipt.payload) === receipt.payloadHash;
    const expectedKeyMatched = expectedKeyId ? expectedKeyId === receipt.keyId : null;
    const { signature, ...unsigned } = receipt;
    const signatureValid = ed25519Verify(
      null,
      Buffer.from(canonicalizeVLinkJson(unsigned)),
      publicKey,
      Buffer.from(signature, "base64url"),
    );
    const valid = keyIdValid && payloadHashValid && signatureValid && expectedKeyMatched !== false;
    return {
      valid,
      signatureValid,
      payloadHashValid,
      keyIdValid,
      expectedKeyMatched,
      keyId: receipt.keyId,
      ...(valid
        ? {}
        : {
            reason: !keyIdValid
              ? "public_key_fingerprint_mismatch"
              : !payloadHashValid
                ? "payload_hash_mismatch"
                : !signatureValid
                  ? "signature_invalid"
                  : "expected_key_mismatch",
          }),
    };
  } catch {
    return {
      valid: false,
      signatureValid: false,
      payloadHashValid: false,
      keyIdValid: false,
      expectedKeyMatched: expectedKeyId ? false : null,
      keyId: receipt?.keyId ?? "unknown",
      reason: "malformed_receipt",
    };
  }
};
