import { createHash, createPublicKey, verify } from "node:crypto";

export type DeviceProofPurpose = "bootstrap" | "unbound-bootstrap" | "exchange";

export interface DevicePublicKey {
  pem: string;
  thumbprint: string;
}

export interface DeviceRequestProof {
  method: string;
  target: string;
  host: string;
  bodyHash: string;
  timestampMs: number;
  nonce: string;
  signature: string;
}

export const deviceRequestProofPayload = (input: {
  vlinkId: string;
  credentialId: string;
  tokenHash: string;
  method: string;
  target: string;
  host: string;
  bodyHash: string;
  timestampMs: number;
  nonce: string;
}): Buffer => Buffer.from(JSON.stringify([
  "vlink-device-request-proof/v1",
  input.vlinkId,
  input.credentialId,
  input.tokenHash,
  input.method,
  input.target,
  input.host,
  input.bodyHash,
  input.timestampMs,
  input.nonce,
]), "utf8");

export const verifyDeviceRequestProof = (input: {
  publicKeyPem: string;
  vlinkId: string;
  credentialId: string;
  tokenHash: string;
  proof: DeviceRequestProof;
  now: Date;
}): boolean => {
  const { proof } = input;
  if (
    !Number.isSafeInteger(proof.timestampMs) ||
    proof.timestampMs < 0 ||
    proof.timestampMs > input.now.getTime() + 5_000 ||
    input.now.getTime() - proof.timestampMs > 60_000 ||
    !/^[A-Za-z0-9_-]{43}$/.test(proof.nonce) ||
    !/^[A-Za-z0-9_-]{80,100}$/.test(proof.signature) ||
    !/^[a-f0-9]{64}$/.test(proof.bodyHash) ||
    !/^[A-Z]{3,12}$/.test(proof.method) ||
    !proof.target.startsWith("/") || proof.target.length > 8_192 || proof.target.includes("#") ||
    !/^[A-Za-z0-9.-]+(?::[0-9]{1,5})?$/.test(proof.host) || proof.host.length > 255
  ) return false;

  try {
    const signature = Buffer.from(proof.signature, "base64url");
    const key = createPublicKey(input.publicKeyPem);
    return signature.length === 64 && key.asymmetricKeyType === "ed25519" && verify(
      null,
      deviceRequestProofPayload({
        vlinkId: input.vlinkId,
        credentialId: input.credentialId,
        tokenHash: input.tokenHash,
        method: proof.method,
        target: proof.target,
        host: proof.host,
        bodyHash: proof.bodyHash,
        timestampMs: proof.timestampMs,
        nonce: proof.nonce,
      }),
      key,
      signature,
    );
  } catch {
    return false;
  }
};

export const parseDevicePublicKey = (value: unknown): DevicePublicKey | undefined => {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > 2_048) return undefined;
  try {
    const key = createPublicKey(value);
    if (key.asymmetricKeyType !== "ed25519") return undefined;
    const der = key.export({ type: "spki", format: "der" });
    return {
      pem: key.export({ type: "spki", format: "pem" }).toString(),
      thumbprint: createHash("sha256").update(der).digest("base64url"),
    };
  } catch {
    return undefined;
  }
};

export const deviceProofPayload = (input: {
  purpose: DeviceProofPurpose;
  vlinkId: string | null;
  pairingId: string;
  keyThumbprint: string;
  nonce: string;
}): Buffer => Buffer.from(JSON.stringify([
  "vlink-device-proof/v1",
  input.purpose,
  input.vlinkId,
  input.pairingId,
  input.keyThumbprint,
  input.nonce,
]), "utf8");

export const verifyDeviceProof = (input: {
  publicKeyPem: string;
  purpose: DeviceProofPurpose;
  vlinkId: string | null;
  pairingId: string;
  keyThumbprint: string;
  nonce: string;
  signature: string;
}): boolean => {
  if (!/^[A-Za-z0-9_-]{40,128}$/.test(input.nonce) || !/^[A-Za-z0-9_-]{80,100}$/.test(input.signature)) {
    return false;
  }
  try {
    const signature = Buffer.from(input.signature, "base64url");
    if (signature.length !== 64) return false;
    const key = createPublicKey(input.publicKeyPem);
    return key.asymmetricKeyType === "ed25519" && verify(
      null,
      deviceProofPayload(input),
      key,
      signature,
    );
  } catch {
    return false;
  }
};
