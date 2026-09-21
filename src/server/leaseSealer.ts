import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export interface LeaseSealer {
  seal(plain: string): string;
  open(sealed: string): string;
}

const decodeKey = (value: string): Buffer | undefined => {
  if (/^[a-f0-9]{64}$/i.test(value)) return Buffer.from(value, "hex");
  try {
    const key = Buffer.from(value, "base64");
    return key.length === 32 ? key : undefined;
  } catch {
    return undefined;
  }
};

export const createLeaseSealer = (configured = process.env.VLINK_LEASE_SEALING_KEY): LeaseSealer | null => {
  const key = configured?.trim() ? decodeKey(configured.trim()) : undefined;
  if (!key) return null;

  return {
    seal(plain) {
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", key, iv);
      const ciphertext = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
      return `v1.${iv.toString("base64url")}.${ciphertext.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}`;
    },
    open(sealed) {
      const [version, ivPart, ciphertextPart, tagPart] = sealed.split(".");
      if (version !== "v1" || !ivPart || !ciphertextPart || !tagPart) throw new Error("Invalid lease seal");
      const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(ivPart, "base64url"));
      decipher.setAuthTag(Buffer.from(tagPart, "base64url"));
      return Buffer.concat([decipher.update(Buffer.from(ciphertextPart, "base64url")), decipher.final()]).toString("utf8");
    },
  };
};
