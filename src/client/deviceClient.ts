import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  type KeyObject,
} from "node:crypto";
import type {
  VLinkAccessCredential,
  VLinkDeviceBootstrapView,
  VLinkSourceType,
} from "../types/vlink";

type FetchLike = typeof fetch;

export interface VLinkDeviceClientOptions {
  /** VLink service origin, for example https://vlink.example.com. */
  apiBaseUrl: string;
  /** Supply this when restoring the device key from protected local storage. */
  privateKeyPem?: string;
  /** Supply this when resuming an interrupted bootstrap/exchange. */
  pairingId?: string;
  fetchImpl?: FetchLike;
}

export interface VLinkBootstrapRequest {
  displayName: string;
  environment: string;
  sourceType: VLinkSourceType;
  ttlSeconds?: number;
}

export interface VLinkBootstrapStarted {
  bootstrap: VLinkDeviceBootstrapView;
  consequenceAuthority: "none";
}

export class VLinkDeviceClientError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = "VLinkDeviceClientError";
  }
}

const sha256 = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");

const deviceProofPayload = (input: {
  purpose: "unbound-bootstrap" | "exchange";
  vlinkId: string | null;
  pairingId: string;
  keyThumbprint: string;
  nonce: string;
}) => Buffer.from(JSON.stringify([
  "vlink-device-proof/v1",
  input.purpose,
  input.vlinkId,
  input.pairingId,
  input.keyThumbprint,
  input.nonce,
]), "utf8");

const deviceRequestProofPayload = (input: {
  vlinkId: string;
  credentialId: string;
  tokenHash: string;
  method: string;
  target: string;
  host: string;
  bodyHash: string;
  timestampMs: number;
  nonce: string;
}) => Buffer.from(JSON.stringify([
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

const signProof = (privateKey: KeyObject, payload: Buffer) => sign(null, payload, privateKey).toString("base64url");

const parseResponse = async <T>(response: Response): Promise<T> => {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new VLinkDeviceClientError(`VLink returned a non-JSON response (${response.status})`, response.status);
  }
  if (!response.ok) {
    const error = typeof body === "object" && body !== null && "error" in body
      ? String((body as { error: unknown }).error)
      : `HTTP ${response.status}`;
    throw new VLinkDeviceClientError(`VLink request failed: ${error}`, response.status);
  }
  return body as T;
};

const normalizeBaseUrl = (value: string) => {
  const url = new URL(value);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error("VLink device credentials require HTTPS (HTTP is allowed only for loopback testing)");
  }
  if (url.username || url.password || url.search || url.hash) throw new Error("VLink base URL must not contain credentials, query, or fragment");
  url.pathname = url.pathname.replace(/\/$/, "");
  return url;
};

/**
 * Device-side VLink onboarding and proof-of-possession client.
 * The private key remains local; pairing yields identity/connectivity only,
 * never CAPPO consequence authority.
 */
export class VLinkDeviceClient {
  readonly apiBaseUrl: string;
  readonly publicKeyPem: string;
  readonly deviceKeyThumbprint: string;
  private readonly privateKey: KeyObject;
  private readonly fetchImpl: FetchLike;
  private pairingIdValue?: string;
  private credentialValue?: VLinkAccessCredential;

  constructor(options: VLinkDeviceClientOptions) {
    const baseUrl = normalizeBaseUrl(options.apiBaseUrl);
    this.apiBaseUrl = baseUrl.toString().replace(/\/$/, "");
    this.fetchImpl = options.fetchImpl ?? fetch;
    if (options.privateKeyPem) {
      this.privateKey = createPrivateKey(options.privateKeyPem);
      if (this.privateKey.asymmetricKeyType !== "ed25519") throw new Error("VLink device key must be Ed25519");
      const publicKey = createPublicKey(this.privateKey);
      this.publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
      this.privateKeyPemValue = this.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    } else {
      const pair = generateKeyPairSync("ed25519");
      this.privateKey = pair.privateKey;
      this.publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
      this.privateKeyPemValue = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    }
    const publicDer = createPublicKey(this.publicKeyPem).export({ type: "spki", format: "der" });
    this.deviceKeyThumbprint = createHash("sha256").update(publicDer).digest("base64url");
    this.pairingIdValue = options.pairingId;
  }

  private readonly privateKeyPemValue: string;

  /** Explicit export only: callers are responsible for protected local storage. */
  exportPrivateKeyPem(): string {
    return this.privateKeyPemValue;
  }

  get pairingId(): string | undefined {
    return this.pairingIdValue;
  }

  get credential(): VLinkAccessCredential | undefined {
    return this.credentialValue;
  }

  private async json<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await this.fetchImpl(new URL(path, `${this.apiBaseUrl}/`), {
      ...init,
      cache: "no-store",
      redirect: "manual",
      credentials: "omit",
      headers: { "content-type": "application/json", ...init?.headers },
    });
    return parseResponse<T>(response);
  }

  async beginPairing(input: VLinkBootstrapRequest): Promise<VLinkBootstrapStarted> {
    if (this.pairingIdValue) throw new Error("This device client already has a pairing ID; create a separate client for a new enrollment");
    const created = await this.json<{
      bootstrap: VLinkDeviceBootstrapView;
      challenge: { nonce: string };
      consequenceAuthority: "none";
    }>("/api/v1/device/bootstrap", {
      method: "POST",
      body: JSON.stringify({ ...input, publicKeyPem: this.publicKeyPem }),
    });
    if (created.consequenceAuthority !== "none") throw new VLinkDeviceClientError("VLink bootstrap returned an unexpected authority state");
    this.pairingIdValue = created.bootstrap.pairingId;
    const signature = signProof(this.privateKey, deviceProofPayload({
      purpose: "unbound-bootstrap",
      vlinkId: null,
      pairingId: created.bootstrap.pairingId,
      keyThumbprint: created.bootstrap.deviceKeyThumbprint,
      nonce: created.challenge.nonce,
    }));
    try {
      const proofResult = await this.json<{ bootstrap: VLinkDeviceBootstrapView }>(`/api/v1/device/bootstrap/${encodeURIComponent(this.pairingIdValue)}/proof`, {
        method: "POST",
        body: JSON.stringify({ nonce: created.challenge.nonce, signature }),
      });
      created.bootstrap = proofResult.bootstrap;
    } catch (error) {
      // The proof is one-use. If its response was lost after acceptance, status
      // readback distinguishes that from a proof that was never accepted.
      const status = await this.getBootstrapStatus();
      if (!status.deviceProofVerified) throw error;
      created.bootstrap = status;
    }
    return { bootstrap: created.bootstrap, consequenceAuthority: "none" };
  }

  async getBootstrapStatus(): Promise<VLinkDeviceBootstrapView> {
    if (!this.pairingIdValue) throw new Error("No VLink pairing is in progress");
    const result = await this.json<{ bootstrap: VLinkDeviceBootstrapView; consequenceAuthority: "none" }>(
      `/api/v1/device/bootstrap/${encodeURIComponent(this.pairingIdValue)}`,
    );
    if (result.consequenceAuthority !== "none") throw new VLinkDeviceClientError("VLink bootstrap status returned an unexpected authority state");
    return result.bootstrap;
  }

  /** Call after the workspace owner has approved the request in Veklom. */
  async recoverCredential(): Promise<VLinkAccessCredential> {
    const bootstrap = await this.getBootstrapStatus();
    if (bootstrap.status === "expired") throw new VLinkDeviceClientError("VLink pairing expired; start a new enrollment", 410);
    if (bootstrap.status !== "approved" || !bootstrap.vlinkId) {
      throw new VLinkDeviceClientError("VLink pairing is awaiting workspace-owner approval", 409);
    }
    const pairingId = bootstrap.pairingId;
    const vlinkId = bootstrap.vlinkId;
    const challenge = await this.json<{ challenge: { nonce: string } }>(
      `/api/v1/vlinks/${encodeURIComponent(vlinkId)}/pairing/${encodeURIComponent(pairingId)}/exchange-challenge`,
      { method: "POST" },
    );
    const signature = signProof(this.privateKey, deviceProofPayload({
      purpose: "exchange",
      vlinkId,
      pairingId,
      keyThumbprint: this.deviceKeyThumbprint,
      nonce: challenge.challenge.nonce,
    }));
    const exchanged = await this.json<{ credential: VLinkAccessCredential }>(
      `/api/v1/vlinks/${encodeURIComponent(vlinkId)}/pairing/${encodeURIComponent(pairingId)}/exchange`,
      { method: "POST", body: JSON.stringify({ nonce: challenge.challenge.nonce, signature }) },
    );
    if (exchanged.credential.vlinkId !== vlinkId || !exchanged.credential.token.startsWith("vlt_")) {
      throw new VLinkDeviceClientError("VLink returned a credential not bound to the approved device");
    }
    this.credentialValue = exchanged.credential;
    return exchanged.credential;
  }

  /** Send one protected VLink request with a fresh, body/path-bound device proof. */
  async request(path: string, init: Omit<RequestInit, "body"> & { body?: string | Uint8Array } = {}): Promise<Response> {
    if (!this.credentialValue) throw new Error("Complete device pairing before making protected VLink requests");
    if (!path.startsWith("/") || path.startsWith("//")) throw new Error("VLink request target must be an absolute path on the configured origin");
    const url = new URL(path, `${this.apiBaseUrl}/`);
    const configuredOrigin = new URL(this.apiBaseUrl).origin;
    if (url.origin !== configuredOrigin || url.hash) throw new Error("VLink device credentials cannot be sent to another origin");
    const method = (init.method ?? "GET").toUpperCase();
    const body = init.body ?? "";
    const bodyBytes = typeof body === "string" ? Buffer.from(body, "utf8") : Buffer.from(body);
    const timestampMs = Date.now();
    const nonce = randomBytes(32).toString("base64url");
    const credential = this.credentialValue;
    const signature = signProof(this.privateKey, deviceRequestProofPayload({
      vlinkId: credential.vlinkId,
      credentialId: credential.credentialId,
      tokenHash: sha256(credential.token),
      method,
      target: `${url.pathname}${url.search}`,
      host: url.host.toLowerCase(),
      bodyHash: sha256(bodyBytes),
      timestampMs,
      nonce,
    }));
    const proof = Buffer.from(JSON.stringify({ timestampMs, nonce, signature }), "utf8").toString("base64url");
    const headers = new Headers(init.headers);
    if (headers.has("authorization") || headers.has("x-vlink-device-proof")) {
      throw new Error("Authorization and device-proof headers are managed by VLinkDeviceClient");
    }
    headers.set("authorization", `Bearer ${credential.token}`);
    headers.set("x-vlink-device-proof", proof);
    return this.fetchImpl(url, {
      ...init,
      method,
      body: bodyBytes.length ? bodyBytes : undefined,
      headers,
      cache: "no-store",
      redirect: "manual",
      credentials: "omit",
    });
  }
}
