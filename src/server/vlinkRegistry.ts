import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type {
  VLinkAccessCredential,
  VLinkAccessCredentialSummary,
  VLinkActivityEvent,
  VLinkEnrollmentGrant,
  VLinkEnrollmentGrantSummary,
  VLinkManifest,
  VLinkPairingRequest,
  VLinkPairingStatusView,
  VLinkRecord,
  VLinkSourceType,
} from "../types/vlink";
import { VLINK_SCHEMA_VERSION } from "../types/vlink";

export interface CreateVLinkInput {
  workspaceId: string;
  environment: string;
  displayName: string;
  sourceType: VLinkSourceType;
  expiresAt?: string;
  machineIdentity?: { value: string; operatorId?: string };
}

export interface DeviceAuthorizationInput {
  machineIdentity: string;
  displayName: string;
  sourceType: VLinkSourceType;
}

export interface DeviceAuthorizationStart {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  expiresAt: string;
  interval: number;
}

export interface DeviceAuthorizationView {
  authorizationId: string;
  machineIdentity: { value: string; assurance: "client-asserted" };
  displayName: string;
  sourceType: VLinkSourceType;
  requestedScope: "vlink:connect";
  verificationUri: string;
  status: "pending" | "authorized" | "denied" | "expired";
  createdAt: string;
  expiresAt: string;
  interval: number;
  workspaceId?: string;
  operatorId?: string;
  vlinkId?: string;
}

export type DeviceAuthorizationPoll =
  | { status: "authorization_pending"; interval: number; expiresAt: string }
  | { status: "slow_down"; interval: number; expiresAt: string }
  | { status: "access_denied"; error?: "credential_revoked"; expiresAt: string }
  | { status: "expired_token" }
  | { status: "authorized"; vlink: VLinkRecord; credential: VLinkAccessCredential };

interface StoredDeviceAuthorization extends DeviceAuthorizationView {
  deviceCodeHash: string;
  userCodeHash: string;
  lastPollAt?: string;
  credentialId?: string;
  credentialCiphertext?: string;
  credentialIv?: string;
  credentialTag?: string;
}

interface StoredPairing extends VLinkPairingStatusView {
  approvalCodeHash: string;
  deviceCodeHash: string;
}

interface StoredEnrollmentGrant {
  grantId: string;
  vlinkId: string;
  tokenHash: string;
  issuedAt: string;
  expiresAt: string;
}

interface StoredCredential {
  credentialId: string;
  vlinkId: string;
  tokenHash: string;
  issuedAt: string;
  expiresAt: string;
  revokedAt?: string;
}

export interface VLinkRegistrySnapshot {
  format: "vlink-registry/v1";
  vlinks: VLinkRecord[];
  enrollmentGrants: StoredEnrollmentGrant[];
  pairings: StoredPairing[];
  credentials: StoredCredential[];
  activities: Array<{ vlinkId: string; events: VLinkActivityEvent[] }>;
  deviceAuthorizations?: StoredDeviceAuthorization[];
}

export interface VLinkRegistry {
  readonly persistenceMode: "memory" | "file";
  configureDeviceAuthorizationEncryptionKey(secret: string | null): void;
  startDeviceAuthorization(input: DeviceAuthorizationInput, verificationUri: string, ttlSeconds?: number, intervalSeconds?: number, now?: Date): DeviceAuthorizationStart;
  getDeviceAuthorization(userCode: string, now?: Date): DeviceAuthorizationView | undefined;
  approveDeviceAuthorization(userCode: string, workspaceId: string, operatorId: string, origin: string, credentialTtlSeconds?: number, now?: Date): DeviceAuthorizationView | undefined;
  denyDeviceAuthorization(userCode: string, workspaceId: string, operatorId: string, now?: Date): DeviceAuthorizationView | undefined;
  pollDeviceAuthorization(deviceCode: string, now?: Date): DeviceAuthorizationPoll | undefined;
  create(input: CreateVLinkInput, origin: string): VLinkRecord;
  list(): VLinkRecord[];
  get(vlinkId: string): VLinkRecord | undefined;
  manifest(vlinkId: string): VLinkManifest | undefined;
  issueEnrollmentGrant(vlinkId: string, ttlSeconds?: number, now?: Date): VLinkEnrollmentGrant | undefined;
  authenticateEnrollment(vlinkId: string, token: string, now?: Date): VLinkEnrollmentGrantSummary | undefined;
  createPairing(vlinkId: string, origin: string, ttlSeconds?: number, now?: Date): VLinkPairingRequest | undefined;
  getPairingStatus(vlinkId: string, pairingId: string, now?: Date): VLinkPairingStatusView | undefined;
  approvePairing(vlinkId: string, pairingId: string, approvalCode: string, now?: Date): VLinkPairingStatusView | undefined;
  exchangePairing(vlinkId: string, pairingId: string, deviceCode: string, credentialTtlSeconds?: number, now?: Date): VLinkAccessCredential | undefined;
  authenticate(vlinkId: string, token: string, now?: Date): VLinkAccessCredentialSummary | undefined;
  revokeCredential(vlinkId: string, credentialId: string, now?: Date): VLinkAccessCredentialSummary | undefined;
  addActivity(event: Omit<VLinkActivityEvent, "eventId" | "timestamp">, now?: Date): VLinkActivityEvent;
  activity(vlinkId: string): VLinkActivityEvent[];
  clear(): void;
}

const cleanOrigin = (origin: string) => origin.replace(/\/$/, "");
const DEVICE_SOURCE_TYPES = new Set<VLinkSourceType>(["ai-client", "agent-mcp", "api-service", "webhook", "local-project", "cicd", "container"]);
const hashSecret = (secret: string) => createHash("sha256").update(secret, "utf8").digest("hex");
const secureHashMatch = (expectedHash: string, providedSecret: string) => {
  const expected = Buffer.from(expectedHash, "hex");
  const actual = Buffer.from(hashSecret(providedSecret), "hex");
  return expected.length === actual.length && timingSafeEqual(expected, actual);
};

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const assertString: (value: unknown, field: string) => asserts value is string = (value, field) => {
  if (typeof value !== "string" || value.length === 0) throw new Error(`Invalid durable VLink state: ${field}`);
};

const assertHash: (value: unknown, field: string) => asserts value is string = (value, field) => {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`Invalid durable VLink state: ${field}`);
  }
};

export class InMemoryVLinkRegistry implements VLinkRegistry {
  readonly persistenceMode = "memory" as const;
  private readonly vlinks = new Map<string, VLinkRecord>();
  private readonly enrollmentGrants = new Map<string, StoredEnrollmentGrant>();
  private readonly pairings = new Map<string, StoredPairing>();
  private readonly credentials = new Map<string, StoredCredential>();
  private readonly activities = new Map<string, VLinkActivityEvent[]>();
  private readonly deviceAuthorizations = new Map<string, StoredDeviceAuthorization>();
  private deviceAuthorizationEncryptionKey?: Buffer;

  create(input: CreateVLinkInput, origin: string): VLinkRecord {
    const now = new Date().toISOString();
    const vlinkId = `vlk_${randomBytes(8).toString("hex")}`;
    const root = cleanOrigin(origin);
    const record: VLinkRecord = {
      version: VLINK_SCHEMA_VERSION,
      vlinkId,
      workspaceId: input.workspaceId.trim(),
      environment: input.environment.trim(),
      displayName: input.displayName.trim(),
      sourceType: input.sourceType,
      mode: "observe",
      endpoints: {
        openaiCompatibleBaseUrl: `${root}/vlinks/${vlinkId}/v1`,
        webhookIngressUrl: `${root}/api/v1/vlinks/${vlinkId}/webhook`,
        mcpEndpoint: `${root}/mcp/v1`,
        activityViewerUrl: `${root}/?vlink=${vlinkId}`,
      },
      connectionStatus: "created",
      enrollmentStatus: "unpaired",
      ...(input.machineIdentity
        ? {
            machineIdentity: {
              value: input.machineIdentity.value,
              assurance: "client-asserted" as const,
              boundAt: now,
              ...(input.machineIdentity.operatorId ? { operatorId: input.machineIdentity.operatorId } : {}),
            },
          }
        : {}),
      createdAt: now,
      updatedAt: now,
      ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
    };
    this.vlinks.set(vlinkId, record);
    this.activities.set(vlinkId, []);
    return structuredClone(record);
  }

  configureDeviceAuthorizationEncryptionKey(secret: string | null): void {
    if (secret !== null && Buffer.byteLength(secret, "utf8") < 32) {
      throw new Error("VLINK_DEVICE_FLOW_ENCRYPTION_KEY must be at least 32 bytes");
    }
    this.deviceAuthorizationEncryptionKey = secret
      ? createHash("sha256").update("veklom:vlink-device-token:v1\\0").update(secret).digest()
      : undefined;
  }

  startDeviceAuthorization(
    input: DeviceAuthorizationInput,
    verificationUri: string,
    ttlSeconds = 900,
    intervalSeconds = 5,
    now = new Date(),
  ): DeviceAuthorizationStart {
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(input.machineIdentity)
      || input.displayName.trim().length < 1 || input.displayName.trim().length > 100
      || !DEVICE_SOURCE_TYPES.has(input.sourceType)) {
      throw new Error("invalid_device_authorization_request");
    }
    let parsedVerificationUri: URL;
    try {
      parsedVerificationUri = new URL(verificationUri.replace("{userCode}", "CODE"));
    } catch {
      throw new Error("invalid_device_authorization_verification_uri");
    }
    if (parsedVerificationUri.protocol !== "https:" && parsedVerificationUri.hostname !== "localhost") {
      throw new Error("invalid_device_authorization_verification_uri");
    }
    for (const [id, item] of this.deviceAuthorizations) {
      if (item.status === "pending" && Date.parse(item.expiresAt) <= now.getTime()) item.status = "expired";
      if (item.status !== "pending" && Date.parse(item.expiresAt) + 86_400_000 <= now.getTime()) {
        this.deviceAuthorizations.delete(id);
      }
    }
    for (const item of this.deviceAuthorizations.values()) {
      if (item.machineIdentity.value !== input.machineIdentity) continue;
      if (item.status === "pending") throw new Error("device_authorization_already_pending");
      if (item.status === "authorized") {
        const credential = this.credentials.get(item.credentialId ?? "");
        if (credential && !credential.revokedAt && Date.parse(credential.expiresAt) > now.getTime()) {
          throw new Error("device_authorization_already_active");
        }
      }
    }
    if (Array.from(this.deviceAuthorizations.values()).filter((item) => item.status === "pending").length >= 500) {
      throw new Error("device_authorization_capacity_reached");
    }

    const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let userCode = "";
    do {
      userCode = Array.from(randomBytes(10), (byte) => alphabet[byte & 31]).join("");
    } while (Array.from(this.deviceAuthorizations.values()).some((item) => secureHashMatch(item.userCodeHash, userCode)));

    const deviceCode = `vda_${randomBytes(32).toString("base64url")}`;
    const authorizationId = `auth_${randomUUID()}`;
    const createdAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + Math.max(60, Math.min(ttlSeconds, 1800)) * 1000).toISOString();
    const interval = Math.max(5, Math.min(intervalSeconds, 30));
    this.deviceAuthorizations.set(authorizationId, {
      authorizationId,
      machineIdentity: { value: input.machineIdentity, assurance: "client-asserted" },
      displayName: input.displayName,
      sourceType: input.sourceType,
      requestedScope: "vlink:connect",
      verificationUri,
      status: "pending",
      createdAt,
      expiresAt,
      interval,
      deviceCodeHash: hashSecret(deviceCode),
      userCodeHash: hashSecret(userCode),
    });
    return {
      deviceCode,
      userCode,
      verificationUri: verificationUri.replace("{userCode}", encodeURIComponent(userCode)),
      expiresAt,
      interval,
    };
  }

  getDeviceAuthorization(userCode: string, now = new Date()): DeviceAuthorizationView | undefined {
    const record = this.findDeviceAuthorization("userCodeHash", userCode);
    if (!record) return undefined;
    this.expireDeviceAuthorizationIfNeeded(record, now);
    return this.publicDeviceAuthorization(record);
  }

  approveDeviceAuthorization(
    userCode: string,
    workspaceId: string,
    operatorId: string,
    origin: string,
    credentialTtlSeconds = 3600,
    now = new Date(),
  ): DeviceAuthorizationView | undefined {
    if (!this.deviceAuthorizationEncryptionKey) throw new Error("device_authorization_encryption_unconfigured");
    const record = this.findDeviceAuthorization("userCodeHash", userCode);
    if (!record) return undefined;
    this.expireDeviceAuthorizationIfNeeded(record, now);
    if (record.status === "authorized") {
      if (record.workspaceId !== workspaceId || record.operatorId !== operatorId) return undefined;
      return this.publicDeviceAuthorization(record);
    }
    if (record.status !== "pending") return this.publicDeviceAuthorization(record);

    const vlink = this.create(
      {
        workspaceId,
        environment: "production",
        displayName: record.displayName,
        sourceType: record.sourceType,
        machineIdentity: { value: record.machineIdentity.value, operatorId },
      },
      origin,
    );
    const storedVLink = this.vlinks.get(vlink.vlinkId)!;
    storedVLink.connectionStatus = "paired";
    storedVLink.enrollmentStatus = "paired";
    storedVLink.updatedAt = now.toISOString();
    const credential = this.issueCredential(vlink.vlinkId, Math.max(60, Math.min(credentialTtlSeconds, 86_400)), now);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.deviceAuthorizationEncryptionKey, iv);
    cipher.setAAD(Buffer.from(record.authorizationId, "utf8"));
    const ciphertext = Buffer.concat([cipher.update(credential.token, "utf8"), cipher.final()]);
    record.status = "authorized";
    record.workspaceId = workspaceId;
    record.operatorId = operatorId;
    record.vlinkId = vlink.vlinkId;
    record.credentialId = credential.credentialId;
    record.credentialCiphertext = ciphertext.toString("base64url");
    record.credentialIv = iv.toString("base64url");
    record.credentialTag = cipher.getAuthTag().toString("base64url");
    return this.publicDeviceAuthorization(record);
  }

  denyDeviceAuthorization(userCode: string, workspaceId: string, operatorId: string, now = new Date()): DeviceAuthorizationView | undefined {
    const record = this.findDeviceAuthorization("userCodeHash", userCode);
    if (!record) return undefined;
    this.expireDeviceAuthorizationIfNeeded(record, now);
    if (record.status === "denied") {
      if (record.workspaceId !== workspaceId || record.operatorId !== operatorId) return undefined;
      return this.publicDeviceAuthorization(record);
    }
    if (record.status === "pending") {
      record.status = "denied";
      record.workspaceId = workspaceId;
      record.operatorId = operatorId;
    }
    return this.publicDeviceAuthorization(record);
  }

  pollDeviceAuthorization(deviceCode: string, now = new Date()): DeviceAuthorizationPoll | undefined {
    const record = this.findDeviceAuthorization("deviceCodeHash", deviceCode);
    if (!record) return undefined;
    this.expireDeviceAuthorizationIfNeeded(record, now);
    if (record.status === "expired") return { status: "expired_token" };
    if (record.status === "denied") return { status: "access_denied", expiresAt: record.expiresAt };
    if (record.status === "pending") {
      if (record.lastPollAt && now.getTime() - Date.parse(record.lastPollAt) < record.interval * 1000) {
        record.interval = Math.min(record.interval + 5, 30);
        record.lastPollAt = now.toISOString();
        return { status: "slow_down", interval: record.interval, expiresAt: record.expiresAt };
      }
      record.lastPollAt = now.toISOString();
      return { status: "authorization_pending", interval: record.interval, expiresAt: record.expiresAt };
    }
    if (!this.deviceAuthorizationEncryptionKey) throw new Error("device_authorization_encryption_unconfigured");
    const storedCredential = this.credentials.get(record.credentialId ?? "");
    if (!storedCredential || storedCredential.revokedAt) {
      return { status: "access_denied", error: "credential_revoked", expiresAt: record.expiresAt };
    }
    if (Date.parse(storedCredential.expiresAt) <= now.getTime()) return { status: "expired_token" };
    const vlink = this.vlinks.get(record.vlinkId ?? "");
    if (!vlink || !record.credentialCiphertext || !record.credentialIv || !record.credentialTag) {
      throw new Error("authorized device flow is missing its bound VLink credential");
    }
    const decipher = createDecipheriv("aes-256-gcm", this.deviceAuthorizationEncryptionKey, Buffer.from(record.credentialIv, "base64url"));
    decipher.setAAD(Buffer.from(record.authorizationId, "utf8"));
    decipher.setAuthTag(Buffer.from(record.credentialTag, "base64url"));
    const token = Buffer.concat([
      decipher.update(Buffer.from(record.credentialCiphertext, "base64url")),
      decipher.final(),
    ]).toString("utf8");
    return {
      status: "authorized",
      vlink: structuredClone(vlink),
      credential: {
        credentialId: storedCredential.credentialId,
        vlinkId: storedCredential.vlinkId,
        token,
        issuedAt: storedCredential.issuedAt,
        expiresAt: storedCredential.expiresAt,
      },
    };
  }

  list(): VLinkRecord[] {
    return Array.from(this.vlinks.values()).map((v) => structuredClone(v));
  }

  get(vlinkId: string): VLinkRecord | undefined {
    const value = this.vlinks.get(vlinkId);
    return value ? structuredClone(value) : undefined;
  }

  manifest(vlinkId: string): VLinkManifest | undefined {
    const vlink = this.vlinks.get(vlinkId);
    if (!vlink) return undefined;
    return {
      version: VLINK_SCHEMA_VERSION,
      protocol: "vlink/v1",
      vlinkId: vlink.vlinkId,
      workspaceId: vlink.workspaceId,
      environment: vlink.environment,
      displayName: vlink.displayName,
      sourceType: vlink.sourceType,
      mode: vlink.mode,
      endpoints: structuredClone(vlink.endpoints),
      connectionMethods: ["endpoint-swap", "webhook", "browser-pairing", "docker", "github-actions", "mcp"],
      governance: { mode: vlink.mode, ...(vlink.governance ?? {}) },
      enrollment: {
        status: vlink.enrollmentStatus,
        pairingRequired: vlink.enrollmentStatus !== "paired",
      },
      access: {
        scheme: "bearer",
        temporaryCredentials: true,
        tokenPublishedInManifest: false,
      },
      generatedAt: new Date().toISOString(),
    };
  }

  issueEnrollmentGrant(vlinkId: string, ttlSeconds = 900, now = new Date()): VLinkEnrollmentGrant | undefined {
    if (!this.vlinks.has(vlinkId)) return undefined;
    const id = randomBytes(8).toString("hex");
    const grantId = `enr_${id}`;
    const secret = randomBytes(32).toString("base64url");
    const token = `vle_${id}.${secret}`;
    const issuedAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + Math.max(1, ttlSeconds) * 1000).toISOString();
    this.enrollmentGrants.set(grantId, {
      grantId,
      vlinkId,
      tokenHash: hashSecret(token),
      issuedAt,
      expiresAt,
    });
    return { grantId, vlinkId, token, issuedAt, expiresAt };
  }

  authenticateEnrollment(vlinkId: string, token: string, now = new Date()): VLinkEnrollmentGrantSummary | undefined {
    const match = /^vle_([a-f0-9]{16})\.([A-Za-z0-9_-]+)$/.exec(token);
    if (!match) return undefined;
    const grantId = `enr_${match[1]}`;
    const grant = this.enrollmentGrants.get(grantId);
    if (!grant || grant.vlinkId !== vlinkId) return undefined;
    if (new Date(grant.expiresAt).getTime() <= now.getTime()) return undefined;
    if (!secureHashMatch(grant.tokenHash, token)) return undefined;
    return {
      grantId: grant.grantId,
      vlinkId: grant.vlinkId,
      issuedAt: grant.issuedAt,
      expiresAt: grant.expiresAt,
    };
  }

  createPairing(vlinkId: string, origin: string, ttlSeconds = 600, now = new Date()): VLinkPairingRequest | undefined {
    const vlink = this.vlinks.get(vlinkId);
    if (!vlink) return undefined;

    const pairingId = `pair_${randomBytes(8).toString("hex")}`;
    const approvalCode = randomBytes(24).toString("base64url");
    const deviceCode = randomBytes(32).toString("base64url");
    const expiresAt = new Date(now.getTime() + Math.max(1, ttlSeconds) * 1000).toISOString();
    const root = cleanOrigin(origin);
    const pairingUrl = `${root}/pair/${vlinkId}/${pairingId}`;

    const stored: StoredPairing = {
      pairingId,
      vlinkId,
      pairingUrl,
      status: "pending",
      createdAt: now.toISOString(),
      expiresAt,
      approvalCodeHash: hashSecret(approvalCode),
      deviceCodeHash: hashSecret(deviceCode),
    };
    this.pairings.set(pairingId, stored);
    vlink.enrollmentStatus = "pending";
    vlink.updatedAt = now.toISOString();

    return {
      pairingId,
      vlinkId,
      approvalCode,
      deviceCode,
      pairingUrl,
      qrPayload: `${pairingUrl}#approval=${encodeURIComponent(approvalCode)}`,
      status: "pending",
      createdAt: stored.createdAt,
      expiresAt,
    };
  }

  getPairingStatus(vlinkId: string, pairingId: string, now = new Date()): VLinkPairingStatusView | undefined {
    const pairing = this.pairings.get(pairingId);
    if (!pairing || pairing.vlinkId !== vlinkId) return undefined;
    this.expirePairingIfNeeded(pairing, now);
    return this.publicPairing(pairing);
  }

  approvePairing(vlinkId: string, pairingId: string, approvalCode: string, now = new Date()): VLinkPairingStatusView | undefined {
    const pairing = this.pairings.get(pairingId);
    const vlink = this.vlinks.get(vlinkId);
    if (!pairing || !vlink || pairing.vlinkId !== vlinkId) return undefined;
    this.expirePairingIfNeeded(pairing, now);
    if (pairing.status !== "pending" || !secureHashMatch(pairing.approvalCodeHash, approvalCode)) return undefined;

    pairing.status = "approved";
    pairing.approvedAt = now.toISOString();
    vlink.enrollmentStatus = "approved";
    vlink.updatedAt = now.toISOString();
    return this.publicPairing(pairing);
  }

  exchangePairing(
    vlinkId: string,
    pairingId: string,
    deviceCode: string,
    credentialTtlSeconds = 3600,
    now = new Date(),
  ): VLinkAccessCredential | undefined {
    const pairing = this.pairings.get(pairingId);
    const vlink = this.vlinks.get(vlinkId);
    if (!pairing || !vlink || pairing.vlinkId !== vlinkId) return undefined;
    this.expirePairingIfNeeded(pairing, now);
    if (pairing.status !== "approved" || !secureHashMatch(pairing.deviceCodeHash, deviceCode)) return undefined;

    const credential = this.issueCredential(vlinkId, Math.max(1, credentialTtlSeconds), now);
    pairing.status = "exchanged";
    pairing.exchangedAt = now.toISOString();
    vlink.enrollmentStatus = "paired";
    vlink.connectionStatus = "paired";
    vlink.updatedAt = now.toISOString();
    return credential;
  }

  authenticate(vlinkId: string, token: string, now = new Date()): VLinkAccessCredentialSummary | undefined {
    const match = /^vlt_([a-f0-9]{16})\.([A-Za-z0-9_-]+)$/.exec(token);
    if (!match) return undefined;
    const credentialId = `cred_${match[1]}`;
    const credential = this.credentials.get(credentialId);
    if (!credential || credential.vlinkId !== vlinkId || credential.revokedAt) return undefined;
    if (new Date(credential.expiresAt).getTime() <= now.getTime()) return undefined;
    if (!secureHashMatch(credential.tokenHash, token)) return undefined;
    return this.credentialSummary(credential, now);
  }

  revokeCredential(vlinkId: string, credentialId: string, now = new Date()): VLinkAccessCredentialSummary | undefined {
    const credential = this.credentials.get(credentialId);
    if (!credential || credential.vlinkId !== vlinkId) return undefined;
    if (!credential.revokedAt) credential.revokedAt = now.toISOString();
    return this.credentialSummary(credential, now);
  }

  addActivity(event: Omit<VLinkActivityEvent, "eventId" | "timestamp">, now = new Date()): VLinkActivityEvent {
    if (!this.vlinks.has(event.vlinkId)) {
      throw new Error(`Unknown VLink: ${event.vlinkId}`);
    }
    const record: VLinkActivityEvent = {
      ...event,
      eventId: `evt_${randomUUID()}`,
      timestamp: now.toISOString(),
    };
    const list = this.activities.get(event.vlinkId) ?? [];
    list.unshift(record);
    this.activities.set(event.vlinkId, list.slice(0, 100));
    const vlink = this.vlinks.get(event.vlinkId)!;
    if (event.status !== "failed") vlink.connectionStatus = "active";
    vlink.updatedAt = now.toISOString();
    return structuredClone(record);
  }

  activity(vlinkId: string): VLinkActivityEvent[] {
    return (this.activities.get(vlinkId) ?? []).map((v) => structuredClone(v));
  }

  clear(): void {
    this.vlinks.clear();
    this.enrollmentGrants.clear();
    this.pairings.clear();
    this.credentials.clear();
    this.activities.clear();
    this.deviceAuthorizations.clear();
  }

  exportSnapshot(): VLinkRegistrySnapshot {
    return {
      format: "vlink-registry/v1",
      vlinks: Array.from(this.vlinks.values()).map((value) => structuredClone(value)),
      enrollmentGrants: Array.from(this.enrollmentGrants.values()).map((value) => structuredClone(value)),
      pairings: Array.from(this.pairings.values()).map((value) => structuredClone(value)),
      credentials: Array.from(this.credentials.values()).map((value) => structuredClone(value)),
      activities: Array.from(this.activities.entries()).map(([vlinkId, events]) => ({
        vlinkId,
        events: events.map((event) => structuredClone(event)),
      })),
      deviceAuthorizations: Array.from(this.deviceAuthorizations.values()).map((value) => structuredClone(value)),
    };
  }

  restoreSnapshot(value: unknown): void {
    if (!isObject(value) || value.format !== "vlink-registry/v1") {
      throw new Error("Invalid durable VLink state: unsupported format");
    }
    const vlinks = value.vlinks;
    const enrollmentGrants = value.enrollmentGrants;
    const pairings = value.pairings;
    const credentials = value.credentials;
    const activities = value.activities;
    const deviceAuthorizations = value.deviceAuthorizations ?? [];
    if (!Array.isArray(vlinks) || !Array.isArray(enrollmentGrants) || !Array.isArray(pairings) || !Array.isArray(credentials) || !Array.isArray(activities) || !Array.isArray(deviceAuthorizations)) {
      throw new Error("Invalid durable VLink state: malformed collections");
    }

    const nextVlinks = new Map<string, VLinkRecord>();
    for (const item of vlinks) {
      if (!isObject(item)) throw new Error("Invalid durable VLink state: vlink entry");
      assertString(item.vlinkId, "vlinkId");
      if (!/^vlk_[a-f0-9]{16}$/.test(item.vlinkId)) throw new Error("Invalid durable VLink state: vlinkId");
      if (nextVlinks.has(item.vlinkId)) throw new Error("Invalid durable VLink state: duplicate vlinkId");
      if (item.version !== VLINK_SCHEMA_VERSION) throw new Error("Invalid durable VLink state: schema version");
      if (item.machineIdentity !== undefined) {
        if (!isObject(item.machineIdentity)) throw new Error("Invalid durable VLink state: vlink.machineIdentity");
        assertString(item.machineIdentity.value, "vlink.machineIdentity.value");
        assertString(item.machineIdentity.boundAt, "vlink.machineIdentity.boundAt");
        if (item.machineIdentity.assurance !== "client-asserted") throw new Error("Invalid durable VLink state: vlink.machineIdentity.assurance");
        if (item.machineIdentity.operatorId !== undefined) assertString(item.machineIdentity.operatorId, "vlink.machineIdentity.operatorId");
      }
      nextVlinks.set(item.vlinkId, structuredClone(item as unknown as VLinkRecord));
    }

    const known = (vlinkId: unknown, field: string): vlinkId is string => {
      assertString(vlinkId, field);
      if (!nextVlinks.has(vlinkId)) throw new Error(`Invalid durable VLink state: orphan ${field}`);
      return true;
    };

    const nextGrants = new Map<string, StoredEnrollmentGrant>();
    for (const item of enrollmentGrants) {
      if (!isObject(item)) throw new Error("Invalid durable VLink state: enrollment grant");
      assertString(item.grantId, "grantId");
      known(item.vlinkId, "grant.vlinkId");
      assertHash(item.tokenHash, "grant.tokenHash");
      assertString(item.issuedAt, "grant.issuedAt");
      assertString(item.expiresAt, "grant.expiresAt");
      if (nextGrants.has(item.grantId)) throw new Error("Invalid durable VLink state: duplicate grantId");
      nextGrants.set(item.grantId, structuredClone(item as unknown as StoredEnrollmentGrant));
    }

    const nextPairings = new Map<string, StoredPairing>();
    for (const item of pairings) {
      if (!isObject(item)) throw new Error("Invalid durable VLink state: pairing");
      assertString(item.pairingId, "pairingId");
      known(item.vlinkId, "pairing.vlinkId");
      assertHash(item.approvalCodeHash, "pairing.approvalCodeHash");
      assertHash(item.deviceCodeHash, "pairing.deviceCodeHash");
      assertString(item.createdAt, "pairing.createdAt");
      assertString(item.expiresAt, "pairing.expiresAt");
      if (nextPairings.has(item.pairingId)) throw new Error("Invalid durable VLink state: duplicate pairingId");
      nextPairings.set(item.pairingId, structuredClone(item as unknown as StoredPairing));
    }

    const nextCredentials = new Map<string, StoredCredential>();
    for (const item of credentials) {
      if (!isObject(item)) throw new Error("Invalid durable VLink state: credential");
      assertString(item.credentialId, "credentialId");
      known(item.vlinkId, "credential.vlinkId");
      assertHash(item.tokenHash, "credential.tokenHash");
      assertString(item.issuedAt, "credential.issuedAt");
      assertString(item.expiresAt, "credential.expiresAt");
      if (item.revokedAt !== undefined) assertString(item.revokedAt, "credential.revokedAt");
      if (nextCredentials.has(item.credentialId)) throw new Error("Invalid durable VLink state: duplicate credentialId");
      nextCredentials.set(item.credentialId, structuredClone(item as unknown as StoredCredential));
    }

    const nextActivities = new Map<string, VLinkActivityEvent[]>();
    for (const item of activities) {
      if (!isObject(item)) throw new Error("Invalid durable VLink state: activity collection");
      assertString(item.vlinkId, "activity.vlinkId");
      if (!nextVlinks.has(item.vlinkId)) throw new Error("Invalid durable VLink state: orphan activity.vlinkId");
      if (!Array.isArray(item.events)) throw new Error("Invalid durable VLink state: activity events");
      if (nextActivities.has(item.vlinkId)) throw new Error("Invalid durable VLink state: duplicate activity collection");
      nextActivities.set(item.vlinkId, structuredClone(item.events as VLinkActivityEvent[]).slice(0, 100));
    }
    const nextDeviceAuthorizations = new Map<string, StoredDeviceAuthorization>();
    for (const item of deviceAuthorizations) {
      if (!isObject(item) || !isObject(item.machineIdentity)) throw new Error("Invalid durable VLink state: device authorization");
      for (const field of ["authorizationId", "displayName", "requestedScope", "verificationUri", "status", "createdAt", "expiresAt", "deviceCodeHash", "userCodeHash"]) {
        assertString(item[field], `deviceAuthorization.${field}`);
      }
      assertString(item.machineIdentity.value, "deviceAuthorization.machineIdentity.value");
      if (item.machineIdentity.assurance !== "client-asserted") throw new Error("Invalid durable VLink state: machine identity assurance");
      if (!["pending", "authorized", "denied", "expired"].includes(String(item.status))) throw new Error("Invalid durable VLink state: device authorization status");
      if (item.requestedScope !== "vlink:connect" || !DEVICE_SOURCE_TYPES.has(String(item.sourceType) as VLinkSourceType)) throw new Error("Invalid durable VLink state: device authorization scope/source");
      assertHash(item.deviceCodeHash, "deviceAuthorization.deviceCodeHash");
      assertHash(item.userCodeHash, "deviceAuthorization.userCodeHash");
      if (typeof item.interval !== "number" || item.interval < 5 || item.interval > 30) throw new Error("Invalid durable VLink state: device authorization interval");
      if (item.lastPollAt !== undefined) assertString(item.lastPollAt, "deviceAuthorization.lastPollAt");
      if (item.workspaceId !== undefined) assertString(item.workspaceId, "deviceAuthorization.workspaceId");
      if (item.operatorId !== undefined) assertString(item.operatorId, "deviceAuthorization.operatorId");
      if (item.vlinkId !== undefined) known(item.vlinkId, "deviceAuthorization.vlinkId");
      if (item.credentialId !== undefined) assertString(item.credentialId, "deviceAuthorization.credentialId");
      for (const field of ["credentialCiphertext", "credentialIv", "credentialTag"]) {
        if (item[field] !== undefined) assertString(item[field], `deviceAuthorization.${field}`);
      }
      if (item.status === "authorized" && (!item.workspaceId || !item.operatorId || !item.vlinkId || !item.credentialId
        || !item.credentialCiphertext || !item.credentialIv || !item.credentialTag)) {
        throw new Error("Invalid durable VLink state: incomplete authorized device flow");
      }
      const id = String(item.authorizationId);
      if (nextDeviceAuthorizations.has(id)) throw new Error("Invalid durable VLink state: duplicate authorizationId");
      nextDeviceAuthorizations.set(id, structuredClone(item as unknown as StoredDeviceAuthorization));
    }
    for (const vlinkId of nextVlinks.keys()) {
      if (!nextActivities.has(vlinkId)) nextActivities.set(vlinkId, []);
    }

    this.clear();
    for (const [key, item] of nextVlinks) this.vlinks.set(key, item);
    for (const [key, item] of nextGrants) this.enrollmentGrants.set(key, item);
    for (const [key, item] of nextPairings) this.pairings.set(key, item);
    for (const [key, item] of nextCredentials) this.credentials.set(key, item);
    for (const [key, item] of nextActivities) this.activities.set(key, item);
    for (const [key, item] of nextDeviceAuthorizations) this.deviceAuthorizations.set(key, item);
  }

  private findDeviceAuthorization(field: "deviceCodeHash" | "userCodeHash", secret: string): StoredDeviceAuthorization | undefined {
    for (const record of this.deviceAuthorizations.values()) {
      if (secureHashMatch(record[field], secret)) return record;
    }
    return undefined;
  }

  private expireDeviceAuthorizationIfNeeded(record: StoredDeviceAuthorization, now: Date): void {
    if (record.status === "pending" && Date.parse(record.expiresAt) <= now.getTime()) record.status = "expired";
  }

  private publicDeviceAuthorization(record: StoredDeviceAuthorization): DeviceAuthorizationView {
    return {
      authorizationId: record.authorizationId,
      machineIdentity: structuredClone(record.machineIdentity),
      displayName: record.displayName,
      sourceType: record.sourceType,
      requestedScope: record.requestedScope,
      verificationUri: record.verificationUri,
      status: record.status,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      interval: record.interval,
      ...(record.workspaceId ? { workspaceId: record.workspaceId } : {}),
      ...(record.operatorId ? { operatorId: record.operatorId } : {}),
      ...(record.vlinkId ? { vlinkId: record.vlinkId } : {}),
    };
  }

  private issueCredential(vlinkId: string, ttlSeconds: number, now: Date): VLinkAccessCredential {
    const id = randomBytes(8).toString("hex");
    const credentialId = `cred_${id}`;
    const secret = randomBytes(32).toString("base64url");
    const token = `vlt_${id}.${secret}`;
    const issuedAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000).toISOString();
    this.credentials.set(credentialId, {
      credentialId,
      vlinkId,
      tokenHash: hashSecret(token),
      issuedAt,
      expiresAt,
    });
    return { credentialId, vlinkId, token, issuedAt, expiresAt };
  }

  private publicPairing(pairing: StoredPairing): VLinkPairingStatusView {
    return {
      pairingId: pairing.pairingId,
      vlinkId: pairing.vlinkId,
      pairingUrl: pairing.pairingUrl,
      status: pairing.status,
      createdAt: pairing.createdAt,
      expiresAt: pairing.expiresAt,
      ...(pairing.approvedAt ? { approvedAt: pairing.approvedAt } : {}),
      ...(pairing.exchangedAt ? { exchangedAt: pairing.exchangedAt } : {}),
    };
  }

  private credentialSummary(credential: StoredCredential, now: Date): VLinkAccessCredentialSummary {
    const status = credential.revokedAt
      ? "revoked"
      : new Date(credential.expiresAt).getTime() <= now.getTime()
        ? "expired"
        : "active";
    return {
      credentialId: credential.credentialId,
      vlinkId: credential.vlinkId,
      issuedAt: credential.issuedAt,
      expiresAt: credential.expiresAt,
      status,
      ...(credential.revokedAt ? { revokedAt: credential.revokedAt } : {}),
    };
  }

  private expirePairingIfNeeded(pairing: StoredPairing, now: Date): void {
    if ((pairing.status === "pending" || pairing.status === "approved") && new Date(pairing.expiresAt).getTime() <= now.getTime()) {
      pairing.status = "expired";
      const vlink = this.vlinks.get(pairing.vlinkId);
      if (vlink) {
        vlink.enrollmentStatus = "expired";
        vlink.updatedAt = now.toISOString();
      }
    }
  }
}
