import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type {
  VLinkAccessCredential,
  VLinkAccessCredentialSummary,
  VLinkActivityEvent,
  VLinkDeviceBootstrapView,
  VLinkEnrollmentGrant,
  VLinkEnrollmentGrantSummary,
  VLinkManifest,
  VLinkPairingRequest,
  VLinkPairingChallenge,
  VLinkPairingStatusView,
  VLinkRecord,
  VLinkLeaseStatus,
  VLinkLeaseView,
  VLinkSourceType,
} from "../types/vlink";
import { VLINK_SCHEMA_VERSION } from "../types/vlink";
import type { LeaseSealer } from "./leaseSealer";
import {
  parseDevicePublicKey,
  verifyDeviceProof,
  verifyDeviceRequestProof,
  type DeviceRequestProof,
} from "./pairingProof";

export interface CreateVLinkInput {
  workspaceId: string;
  environment: string;
  displayName: string;
  sourceType: VLinkSourceType;
  expiresAt?: string;
}

interface StoredPairing extends VLinkPairingStatusView {
  approvalCodeHash?: string;
  deviceCodeHash?: string;
  devicePublicKeyPem?: string;
  bootstrapChallengeHash?: string;
  bootstrapChallengeExpiresAt?: string;
  deviceProofVerifiedAt?: string;
  exchangeChallenges?: Array<{ nonceHash: string; expiresAt: string }>;
  credentialId?: string;
  credentialSealed?: string;
}

export interface CreateDeviceBootstrapInput {
  displayName: string;
  environment: string;
  sourceType: VLinkSourceType;
}

interface StoredDeviceBootstrap extends VLinkDeviceBootstrapView {
  approvalUrl: string;
  devicePublicKeyPem: string;
  bootstrapChallengeHash?: string;
  bootstrapChallengeExpiresAt?: string;
  deviceProofVerifiedAt?: string;
  enrollmentGrantSealed?: string;
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
  deviceKeyThumbprint?: string;
  devicePublicKeyPem?: string;
}

interface StoredRequestProof {
  proofId: string;
  expiresAt: string;
}

const MAX_ACTIVE_REQUEST_PROOFS = 50_000;

export interface StoredLease {
  leaseId: string;
  vlinkId: string;
  mountId: string;
  tokenId: string;
  nonce: string;
  holderCredentialSealed: string;
  packageRef: string;
  workspace: string;
  project: string;
  targetRef: string;
  allowedActions: string[];
  blockedActions: string[];
  issuedAt: string;
  expiresAt: string;
  status: VLinkLeaseStatus;
  lastDecision?: {
    action: string;
    decision: "allow" | "deny";
    reason: string;
    at: string;
  };
}

export interface BindLeaseInput {
  mountId: string;
  tokenId: string;
  nonce: string;
  holderCredential: string;
  packageRef: string;
  workspace: string;
  project: string;
  targetRef: string;
  allowedActions: string[];
  blockedActions: string[];
  expiresAt: string;
}

export interface LeasePatch {
  status?: VLinkLeaseStatus;
  lastDecision?: StoredLease["lastDecision"];
}

export interface VLinkRegistrySnapshot {
  format: "vlink-registry/v1";
  vlinks: VLinkRecord[];
  enrollmentGrants: StoredEnrollmentGrant[];
  pairings: StoredPairing[];
  credentials: StoredCredential[];
  activities: Array<{ vlinkId: string; events: VLinkActivityEvent[] }>;
  leases: StoredLease[];
  deviceBootstraps?: StoredDeviceBootstrap[];
  bootstrapAdmissionWindows?: BootstrapAdmissionWindow[];
  requestProofs?: StoredRequestProof[];
}

export interface BootstrapAdmissionWindow {
  bucket: string;
  windowStartMs: number;
  attempts: number;
}

export interface BootstrapAdmissionPolicy {
  perSourceLimit: number;
  perSourceWindowSeconds: number;
  globalLimit: number;
  globalWindowSeconds: number;
}

export interface BootstrapAdmissionResult {
  allowed: boolean;
  retryAfterSeconds: number;
}

export interface VLinkRegistry {
  create(input: CreateVLinkInput, origin: string): VLinkRecord;
  list(): VLinkRecord[];
  get(vlinkId: string): VLinkRecord | undefined;
  manifest(vlinkId: string): VLinkManifest | undefined;
  issueEnrollmentGrant(vlinkId: string, ttlSeconds?: number, now?: Date): VLinkEnrollmentGrant | undefined;
  authenticateEnrollment(vlinkId: string, token: string, now?: Date): VLinkEnrollmentGrantSummary | undefined;
  createPairing(vlinkId: string, origin: string, ttlSeconds?: number, now?: Date): VLinkPairingRequest | undefined;
  createDevicePairing(vlinkId: string, origin: string, publicKeyPem: string, ttlSeconds?: number, now?: Date): { pairing: VLinkPairingStatusView; challenge: VLinkPairingChallenge } | undefined;
  createDeviceBootstrap(origin: string, publicKeyPem: string, input: CreateDeviceBootstrapInput, ttlSeconds?: number, now?: Date): { bootstrap: VLinkDeviceBootstrapView; challenge: VLinkPairingChallenge } | undefined;
  consumeDeviceBootstrapAdmission(sourceFingerprint: string, policy: BootstrapAdmissionPolicy, now?: Date): BootstrapAdmissionResult;
  verifyUnboundDeviceProof(pairingId: string, nonce: string, signature: string, now?: Date): VLinkDeviceBootstrapView | undefined;
  getDeviceBootstrap(pairingId: string, now?: Date): VLinkDeviceBootstrapView | undefined;
  approveDeviceBootstrap(pairingId: string, workspaceId: string, origin: string, grantTtlSeconds?: number, now?: Date): { bootstrap: VLinkDeviceBootstrapView; vlink: VLinkRecord; enrollmentGrant: VLinkEnrollmentGrant } | undefined;
  verifyDevicePairingProof(vlinkId: string, pairingId: string, nonce: string, signature: string, now?: Date): VLinkPairingStatusView | undefined;
  issueDeviceExchangeChallenge(vlinkId: string, pairingId: string, now?: Date): VLinkPairingChallenge | undefined;
  exchangeDevicePairing(vlinkId: string, pairingId: string, nonce: string, signature: string, credentialTtlSeconds?: number, now?: Date): VLinkAccessCredential | undefined;
  getPairingStatus(vlinkId: string, pairingId: string, now?: Date): VLinkPairingStatusView | undefined;
  approvePairing(vlinkId: string, pairingId: string, approvalCode?: string, now?: Date): VLinkPairingStatusView | undefined;
  exchangePairing(vlinkId: string, pairingId: string, deviceCode: string, credentialTtlSeconds?: number, now?: Date): VLinkAccessCredential | undefined;
  authenticate(vlinkId: string, token: string, now?: Date, requestProof?: DeviceRequestProof): VLinkAccessCredentialSummary | undefined;
  revokeCredential(vlinkId: string, credentialId: string, now?: Date): VLinkAccessCredentialSummary | undefined;
  configureLeaseSealer(sealer: LeaseSealer | null): void;
  bindLease(vlinkId: string, input: BindLeaseInput): VLinkLeaseView | undefined;
  getLease(vlinkId: string, leaseId: string): VLinkLeaseView | undefined;
  listLeases(vlinkId: string): VLinkLeaseView[];
  leaseSecret(vlinkId: string, leaseId: string): { holderCredential: string; tokenId: string; nonce: string } | undefined;
  updateLease(vlinkId: string, leaseId: string, patch: LeasePatch): VLinkLeaseView | undefined;
  addActivity(event: Omit<VLinkActivityEvent, "eventId" | "timestamp">, now?: Date): VLinkActivityEvent;
  activity(vlinkId: string): VLinkActivityEvent[];
  clear(): void;
}

const cleanOrigin = (origin: string) => origin.replace(/\/$/, "");
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
  private readonly vlinks = new Map<string, VLinkRecord>();
  private readonly enrollmentGrants = new Map<string, StoredEnrollmentGrant>();
  private readonly pairings = new Map<string, StoredPairing>();
  private readonly deviceBootstraps = new Map<string, StoredDeviceBootstrap>();
  private readonly bootstrapAdmissionWindows = new Map<string, BootstrapAdmissionWindow>();
  private readonly credentials = new Map<string, StoredCredential>();
  private readonly requestProofs = new Map<string, string>();
  private readonly leases = new Map<string, StoredLease>();
  private readonly activities = new Map<string, VLinkActivityEvent[]>();
  private leaseSealer?: LeaseSealer;

  constructor(leaseSealer?: LeaseSealer | null) {
    this.leaseSealer = leaseSealer ?? undefined;
  }

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
      createdAt: now,
      updatedAt: now,
      ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
    };
    this.vlinks.set(vlinkId, record);
    this.activities.set(vlinkId, []);
    return structuredClone(record);
  }

  list(): VLinkRecord[] {
    return Array.from(this.vlinks.values()).map((v) => structuredClone(v));
  }

  get(vlinkId: string): VLinkRecord | undefined {
    const value = this.vlinks.get(vlinkId);
    return value ? structuredClone(value) : undefined;
  }

  configureLeaseSealer(sealer: LeaseSealer | null): void {
    this.leaseSealer = sealer ?? undefined;
  }

  bindLease(vlinkId: string, input: BindLeaseInput): VLinkLeaseView | undefined {
    if (!this.vlinks.has(vlinkId) || !this.leaseSealer) return undefined;
    const leaseId = `lease_${randomUUID()}`;
    const stored: StoredLease = {
      leaseId,
      vlinkId,
      mountId: input.mountId,
      tokenId: input.tokenId,
      nonce: input.nonce,
      holderCredentialSealed: this.leaseSealer.seal(input.holderCredential),
      packageRef: input.packageRef,
      workspace: input.workspace,
      project: input.project,
      targetRef: input.targetRef,
      allowedActions: [...input.allowedActions],
      blockedActions: [...input.blockedActions],
      issuedAt: new Date().toISOString(),
      expiresAt: input.expiresAt,
      status: "active",
    };
    this.leases.set(leaseId, stored);
    return this.leaseView(stored);
  }

  getLease(vlinkId: string, leaseId: string): VLinkLeaseView | undefined {
    const lease = this.leases.get(leaseId);
    return lease?.vlinkId === vlinkId ? this.leaseView(lease) : undefined;
  }

  listLeases(vlinkId: string): VLinkLeaseView[] {
    return Array.from(this.leases.values())
      .filter((lease) => lease.vlinkId === vlinkId)
      .map((lease) => this.leaseView(lease));
  }

  leaseSecret(vlinkId: string, leaseId: string): { holderCredential: string; tokenId: string; nonce: string } | undefined {
    const lease = this.leases.get(leaseId);
    if (!lease || lease.vlinkId !== vlinkId || !this.leaseSealer) return undefined;
    try {
      return {
        holderCredential: this.leaseSealer.open(lease.holderCredentialSealed),
        tokenId: lease.tokenId,
        nonce: lease.nonce,
      };
    } catch {
      return undefined;
    }
  }

  updateLease(vlinkId: string, leaseId: string, patch: LeasePatch): VLinkLeaseView | undefined {
    const lease = this.leases.get(leaseId);
    if (!lease || lease.vlinkId !== vlinkId) return undefined;
    if (patch.status) lease.status = patch.status;
    if (patch.lastDecision) lease.lastDecision = structuredClone(patch.lastDecision);
    return this.leaseView(lease);
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

  createDevicePairing(
    vlinkId: string,
    origin: string,
    publicKeyPem: string,
    ttlSeconds = 600,
    now = new Date(),
  ): { pairing: VLinkPairingStatusView; challenge: VLinkPairingChallenge } | undefined {
    const vlink = this.vlinks.get(vlinkId);
    const deviceKey = parseDevicePublicKey(publicKeyPem);
    if (!vlink || !deviceKey) return undefined;

    const pairingId = `pair_${randomBytes(24).toString("hex")}`;
    const expiresAt = new Date(now.getTime() + Math.min(Math.max(1, ttlSeconds), 900) * 1000).toISOString();
    const pairingUrl = `${cleanOrigin(origin)}/pair/${vlinkId}/${pairingId}`;
    const challenge = this.newDeviceChallenge(now);
    const stored: StoredPairing = {
      pairingId,
      vlinkId,
      pairingUrl,
      status: "pending",
      createdAt: now.toISOString(),
      expiresAt,
      deviceKeyThumbprint: deviceKey.thumbprint,
      devicePublicKeyPem: deviceKey.pem,
      bootstrapChallengeHash: hashSecret(challenge.nonce),
      bootstrapChallengeExpiresAt: challenge.expiresAt,
      exchangeChallenges: [],
    };
    this.pairings.set(pairingId, stored);
    vlink.enrollmentStatus = "pending";
    vlink.updatedAt = now.toISOString();
    return { pairing: this.publicPairing(stored), challenge };
  }

  createDeviceBootstrap(
    origin: string,
    publicKeyPem: string,
    input: CreateDeviceBootstrapInput,
    ttlSeconds = 600,
    now = new Date(),
  ): { bootstrap: VLinkDeviceBootstrapView; challenge: VLinkPairingChallenge } | undefined {
    this.pruneDeviceBootstraps(now);
    const deviceKey = parseDevicePublicKey(publicKeyPem);
    const displayName = input.displayName.trim();
    const environment = input.environment.trim();
    if (
      !deviceKey ||
      !displayName || displayName.length > 120 ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/.test(environment) ||
      !["ai-client", "agent-mcp", "api-service", "webhook", "local-project", "cicd", "container"].includes(input.sourceType) ||
      Array.from(this.deviceBootstraps.values()).filter((item) => item.status === "pending" && Date.parse(item.expiresAt) > now.getTime()).length >= 500
    ) return undefined;

    const pairingId = `pair_${randomBytes(24).toString("hex")}`;
    const expiresAt = new Date(now.getTime() + Math.min(Math.max(1, ttlSeconds), 900) * 1000).toISOString();
    const approvalUrl = `${cleanOrigin(origin)}/pair/bootstrap/${pairingId}`;
    const challenge = this.newDeviceChallenge(now);
    const stored: StoredDeviceBootstrap = {
      pairingId,
      approvalUrl,
      status: "pending",
      createdAt: now.toISOString(),
      expiresAt,
      displayName,
      environment,
      sourceType: input.sourceType,
      deviceKeyThumbprint: deviceKey.thumbprint,
      deviceProofVerified: false,
      devicePublicKeyPem: deviceKey.pem,
      bootstrapChallengeHash: hashSecret(challenge.nonce),
      bootstrapChallengeExpiresAt: challenge.expiresAt,
    };
    this.deviceBootstraps.set(pairingId, stored);
    return { bootstrap: this.publicDeviceBootstrap(stored), challenge };
  }

  consumeDeviceBootstrapAdmission(
    sourceFingerprint: string,
    policy: BootstrapAdmissionPolicy,
    now = new Date(),
  ): BootstrapAdmissionResult {
    if (!/^[a-f0-9]{64}$/.test(sourceFingerprint)) throw new Error("Invalid bootstrap source fingerprint");
    if (
      !Number.isSafeInteger(policy.perSourceLimit) || policy.perSourceLimit < 1 || policy.perSourceLimit > 10_000 ||
      !Number.isSafeInteger(policy.perSourceWindowSeconds) || policy.perSourceWindowSeconds < 1 || policy.perSourceWindowSeconds > 86_400 ||
      !Number.isSafeInteger(policy.globalLimit) || policy.globalLimit < 1 || policy.globalLimit > 100_000 ||
      !Number.isSafeInteger(policy.globalWindowSeconds) || policy.globalWindowSeconds < 1 || policy.globalWindowSeconds > 86_400
    ) throw new Error("Invalid anonymous bootstrap admission policy");

    const sourceWindowMs = policy.perSourceWindowSeconds * 1000;
    const globalWindowMs = policy.globalWindowSeconds * 1000;
    const sourceWindowStartMs = Math.floor(now.getTime() / sourceWindowMs) * sourceWindowMs;
    const globalWindowStartMs = Math.floor(now.getTime() / globalWindowMs) * globalWindowMs;
    for (const [bucket, record] of this.bootstrapAdmissionWindows) {
      const durationMs = bucket === "global" ? globalWindowMs : sourceWindowMs;
      if (record.windowStartMs + durationMs <= now.getTime()) this.bootstrapAdmissionWindows.delete(bucket);
    }

    const sourceBucket = `source:${sourceFingerprint}`;
    const globalBucket = "global";
    const sourceWindow = this.bootstrapAdmissionWindows.get(sourceBucket);
    const globalWindow = this.bootstrapAdmissionWindows.get(globalBucket);
    const sourceAttempts = sourceWindow?.windowStartMs === sourceWindowStartMs ? sourceWindow.attempts : 0;
    const globalAttempts = globalWindow?.windowStartMs === globalWindowStartMs ? globalWindow.attempts : 0;
    const sourceRetryAfter = Math.max(1, Math.ceil((sourceWindowStartMs + sourceWindowMs - now.getTime()) / 1000));
    const globalRetryAfter = Math.max(1, Math.ceil((globalWindowStartMs + globalWindowMs - now.getTime()) / 1000));

    if (sourceAttempts >= policy.perSourceLimit) {
      return { allowed: false, retryAfterSeconds: sourceRetryAfter };
    }
    if (globalAttempts >= policy.globalLimit) {
      return { allowed: false, retryAfterSeconds: globalRetryAfter };
    }
    if (!sourceWindow && this.bootstrapAdmissionWindows.size >= 4_096) {
      return { allowed: false, retryAfterSeconds: Math.max(sourceRetryAfter, globalRetryAfter) };
    }

    this.bootstrapAdmissionWindows.set(sourceBucket, {
      bucket: sourceBucket,
      windowStartMs: sourceWindowStartMs,
      attempts: sourceAttempts + 1,
    });
    this.bootstrapAdmissionWindows.set(globalBucket, {
      bucket: globalBucket,
      windowStartMs: globalWindowStartMs,
      attempts: globalAttempts + 1,
    });
    return { allowed: true, retryAfterSeconds: 0 };
  }

  verifyUnboundDeviceProof(
    pairingId: string,
    nonce: string,
    signature: string,
    now = new Date(),
  ): VLinkDeviceBootstrapView | undefined {
    const bootstrap = this.deviceBootstraps.get(pairingId);
    if (!bootstrap) return undefined;
    this.expireDeviceBootstrapIfNeeded(bootstrap, now);
    if (
      bootstrap.status !== "pending" ||
      bootstrap.deviceProofVerifiedAt ||
      !bootstrap.bootstrapChallengeHash ||
      !bootstrap.bootstrapChallengeExpiresAt ||
      Date.parse(bootstrap.bootstrapChallengeExpiresAt) <= now.getTime() ||
      !secureHashMatch(bootstrap.bootstrapChallengeHash, nonce)
    ) return undefined;
    if (!verifyDeviceProof({
      publicKeyPem: bootstrap.devicePublicKeyPem,
      purpose: "unbound-bootstrap",
      vlinkId: null,
      pairingId,
      keyThumbprint: bootstrap.deviceKeyThumbprint,
      nonce,
      signature,
    })) return undefined;
    bootstrap.deviceProofVerifiedAt = now.toISOString();
    bootstrap.deviceProofVerified = true;
    delete bootstrap.bootstrapChallengeHash;
    delete bootstrap.bootstrapChallengeExpiresAt;
    return this.publicDeviceBootstrap(bootstrap);
  }

  getDeviceBootstrap(pairingId: string, now = new Date()): VLinkDeviceBootstrapView | undefined {
    const bootstrap = this.deviceBootstraps.get(pairingId);
    if (!bootstrap) return undefined;
    this.expireDeviceBootstrapIfNeeded(bootstrap, now);
    return this.publicDeviceBootstrap(bootstrap);
  }

  approveDeviceBootstrap(
    pairingId: string,
    workspaceId: string,
    origin: string,
    grantTtlSeconds = 900,
    now = new Date(),
  ): { bootstrap: VLinkDeviceBootstrapView; vlink: VLinkRecord; enrollmentGrant: VLinkEnrollmentGrant } | undefined {
    const bootstrap = this.deviceBootstraps.get(pairingId);
    if (!bootstrap || !this.leaseSealer) return undefined;
    this.expireDeviceBootstrapIfNeeded(bootstrap, now);
    const normalizedWorkspaceId = workspaceId.trim();
    if (!normalizedWorkspaceId) return undefined;

    if (bootstrap.status === "approved" && bootstrap.vlinkId) {
      const existing = this.vlinks.get(bootstrap.vlinkId);
      if (existing?.workspaceId === normalizedWorkspaceId) {
        const enrollmentGrant = this.recoverOrIssueBootstrapEnrollmentGrant(bootstrap, grantTtlSeconds, now);
        if (!enrollmentGrant) return undefined;
        return { bootstrap: this.publicDeviceBootstrap(bootstrap), vlink: structuredClone(existing), enrollmentGrant };
      }
      return undefined;
    }
    if (bootstrap.status !== "pending" || !bootstrap.deviceProofVerifiedAt || this.pairings.has(pairingId)) return undefined;

    const createdVlink = this.create({
      workspaceId: normalizedWorkspaceId,
      displayName: bootstrap.displayName,
      environment: bootstrap.environment,
      sourceType: bootstrap.sourceType,
    }, cleanOrigin(origin));
    const vlink = this.vlinks.get(createdVlink.vlinkId)!;
    const approvedAt = now.toISOString();
    const pairingUrl = `${cleanOrigin(origin)}/pair/${vlink.vlinkId}/${pairingId}`;
    this.pairings.set(pairingId, {
      pairingId,
      vlinkId: vlink.vlinkId,
      pairingUrl,
      status: "approved",
      createdAt: bootstrap.createdAt,
      expiresAt: bootstrap.expiresAt,
      approvedAt,
      deviceKeyThumbprint: bootstrap.deviceKeyThumbprint,
      devicePublicKeyPem: bootstrap.devicePublicKeyPem,
      deviceProofVerifiedAt: bootstrap.deviceProofVerifiedAt,
      exchangeChallenges: [],
    });
    vlink.enrollmentStatus = "approved";
    vlink.updatedAt = now.toISOString();
    bootstrap.status = "approved";
    bootstrap.vlinkId = vlink.vlinkId;
    const enrollmentGrant = this.recoverOrIssueBootstrapEnrollmentGrant(bootstrap, grantTtlSeconds, now);
    if (!enrollmentGrant) return undefined;
    return { bootstrap: this.publicDeviceBootstrap(bootstrap), vlink: structuredClone(vlink), enrollmentGrant };
  }

  private recoverOrIssueBootstrapEnrollmentGrant(
    bootstrap: StoredDeviceBootstrap,
    ttlSeconds: number,
    now: Date,
  ): VLinkEnrollmentGrant | undefined {
    if (!this.leaseSealer || !bootstrap.vlinkId) return undefined;
    if (bootstrap.enrollmentGrantSealed) {
      let stored: VLinkEnrollmentGrant;
      try {
        stored = JSON.parse(this.leaseSealer.open(bootstrap.enrollmentGrantSealed)) as VLinkEnrollmentGrant;
      } catch {
        return undefined;
      }
      if (
        !stored || typeof stored !== "object" ||
        typeof stored.grantId !== "string" || typeof stored.vlinkId !== "string" ||
        typeof stored.token !== "string" || typeof stored.issuedAt !== "string" || typeof stored.expiresAt !== "string" ||
        stored.vlinkId !== bootstrap.vlinkId
      ) return undefined;
      if (Date.parse(stored.expiresAt) > now.getTime()) {
        return this.authenticateEnrollment(bootstrap.vlinkId, stored.token, now) ? stored : undefined;
      }
    }
    const enrollmentGrant = this.issueEnrollmentGrant(bootstrap.vlinkId, ttlSeconds, now);
    if (!enrollmentGrant) return undefined;
    bootstrap.enrollmentGrantSealed = this.leaseSealer.seal(JSON.stringify(enrollmentGrant));
    return enrollmentGrant;
  }

  verifyDevicePairingProof(
    vlinkId: string,
    pairingId: string,
    nonce: string,
    signature: string,
    now = new Date(),
  ): VLinkPairingStatusView | undefined {
    const pairing = this.pairings.get(pairingId);
    if (!pairing || pairing.vlinkId !== vlinkId || !pairing.devicePublicKeyPem || !pairing.deviceKeyThumbprint) return undefined;
    this.expirePairingIfNeeded(pairing, now);
    if (
      pairing.status !== "pending" ||
      !pairing.bootstrapChallengeHash ||
      !pairing.bootstrapChallengeExpiresAt ||
      Date.parse(pairing.bootstrapChallengeExpiresAt) <= now.getTime() ||
      !secureHashMatch(pairing.bootstrapChallengeHash, nonce)
    ) return undefined;

    const valid = verifyDeviceProof({
      publicKeyPem: pairing.devicePublicKeyPem,
      purpose: "bootstrap",
      vlinkId,
      pairingId,
      keyThumbprint: pairing.deviceKeyThumbprint,
      nonce,
      signature,
    });
    if (!valid) return undefined;
    pairing.deviceProofVerifiedAt = now.toISOString();
    delete pairing.bootstrapChallengeHash;
    delete pairing.bootstrapChallengeExpiresAt;
    return this.publicPairing(pairing);
  }

  issueDeviceExchangeChallenge(vlinkId: string, pairingId: string, now = new Date()): VLinkPairingChallenge | undefined {
    const pairing = this.pairings.get(pairingId);
    if (!pairing || pairing.vlinkId !== vlinkId || !pairing.devicePublicKeyPem || !pairing.deviceKeyThumbprint || !pairing.deviceProofVerifiedAt) return undefined;
    this.expirePairingIfNeeded(pairing, now);
    if (pairing.status !== "approved" && pairing.status !== "exchanged") return undefined;
    if (pairing.status === "exchanged") {
      const credential = pairing.credentialId ? this.credentials.get(pairing.credentialId) : undefined;
      if (!credential || credential.revokedAt || Date.parse(credential.expiresAt) <= now.getTime() || !pairing.credentialSealed) return undefined;
    }
    const challenge = this.newDeviceChallenge(now);
    const unexpired = (pairing.exchangeChallenges ?? []).filter((item) => Date.parse(item.expiresAt) > now.getTime());
    pairing.exchangeChallenges = [...unexpired, { nonceHash: hashSecret(challenge.nonce), expiresAt: challenge.expiresAt }].slice(-4);
    return challenge;
  }

  exchangeDevicePairing(
    vlinkId: string,
    pairingId: string,
    nonce: string,
    signature: string,
    credentialTtlSeconds = 3600,
    now = new Date(),
  ): VLinkAccessCredential | undefined {
    const pairing = this.pairings.get(pairingId);
    const vlink = this.vlinks.get(vlinkId);
    if (!pairing || !vlink || pairing.vlinkId !== vlinkId || !pairing.devicePublicKeyPem || !pairing.deviceKeyThumbprint || !pairing.deviceProofVerifiedAt || !this.leaseSealer) return undefined;
    this.expirePairingIfNeeded(pairing, now);
    if (pairing.status !== "approved" && pairing.status !== "exchanged") return undefined;

    const challengeIndex = (pairing.exchangeChallenges ?? []).findIndex((item) =>
      Date.parse(item.expiresAt) > now.getTime() && secureHashMatch(item.nonceHash, nonce),
    );
    if (challengeIndex < 0) return undefined;
    if (!verifyDeviceProof({
      publicKeyPem: pairing.devicePublicKeyPem,
      purpose: "exchange",
      vlinkId,
      pairingId,
      keyThumbprint: pairing.deviceKeyThumbprint,
      nonce,
      signature,
    })) return undefined;
    pairing.exchangeChallenges!.splice(challengeIndex, 1);

    if (pairing.status === "exchanged") {
      const stored = pairing.credentialId ? this.credentials.get(pairing.credentialId) : undefined;
      if (!stored || stored.revokedAt || Date.parse(stored.expiresAt) <= now.getTime() || !pairing.credentialSealed) return undefined;
      try {
        const recovered = JSON.parse(this.leaseSealer.open(pairing.credentialSealed)) as VLinkAccessCredential;
        if (
          recovered.credentialId !== stored.credentialId ||
          recovered.vlinkId !== vlinkId ||
          recovered.issuedAt !== stored.issuedAt ||
          recovered.expiresAt !== stored.expiresAt ||
          !secureHashMatch(stored.tokenHash, recovered.token)
        ) return undefined;
        return recovered;
      } catch {
        return undefined;
      }
    }

    const credential = this.issueCredential(
      vlinkId,
      Math.max(1, credentialTtlSeconds),
      now,
      pairing.deviceKeyThumbprint,
      pairing.devicePublicKeyPem,
    );
    try {
      pairing.credentialSealed = this.leaseSealer.seal(JSON.stringify(credential));
    } catch {
      this.credentials.delete(credential.credentialId);
      return undefined;
    }
    pairing.credentialId = credential.credentialId;
    pairing.status = "exchanged";
    pairing.exchangedAt = now.toISOString();
    vlink.enrollmentStatus = "paired";
    vlink.connectionStatus = "paired";
    vlink.updatedAt = now.toISOString();
    return credential;
  }

  getPairingStatus(vlinkId: string, pairingId: string, now = new Date()): VLinkPairingStatusView | undefined {
    const pairing = this.pairings.get(pairingId);
    if (!pairing || pairing.vlinkId !== vlinkId) return undefined;
    this.expirePairingIfNeeded(pairing, now);
    return this.publicPairing(pairing);
  }

  approvePairing(vlinkId: string, pairingId: string, approvalCode?: string, now = new Date()): VLinkPairingStatusView | undefined {
    const pairing = this.pairings.get(pairingId);
    const vlink = this.vlinks.get(vlinkId);
    if (!pairing || !vlink || pairing.vlinkId !== vlinkId) return undefined;
    this.expirePairingIfNeeded(pairing, now);
    const deviceBound = Boolean(pairing.devicePublicKeyPem && pairing.deviceKeyThumbprint);
    const authorizedProof = deviceBound
      ? Boolean(pairing.deviceProofVerifiedAt)
      : Boolean(pairing.approvalCodeHash && pairing.deviceCodeHash && approvalCode && secureHashMatch(pairing.approvalCodeHash, approvalCode));
    if (pairing.status !== "pending" || !authorizedProof) return undefined;

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
    if (pairing.status !== "approved" || !pairing.deviceCodeHash || !secureHashMatch(pairing.deviceCodeHash, deviceCode)) return undefined;

    const credential = this.issueCredential(vlinkId, Math.max(1, credentialTtlSeconds), now);
    pairing.status = "exchanged";
    pairing.exchangedAt = now.toISOString();
    vlink.enrollmentStatus = "paired";
    vlink.connectionStatus = "paired";
    vlink.updatedAt = now.toISOString();
    return credential;
  }

  authenticate(vlinkId: string, token: string, now = new Date(), requestProof?: DeviceRequestProof): VLinkAccessCredentialSummary | undefined {
    const match = /^vlt_([a-f0-9]{16})\.([A-Za-z0-9_-]+)$/.exec(token);
    if (!match) return undefined;
    const credentialId = `cred_${match[1]}`;
    const credential = this.credentials.get(credentialId);
    if (!credential || credential.vlinkId !== vlinkId || credential.revokedAt) return undefined;
    if (new Date(credential.expiresAt).getTime() <= now.getTime()) return undefined;
    if (!secureHashMatch(credential.tokenHash, token)) return undefined;
    if (credential.deviceKeyThumbprint || credential.devicePublicKeyPem) {
      if (
        !credential.deviceKeyThumbprint ||
        !credential.devicePublicKeyPem ||
        !requestProof ||
        !verifyDeviceRequestProof({
          publicKeyPem: credential.devicePublicKeyPem,
          vlinkId,
          credentialId: credential.credentialId,
          tokenHash: credential.tokenHash,
          proof: requestProof,
          now,
        }) ||
        !this.consumeRequestProof(credential.credentialId, requestProof.nonce, requestProof.timestampMs, now)
      ) return undefined;
    }
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
    this.deviceBootstraps.clear();
    this.bootstrapAdmissionWindows.clear();
    this.credentials.clear();
    this.requestProofs.clear();
    this.leases.clear();
    this.activities.clear();
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
      leases: Array.from(this.leases.values()).map((lease) => structuredClone(lease)),
      deviceBootstraps: Array.from(this.deviceBootstraps.values()).map((item) => structuredClone(item)),
      bootstrapAdmissionWindows: Array.from(this.bootstrapAdmissionWindows.values()).map((item) => structuredClone(item)),
      requestProofs: Array.from(this.requestProofs.entries()).map(([proofId, expiresAt]) => ({ proofId, expiresAt })),
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
    const leases = value.leases ?? [];
    const deviceBootstraps = value.deviceBootstraps ?? [];
    const bootstrapAdmissionWindows = value.bootstrapAdmissionWindows ?? [];
    const requestProofs = value.requestProofs ?? [];
    if (!Array.isArray(vlinks) || !Array.isArray(enrollmentGrants) || !Array.isArray(pairings) || !Array.isArray(credentials) || !Array.isArray(activities) || !Array.isArray(leases) || !Array.isArray(deviceBootstraps) || !Array.isArray(bootstrapAdmissionWindows) || !Array.isArray(requestProofs)) {
      throw new Error("Invalid durable VLink state: malformed collections");
    }

    const nextBootstrapAdmissionWindows = new Map<string, BootstrapAdmissionWindow>();
    for (const item of bootstrapAdmissionWindows) {
      if (!isObject(item)) throw new Error("Invalid durable VLink state: bootstrap admission window");
      assertString(item.bucket, "bootstrapAdmission.bucket");
      if (item.bucket !== "global" && !/^source:[a-f0-9]{64}$/.test(item.bucket)) {
        throw new Error("Invalid durable VLink state: bootstrap admission bucket");
      }
      if (!Number.isSafeInteger(item.windowStartMs) || Number(item.windowStartMs) < 0) {
        throw new Error("Invalid durable VLink state: bootstrap admission window start");
      }
      if (!Number.isSafeInteger(item.attempts) || Number(item.attempts) < 1 || Number(item.attempts) > 100_000) {
        throw new Error("Invalid durable VLink state: bootstrap admission attempts");
      }
      if (nextBootstrapAdmissionWindows.has(item.bucket)) throw new Error("Invalid durable VLink state: duplicate bootstrap admission bucket");
      nextBootstrapAdmissionWindows.set(item.bucket, structuredClone(item as unknown as BootstrapAdmissionWindow));
    }

    const nextVlinks = new Map<string, VLinkRecord>();
    for (const item of vlinks) {
      if (!isObject(item)) throw new Error("Invalid durable VLink state: vlink entry");
      assertString(item.vlinkId, "vlinkId");
      if (!/^vlk_[a-f0-9]{16}$/.test(item.vlinkId)) throw new Error("Invalid durable VLink state: vlinkId");
      if (nextVlinks.has(item.vlinkId)) throw new Error("Invalid durable VLink state: duplicate vlinkId");
      if (item.version !== VLINK_SCHEMA_VERSION) throw new Error("Invalid durable VLink state: schema version");
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
      if (item.approvalCodeHash !== undefined) assertHash(item.approvalCodeHash, "pairing.approvalCodeHash");
      if (item.deviceCodeHash !== undefined) assertHash(item.deviceCodeHash, "pairing.deviceCodeHash");
      if ((item.approvalCodeHash === undefined) !== (item.deviceCodeHash === undefined)) {
        throw new Error("Invalid durable VLink state: incomplete legacy pairing secrets");
      }
      if (item.devicePublicKeyPem !== undefined) {
        assertString(item.devicePublicKeyPem, "pairing.devicePublicKeyPem");
        const parsedKey = parseDevicePublicKey(item.devicePublicKeyPem);
        if (!parsedKey || parsedKey.pem !== item.devicePublicKeyPem) throw new Error("Invalid durable VLink state: device public key");
      }
      if (item.deviceKeyThumbprint !== undefined) {
        assertString(item.deviceKeyThumbprint, "pairing.deviceKeyThumbprint");
        if (!/^[A-Za-z0-9_-]{43}$/.test(item.deviceKeyThumbprint)) throw new Error("Invalid durable VLink state: device key thumbprint");
      }
      if (item.bootstrapChallengeHash !== undefined) assertHash(item.bootstrapChallengeHash, "pairing.bootstrapChallengeHash");
      if (item.bootstrapChallengeExpiresAt !== undefined) assertString(item.bootstrapChallengeExpiresAt, "pairing.bootstrapChallengeExpiresAt");
      if (item.deviceProofVerifiedAt !== undefined) assertString(item.deviceProofVerifiedAt, "pairing.deviceProofVerifiedAt");
      if (item.exchangeChallenges !== undefined) {
        if (!Array.isArray(item.exchangeChallenges)) throw new Error("Invalid durable VLink state: exchange challenges");
        for (const challenge of item.exchangeChallenges) {
          if (!isObject(challenge)) throw new Error("Invalid durable VLink state: exchange challenge");
          assertHash(challenge.nonceHash, "pairing.exchangeChallenge.nonceHash");
          assertString(challenge.expiresAt, "pairing.exchangeChallenge.expiresAt");
        }
      }
      if (item.credentialId !== undefined) assertString(item.credentialId, "pairing.credentialId");
      if (item.credentialSealed !== undefined) assertString(item.credentialSealed, "pairing.credentialSealed");
      if ((item.credentialId === undefined) !== (item.credentialSealed === undefined)) {
        throw new Error("Invalid durable VLink state: incomplete recoverable credential");
      }
      if (item.devicePublicKeyPem !== undefined && !item.deviceKeyThumbprint) {
        throw new Error("Invalid durable VLink state: incomplete device key binding");
      }
      if (item.devicePublicKeyPem === undefined && (!item.approvalCodeHash || !item.deviceCodeHash)) {
        throw new Error("Invalid durable VLink state: pairing has no authentication material");
      }
      assertString(item.createdAt, "pairing.createdAt");
      assertString(item.expiresAt, "pairing.expiresAt");
      if (nextPairings.has(item.pairingId)) throw new Error("Invalid durable VLink state: duplicate pairingId");
      nextPairings.set(item.pairingId, structuredClone(item as unknown as StoredPairing));
    }

    const nextDeviceBootstraps = new Map<string, StoredDeviceBootstrap>();
    for (const item of deviceBootstraps) {
      if (!isObject(item)) throw new Error("Invalid durable VLink state: device bootstrap");
      assertString(item.pairingId, "deviceBootstrap.pairingId");
      if (!/^pair_[a-f0-9]{48}$/.test(item.pairingId)) throw new Error("Invalid durable VLink state: deviceBootstrap.pairingId");
      assertString(item.approvalUrl, "deviceBootstrap.approvalUrl");
      assertString(item.createdAt, "deviceBootstrap.createdAt");
      assertString(item.expiresAt, "deviceBootstrap.expiresAt");
      assertString(item.displayName, "deviceBootstrap.displayName");
      assertString(item.environment, "deviceBootstrap.environment");
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/.test(item.environment)) throw new Error("Invalid durable VLink state: deviceBootstrap.environment");
      if (![
        "ai-client", "agent-mcp", "api-service", "webhook", "local-project", "cicd", "container",
      ].includes(String(item.sourceType))) throw new Error("Invalid durable VLink state: deviceBootstrap.sourceType");
      if (!["pending", "approved", "expired"].includes(String(item.status))) throw new Error("Invalid durable VLink state: deviceBootstrap.status");
      assertString(item.deviceKeyThumbprint, "deviceBootstrap.deviceKeyThumbprint");
      if (!/^[A-Za-z0-9_-]{43}$/.test(item.deviceKeyThumbprint)) throw new Error("Invalid durable VLink state: deviceBootstrap.deviceKeyThumbprint");
      assertString(item.devicePublicKeyPem, "deviceBootstrap.devicePublicKeyPem");
      if (item.enrollmentGrantSealed !== undefined) assertString(item.enrollmentGrantSealed, "deviceBootstrap.enrollmentGrantSealed");
      const bootstrapKey = parseDevicePublicKey(item.devicePublicKeyPem);
      if (!bootstrapKey || bootstrapKey.pem !== item.devicePublicKeyPem || bootstrapKey.thumbprint !== item.deviceKeyThumbprint) {
        throw new Error("Invalid durable VLink state: device bootstrap public key");
      }
      if (typeof item.deviceProofVerified !== "boolean") throw new Error("Invalid durable VLink state: deviceBootstrap.deviceProofVerified");
      if (item.bootstrapChallengeHash !== undefined) assertHash(item.bootstrapChallengeHash, "deviceBootstrap.challengeHash");
      if (item.bootstrapChallengeExpiresAt !== undefined) assertString(item.bootstrapChallengeExpiresAt, "deviceBootstrap.challengeExpiresAt");
      if (item.deviceProofVerifiedAt !== undefined) assertString(item.deviceProofVerifiedAt, "deviceBootstrap.deviceProofVerifiedAt");
      if (item.deviceProofVerified !== Boolean(item.deviceProofVerifiedAt)) throw new Error("Invalid durable VLink state: device bootstrap proof state");
      if (item.vlinkId !== undefined) known(item.vlinkId, "deviceBootstrap.vlinkId");
      if (item.status === "approved" && item.vlinkId === undefined) throw new Error("Invalid durable VLink state: approved bootstrap has no VLink");
      if (item.status !== "approved" && item.vlinkId !== undefined) throw new Error("Invalid durable VLink state: unapproved bootstrap has a VLink");
      if (item.status === "pending" && !item.deviceProofVerified && !item.bootstrapChallengeHash) {
        throw new Error("Invalid durable VLink state: pending bootstrap has no proof challenge");
      }
      if (nextDeviceBootstraps.has(item.pairingId)) throw new Error("Invalid durable VLink state: duplicate device bootstrap");
      nextDeviceBootstraps.set(item.pairingId, structuredClone(item as unknown as StoredDeviceBootstrap));
    }
    for (const item of nextDeviceBootstraps.values()) {
      if (item.status === "approved") {
        const pairing = nextPairings.get(item.pairingId);
        if (!pairing || pairing.vlinkId !== item.vlinkId || pairing.deviceKeyThumbprint !== item.deviceKeyThumbprint || !pairing.deviceProofVerifiedAt) {
          throw new Error("Invalid durable VLink state: approved bootstrap pairing mismatch");
        }
      } else if (nextPairings.has(item.pairingId)) {
        throw new Error("Invalid durable VLink state: unapproved bootstrap has a bound pairing");
      }
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
      if (item.deviceKeyThumbprint !== undefined) {
        assertString(item.deviceKeyThumbprint, "credential.deviceKeyThumbprint");
        if (!/^[A-Za-z0-9_-]{43}$/.test(item.deviceKeyThumbprint)) throw new Error("Invalid durable VLink state: credential device key thumbprint");
      }
      if (item.devicePublicKeyPem !== undefined) {
        assertString(item.devicePublicKeyPem, "credential.devicePublicKeyPem");
        const credentialKey = parseDevicePublicKey(item.devicePublicKeyPem);
        if (!credentialKey || credentialKey.pem !== item.devicePublicKeyPem || credentialKey.thumbprint !== item.deviceKeyThumbprint) {
          throw new Error("Invalid durable VLink state: credential device public key");
        }
      }
      // Older canary credentials may have a thumbprint but no persisted public key. Keep the
      // registry loadable, but authenticate() rejects them because their PoP key is unavailable.
      if (item.devicePublicKeyPem !== undefined && item.deviceKeyThumbprint === undefined) {
        throw new Error("Invalid durable VLink state: incomplete credential device key binding");
      }
      if (nextCredentials.has(item.credentialId)) throw new Error("Invalid durable VLink state: duplicate credentialId");
      nextCredentials.set(item.credentialId, structuredClone(item as unknown as StoredCredential));
    }

    if (requestProofs.length > MAX_ACTIVE_REQUEST_PROOFS) {
      throw new Error("Invalid durable VLink state: too many request proof replay records");
    }
    const nextRequestProofs = new Map<string, string>();
    for (const item of requestProofs) {
      if (!isObject(item)) throw new Error("Invalid durable VLink state: request proof replay record");
      assertHash(item.proofId, "requestProof.proofId");
      assertString(item.expiresAt, "requestProof.expiresAt");
      if (!Number.isFinite(Date.parse(item.expiresAt))) throw new Error("Invalid durable VLink state: request proof expiry");
      if (nextRequestProofs.has(item.proofId)) throw new Error("Invalid durable VLink state: duplicate request proof");
      nextRequestProofs.set(item.proofId, item.expiresAt);
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
    const nextLeases = new Map<string, StoredLease>();
    for (const item of leases) {
      if (!isObject(item)) throw new Error("Invalid durable VLink state: lease");
      for (const field of ["leaseId", "vlinkId", "mountId", "tokenId", "nonce", "holderCredentialSealed", "packageRef", "workspace", "project", "targetRef", "issuedAt", "expiresAt"]) {
        assertString(item[field], `lease.${field}`);
      }
      const leaseId = item.leaseId;
      const leaseVlinkId = item.vlinkId;
      assertString(leaseId, "lease.leaseId");
      assertString(leaseVlinkId, "lease.vlinkId");
      known(leaseVlinkId, "lease.vlinkId");
      if (!Array.isArray(item.allowedActions) || !Array.isArray(item.blockedActions)) {
        throw new Error("Invalid durable VLink state: lease action scope");
      }
      if (
        !item.allowedActions.every((action) => typeof action === "string") ||
        !item.blockedActions.every((action) => typeof action === "string")
      ) {
        throw new Error("Invalid durable VLink state: lease action scope");
      }
      if (!["active", "terminated", "expired"].includes(String(item.status))) {
        throw new Error("Invalid durable VLink state: lease status");
      }
      if (item.lastDecision !== undefined) {
        if (!isObject(item.lastDecision)) throw new Error("Invalid durable VLink state: lease decision");
        if (
          typeof item.lastDecision.action !== "string" ||
          !["allow", "deny"].includes(String(item.lastDecision.decision)) ||
          typeof item.lastDecision.reason !== "string" ||
          typeof item.lastDecision.at !== "string"
        ) {
          throw new Error("Invalid durable VLink state: lease decision");
        }
      }
      if (nextLeases.has(leaseId)) throw new Error("Invalid durable VLink state: duplicate leaseId");
      nextLeases.set(leaseId, structuredClone(item as unknown as StoredLease));
    }
    for (const vlinkId of nextVlinks.keys()) {
      if (!nextActivities.has(vlinkId)) nextActivities.set(vlinkId, []);
    }

    this.clear();
    for (const [key, item] of nextVlinks) this.vlinks.set(key, item);
    for (const [key, item] of nextGrants) this.enrollmentGrants.set(key, item);
    for (const [key, item] of nextPairings) this.pairings.set(key, item);
    for (const [key, item] of nextDeviceBootstraps) this.deviceBootstraps.set(key, item);
    for (const [key, item] of nextBootstrapAdmissionWindows) this.bootstrapAdmissionWindows.set(key, item);
    for (const [key, item] of nextCredentials) this.credentials.set(key, item);
    for (const [key, expiresAt] of nextRequestProofs) this.requestProofs.set(key, expiresAt);
    for (const [key, item] of nextLeases) this.leases.set(key, item);
    for (const [key, item] of nextActivities) this.activities.set(key, item);
  }

  private leaseView(lease: StoredLease): VLinkLeaseView {
    const status =
      lease.status === "active" && Date.parse(lease.expiresAt) <= Date.now()
        ? "expired"
        : lease.status;
    return {
      leaseId: lease.leaseId,
      vlinkId: lease.vlinkId,
      mountId: lease.mountId,
      packageRef: lease.packageRef,
      workspace: lease.workspace,
      project: lease.project,
      targetRef: lease.targetRef,
      allowedActions: [...lease.allowedActions],
      blockedActions: [...lease.blockedActions],
      issuedAt: lease.issuedAt,
      expiresAt: lease.expiresAt,
      status,
      ...(lease.lastDecision ? { lastDecision: structuredClone(lease.lastDecision) } : {}),
      holderCredentialStored: true,
      holderCredentialDisclosed: false,
    };
  }

  private issueCredential(
    vlinkId: string,
    ttlSeconds: number,
    now: Date,
    deviceKeyThumbprint?: string,
    devicePublicKeyPem?: string,
  ): VLinkAccessCredential {
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
      ...(deviceKeyThumbprint ? { deviceKeyThumbprint } : {}),
      ...(devicePublicKeyPem ? { devicePublicKeyPem } : {}),
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
      ...(pairing.deviceKeyThumbprint ? { deviceKeyThumbprint: pairing.deviceKeyThumbprint } : {}),
      ...(pairing.devicePublicKeyPem ? { deviceProofVerified: Boolean(pairing.deviceProofVerifiedAt) } : {}),
    };
  }

  private consumeRequestProof(credentialId: string, nonce: string, timestampMs: number, now: Date): boolean {
    for (const [proofId, expiresAt] of this.requestProofs) {
      if (Date.parse(expiresAt) <= now.getTime()) this.requestProofs.delete(proofId);
    }
    const proofId = hashSecret(`${credentialId}\0${nonce}`);
    if (this.requestProofs.has(proofId) || this.requestProofs.size >= MAX_ACTIVE_REQUEST_PROOFS) return false;
    this.requestProofs.set(proofId, new Date(timestampMs + 120_000).toISOString());
    return true;
  }

  private publicDeviceBootstrap(bootstrap: StoredDeviceBootstrap): VLinkDeviceBootstrapView {
    return {
      pairingId: bootstrap.pairingId,
      approvalUrl: bootstrap.approvalUrl,
      status: bootstrap.status,
      createdAt: bootstrap.createdAt,
      expiresAt: bootstrap.expiresAt,
      displayName: bootstrap.displayName,
      environment: bootstrap.environment,
      sourceType: bootstrap.sourceType,
      deviceKeyThumbprint: bootstrap.deviceKeyThumbprint,
      deviceProofVerified: bootstrap.deviceProofVerified,
      ...(bootstrap.vlinkId ? { vlinkId: bootstrap.vlinkId } : {}),
    };
  }

  private expireDeviceBootstrapIfNeeded(bootstrap: StoredDeviceBootstrap, now: Date): void {
    if (bootstrap.status === "pending" && Date.parse(bootstrap.expiresAt) <= now.getTime()) {
      bootstrap.status = "expired";
    }
  }

  private pruneDeviceBootstraps(now: Date): void {
    const retentionMs = 24 * 60 * 60 * 1000;
    for (const [pairingId, bootstrap] of this.deviceBootstraps) {
      this.expireDeviceBootstrapIfNeeded(bootstrap, now);
      if (Date.parse(bootstrap.createdAt) + retentionMs <= now.getTime()) this.deviceBootstraps.delete(pairingId);
    }
  }

  private newDeviceChallenge(now: Date): VLinkPairingChallenge {
    return {
      nonce: randomBytes(32).toString("base64url"),
      expiresAt: new Date(now.getTime() + 120_000).toISOString(),
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
