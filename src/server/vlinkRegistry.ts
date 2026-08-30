import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type {
  VLinkAccessCredential,
  VLinkAccessCredentialSummary,
  VLinkActivityEvent,
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
}

interface StoredPairing extends VLinkPairingStatusView {
  approvalCodeHash: string;
  deviceCodeHash: string;
}

interface StoredCredential {
  credentialId: string;
  vlinkId: string;
  tokenHash: string;
  issuedAt: string;
  expiresAt: string;
  revokedAt?: string;
}

export interface VLinkRegistry {
  create(input: CreateVLinkInput, origin: string): VLinkRecord;
  list(): VLinkRecord[];
  get(vlinkId: string): VLinkRecord | undefined;
  manifest(vlinkId: string): VLinkManifest | undefined;
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
const hashSecret = (secret: string) => createHash("sha256").update(secret, "utf8").digest("hex");
const secureHashMatch = (expectedHash: string, providedSecret: string) => {
  const expected = Buffer.from(expectedHash, "hex");
  const actual = Buffer.from(hashSecret(providedSecret), "hex");
  return expected.length === actual.length && timingSafeEqual(expected, actual);
};

export class InMemoryVLinkRegistry implements VLinkRegistry {
  private readonly vlinks = new Map<string, VLinkRecord>();
  private readonly pairings = new Map<string, StoredPairing>();
  private readonly credentials = new Map<string, StoredCredential>();
  private readonly activities = new Map<string, VLinkActivityEvent[]>();

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
    this.pairings.clear();
    this.credentials.clear();
    this.activities.clear();
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
