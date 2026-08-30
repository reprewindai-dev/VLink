import { randomBytes, randomUUID } from "node:crypto";
import type {
  VLinkActivityEvent,
  VLinkManifest,
  VLinkPairingRequest,
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

export interface VLinkRegistry {
  create(input: CreateVLinkInput, origin: string): VLinkRecord;
  list(): VLinkRecord[];
  get(vlinkId: string): VLinkRecord | undefined;
  manifest(vlinkId: string): VLinkManifest | undefined;
  createPairing(vlinkId: string, origin: string, ttlSeconds?: number, now?: Date): VLinkPairingRequest | undefined;
  getPairing(vlinkId: string, pairingId: string, now?: Date): VLinkPairingRequest | undefined;
  completePairing(vlinkId: string, pairingId: string, oneTimeCode: string, now?: Date): VLinkPairingRequest | undefined;
  addActivity(event: Omit<VLinkActivityEvent, "eventId" | "timestamp">, now?: Date): VLinkActivityEvent;
  activity(vlinkId: string): VLinkActivityEvent[];
  clear(): void;
}

const cleanOrigin = (origin: string) => origin.replace(/\/$/, "");

export class InMemoryVLinkRegistry implements VLinkRegistry {
  private readonly vlinks = new Map<string, VLinkRecord>();
  private readonly pairings = new Map<string, VLinkPairingRequest>();
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
        openaiCompatibleBaseUrl: `${root}/v1`,
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
      generatedAt: new Date().toISOString(),
    };
  }

  createPairing(vlinkId: string, origin: string, ttlSeconds = 600, now = new Date()): VLinkPairingRequest | undefined {
    const vlink = this.vlinks.get(vlinkId);
    if (!vlink) return undefined;
    const pairingId = `pair_${randomBytes(8).toString("hex")}`;
    const oneTimeCode = randomBytes(18).toString("base64url");
    const expiresAt = new Date(now.getTime() + Math.max(1, ttlSeconds) * 1000).toISOString();
    const root = cleanOrigin(origin);
    const pairingUrl = `${root}/pair/${pairingId}`;
    const request: VLinkPairingRequest = {
      pairingId,
      vlinkId,
      oneTimeCode,
      pairingUrl,
      qrPayload: JSON.stringify({ protocol: "vlink-pair/v1", pairingId, vlinkId, pairingUrl, oneTimeCode, expiresAt }),
      status: "pending",
      createdAt: now.toISOString(),
      expiresAt,
    };
    this.pairings.set(pairingId, request);
    vlink.enrollmentStatus = "pending";
    vlink.updatedAt = now.toISOString();
    return structuredClone(request);
  }

  getPairing(vlinkId: string, pairingId: string, now = new Date()): VLinkPairingRequest | undefined {
    const pairing = this.pairings.get(pairingId);
    if (!pairing || pairing.vlinkId !== vlinkId) return undefined;
    this.expirePairingIfNeeded(pairing, now);
    return structuredClone(pairing);
  }

  completePairing(vlinkId: string, pairingId: string, oneTimeCode: string, now = new Date()): VLinkPairingRequest | undefined {
    const pairing = this.pairings.get(pairingId);
    const vlink = this.vlinks.get(vlinkId);
    if (!pairing || !vlink || pairing.vlinkId !== vlinkId) return undefined;
    this.expirePairingIfNeeded(pairing, now);
    if (pairing.status !== "pending" || pairing.oneTimeCode !== oneTimeCode) return undefined;
    pairing.status = "completed";
    pairing.completedAt = now.toISOString();
    vlink.enrollmentStatus = "paired";
    vlink.connectionStatus = "paired";
    vlink.updatedAt = now.toISOString();
    return structuredClone(pairing);
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
    this.activities.clear();
  }

  private expirePairingIfNeeded(pairing: VLinkPairingRequest, now: Date): void {
    if (pairing.status === "pending" && new Date(pairing.expiresAt).getTime() <= now.getTime()) {
      pairing.status = "expired";
      const vlink = this.vlinks.get(pairing.vlinkId);
      if (vlink) {
        vlink.enrollmentStatus = "expired";
        vlink.updatedAt = now.toISOString();
      }
    }
  }
}
