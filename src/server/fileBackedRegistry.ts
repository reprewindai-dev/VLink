import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
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
} from "../types/vlink";
import {
  InMemoryVLinkRegistry,
  type CreateVLinkInput,
  type VLinkRegistry,
  type VLinkRegistrySnapshot,
} from "./vlinkRegistry";

export interface FileBackedVLinkRegistryOptions {
  statePath: string;
}

const stableJson = (snapshot: VLinkRegistrySnapshot) => `${JSON.stringify(snapshot, null, 2)}\n`;

export class FileBackedVLinkRegistry implements VLinkRegistry {
  private readonly inner = new InMemoryVLinkRegistry();
  private readonly statePath: string;

  constructor(options: FileBackedVLinkRegistryOptions) {
    const configured = options.statePath.trim();
    if (!configured) throw new Error("VLink durable state path must not be empty");
    this.statePath = path.resolve(configured);
    this.load();
  }

  create(input: CreateVLinkInput, origin: string): VLinkRecord {
    return this.commit(() => this.inner.create(input, origin));
  }

  list(): VLinkRecord[] {
    return this.inner.list();
  }

  get(vlinkId: string): VLinkRecord | undefined {
    return this.inner.get(vlinkId);
  }

  manifest(vlinkId: string): VLinkManifest | undefined {
    return this.inner.manifest(vlinkId);
  }

  issueEnrollmentGrant(vlinkId: string, ttlSeconds?: number, now?: Date): VLinkEnrollmentGrant | undefined {
    return this.commit(() => this.inner.issueEnrollmentGrant(vlinkId, ttlSeconds, now));
  }

  authenticateEnrollment(vlinkId: string, token: string, now?: Date): VLinkEnrollmentGrantSummary | undefined {
    return this.inner.authenticateEnrollment(vlinkId, token, now);
  }

  createPairing(vlinkId: string, origin: string, ttlSeconds?: number, now?: Date): VLinkPairingRequest | undefined {
    return this.commit(() => this.inner.createPairing(vlinkId, origin, ttlSeconds, now));
  }

  getPairingStatus(vlinkId: string, pairingId: string, now?: Date): VLinkPairingStatusView | undefined {
    return this.commit(() => this.inner.getPairingStatus(vlinkId, pairingId, now));
  }

  approvePairing(vlinkId: string, pairingId: string, approvalCode: string, now?: Date): VLinkPairingStatusView | undefined {
    return this.commit(() => this.inner.approvePairing(vlinkId, pairingId, approvalCode, now));
  }

  exchangePairing(
    vlinkId: string,
    pairingId: string,
    deviceCode: string,
    credentialTtlSeconds?: number,
    now?: Date,
  ): VLinkAccessCredential | undefined {
    return this.commit(() => this.inner.exchangePairing(vlinkId, pairingId, deviceCode, credentialTtlSeconds, now));
  }

  authenticate(vlinkId: string, token: string, now?: Date): VLinkAccessCredentialSummary | undefined {
    return this.inner.authenticate(vlinkId, token, now);
  }

  revokeCredential(vlinkId: string, credentialId: string, now?: Date): VLinkAccessCredentialSummary | undefined {
    return this.commit(() => this.inner.revokeCredential(vlinkId, credentialId, now));
  }

  addActivity(event: Omit<VLinkActivityEvent, "eventId" | "timestamp">, now?: Date): VLinkActivityEvent {
    return this.commit(() => this.inner.addActivity(event, now));
  }

  activity(vlinkId: string): VLinkActivityEvent[] {
    return this.inner.activity(vlinkId);
  }

  clear(): void {
    this.commit(() => this.inner.clear());
  }

  private load(): void {
    if (!existsSync(this.statePath)) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(this.statePath, "utf8"));
    } catch (error) {
      throw new Error(`VLink durable state could not be parsed: ${error instanceof Error ? error.message : String(error)}`);
    }
    this.inner.restoreSnapshot(parsed);
  }

  private commit<T>(operation: () => T): T {
    const before = this.inner.exportSnapshot();
    const beforeJson = stableJson(before);
    const result = operation();
    const after = this.inner.exportSnapshot();
    const afterJson = stableJson(after);
    if (beforeJson === afterJson) return result;
    try {
      this.persist(afterJson);
      return result;
    } catch (error) {
      this.inner.restoreSnapshot(before);
      throw error;
    }
  }

  private persist(payload: string): void {
    const directory = path.dirname(this.statePath);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const tempPath = `${this.statePath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    let fd: number | undefined;
    try {
      fd = openSync(tempPath, "wx", 0o600);
      writeFileSync(fd, payload, { encoding: "utf8" });
      fsyncSync(fd);
      closeSync(fd);
      fd = undefined;
      renameSync(tempPath, this.statePath);
    } catch (error) {
      if (fd !== undefined) {
        try {
          closeSync(fd);
        } catch {
          // Best effort cleanup only.
        }
      }
      try {
        unlinkSync(tempPath);
      } catch {
        // The rename may already have completed or cleanup may be blocked.
      }
      throw new Error(`VLink durable state write failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}
