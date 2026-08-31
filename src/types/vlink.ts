export const VLINK_SCHEMA_VERSION = "1.0" as const;
export const VLINK_RECEIPT_VERSION = "vlink-receipt/v1" as const;

export type VLinkMode = "observe" | "guard" | "enforce";
export type VLinkEnvironment = "development" | "staging" | "production" | string;
export type VLinkSourceType =
  | "ai-client"
  | "agent-mcp"
  | "api-service"
  | "webhook"
  | "local-project"
  | "cicd"
  | "container";
export type VLinkConnectionStatus = "created" | "paired" | "active" | "expired" | "revoked";
export type VLinkEnrollmentStatus = "unpaired" | "pending" | "approved" | "paired" | "expired";

export interface VLinkEndpoints {
  openaiCompatibleBaseUrl: string;
  webhookIngressUrl: string;
  mcpEndpoint: string;
  activityViewerUrl: string;
}

export interface VLinkGovernanceRefs {
  capabilityRef?: string;
  policyRef?: string;
  authorityDigest?: string;
}

export interface VLinkRecord {
  version: typeof VLINK_SCHEMA_VERSION;
  vlinkId: string;
  workspaceId: string;
  environment: VLinkEnvironment;
  displayName: string;
  sourceType: VLinkSourceType;
  mode: VLinkMode;
  endpoints: VLinkEndpoints;
  governance?: VLinkGovernanceRefs;
  connectionStatus: VLinkConnectionStatus;
  enrollmentStatus: VLinkEnrollmentStatus;
  createdAt: string;
  updatedAt: string;
  expiresAt?: string;
}

export interface VLinkManifest {
  version: typeof VLINK_SCHEMA_VERSION;
  protocol: "vlink/v1";
  vlinkId: string;
  workspaceId: string;
  environment: VLinkEnvironment;
  displayName: string;
  sourceType: VLinkSourceType;
  mode: VLinkMode;
  endpoints: VLinkEndpoints;
  connectionMethods: Array<"endpoint-swap" | "webhook" | "browser-pairing" | "docker" | "github-actions" | "mcp">;
  governance: {
    mode: VLinkMode;
    capabilityRef?: string;
    policyRef?: string;
    authorityDigest?: string;
  };
  enrollment: {
    status: VLinkEnrollmentStatus;
    pairingRequired: boolean;
  };
  access: {
    scheme: "bearer";
    temporaryCredentials: true;
    tokenPublishedInManifest: false;
  };
  generatedAt: string;
}

export interface VLinkActivityEvent {
  eventId: string;
  vlinkId: string;
  timestamp: string;
  sourceType: VLinkSourceType;
  route: string;
  method: string;
  mode: VLinkMode;
  status: "completed" | "accepted" | "failed";
  latencyMs: number;
  backend?: string;
  metadata: Record<string, string | number | boolean | null>;
}

export interface VLinkReceiptPublicKeyJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
}

export interface VLinkSignedReceipt {
  version: typeof VLINK_RECEIPT_VERSION;
  receiptId: string;
  eventId: string;
  vlinkId: string;
  issuedAt: string;
  algorithm: "Ed25519";
  digestAlgorithm: "SHA-256";
  canonicalization: "vlink-canonical-json/v1";
  keyId: string;
  publicKeyJwk: VLinkReceiptPublicKeyJwk;
  payloadHash: string;
  payload: VLinkActivityEvent;
  signature: string;
}

export interface VLinkReceiptKeyDescriptor {
  keyId: string;
  algorithm: "Ed25519";
  publicKeyJwk: VLinkReceiptPublicKeyJwk;
  persistence: "configured" | "ephemeral";
  trustNote: string;
}

export interface VLinkReceiptVerification {
  valid: boolean;
  signatureValid: boolean;
  payloadHashValid: boolean;
  keyIdValid: boolean;
  expectedKeyMatched: boolean | null;
  keyId: string;
  reason?: string;
}

export interface VLinkEnrollmentGrant {
  grantId: string;
  vlinkId: string;
  token: string;
  issuedAt: string;
  expiresAt: string;
}

export interface VLinkEnrollmentGrantSummary {
  grantId: string;
  vlinkId: string;
  issuedAt: string;
  expiresAt: string;
}

export type VLinkPairingStatus = "pending" | "approved" | "exchanged" | "expired";

export interface VLinkPairingRequest {
  pairingId: string;
  vlinkId: string;
  approvalCode: string;
  deviceCode: string;
  pairingUrl: string;
  qrPayload: string;
  status: VLinkPairingStatus;
  createdAt: string;
  expiresAt: string;
}

export interface VLinkPairingStatusView {
  pairingId: string;
  vlinkId: string;
  pairingUrl: string;
  status: VLinkPairingStatus;
  createdAt: string;
  expiresAt: string;
  approvedAt?: string;
  exchangedAt?: string;
}

export interface VLinkAccessCredential {
  credentialId: string;
  vlinkId: string;
  token: string;
  issuedAt: string;
  expiresAt: string;
}

export interface VLinkAccessCredentialSummary {
  credentialId: string;
  vlinkId: string;
  issuedAt: string;
  expiresAt: string;
  status: "active" | "expired" | "revoked";
  revokedAt?: string;
}
