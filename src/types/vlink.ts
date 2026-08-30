export const VLINK_SCHEMA_VERSION = "1.0" as const;

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
export type VLinkEnrollmentStatus = "unpaired" | "pending" | "paired" | "expired";

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

export interface VLinkPairingRequest {
  pairingId: string;
  vlinkId: string;
  oneTimeCode: string;
  pairingUrl: string;
  qrPayload: string;
  status: "pending" | "completed" | "expired";
  createdAt: string;
  expiresAt: string;
  completedAt?: string;
}
