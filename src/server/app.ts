import express, { type NextFunction, type Request, type Response } from "express";
import { createHmac, randomBytes } from "node:crypto";
import { GoogleGenAI } from "@google/genai";
import {
  InMemoryVLinkRegistry,
  type BootstrapAdmissionPolicy,
  type VLinkRegistry,
} from "./vlinkRegistry";
import { createLeaseSealer } from "./leaseSealer";
import type { LeaseSealer } from "./leaseSealer";
import { authenticateVLinkRequest, captureVLinkRequestBodyHash } from "./requestProof";
import * as cappoRelay from "./cappoRelay";
import type { VLinkAccessCredentialSummary, VLinkDeviceBootstrapView, VLinkSourceType } from "../types/vlink";

export interface VLinkWorkspaceIdentity {
  userId?: string;
  email?: string;
  workspaceId: string;
  mfaVerified?: boolean;
}

export interface VLinkWorkspaceAuthContext {
  workspaceId?: string;
  mfaCode?: string;
  requireMfa?: boolean;
}

export type VLinkWorkspaceAuthenticator = (
  token: string,
  context?: VLinkWorkspaceAuthContext,
) => Promise<VLinkWorkspaceIdentity | undefined>;

export interface CreateAppOptions {
  registry?: VLinkRegistry;
  publicOrigin?: string;
  pairingOrigin?: string;
  enableDemoResponses?: boolean;
  allowUnboundCompatibility?: boolean;
  allowUnauthenticatedCreate?: boolean;
  enableAnonymousBootstrap?: boolean;
  enrollmentGrantTtlSeconds?: number;
  accessTokenTtlSeconds?: number;
  lockerPhycerBaseUrl?: string;
  workspaceAuthenticator?: VLinkWorkspaceAuthenticator;
  leaseSealer?: LeaseSealer | null;
  bootstrapRateLimitKey?: string;
  trustedProxyCidrs?: string[];
  bootstrapAdmissionPolicy?: Partial<BootstrapAdmissionPolicy>;
}

const SOURCE_TYPES = new Set<VLinkSourceType>([
  "ai-client",
  "agent-mcp",
  "api-service",
  "webhook",
  "local-project",
  "cicd",
  "container",
]);

const originFor = (req: Request, configured?: string) => {
  if (configured) return configured.replace(/\/$/, "");
  return `${req.protocol}://${req.get("host")}`;
};

const getBoundVLinkId = (req: Request): string | undefined => {
  const header = req.header("x-vlink-id")?.trim();
  const query = typeof req.query.vlinkId === "string" ? req.query.vlinkId.trim() : undefined;
  return header || query || undefined;
};

const getBearerToken = (req: Request): string | undefined => {
  const authorization = req.header("authorization")?.trim();
  if (!authorization) return undefined;
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  return match?.[1]?.trim() || undefined;
};

const clampSeconds = (value: number, fallback: number, max: number) => {
  if (!Number.isFinite(value)) return fallback;
  return Math.min(Math.max(Math.floor(value), 1), max);
};

const configuredInteger = (value: number | string | undefined, fallback: number, name: string, max: number) => {
  if (value === undefined || value === "") return fallback;
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > max) {
    throw new Error(`${name} must be an integer between 1 and ${max}`);
  }
  return parsed;
};

const parseAllowedTargetHosts = () =>
  new Set(
    (process.env.VLINK_ALLOWED_TARGET_HOSTS ?? "")
      .split(",")
      .map((host) => host.trim().toLowerCase())
      .filter(Boolean),
  );

const validateTargetUrl = (value: string): URL => {
  const url = new URL(value);
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Only HTTP(S) targets are supported");
  }
  const allowedHosts = parseAllowedTargetHosts();
  if (!allowedHosts.has(url.hostname.toLowerCase())) {
    throw new Error("Target host is not in VLINK_ALLOWED_TARGET_HOSTS");
  }
  return url;
};

const safeManifestJson = (manifest: unknown) => {
  const serialized = JSON.stringify(manifest).toLowerCase();
  const forbidden = [
    "api_key",
    "apikey",
    "bearer ",
    "privatekey",
    "approvalcode",
    "devicecode",
    "vle_",
    "vlt_",
  ];
  if (forbidden.some((term) => serialized.includes(term))) {
    throw new Error("Manifest unexpectedly contains secret-bearing fields");
  }
  return manifest;
};

export function createApp(options: CreateAppOptions = {}) {
  const app = express();
  const registry = options.registry ?? new InMemoryVLinkRegistry();
  const leaseSealer = Object.hasOwn(options, "leaseSealer") ? options.leaseSealer ?? null : createLeaseSealer();
  registry.configureLeaseSealer(leaseSealer);
  const enableDemoResponses = options.enableDemoResponses ?? process.env.VLINK_ENABLE_DEMO_RESPONSES === "true";
  const allowUnboundCompatibility = options.allowUnboundCompatibility ?? process.env.VLINK_ALLOW_UNBOUND_COMPAT === "true";
  const allowUnauthenticatedCreate =
    options.allowUnauthenticatedCreate ??
    (process.env.NODE_ENV !== "production" || process.env.VLINK_ALLOW_UNAUTHENTICATED_CREATE === "true");
  const enableAnonymousBootstrap = options.enableAnonymousBootstrap ??
    (process.env.NODE_ENV !== "production" || process.env.VLINK_ANONYMOUS_BOOTSTRAP_ENABLED === "true");
  const bootstrapPublicOrigin = options.pairingOrigin || process.env.VLINK_PAIRING_ORIGIN || options.publicOrigin || process.env.VLINK_PUBLIC_ORIGIN;
  if (process.env.NODE_ENV === "production" && enableAnonymousBootstrap) {
    if (!bootstrapPublicOrigin?.trim()) {
      throw new Error("VLINK_PAIRING_ORIGIN or VLINK_PUBLIC_ORIGIN must be configured before anonymous bootstrap can be enabled in production");
    }
    let parsedOrigin: URL;
    try {
      parsedOrigin = new URL(bootstrapPublicOrigin);
    } catch {
      throw new Error("The configured VLink bootstrap origin must be an absolute HTTPS origin");
    }
    const normalizedOrigin = bootstrapPublicOrigin.trim().replace(/\/+$/, "");
    if (parsedOrigin.protocol !== "https:" || parsedOrigin.origin !== normalizedOrigin || parsedOrigin.username || parsedOrigin.password) {
      throw new Error("The configured VLink bootstrap origin must be a canonical HTTPS origin without credentials or a path");
    }
  }
  const configuredRateLimitKey = options.bootstrapRateLimitKey ?? process.env.VLINK_BOOTSTRAP_RATE_LIMIT_KEY;
  if (process.env.NODE_ENV === "production" && enableAnonymousBootstrap && (!configuredRateLimitKey || Buffer.byteLength(configuredRateLimitKey, "utf8") < 32)) {
    throw new Error("VLINK_BOOTSTRAP_RATE_LIMIT_KEY must contain at least 32 bytes before anonymous bootstrap can be enabled in production");
  }
  const bootstrapRateLimitKey = configuredRateLimitKey || randomBytes(32).toString("hex");
  const bootstrapAdmissionPolicy: BootstrapAdmissionPolicy = {
    perSourceLimit: configuredInteger(options.bootstrapAdmissionPolicy?.perSourceLimit ?? process.env.VLINK_BOOTSTRAP_SOURCE_LIMIT, 10, "VLINK_BOOTSTRAP_SOURCE_LIMIT", 10_000),
    perSourceWindowSeconds: configuredInteger(options.bootstrapAdmissionPolicy?.perSourceWindowSeconds ?? process.env.VLINK_BOOTSTRAP_SOURCE_WINDOW_SECONDS, 600, "VLINK_BOOTSTRAP_SOURCE_WINDOW_SECONDS", 86_400),
    globalLimit: configuredInteger(options.bootstrapAdmissionPolicy?.globalLimit ?? process.env.VLINK_BOOTSTRAP_GLOBAL_LIMIT, 100, "VLINK_BOOTSTRAP_GLOBAL_LIMIT", 100_000),
    globalWindowSeconds: configuredInteger(options.bootstrapAdmissionPolicy?.globalWindowSeconds ?? process.env.VLINK_BOOTSTRAP_GLOBAL_WINDOW_SECONDS, 3600, "VLINK_BOOTSTRAP_GLOBAL_WINDOW_SECONDS", 86_400),
  };
  const trustedProxyCidrs = options.trustedProxyCidrs ?? (process.env.VLINK_TRUST_PROXY_CIDRS ?? "")
    .split(",")
    .map((cidr) => cidr.trim())
    .filter(Boolean);
  if (trustedProxyCidrs.some((cidr) => cidr === "*")) {
    throw new Error("VLINK_TRUST_PROXY_CIDRS must not trust every proxy");
  }
  const enrollmentGrantTtlSeconds = clampSeconds(
    options.enrollmentGrantTtlSeconds ?? Number(process.env.VLINK_ENROLLMENT_TTL_SECONDS ?? 900),
    900,
    3600,
  );
  const accessTokenTtlSeconds = clampSeconds(
    options.accessTokenTtlSeconds ?? Number(process.env.VLINK_ACCESS_TOKEN_TTL_SECONDS ?? 3600),
    3600,
    86400,
  );

  const lockerPhycerBaseUrl = (
    options.lockerPhycerBaseUrl ??
    process.env.VLINK_LOCKERPHYCER_URL ??
    process.env.LOCKERPHYCER_URL ??
    ""
  ).replace(/\/+$/, "");

  const workspaceAuthenticator: VLinkWorkspaceAuthenticator | undefined =
    options.workspaceAuthenticator ??
    (lockerPhycerBaseUrl
      ? async (token: string, context: VLinkWorkspaceAuthContext = {}) => {
          const response = await fetch(`${lockerPhycerBaseUrl}/api/v1/auth/me`, {
            headers: { authorization: `Bearer ${token}`, accept: "application/json" },
            signal: AbortSignal.timeout(5_000),
          });
          if (response.status === 401 || response.status === 403) return undefined;
          if (!response.ok) throw new Error(`LockerPhycer auth/me returned HTTP ${response.status}`);
          const identity = (await response.json()) as {
            id?: string;
            email?: string;
            workspace_id?: string | null;
            mfa_verified?: boolean;
          };
          const workspaceId = identity.workspace_id?.trim();
          if (!workspaceId) {
            throw new Error("LockerPhycer session is authenticated but is not bound to a workspace");
          }
          const authorizedWorkspaceId = context.workspaceId?.trim() || workspaceId;
          const ownerResponse = await fetch(
            `${lockerPhycerBaseUrl}/api/v1/workspace/${encodeURIComponent(authorizedWorkspaceId)}/vlink-authorization`,
            {
              headers: { authorization: `Bearer ${token}`, accept: "application/json" },
              signal: AbortSignal.timeout(5_000),
            },
          );
          if (ownerResponse.status === 401) return undefined;
          if (ownerResponse.status === 403 || ownerResponse.status === 404) {
            throw new Error("LockerPhycer workspace authorization denied");
          }
          if (!ownerResponse.ok) throw new Error(`LockerPhycer workspace authorization returned HTTP ${ownerResponse.status}`);
          const ownerProof = (await ownerResponse.json()) as { authorized?: boolean; workspace_id?: string };
          if (ownerProof.authorized !== true || ownerProof.workspace_id !== authorizedWorkspaceId) {
            throw new Error("LockerPhycer workspace authorization denied");
          }

          let mfaVerified = false;
          if (context.requireMfa && context.mfaCode?.trim()) {
            const mfaResponse = await fetch(`${lockerPhycerBaseUrl}/api/v1/auth/mfa/verify`, {
              method: "POST",
              headers: { authorization: `Bearer ${token}`, accept: "application/json", "content-type": "application/json" },
              body: JSON.stringify({ code: context.mfaCode.trim() }),
              signal: AbortSignal.timeout(5_000),
            });
            if (mfaResponse.status !== 401 && mfaResponse.status !== 403) {
              if (!mfaResponse.ok) throw new Error(`LockerPhycer MFA verification returned HTTP ${mfaResponse.status}`);
              const result = (await mfaResponse.json()) as { verified?: boolean };
              mfaVerified = result.verified === true;
            }
          }
          return {
            ...(identity.id ? { userId: identity.id } : {}),
            ...(identity.email ? { email: identity.email } : {}),
            workspaceId,
            mfaVerified,
          };
        }
      : undefined);

  app.disable("x-powered-by");
  if (trustedProxyCidrs.length) app.set("trust proxy", trustedProxyCidrs);
  app.use((req: Request, res: Response, next: NextFunction) => {
    const allowedOrigin = process.env.VLINK_CORS_ORIGIN || "*";
    res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization,X-VLink-Id,X-Target-Url,X-VLink-Device-Proof");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    if (req.method === "OPTIONS") return res.status(204).end();
    next();
  });

  app.use((req: Request, res: Response, next: NextFunction) => {
    if (!enableAnonymousBootstrap || req.method !== "POST") return next();
    const rawPath = req.originalUrl.split("?", 1)[0] || "";
    let decodedPath = rawPath;
    try {
      decodedPath = decodeURIComponent(rawPath);
    } catch {
      // Malformed paths are left to Express routing and cannot change the peer identity used below.
    }
    const isBootstrapPath = [rawPath, decodedPath].some((pathname) =>
      pathname === "/api/v1/device/bootstrap" || pathname === "/api/v1/device/bootstrap/",
    );
    if (!isBootstrapPath) return next();

    const peerAddress = (req.ip || req.socket.remoteAddress || "unknown").trim().toLowerCase();
    const sourceFingerprint = createHmac("sha256", bootstrapRateLimitKey)
      .update("vlink-anonymous-bootstrap-source/v1\0", "utf8")
      .update(peerAddress, "utf8")
      .digest("hex");
    try {
      const admission = registry.consumeDeviceBootstrapAdmission(sourceFingerprint, bootstrapAdmissionPolicy);
      if (!admission.allowed) {
        res.setHeader("Retry-After", String(admission.retryAfterSeconds));
        return res.status(429).json({ error: "device_bootstrap_rate_limited", retryAfterSeconds: admission.retryAfterSeconds });
      }
      return next();
    } catch {
      return res.status(503).json({ error: "device_bootstrap_admission_unavailable" });
    }
  });

  app.use(express.json({ limit: "2mb", verify: captureVLinkRequestBodyHash }));
  app.use(express.urlencoded({ extended: true, limit: "2mb", verify: captureVLinkRequestBodyHash }));

  const resolveVLinkBinding = (req: Request, res: Response, forcedVLinkId?: string): string | undefined | null => {
    const suppliedVLinkId = getBoundVLinkId(req);
    if (forcedVLinkId && suppliedVLinkId && suppliedVLinkId !== forcedVLinkId) {
      res.status(400).json({
        error: "vlink_binding_conflict",
        message: "The VLink ID in the connection URL does not match the supplied header/query binding.",
      });
      return null;
    }

    const vlinkId = forcedVLinkId || suppliedVLinkId;
    if (!vlinkId) return undefined;
    if (!registry.get(vlinkId)) {
      res.status(forcedVLinkId ? 404 : 400).json({
        error: "invalid_vlink_id",
        message: "The supplied VLink ID does not exist.",
      });
      return null;
    }
    return vlinkId;
  };

  const requireEnrollmentGrant = (req: Request, res: Response, vlinkId: string) => {
    const token = getBearerToken(req);
    if (!token || !token.startsWith("vle_")) {
      res.setHeader("WWW-Authenticate", 'Bearer realm="VLink enrollment"');
      res.status(401).json({ error: "enrollment_grant_required" });
      return null;
    }
    const grant = registry.authenticateEnrollment(vlinkId, token);
    if (!grant) {
      res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
      res.status(401).json({ error: "invalid_or_expired_enrollment_grant" });
      return null;
    }
    return grant;
  };

  const requireAccess = (req: Request, res: Response, vlinkId: string): VLinkAccessCredentialSummary | null => {
    const token = getBearerToken(req);
    if (!token || !token.startsWith("vlt_")) {
      res.setHeader("WWW-Authenticate", 'Bearer realm="VLink"');
      res.status(401).json({ error: "vlink_access_token_required" });
      return null;
    }
    const credential = authenticateVLinkRequest(registry, req, vlinkId, token);
    if (!credential) {
      res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
      res.status(401).json({ error: "invalid_or_expired_vlink_access_token" });
      return null;
    }
    return credential;
  };

  const requireBoundOrCompatibility = (req: Request, res: Response, forcedVLinkId?: string) => {
    const bound = resolveVLinkBinding(req, res, forcedVLinkId);
    if (bound === null) return null;
    if (!bound && !allowUnboundCompatibility) {
      res.status(400).json({
        error: "vlink_required",
        message: "Use a VLink-specific base URL or supply X-VLink-Id. Unbound compatibility is disabled by default.",
      });
      return null;
    }
    return bound;
  };

  app.get("/api/health", (_req, res) => {
    res.json({
      status: "online",
      service: "VLink",
      version: "0.2.0",
      geminiConfigured: Boolean(process.env.GEMINI_API_KEY),
      demoResponsesEnabled: enableDemoResponses,
      unboundCompatibilityEnabled: allowUnboundCompatibility,
      unauthenticatedCreateEnabled: allowUnauthenticatedCreate,
      anonymousBootstrapEnabled: enableAnonymousBootstrap,
      workspaceAuthConfigured: Boolean(workspaceAuthenticator),
      persistence: registry.persistenceMode ?? "unknown",
      leaseSealing: Boolean(leaseSealer),
      capiConfigured: Boolean(process.env.VLINK_CAPI_BASE_URL?.trim()),
      timestamp: new Date().toISOString(),
    });
  });

  app.post("/api/v1/vlinks", async (req, res) => {
    let { workspaceId, environment, displayName, sourceType, expiresAt } = req.body ?? {};

    if (!allowUnauthenticatedCreate) {
      const token = getBearerToken(req);
      if (!token) {
        res.setHeader("WWW-Authenticate", 'Bearer realm="Veklom workspace"');
        return res.status(401).json({
          error: "workspace_auth_required",
          message: "Authenticate with a LockerPhycer workspace-bound session before creating a VLink.",
        });
      }
      if (!workspaceAuthenticator) {
        return res.status(503).json({
          error: "workspace_auth_unconfigured",
          message: "VLink cannot validate LockerPhycer workspace identity on this deployment.",
        });
      }

      let identity: VLinkWorkspaceIdentity | undefined;
      try {
        identity = await workspaceAuthenticator(token);
      } catch (error) {
        const message = error instanceof Error ? error.message : "workspace authentication unavailable";
        if (message.includes("workspace authorization denied")) {
          return res.status(403).json({ error: "workspace_access_denied" });
        }
        if (message.includes("not bound to a workspace")) {
          return res.status(409).json({
            error: "workspace_binding_required",
            message: "The authenticated LockerPhycer session must be bound to a workspace before VLink creation.",
          });
        }
        return res.status(502).json({
          error: "workspace_auth_unavailable",
          message: "VLink could not validate the LockerPhycer session.",
        });
      }
      if (!identity) {
        res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
        return res.status(401).json({ error: "invalid_workspace_session" });
      }

      // The authenticated identity is authoritative. Never trust a caller-supplied
      // workspaceId over the workspace bound into the LockerPhycer session.
      workspaceId = identity.workspaceId;
    }

    if (!workspaceId || !environment || !displayName || !SOURCE_TYPES.has(sourceType)) {
      return res.status(400).json({
        error: "invalid_vlink_request",
        required: ["workspaceId", "environment", "displayName", "sourceType"],
        allowedSourceTypes: Array.from(SOURCE_TYPES),
      });
    }
    if (expiresAt && Number.isNaN(Date.parse(expiresAt))) {
      return res.status(400).json({ error: "invalid_expires_at" });
    }

    const vlink = registry.create(
      { workspaceId, environment, displayName, sourceType, ...(expiresAt ? { expiresAt } : {}) },
      originFor(req, options.publicOrigin),
    );
    const enrollmentGrant = registry.issueEnrollmentGrant(vlink.vlinkId, enrollmentGrantTtlSeconds);
    res.setHeader("Cache-Control", "no-store");
    res.status(201).json({
      vlink,
      enrollmentGrant,
      manifestUrl: `/api/v1/vlinks/${vlink.vlinkId}/manifest`,
    });
  });

  app.get("/api/v1/vlinks", (_req, res) => {
    res.json({ total: registry.list().length, vlinks: registry.list() });
  });

  app.get("/api/v1/vlinks/:vlinkId", (req, res) => {
    const vlink = registry.get(req.params.vlinkId);
    if (!vlink) return res.status(404).json({ error: "vlink_not_found" });
    res.json({ vlink });
  });

  app.get("/api/v1/vlinks/:vlinkId/manifest", (req, res) => {
    const manifest = registry.manifest(req.params.vlinkId);
    if (!manifest) return res.status(404).json({ error: "vlink_not_found" });
    res.json(safeManifestJson(manifest));
  });

  app.get("/.well-known/vlink.json", (req, res) => {
    const requestedId = typeof req.query.vlinkId === "string" ? req.query.vlinkId : undefined;
    if (requestedId) {
      const manifest = registry.manifest(requestedId);
      if (!manifest) return res.status(404).json({ error: "vlink_not_found" });
      return res.json(safeManifestJson(manifest));
    }
    res.json({
      version: "1.0",
      protocol: "vlink/v1",
      service: "VLink",
      createVLink: `${originFor(req, options.publicOrigin)}/api/v1/vlinks`,
      discovery: `${originFor(req, options.publicOrigin)}/.well-known/vlink.json?vlinkId=<vlk_...>`,
      managementAuth: {
        scheme: "bearer",
        authority: "LockerPhycer",
        login: "https://veklom.com/login",
        workspaceBootstrap: "https://veklom.com/os/onboarding",
        authenticatedConnect: "https://veklom.com/vlink/connect/",
      },
      note: "Discovery is secret-free. Production VLink creation requires a LockerPhycer workspace-bound session; VLink connection identity is not consequence authority.",
    });
  });

  app.post("/api/v1/vlinks/:vlinkId/pairing", (req, res) => {
    if (!registry.get(req.params.vlinkId)) return res.status(404).json({ error: "vlink_not_found" });
    if (!requireEnrollmentGrant(req, res, req.params.vlinkId)) return;

    const ttlSeconds = clampSeconds(Number(req.body?.ttlSeconds ?? 600), 600, 900);
    const pairing = registry.createPairing(
      req.params.vlinkId,
      originFor(req, options.pairingOrigin || process.env.VLINK_PAIRING_ORIGIN || options.publicOrigin),
      ttlSeconds,
    );
    if (!pairing) return res.status(404).json({ error: "vlink_not_found" });
    res.setHeader("Cache-Control", "no-store");
    res.status(201).json({ pairing });
  });

  app.post("/api/v1/device/bootstrap", (req, res) => {
    if (!enableAnonymousBootstrap) return res.status(404).json({ error: "anonymous_bootstrap_disabled" });
    const publicKeyPem = req.body?.publicKeyPem;
    if (typeof publicKeyPem !== "string" || Buffer.byteLength(publicKeyPem, "utf8") > 2_048) {
      return res.status(400).json({ error: "invalid_device_public_key" });
    }
    const input = {
      displayName: typeof req.body?.displayName === "string" ? req.body.displayName : "",
      environment: typeof req.body?.environment === "string" ? req.body.environment : "",
      sourceType: req.body?.sourceType as VLinkSourceType,
    };
    if (!input.displayName.trim() || input.displayName.trim().length > 120 ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/.test(input.environment.trim()) || !SOURCE_TYPES.has(input.sourceType)) {
      return res.status(400).json({ error: "invalid_device_bootstrap_request" });
    }
    const created = registry.createDeviceBootstrap(
      originFor(req, options.pairingOrigin || process.env.VLINK_PAIRING_ORIGIN || options.publicOrigin),
      publicKeyPem,
      input,
      clampSeconds(Number(req.body?.ttlSeconds ?? 600), 600, 900),
    );
    if (!created) return res.status(503).json({ error: "device_bootstrap_capacity_or_key_error" });
    res.setHeader("Cache-Control", "no-store");
    return res.status(201).json({ ...created, consequenceAuthority: "none" });
  });

  app.get("/api/v1/device/bootstrap/:pairingId", (req, res) => {
    const bootstrap = registry.getDeviceBootstrap(req.params.pairingId);
    if (!bootstrap) return res.status(404).json({ error: "device_bootstrap_not_found" });
    res.setHeader("Cache-Control", "no-store");
    return res.json({ bootstrap, consequenceAuthority: "none" });
  });

  app.post("/api/v1/device/bootstrap/:pairingId/proof", (req, res) => {
    const bootstrap = registry.verifyUnboundDeviceProof(
      req.params.pairingId,
      String(req.body?.nonce ?? ""),
      String(req.body?.signature ?? ""),
    );
    if (!bootstrap) {
      const current = registry.getDeviceBootstrap(req.params.pairingId);
      if (!current) return res.status(404).json({ error: "device_bootstrap_not_found" });
      if (current.status === "expired") return res.status(410).json({ error: "device_bootstrap_expired" });
      return res.status(400).json({ error: "invalid_device_proof" });
    }
    res.setHeader("Cache-Control", "no-store");
    return res.json({ bootstrap, consequenceAuthority: "none" });
  });

  app.post("/api/v1/device/bootstrap/:pairingId/approve", async (req, res) => {
    const current = registry.getDeviceBootstrap(req.params.pairingId);
    if (!current) return res.status(404).json({ error: "device_bootstrap_not_found" });
    if (current.status === "expired") return res.status(410).json({ error: "device_bootstrap_expired" });
    if (current.status === "pending" && !current.deviceProofVerified) {
      return res.status(409).json({ error: "device_proof_required" });
    }
    const token = getBearerToken(req);
    if (!token || token.startsWith("vle_") || token.startsWith("vlt_")) {
      res.setHeader("WWW-Authenticate", 'Bearer realm="VLink workspace approval"');
      return res.status(401).json({ error: "workspace_session_required" });
    }
    if (!workspaceAuthenticator) return res.status(503).json({ error: "workspace_authority_unconfigured" });

    const mfaCode = String(req.body?.mfaCode ?? "").trim();
    if (!mfaCode) return res.status(403).json({ error: "mfa_required" });

    let identity: VLinkWorkspaceIdentity | undefined;
    try {
      identity = await workspaceAuthenticator(token, {
        ...(current.vlinkId ? { workspaceId: registry.get(current.vlinkId)?.workspaceId } : {}),
        requireMfa: true,
        mfaCode,
      });
    } catch (error) {
      if (error instanceof Error && error.message.includes("workspace authorization denied")) {
        return res.status(403).json({ error: "workspace_access_denied" });
      }
      return res.status(503).json({ error: "workspace_authority_unavailable" });
    }
    if (!identity) return res.status(401).json({ error: "invalid_workspace_session" });
    if (current.vlinkId) {
      const existing = registry.get(current.vlinkId);
      if (!existing || identity.workspaceId !== existing.workspaceId) return res.status(403).json({ error: "workspace_access_denied" });
    }
    if (!identity.mfaVerified) return res.status(403).json({ error: "mfa_required" });
    if (!leaseSealer) return res.status(503).json({ error: "enrollment_grant_recovery_unavailable" });

    const approved = registry.approveDeviceBootstrap(
      req.params.pairingId,
      identity.workspaceId,
      originFor(req, options.pairingOrigin || process.env.VLINK_PAIRING_ORIGIN || options.publicOrigin),
      enrollmentGrantTtlSeconds,
    );
    if (!approved) {
      const latest = registry.getDeviceBootstrap(req.params.pairingId);
      if (latest?.status === "expired") return res.status(410).json({ error: "device_bootstrap_expired" });
      return res.status(409).json({ error: "device_bootstrap_not_approvable" });
    }
    res.setHeader("Cache-Control", "no-store");
    return res.json({ ...approved, consequenceAuthority: "none" });
  });

  app.post("/api/v1/vlinks/:vlinkId/device-pairings", (req, res) => {
    if (!registry.get(req.params.vlinkId)) return res.status(404).json({ error: "vlink_not_found" });
    const publicKeyPem = req.body?.publicKeyPem;
    if (typeof publicKeyPem !== "string" || Buffer.byteLength(publicKeyPem, "utf8") > 2_048) {
      return res.status(400).json({ error: "invalid_device_public_key" });
    }
    const ttlSeconds = clampSeconds(Number(req.body?.ttlSeconds ?? 600), 600, 900);
    const created = registry.createDevicePairing(
      req.params.vlinkId,
      originFor(req, options.pairingOrigin || process.env.VLINK_PAIRING_ORIGIN || options.publicOrigin),
      publicKeyPem,
      ttlSeconds,
    );
    if (!created) return res.status(400).json({ error: "invalid_device_public_key" });
    res.setHeader("Cache-Control", "no-store");
    return res.status(201).json({ ...created, consequenceAuthority: "none" });
  });

  app.post("/api/v1/vlinks/:vlinkId/pairing/:pairingId/device-proof", (req, res) => {
    const pairing = registry.verifyDevicePairingProof(
      req.params.vlinkId,
      req.params.pairingId,
      String(req.body?.nonce ?? ""),
      String(req.body?.signature ?? ""),
    );
    if (!pairing) {
      const current = registry.getPairingStatus(req.params.vlinkId, req.params.pairingId);
      if (!current) return res.status(404).json({ error: "pairing_not_found" });
      if (current.status === "expired") return res.status(410).json({ error: "pairing_expired" });
      return res.status(400).json({ error: "invalid_device_proof" });
    }
    res.setHeader("Cache-Control", "no-store");
    return res.json({ pairing });
  });

  app.get("/api/v1/vlinks/:vlinkId/pairing/:pairingId", (req, res) => {
    const pairing = registry.getPairingStatus(req.params.vlinkId, req.params.pairingId);
    if (!pairing) return res.status(404).json({ error: "pairing_not_found" });
    res.setHeader("Cache-Control", "no-store");
    res.json({ pairing });
  });

  const approvePairing = async (req: Request, res: Response) => {
    const vlink = registry.get(req.params.vlinkId);
    if (!vlink) return res.status(404).json({ error: "vlink_not_found" });
    const token = getBearerToken(req);
    if (!token || token.startsWith("vle_") || token.startsWith("vlt_")) {
      res.setHeader("WWW-Authenticate", 'Bearer realm="VLink workspace approval"');
      return res.status(401).json({ error: "workspace_session_required" });
    }

    const current = registry.getPairingStatus(req.params.vlinkId, req.params.pairingId);
    if (!current) return res.status(404).json({ error: "pairing_not_found" });
    if (current.deviceKeyThumbprint && current.deviceProofVerified !== true) {
      return res.status(409).json({ error: "device_proof_required" });
    }

    if (!workspaceAuthenticator) return res.status(503).json({ error: "workspace_authority_unconfigured" });
    const mfaCode = String(req.body?.mfaCode ?? "").trim();
    if (!mfaCode) return res.status(403).json({ error: "mfa_required" });

    let identity: VLinkWorkspaceIdentity | undefined;
    try {
      identity = await workspaceAuthenticator(token, {
        workspaceId: vlink.workspaceId,
        requireMfa: true,
        mfaCode,
      });
    } catch (error) {
      if (error instanceof Error && error.message.includes("workspace authorization denied")) {
        return res.status(403).json({ error: "workspace_access_denied" });
      }
      return res.status(503).json({ error: "workspace_authority_unavailable" });
    }
    if (!identity) return res.status(401).json({ error: "invalid_workspace_session" });
    if (identity.workspaceId !== vlink.workspaceId) {
      return res.status(403).json({ error: "workspace_access_denied" });
    }
    if (identity.mfaVerified !== true) return res.status(403).json({ error: "mfa_required" });

    const approvalCode = String(req.body?.approvalCode ?? req.body?.oneTimeCode ?? "");
    const approved = registry.approvePairing(req.params.vlinkId, req.params.pairingId, approvalCode);
    if (!approved) {
      const current = registry.getPairingStatus(req.params.vlinkId, req.params.pairingId);
      if (current?.status === "expired") return res.status(410).json({ error: "pairing_expired" });
      if (current?.status === "approved" || current?.status === "exchanged") {
        return res.status(400).json({ error: "pairing_approval_already_used" });
      }
      return res.status(400).json({ error: "invalid_pairing_approval" });
    }
    res.setHeader("Cache-Control", "no-store");
    return res.json({ pairing: approved, vlink: registry.get(req.params.vlinkId) });
  };

  app.post("/api/v1/vlinks/:vlinkId/pairing/:pairingId/approve", approvePairing);
  app.post("/api/v1/vlinks/:vlinkId/pairing/:pairingId/complete", approvePairing);

  app.post("/api/v1/vlinks/:vlinkId/pairing/:pairingId/exchange-challenge", (req, res) => {
    if (!leaseSealer) return res.status(503).json({ error: "recoverable_exchange_unavailable" });
    const current = registry.getPairingStatus(req.params.vlinkId, req.params.pairingId);
    if (!current) return res.status(404).json({ error: "pairing_not_found" });
    if (current.status === "expired") return res.status(410).json({ error: "pairing_expired" });
    if (current.status === "pending") return res.status(409).json({ error: "pairing_not_approved" });
    if (!current.deviceKeyThumbprint) return res.status(409).json({ error: "device_key_binding_required" });
    const challenge = registry.issueDeviceExchangeChallenge(req.params.vlinkId, req.params.pairingId);
    if (!challenge) return res.status(409).json({ error: "pairing_not_recoverable" });
    res.setHeader("Cache-Control", "no-store");
    return res.json({ challenge });
  });

  app.post("/api/v1/vlinks/:vlinkId/pairing/:pairingId/exchange", (req, res) => {
    const current = registry.getPairingStatus(req.params.vlinkId, req.params.pairingId);
    if (!current) return res.status(404).json({ error: "pairing_not_found" });
    if (current.status === "expired") return res.status(410).json({ error: "pairing_expired" });
    if (current.status === "pending") return res.status(409).json({ error: "pairing_not_approved" });

    if (current.deviceKeyThumbprint) {
      if (!leaseSealer) return res.status(503).json({ error: "recoverable_exchange_unavailable" });
      const credential = registry.exchangeDevicePairing(
        req.params.vlinkId,
        req.params.pairingId,
        String(req.body?.nonce ?? ""),
        String(req.body?.signature ?? ""),
        accessTokenTtlSeconds,
      );
      if (!credential) return res.status(400).json({ error: "invalid_device_proof_or_exchange" });
      res.setHeader("Cache-Control", "no-store");
      return res.json({ credential, pairing: registry.getPairingStatus(req.params.vlinkId, req.params.pairingId) });
    }

    if (current.status === "exchanged") return res.status(400).json({ error: "pairing_already_exchanged" });
    const deviceCode = String(req.body?.deviceCode ?? "");

    const credential = registry.exchangePairing(
      req.params.vlinkId,
      req.params.pairingId,
      deviceCode,
      accessTokenTtlSeconds,
    );
    if (!credential) return res.status(400).json({ error: "invalid_device_code" });
    res.setHeader("Cache-Control", "no-store");
    res.json({ credential, pairing: registry.getPairingStatus(req.params.vlinkId, req.params.pairingId) });
  });

  const leaseActivity = (
    vlinkId: string,
    vlink: NonNullable<ReturnType<VLinkRegistry["get"]>>,
    route: string,
    method: string,
    status: "completed" | "failed",
    metadata: Record<string, unknown>,
  ) =>
    registry.addActivity({
      vlinkId,
      sourceType: vlink.sourceType,
      route,
      method,
      mode: vlink.mode,
      status,
      latencyMs: 0,
      backend: "cappo-interlink",
      metadata,
    });

  const requireLeaseHuman = (req: Request, res: Response, vlinkId: string) => {
    const token = getBearerToken(req);
    if (!token || !token.startsWith("vle_")) {
      res.setHeader("WWW-Authenticate", 'Bearer realm="VLink enrollment"');
      res.status(401).json({ error: "enrollment_grant_required" });
      return false;
    }
    if (!registry.authenticateEnrollment(vlinkId, token)) {
      res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
      res.status(401).json({ error: "invalid_or_expired_enrollment_grant" });
      return false;
    }
    return true;
  };

  const requireLeaseEither = (req: Request, res: Response, vlinkId: string) => {
    const token = getBearerToken(req);
    if (token?.startsWith("vle_")) {
      if (registry.authenticateEnrollment(vlinkId, token)) return true;
      res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
      res.status(401).json({ error: "invalid_or_expired_enrollment_grant" });
      return false;
    }
    if (token?.startsWith("vlt_")) {
      if (authenticateVLinkRequest(registry, req, vlinkId, token)) return true;
      res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
      res.status(401).json({ error: "invalid_or_expired_vlink_access_token" });
      return false;
    }
    res.setHeader("WWW-Authenticate", 'Bearer realm="VLink"');
    res.status(401).json({ error: "vlink_credential_required" });
    return false;
  };

  const relayBody = (body: unknown): Record<string, unknown> =>
    typeof body === "object" && body !== null ? (body as Record<string, unknown>) : {};

  const applyHolderStatus = (vlinkId: string, leaseId: string, result: cappoRelay.RelayResult) => {
    const body = relayBody(result.body);
    if (result.status !== 401) return;
    if (body.error === "HOLDER_CREDENTIAL_REVOKED") registry.updateLease(vlinkId, leaseId, { status: "terminated" });
    if (body.error === "HOLDER_CREDENTIAL_EXPIRED") registry.updateLease(vlinkId, leaseId, { status: "expired" });
  };

  app.post("/api/v1/vlinks/:vlinkId/leases", (req, res) => {
    const vlink = registry.get(req.params.vlinkId);
    if (!vlink) return res.status(404).json({ error: "vlink_not_found" });
    if (!requireEnrollmentGrant(req, res, vlink.vlinkId)) return;
    if (!leaseSealer) return res.status(503).json({ error: "lease_sealing_unconfigured" });

    const body = req.body ?? {};
    const required = ["mountId", "tokenId", "nonce", "holderCredential", "packageRef", "workspace", "project", "targetRef", "expiresAt"];
    const actionScope = (value: unknown): value is string[] =>
      Array.isArray(value) && value.every((action) => typeof action === "string" && action.trim().length > 0);
    if (
      required.some((field) => typeof body[field] !== "string" || !body[field].trim()) ||
      !actionScope(body.allowedActions) ||
      !actionScope(body.blockedActions)
    ) {
      return res.status(400).json({ error: "invalid_lease_request" });
    }
    if (!body.holderCredential.startsWith(`vlm_${body.mountId}.`) || Number.isNaN(Date.parse(body.expiresAt))) {
      return res.status(400).json({ error: "invalid_lease_request" });
    }
    const lease = registry.bindLease(vlink.vlinkId, body);
    if (!lease) return res.status(503).json({ error: "lease_sealing_unconfigured" });
    res.status(201).json({ lease });
  });

  app.get("/api/v1/vlinks/:vlinkId/leases", (req, res) => {
    if (!registry.get(req.params.vlinkId)) return res.status(404).json({ error: "vlink_not_found" });
    if (!requireLeaseHuman(req, res, req.params.vlinkId)) return;
    res.json({ leases: registry.listLeases(req.params.vlinkId) });
  });

  app.get("/api/v1/vlinks/:vlinkId/leases/:leaseId", (req, res) => {
    if (!registry.get(req.params.vlinkId)) return res.status(404).json({ error: "vlink_not_found" });
    if (!requireLeaseEither(req, res, req.params.vlinkId)) return;
    const lease = registry.getLease(req.params.vlinkId, req.params.leaseId);
    if (!lease) return res.status(404).json({ error: "lease_not_found" });
    res.json({ lease });
  });

  app.post("/api/v1/vlinks/:vlinkId/leases/:leaseId/revoke", async (req, res) => {
    const vlink = registry.get(req.params.vlinkId);
    if (!vlink) return res.status(404).json({ error: "vlink_not_found" });
    if (!requireLeaseHuman(req, res, vlink.vlinkId)) return;
    const lease = registry.getLease(vlink.vlinkId, req.params.leaseId);
    const secret = registry.leaseSecret(vlink.vlinkId, req.params.leaseId);
    if (!lease || !secret) return res.status(404).json({ error: "lease_not_found" });
    const cappo = await cappoRelay.terminate(lease.mountId, secret.holderCredential, {
      token_id: secret.tokenId,
      nonce: secret.nonce,
    });
    const cappoBody = relayBody(cappo.body);
    const alreadyRevoked = cappo.status === 401 && cappoBody.error === "HOLDER_CREDENTIAL_REVOKED";
    if ((cappo.status >= 200 && cappo.status < 300) || alreadyRevoked) {
      const updated = registry.updateLease(vlink.vlinkId, lease.leaseId, { status: "terminated" })!;
      leaseActivity(vlink.vlinkId, vlink, "/api/v1/vlinks/:vlinkId/leases/:leaseId/revoke", "POST", "completed", {
        cappoStatus: cappo.status,
        cappoDecision: cappoBody.decision ?? null,
      });
      return res.json({ lease: updated, cappo });
    }
    applyHolderStatus(vlink.vlinkId, lease.leaseId, cappo);
    const updated = registry.getLease(vlink.vlinkId, lease.leaseId)!;
    leaseActivity(vlink.vlinkId, vlink, "/api/v1/vlinks/:vlinkId/leases/:leaseId/revoke", "POST", "failed", {
      cappoStatus: cappo.status,
      cappoDecision: cappoBody.decision ?? null,
    });
    res.status(cappo.status).json({ lease: updated, cappo });
  });

  app.post("/api/v1/vlinks/:vlinkId/leases/:leaseId/actions", async (req, res) => {
    const vlink = registry.get(req.params.vlinkId);
    if (!vlink) return res.status(404).json({ error: "vlink_not_found" });
    if (!requireAccess(req, res, vlink.vlinkId)) return;
    const lease = registry.getLease(vlink.vlinkId, req.params.leaseId);
    const secret = registry.leaseSecret(vlink.vlinkId, req.params.leaseId);
    if (!lease || !secret) return res.status(404).json({ error: "lease_not_found" });
    if (typeof req.body?.action !== "string" || typeof req.body?.resource !== "string") {
      return res.status(400).json({ error: "invalid_action_request" });
    }
    const cappo = await cappoRelay.evaluateAction(lease.mountId, secret.holderCredential, {
      token_id: secret.tokenId,
      nonce: secret.nonce,
      action: req.body.action,
      resource: req.body.resource,
    });
    const body = relayBody(cappo.body);
    if (body.decision === "allow" || body.decision === "deny") {
      registry.updateLease(vlink.vlinkId, lease.leaseId, {
        lastDecision: {
          action: req.body.action,
          decision: body.decision,
          reason: typeof body.reason === "string" ? body.reason : "",
          at: new Date().toISOString(),
        },
      });
    }
    applyHolderStatus(vlink.vlinkId, lease.leaseId, cappo);
    const updated = registry.getLease(vlink.vlinkId, lease.leaseId)!;
    leaseActivity(vlink.vlinkId, vlink, "/api/v1/vlinks/:vlinkId/leases/:leaseId/actions", "POST", cappo.status >= 200 && cappo.status < 300 ? "completed" : "failed", {
      cappoDecision: body.decision ?? null,
    });
    res.status(cappo.status).json({ lease: updated, cappo });
  });

  app.post("/api/v1/vlinks/:vlinkId/leases/:leaseId/execute", async (req, res) => {
    const vlink = registry.get(req.params.vlinkId);
    if (!vlink) return res.status(404).json({ error: "vlink_not_found" });
    if (!requireAccess(req, res, vlink.vlinkId)) return;
    const lease = registry.getLease(vlink.vlinkId, req.params.leaseId);
    const secret = registry.leaseSecret(vlink.vlinkId, req.params.leaseId);
    if (!lease || !secret) return res.status(404).json({ error: "lease_not_found" });
    if (typeof req.body?.action !== "string" || typeof req.body?.resource !== "string") {
      return res.status(400).json({ error: "invalid_execute_request" });
    }
    const cappo = await cappoRelay.execute(lease.mountId, secret.holderCredential, {
      token_id: secret.tokenId,
      nonce: secret.nonce,
      action: req.body.action,
      target_ref: lease.targetRef,
      resource: req.body.resource,
      arguments: req.body.arguments,
      ...(typeof req.body.operation_id === "string" ? { operation_id: req.body.operation_id } : {}),
    });
    const body = relayBody(cappo.body);
    const decision = body.decision;
    const patch =
      decision === "allow" || decision === "deny"
        ? {
            lastDecision: {
              action: req.body.action,
              decision,
              reason: typeof body.reason === "string" ? body.reason : "",
              at: new Date().toISOString(),
            },
            ...(decision === "allow" ? { status: "terminated" as const } : {}),
          }
        : {};
    if (Object.keys(patch).length > 0) registry.updateLease(vlink.vlinkId, lease.leaseId, patch);
    applyHolderStatus(vlink.vlinkId, lease.leaseId, cappo);
    const updated = registry.getLease(vlink.vlinkId, lease.leaseId)!;
    leaseActivity(vlink.vlinkId, vlink, "/api/v1/vlinks/:vlinkId/leases/:leaseId/execute", "POST", cappo.status >= 200 && cappo.status < 300 ? "completed" : "failed", {
      cappoDecision: decision ?? null,
      anchoring: body.anchoring ?? null,
      receiptContentHash: relayBody(body.receipt).content_hash ?? null,
      evidenceType: "cappo-governed-consequence",
    });
    res.status(cappo.status).json({ lease: updated, cappo });
  });

  app.get("/api/v1/vlinks/:vlinkId/leases/:leaseId/state", async (req, res) => {
    const vlink = registry.get(req.params.vlinkId);
    if (!vlink) return res.status(404).json({ error: "vlink_not_found" });
    const credential = requireAccess(req, res, vlink.vlinkId);
    if (!credential) return;
    const lease = registry.getLease(vlink.vlinkId, req.params.leaseId);
    const secret = registry.leaseSecret(vlink.vlinkId, req.params.leaseId);
    if (!lease || !secret) return res.status(404).json({ error: "lease_not_found" });
    const resource = typeof req.query.resource === "string" ? req.query.resource : "";
    if (!resource) return res.status(400).json({ error: "resource_required" });
    const cappo = await cappoRelay.readState(lease.mountId, secret.holderCredential, lease.targetRef, resource);
    applyHolderStatus(vlink.vlinkId, lease.leaseId, cappo);
    const updated = registry.getLease(vlink.vlinkId, lease.leaseId)!;
    res.status(cappo.status).json({ lease: updated, cappo });
  });

  app.post("/api/v1/vlinks/:vlinkId/access-test", (req, res) => {
    const vlink = registry.get(req.params.vlinkId);
    if (!vlink) return res.status(404).json({ error: "vlink_not_found" });
    const credential = requireAccess(req, res, vlink.vlinkId);
    if (!credential) return;
    const started = performance.now();
    const event = registry.addActivity({
      vlinkId: vlink.vlinkId,
      sourceType: vlink.sourceType,
      route: "/api/v1/vlinks/:vlinkId/access-test",
      method: "POST",
      mode: vlink.mode,
      status: "completed",
      latencyMs: Math.max(0, Math.round(performance.now() - started)),
      backend: "vlink-access",
      metadata: {
        evidenceType: "authenticated-request-response-metadata",
        cryptographicReceipt: false,
        credentialId: credential.credentialId,
        tokenStoredInActivity: false,
      },
    });
    res.json({ ok: true, credential, event });
  });

  app.post("/api/v1/vlinks/:vlinkId/access/revoke", (req, res) => {
    const credential = requireAccess(req, res, req.params.vlinkId);
    if (!credential) return;
    const revoked = registry.revokeCredential(req.params.vlinkId, credential.credentialId);
    res.json({ revoked });
  });

  app.post("/api/v1/vlinks/:vlinkId/test", (req, res) => {
    const vlink = registry.get(req.params.vlinkId);
    if (!vlink) return res.status(404).json({ error: "vlink_not_found" });
    const credential = requireAccess(req, res, vlink.vlinkId);
    if (!credential) return;
    const started = performance.now();
    const event = registry.addActivity({
      vlinkId: vlink.vlinkId,
      sourceType: vlink.sourceType,
      route: "/api/v1/vlinks/:vlinkId/test",
      method: "POST",
      mode: vlink.mode,
      status: "completed",
      latencyMs: Math.max(0, Math.round(performance.now() - started)),
      backend: "vlink-registry",
      metadata: {
        evidenceType: "authenticated-request-response-metadata",
        cryptographicReceipt: false,
        credentialId: credential.credentialId,
        message: "Authenticated connection test received and bound to an existing VLink.",
      },
    });
    res.json({ ok: true, event });
  });

  app.get("/api/v1/vlinks/:vlinkId/activity", (req, res) => {
    if (!registry.get(req.params.vlinkId)) return res.status(404).json({ error: "vlink_not_found" });
    if (!requireAccess(req, res, req.params.vlinkId)) return;
    res.json({ vlinkId: req.params.vlinkId, events: registry.activity(req.params.vlinkId) });
  });

  app.post("/api/v1/vlinks/:vlinkId/webhook", (req, res) => {
    const vlink = registry.get(req.params.vlinkId);
    if (!vlink) return res.status(404).json({ error: "vlink_not_found" });
    const credential = requireAccess(req, res, vlink.vlinkId);
    if (!credential) return;
    const started = performance.now();
    const event = registry.addActivity({
      vlinkId: vlink.vlinkId,
      sourceType: vlink.sourceType,
      route: "/api/v1/vlinks/:vlinkId/webhook",
      method: "POST",
      mode: vlink.mode,
      status: "accepted",
      latencyMs: Math.max(0, Math.round(performance.now() - started)),
      backend: "webhook-ingress",
      metadata: {
        credentialId: credential.credentialId,
        contentType: req.header("content-type") ?? null,
        payloadBytes: Buffer.byteLength(JSON.stringify(req.body ?? {})),
        bodyStored: false,
      },
    });
    res.status(202).json({ accepted: true, eventId: event.eventId, vlinkId: vlink.vlinkId });
  });

  app.post("/api/v1/webhooks/:connectorId", (req, res) => {
    const bound = requireBoundOrCompatibility(req, res);
    if (bound === null) return;
    let eventId: string | undefined;
    if (bound) {
      const credential = requireAccess(req, res, bound);
      if (!credential) return;
      const vlink = registry.get(bound)!;
      const event = registry.addActivity({
        vlinkId: bound,
        sourceType: vlink.sourceType,
        route: `/api/v1/webhooks/${req.params.connectorId}`,
        method: "POST",
        mode: vlink.mode,
        status: "accepted",
        latencyMs: 0,
        backend: "webhook-ingress",
        metadata: {
          credentialId: credential.credentialId,
          connectorId: req.params.connectorId,
          payloadBytes: Buffer.byteLength(JSON.stringify(req.body ?? {})),
          bodyStored: false,
        },
      });
      eventId = event.eventId;
    }
    res.status(202).json({ accepted: true, connectorId: req.params.connectorId, vlinkId: bound ?? null, eventId: eventId ?? null });
  });

  const sendModels = (res: Response, bound?: string, credential?: VLinkAccessCredentialSummary) => {
    const configuredModel = process.env.GEMINI_MODEL || "gemini-configured-model";
    res.json({
      object: "list",
      data: process.env.GEMINI_API_KEY
        ? [{ id: configuredModel, object: "model", owned_by: "google", availability: "configured" }]
        : [],
      metadata: {
        providerConfigured: Boolean(process.env.GEMINI_API_KEY),
        demoResponsesEnabled: enableDemoResponses,
        vlinkId: bound ?? null,
        credentialId: credential?.credentialId ?? null,
      },
    });
  };

  const handleChatCompletions = async (
    req: Request,
    res: Response,
    forcedVLinkId?: string,
    activityRoute = "/v1/chat/completions",
  ) => {
    const bound = requireBoundOrCompatibility(req, res, forcedVLinkId);
    if (bound === null) return;
    const credential = bound ? requireAccess(req, res, bound) : undefined;
    if (bound && !credential) return;

    const started = performance.now();
    const targetHeader = req.header("x-target-url");
    let backend = "unconfigured";
    let status: "completed" | "failed" = "completed";

    try {
      if (targetHeader) {
        const target = validateTargetUrl(targetHeader);
        backend = target.hostname;
        const upstream = await fetch(target, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(req.body ?? {}),
          signal: AbortSignal.timeout(10_000),
        });
        const text = await upstream.text();
        res.status(upstream.status);
        res.type(upstream.headers.get("content-type") || "application/json");
        res.send(text);
      } else if (process.env.GEMINI_API_KEY) {
        backend = "gemini";
        const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
        const messages = Array.isArray(req.body?.messages) ? req.body.messages : [];
        const prompt = messages
          .map(
            (m: { role?: string; content?: unknown }) =>
              `${m.role ?? "user"}: ${typeof m.content === "string" ? m.content : JSON.stringify(m.content)}`,
          )
          .join("\n");
        const model = process.env.GEMINI_MODEL || req.body?.model;
        if (!model) throw new Error("Set GEMINI_MODEL or provide a model in the request");
        const result = await ai.models.generateContent({ model, contents: prompt || "Hello" });
        res.json({
          id: `chatcmpl_${Date.now()}`,
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model,
          choices: [{ index: 0, message: { role: "assistant", content: result.text ?? "" }, finish_reason: "stop" }],
          metadata: {
            executionMode: "live",
            routedBy: "VLink",
            vlinkId: bound ?? null,
            credentialId: credential?.credentialId ?? null,
          },
        });
      } else if (enableDemoResponses) {
        backend = "demo";
        res.json({
          id: `chatcmpl_demo_${Date.now()}`,
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model: req.body?.model ?? "demo",
          choices: [
            {
              index: 0,
              message: { role: "assistant", content: "[DEMO RESPONSE] No live provider is configured." },
              finish_reason: "stop",
            },
          ],
          metadata: {
            executionMode: "demo",
            providerConfigured: false,
            routedBy: "VLink",
            vlinkId: bound ?? null,
            credentialId: credential?.credentialId ?? null,
          },
        });
      } else {
        status = "failed";
        res.status(503).json({
          error: "provider_not_configured",
          message:
            "Configure GEMINI_API_KEY/GEMINI_MODEL or an allowlisted X-Target-Url. Demo responses are disabled by default.",
        });
      }
    } catch (error) {
      status = "failed";
      if (!res.headersSent) {
        res.status(502).json({
          error: "upstream_failure",
          message: error instanceof Error ? error.message : "Unknown upstream error",
        });
      }
    } finally {
      if (bound) {
        const vlink = registry.get(bound)!;
        registry.addActivity({
          vlinkId: bound,
          sourceType: vlink.sourceType,
          route: activityRoute,
          method: "POST",
          mode: vlink.mode,
          status,
          latencyMs: Math.max(0, Math.round(performance.now() - started)),
          backend,
          metadata: {
            credentialId: credential?.credentialId ?? null,
            requestBodyStored: false,
            responseBodyStored: false,
            vlinkAccessTokenForwardedUpstream: false,
            executionMode: backend === "demo" ? "demo" : "live-or-forwarded",
            binding: forcedVLinkId ? "connection-url" : "header-or-query",
          },
        });
      }
    }
  };

  app.get("/v1/models", (req, res) => {
    const bound = requireBoundOrCompatibility(req, res);
    if (bound === null) return;
    const credential = bound ? requireAccess(req, res, bound) : undefined;
    if (bound && !credential) return;
    sendModels(res, bound, credential ?? undefined);
  });

  app.post("/v1/chat/completions", (req, res) => handleChatCompletions(req, res));

  app.get("/vlinks/:vlinkId/v1/models", (req, res) => {
    const bound = requireBoundOrCompatibility(req, res, req.params.vlinkId);
    if (bound === null || !bound) return;
    const credential = requireAccess(req, res, bound);
    if (!credential) return;
    sendModels(res, bound, credential);
  });

  app.post("/vlinks/:vlinkId/v1/chat/completions", (req, res) =>
    handleChatCompletions(req, res, req.params.vlinkId, "/vlinks/:vlinkId/v1/chat/completions"),
  );

  app.get("/mcp/v1", (_req, res) => {
    res.status(501).json({
      status: "planned",
      protocol: "mcp",
      message: "VLink publishes an MCP endpoint placeholder; full MCP transport is not implemented in this release.",
    });
  });

  app.use(["/api", "/v1", "/mcp", "/vlinks"], (_req, res) => res.status(404).json({ error: "not_found" }));

  return { app, registry };
}
