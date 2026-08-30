import express, { type NextFunction, type Request, type Response } from "express";
import { GoogleGenAI } from "@google/genai";
import { InMemoryVLinkRegistry, type VLinkRegistry } from "./vlinkRegistry";
import type { VLinkAccessCredentialSummary, VLinkSourceType } from "../types/vlink";

export interface CreateAppOptions {
  registry?: VLinkRegistry;
  publicOrigin?: string;
  enableDemoResponses?: boolean;
  allowUnboundCompatibility?: boolean;
  allowUnauthenticatedCreate?: boolean;
  enrollmentGrantTtlSeconds?: number;
  accessTokenTtlSeconds?: number;
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
  const forwardedProto = req.header("x-forwarded-proto")?.split(",")[0]?.trim();
  const proto = forwardedProto || req.protocol;
  return `${proto}://${req.get("host")}`;
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
  const enableDemoResponses = options.enableDemoResponses ?? process.env.VLINK_ENABLE_DEMO_RESPONSES === "true";
  const allowUnboundCompatibility = options.allowUnboundCompatibility ?? process.env.VLINK_ALLOW_UNBOUND_COMPAT === "true";
  const allowUnauthenticatedCreate =
    options.allowUnauthenticatedCreate ??
    (process.env.NODE_ENV !== "production" || process.env.VLINK_ALLOW_UNAUTHENTICATED_CREATE === "true");
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

  app.disable("x-powered-by");
  app.use(express.json({ limit: "2mb" }));
  app.use(express.urlencoded({ extended: true, limit: "2mb" }));
  app.use((req: Request, res: Response, next: NextFunction) => {
    const allowedOrigin = process.env.VLINK_CORS_ORIGIN || "*";
    res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization,X-VLink-Id,X-Target-Url");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    if (req.method === "OPTIONS") return res.status(204).end();
    next();
  });

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
    const credential = registry.authenticate(vlinkId, token);
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
      persistence: "memory",
      timestamp: new Date().toISOString(),
    });
  });

  app.post("/api/v1/vlinks", (req, res) => {
    if (!allowUnauthenticatedCreate) {
      return res.status(403).json({
        error: "workspace_auth_required",
        message: "Unauthenticated VLink creation is disabled in production until workspace/account authentication is integrated.",
      });
    }

    const { workspaceId, environment, displayName, sourceType, expiresAt } = req.body ?? {};
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
      note: "Discovery manifests contain connection metadata only. Enrollment grants and workload access tokens are never published here.",
    });
  });

  app.post("/api/v1/vlinks/:vlinkId/pairing", (req, res) => {
    if (!registry.get(req.params.vlinkId)) return res.status(404).json({ error: "vlink_not_found" });
    if (!requireEnrollmentGrant(req, res, req.params.vlinkId)) return;

    const ttlSeconds = clampSeconds(Number(req.body?.ttlSeconds ?? 600), 600, 900);
    const pairing = registry.createPairing(req.params.vlinkId, originFor(req, options.publicOrigin), ttlSeconds);
    if (!pairing) return res.status(404).json({ error: "vlink_not_found" });
    res.setHeader("Cache-Control", "no-store");
    res.status(201).json({ pairing });
  });

  app.get("/api/v1/vlinks/:vlinkId/pairing/:pairingId", (req, res) => {
    const pairing = registry.getPairingStatus(req.params.vlinkId, req.params.pairingId);
    if (!pairing) return res.status(404).json({ error: "pairing_not_found" });
    res.setHeader("Cache-Control", "no-store");
    res.json({ pairing });
  });

  const approvePairing = (req: Request, res: Response) => {
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

  app.post("/api/v1/vlinks/:vlinkId/pairing/:pairingId/exchange", (req, res) => {
    const deviceCode = String(req.body?.deviceCode ?? "");
    const current = registry.getPairingStatus(req.params.vlinkId, req.params.pairingId);
    if (!current) return res.status(404).json({ error: "pairing_not_found" });
    if (current.status === "expired") return res.status(410).json({ error: "pairing_expired" });
    if (current.status === "pending") return res.status(409).json({ error: "pairing_not_approved" });
    if (current.status === "exchanged") return res.status(400).json({ error: "pairing_already_exchanged" });

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
