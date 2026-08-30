import express, { type NextFunction, type Request, type Response } from "express";
import { GoogleGenAI } from "@google/genai";
import { InMemoryVLinkRegistry, type VLinkRegistry } from "./vlinkRegistry";
import type { VLinkSourceType } from "../types/vlink";

export interface CreateAppOptions {
  registry?: VLinkRegistry;
  publicOrigin?: string;
  enableDemoResponses?: boolean;
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
  const forbidden = ["api_key", "apikey", "bearer ", "secret", "privatekey", "oneTimeCode".toLowerCase()];
  if (forbidden.some((term) => serialized.includes(term))) {
    throw new Error("Manifest unexpectedly contains secret-bearing fields");
  }
  return manifest;
};

export function createApp(options: CreateAppOptions = {}) {
  const app = express();
  const registry = options.registry ?? new InMemoryVLinkRegistry();
  const enableDemoResponses = options.enableDemoResponses ?? process.env.VLINK_ENABLE_DEMO_RESPONSES === "true";

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

  app.get("/api/health", (_req, res) => {
    res.json({
      status: "online",
      service: "VLink",
      version: "0.1.0",
      geminiConfigured: Boolean(process.env.GEMINI_API_KEY),
      demoResponsesEnabled: enableDemoResponses,
      persistence: "memory",
      timestamp: new Date().toISOString(),
    });
  });

  app.post("/api/v1/vlinks", (req, res) => {
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
    res.status(201).json({ vlink, manifestUrl: `/api/v1/vlinks/${vlink.vlinkId}/manifest` });
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
      note: "This service manifest contains connection metadata only; enrollment secrets are never published here.",
    });
  });

  app.post("/api/v1/vlinks/:vlinkId/pairing", (req, res) => {
    const ttlSeconds = Number(req.body?.ttlSeconds ?? 600);
    const pairing = registry.createPairing(req.params.vlinkId, originFor(req, options.publicOrigin), Math.min(Math.max(ttlSeconds, 1), 900));
    if (!pairing) return res.status(404).json({ error: "vlink_not_found" });
    res.status(201).json({ pairing });
  });

  app.get("/api/v1/vlinks/:vlinkId/pairing/:pairingId", (req, res) => {
    const pairing = registry.getPairing(req.params.vlinkId, req.params.pairingId);
    if (!pairing) return res.status(404).json({ error: "pairing_not_found" });
    const { oneTimeCode: _secret, qrPayload: _qrSecret, ...publicPairing } = pairing;
    res.json({ pairing: publicPairing });
  });

  app.post("/api/v1/vlinks/:vlinkId/pairing/:pairingId/complete", (req, res) => {
    const oneTimeCode = String(req.body?.oneTimeCode ?? "");
    const completed = registry.completePairing(req.params.vlinkId, req.params.pairingId, oneTimeCode);
    if (!completed) {
      const current = registry.getPairing(req.params.vlinkId, req.params.pairingId);
      if (current?.status === "expired") return res.status(410).json({ error: "pairing_expired" });
      return res.status(400).json({ error: "pairing_invalid_or_already_used" });
    }
    const { oneTimeCode: _secret, qrPayload: _qrSecret, ...publicPairing } = completed;
    res.json({ pairing: publicPairing, vlink: registry.get(req.params.vlinkId) });
  });

  app.post("/api/v1/vlinks/:vlinkId/test", (req, res) => {
    const vlink = registry.get(req.params.vlinkId);
    if (!vlink) return res.status(404).json({ error: "vlink_not_found" });
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
        evidenceType: "request-response-metadata",
        cryptographicReceipt: false,
        message: "Connection test received and bound to an existing VLink.",
      },
    });
    res.json({ ok: true, event });
  });

  app.get("/api/v1/vlinks/:vlinkId/activity", (req, res) => {
    if (!registry.get(req.params.vlinkId)) return res.status(404).json({ error: "vlink_not_found" });
    res.json({ vlinkId: req.params.vlinkId, events: registry.activity(req.params.vlinkId) });
  });

  app.post("/api/v1/vlinks/:vlinkId/webhook", (req, res) => {
    const vlink = registry.get(req.params.vlinkId);
    if (!vlink) return res.status(404).json({ error: "vlink_not_found" });
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
        contentType: req.header("content-type") ?? null,
        payloadBytes: Buffer.byteLength(JSON.stringify(req.body ?? {})),
        bodyStored: false,
      },
    });
    res.status(202).json({ accepted: true, eventId: event.eventId, vlinkId: vlink.vlinkId });
  });

  app.post("/api/v1/webhooks/:connectorId", (req, res) => {
    const bound = resolveVLinkBinding(req, res);
    if (bound === null) return;
    let eventId: string | undefined;
    if (bound) {
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
        metadata: { connectorId: req.params.connectorId, payloadBytes: Buffer.byteLength(JSON.stringify(req.body ?? {})), bodyStored: false },
      });
      eventId = event.eventId;
    }
    res.status(202).json({ accepted: true, connectorId: req.params.connectorId, vlinkId: bound ?? null, eventId: eventId ?? null });
  });

  const sendModels = (res: Response, bound?: string) => {
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
      },
    });
  };

  const handleChatCompletions = async (
    req: Request,
    res: Response,
    forcedVLinkId?: string,
    activityRoute = "/v1/chat/completions",
  ) => {
    const bound = resolveVLinkBinding(req, res, forcedVLinkId);
    if (bound === null) return;

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
          headers: {
            "content-type": "application/json",
            ...(req.header("authorization") ? { authorization: req.header("authorization")! } : {}),
          },
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
          metadata: { executionMode: "live", routedBy: "VLink", vlinkId: bound ?? null },
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
          metadata: { executionMode: "demo", providerConfigured: false, routedBy: "VLink", vlinkId: bound ?? null },
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
            requestBodyStored: false,
            responseBodyStored: false,
            executionMode: backend === "demo" ? "demo" : "live-or-forwarded",
            binding: forcedVLinkId ? "connection-url" : "header-or-query",
          },
        });
      }
    }
  };

  app.get("/v1/models", (req, res) => {
    const bound = resolveVLinkBinding(req, res);
    if (bound === null) return;
    sendModels(res, bound);
  });

  app.post("/v1/chat/completions", (req, res) => handleChatCompletions(req, res));

  app.get("/vlinks/:vlinkId/v1/models", (req, res) => {
    const bound = resolveVLinkBinding(req, res, req.params.vlinkId);
    if (bound === null || !bound) return;
    sendModels(res, bound);
  });

  app.post("/vlinks/:vlinkId/v1/chat/completions", (req, res) =>
    handleChatCompletions(req, res, req.params.vlinkId, "/vlinks/:vlinkId/v1/chat/completions"),
  );

  app.get("/mcp/v1", (_req, res) => {
    res.status(501).json({ status: "planned", protocol: "mcp", message: "VLink publishes an MCP endpoint placeholder; full MCP transport is not implemented in this release." });
  });

  app.use(["/api", "/v1", "/mcp", "/vlinks"], (_req, res) => res.status(404).json({ error: "not_found" }));

  return { app, registry };
}
