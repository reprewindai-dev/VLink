import express, { type Express, type Request, type Response } from "express";

/**
 * Same-origin relay for Veklom's first-party analytics when VLink is opened on
 * vlink.veklom.com (on veklom.com/vlink/connect/ the Next app routes these paths
 * to LockerPhycer directly). Nothing is stored here; only the headers the
 * analytics endpoint needs for privacy mode and rate limiting are forwarded.
 * Cookies are never forwarded.
 */
const FORWARDED_HEADERS = [
  "content-type",
  "sec-gpc",
  "dnt",
  "cf-ipcountry",
  "cf-connecting-ip",
  "x-forwarded-for",
  "user-agent",
  "authorization",
] as const;

export function installAnalyticsProxy(
  app: Express,
  options: { lockerPhycerBaseUrl?: string; fetchImpl?: typeof fetch } = {},
) {
  const base = (
    options.lockerPhycerBaseUrl ?? process.env.VLINK_LOCKERPHYCER_URL ?? process.env.LOCKERPHYCER_URL ?? ""
  ).replace(/\/+$/, "");
  const doFetch = options.fetchImpl ?? fetch;

  const relay = async (req: Request, res: Response, upstreamPath: string, method: "GET" | "POST") => {
    if (!base) {
      res.status(503).json({ error: "analytics_unavailable" });
      return;
    }
    const headers: Record<string, string> = { accept: "application/json" };
    for (const name of FORWARDED_HEADERS) {
      const value = req.header(name);
      if (value) headers[name] = value;
    }
    let body: string | undefined;
    if (method === "POST") {
      body = typeof req.body === "string" ? req.body : JSON.stringify(req.body ?? {});
      if (Buffer.byteLength(body) > 16 * 1024) {
        res.status(413).json({ error: "payload_too_large" });
        return;
      }
    }
    const query = new URLSearchParams();
    if (typeof req.query.consent === "string") query.set("consent", req.query.consent.slice(0, 16));
    const qs = method === "GET" && query.toString() ? `?${query.toString()}` : "";
    try {
      const upstream = await doFetch(`${base}${upstreamPath}${qs}`, {
        method,
        headers,
        body,
        redirect: "error",
        signal: AbortSignal.timeout(5_000),
      });
      const text = await upstream.text();
      res.status(upstream.status);
      res.setHeader("content-type", upstream.headers.get("content-type") || "application/json");
      res.setHeader("cache-control", "private, no-store");
      const retryAfter = upstream.headers.get("retry-after");
      if (retryAfter) res.setHeader("retry-after", retryAfter);
      res.send(text);
    } catch {
      res.status(502).json({ error: "analytics_upstream_unavailable" });
    }
  };

  const textBody = express.text({ type: () => true, limit: "16kb" });
  app.post("/api/v1/analytics/events", textBody, (req, res) => void relay(req, res, "/api/v1/analytics/events", "POST"));
  app.post("/api/v1/analytics/link", textBody, (req, res) => void relay(req, res, "/api/v1/analytics/link", "POST"));
  app.get("/api/v1/analytics/config", (req, res) => void relay(req, res, "/api/v1/analytics/config", "GET"));
}
