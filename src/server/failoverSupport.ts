import type { Express, Request, Response } from "express";
import type { VLinkRegistry } from "./vlinkRegistry";

export type VLinkFailoverAttemptOutcome = "success" | "upstream_4xx" | "upstream_5xx" | "timeout" | "transport_error";

export interface VLinkFailoverAttempt {
  role: "primary" | "secondary";
  targetHost: string;
  outcome: VLinkFailoverAttemptOutcome;
  statusCode?: number;
  latencyMs: number;
}

export interface VLinkFailoverResult {
  response: {
    status: number;
    contentType: string;
    body: string;
  };
  attempts: VLinkFailoverAttempt[];
  failoverEngaged: boolean;
  recovered: boolean;
}

export interface FailoverSupportOptions {
  timeoutMs?: number;
}

const getBearerToken = (req: Request) => {
  const authorization = req.header("authorization")?.trim();
  if (!authorization) return undefined;
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  return match?.[1]?.trim() || undefined;
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
    throw new Error("Only HTTP(S) failover targets are supported");
  }
  const allowedHosts = parseAllowedTargetHosts();
  if (!allowedHosts.has(url.hostname.toLowerCase())) {
    throw new Error("Failover target host is not in VLINK_ALLOWED_TARGET_HOSTS");
  }
  return url;
};

const clampTimeout = (value: number) => {
  if (!Number.isFinite(value)) return 4_000;
  return Math.min(Math.max(Math.floor(value), 25), 30_000);
};

const attemptTarget = async (
  role: "primary" | "secondary",
  target: URL,
  body: unknown,
  timeoutMs: number,
): Promise<{ attempt: VLinkFailoverAttempt; response?: VLinkFailoverResult["response"] }> => {
  const started = performance.now();
  try {
    const upstream = await fetch(target, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body ?? {}),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await upstream.text();
    const latencyMs = Math.max(0, Math.round(performance.now() - started));
    const outcome: VLinkFailoverAttemptOutcome = upstream.status >= 500
      ? "upstream_5xx"
      : upstream.status >= 400
        ? "upstream_4xx"
        : "success";
    return {
      attempt: {
        role,
        targetHost: target.host,
        outcome,
        statusCode: upstream.status,
        latencyMs,
      },
      response: {
        status: upstream.status,
        contentType: upstream.headers.get("content-type") || "application/json",
        body: text,
      },
    };
  } catch (error) {
    const latencyMs = Math.max(0, Math.round(performance.now() - started));
    const timeout = error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError");
    return {
      attempt: {
        role,
        targetHost: target.host,
        outcome: timeout ? "timeout" : "transport_error",
        latencyMs,
      },
    };
  }
};

export const executeBoundedFailover = async (input: {
  primary: URL;
  secondary: URL;
  body: unknown;
  timeoutMs: number;
}): Promise<VLinkFailoverResult> => {
  const attempts: VLinkFailoverAttempt[] = [];
  const primary = await attemptTarget("primary", input.primary, input.body, input.timeoutMs);
  attempts.push(primary.attempt);

  if (primary.response && primary.attempt.outcome !== "upstream_5xx") {
    return {
      response: primary.response,
      attempts,
      failoverEngaged: false,
      recovered: false,
    };
  }

  const secondary = await attemptTarget("secondary", input.secondary, input.body, input.timeoutMs);
  attempts.push(secondary.attempt);

  if (secondary.response) {
    return {
      response: secondary.response,
      attempts,
      failoverEngaged: true,
      recovered: secondary.attempt.outcome === "success",
    };
  }

  return {
    response: {
      status: 502,
      contentType: "application/json",
      body: JSON.stringify({
        error: "failover_exhausted",
        message: "Primary and secondary failover targets both failed before returning an HTTP response.",
      }),
    },
    attempts,
    failoverEngaged: true,
    recovered: false,
  };
};

export const installFailoverSupport = (
  app: Express,
  registry: VLinkRegistry,
  options: FailoverSupportOptions = {},
) => {
  const timeoutMs = clampTimeout(options.timeoutMs ?? Number(process.env.VLINK_FAILOVER_TIMEOUT_MS ?? 4_000));

  app.post("/failover/vlinks/:vlinkId/v1/chat/completions", async (req, res) => {
    const vlink = registry.get(req.params.vlinkId);
    if (!vlink) return res.status(404).json({ error: "vlink_not_found" });

    const token = getBearerToken(req);
    if (!token || !token.startsWith("vlt_")) {
      res.setHeader("WWW-Authenticate", 'Bearer realm="VLink failover"');
      return res.status(401).json({ error: "vlink_access_token_required" });
    }
    const credential = registry.authenticate(vlink.vlinkId, token);
    if (!credential) {
      res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
      return res.status(401).json({ error: "invalid_or_expired_vlink_access_token" });
    }

    if (req.header("x-vlink-retry-safe")?.trim().toLowerCase() !== "true") {
      return res.status(409).json({
        error: "failover_requires_retry_safe_request",
        message: "Bounded failover is disabled unless the caller explicitly declares this request safe to retry once.",
      });
    }

    const primaryValue = req.header("x-vlink-primary-url")?.trim();
    const secondaryValue = req.header("x-vlink-secondary-url")?.trim();
    if (!primaryValue || !secondaryValue) {
      return res.status(400).json({
        error: "failover_targets_required",
        requiredHeaders: ["X-VLink-Primary-Url", "X-VLink-Secondary-Url", "X-VLink-Retry-Safe: true"],
      });
    }

    let primary: URL;
    let secondary: URL;
    try {
      primary = validateTargetUrl(primaryValue);
      secondary = validateTargetUrl(secondaryValue);
    } catch (error) {
      return res.status(400).json({
        error: "invalid_failover_target",
        message: error instanceof Error ? error.message : "Invalid failover target",
      });
    }
    if (primary.href === secondary.href) {
      return res.status(400).json({ error: "failover_targets_must_differ" });
    }

    const started = performance.now();
    const result = await executeBoundedFailover({ primary, secondary, body: req.body, timeoutMs });
    const totalLatencyMs = Math.max(0, Math.round(performance.now() - started));
    const primaryAttempt = result.attempts[0];
    const secondaryAttempt = result.attempts[1];

    registry.addActivity({
      vlinkId: vlink.vlinkId,
      sourceType: vlink.sourceType,
      route: "/failover/vlinks/:vlinkId/v1/chat/completions",
      method: "POST",
      mode: vlink.mode,
      status: result.response.status >= 500 ? "failed" : "completed",
      latencyMs: totalLatencyMs,
      backend: result.recovered ? secondary.host : primary.host,
      metadata: {
        evidenceType: "bounded-failover-attempt",
        credentialId: credential.credentialId,
        retrySafeDeclared: true,
        failoverEngaged: result.failoverEngaged,
        failoverRecovered: result.recovered,
        attemptCount: result.attempts.length,
        primaryHost: primary.host,
        primaryOutcome: primaryAttempt.outcome,
        primaryStatus: primaryAttempt.statusCode ?? null,
        primaryLatencyMs: primaryAttempt.latencyMs,
        secondaryHost: secondaryAttempt?.targetHost ?? null,
        secondaryOutcome: secondaryAttempt?.outcome ?? null,
        secondaryStatus: secondaryAttempt?.statusCode ?? null,
        secondaryLatencyMs: secondaryAttempt?.latencyMs ?? null,
        totalLatencyMs,
        requestBodyStored: false,
        responseBodyStored: false,
        vlinkAccessTokenForwardedUpstream: false,
      },
    });

    res.setHeader("X-VLink-Failover-Engaged", String(result.failoverEngaged));
    res.setHeader("X-VLink-Failover-Recovered", String(result.recovered));
    res.setHeader("X-VLink-Failover-Attempts", String(result.attempts.length));
    res.setHeader("X-VLink-Primary-Outcome", primaryAttempt.outcome);
    if (secondaryAttempt) res.setHeader("X-VLink-Secondary-Outcome", secondaryAttempt.outcome);
    res.setHeader("X-VLink-Total-Latency-Ms", String(totalLatencyMs));
    res.status(result.response.status);
    res.type(result.response.contentType);
    return res.send(result.response.body);
  });
};
