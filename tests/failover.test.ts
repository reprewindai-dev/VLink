import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { createApp } from "../src/server/app";
import { installFailoverSupport } from "../src/server/failoverSupport";
import { installReceiptSupport } from "../src/server/receiptSupport";
import { InMemoryVLinkRegistry } from "../src/server/vlinkRegistry";

type BackendMode = "success" | "server_error" | "client_error" | "delay" | "drop";

let primaryMode: BackendMode = "success";
let secondaryMode: BackendMode = "success";
let primaryCalls = 0;
let secondaryCalls = 0;
let primaryAuthorization: string | undefined;
let secondaryAuthorization: string | undefined;

const backendHandler = (role: "primary" | "secondary") => (req: IncomingMessage, res: ServerResponse) => {
  const mode = role === "primary" ? primaryMode : secondaryMode;
  if (role === "primary") {
    primaryCalls += 1;
    primaryAuthorization = req.headers.authorization;
  } else {
    secondaryCalls += 1;
    secondaryAuthorization = req.headers.authorization;
  }

  if (mode === "drop") {
    req.socket.destroy();
    return;
  }
  if (mode === "delay") {
    setTimeout(() => {
      if (res.destroyed || res.writableEnded) return;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ backend: role, delayed: true }));
    }, 120);
    return;
  }
  if (mode === "server_error") {
    res.writeHead(503, { "content-type": "application/json" });
    res.end(JSON.stringify({ backend: role, error: "temporarily_unavailable" }));
    return;
  }
  if (mode === "client_error") {
    res.writeHead(422, { "content-type": "application/json" });
    res.end(JSON.stringify({ backend: role, error: "invalid_request" }));
    return;
  }
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ backend: role, ok: true }));
};

const primaryServer = createServer(backendHandler("primary"));
const secondaryServer = createServer(backendHandler("secondary"));
const registry = new InMemoryVLinkRegistry();
const { app } = createApp({
  registry,
  publicOrigin: "https://connect.example.test",
  enableDemoResponses: true,
  accessTokenTtlSeconds: 3600,
  enrollmentGrantTtlSeconds: 900,
});
const receiptSupport = installReceiptSupport(app, registry);
installFailoverSupport(app, registry, { timeoutMs: 30 });
app.get("*", (_req, res) => res.status(200).type("text/plain").send("ui-fallback"));

let appBase = "";
let primaryUrl = "";
let secondaryUrl = "";
let appServer: ReturnType<typeof app.listen>;
let previousAllowedHosts: string | undefined;

before(async () => {
  previousAllowedHosts = process.env.VLINK_ALLOWED_TARGET_HOSTS;
  process.env.VLINK_ALLOWED_TARGET_HOSTS = "127.0.0.1";

  appServer = app.listen(0, "127.0.0.1");
  primaryServer.listen(0, "127.0.0.1");
  secondaryServer.listen(0, "127.0.0.1");
  await Promise.all([
    new Promise<void>((resolve) => appServer.once("listening", () => resolve())),
    new Promise<void>((resolve) => primaryServer.once("listening", () => resolve())),
    new Promise<void>((resolve) => secondaryServer.once("listening", () => resolve())),
  ]);
  appBase = `http://127.0.0.1:${(appServer.address() as AddressInfo).port}`;
  primaryUrl = `http://127.0.0.1:${(primaryServer.address() as AddressInfo).port}/chat`;
  secondaryUrl = `http://127.0.0.1:${(secondaryServer.address() as AddressInfo).port}/chat`;
});

after(async () => {
  if (previousAllowedHosts === undefined) delete process.env.VLINK_ALLOWED_TARGET_HOSTS;
  else process.env.VLINK_ALLOWED_TARGET_HOSTS = previousAllowedHosts;
  await Promise.all([
    new Promise<void>((resolve, reject) => appServer.close((err) => (err ? reject(err) : resolve()))),
    new Promise<void>((resolve, reject) => primaryServer.close((err) => (err ? reject(err) : resolve()))),
    new Promise<void>((resolve, reject) => secondaryServer.close((err) => (err ? reject(err) : resolve()))),
  ]);
});

const resetBackends = (primary: BackendMode, secondary: BackendMode = "success") => {
  primaryMode = primary;
  secondaryMode = secondary;
  primaryCalls = 0;
  secondaryCalls = 0;
  primaryAuthorization = undefined;
  secondaryAuthorization = undefined;
};

type Created = {
  vlink: { vlinkId: string };
  enrollmentGrant: { token: string };
};

type Credential = { token: string; credentialId: string };

async function createCredential(): Promise<{ created: Created; credential: Credential }> {
  const create = await fetch(`${appBase}/api/v1/vlinks`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      workspaceId: "ws-failover",
      environment: "development",
      displayName: `Failover ${Date.now()} ${Math.random()}`,
      sourceType: "ai-client",
    }),
  });
  assert.equal(create.status, 201);
  const created = (await create.json()) as Created;

  const pair = await fetch(`${appBase}/api/v1/vlinks/${created.vlink.vlinkId}/pairing`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${created.enrollmentGrant.token}`,
    },
    body: "{}",
  });
  assert.equal(pair.status, 201);
  const pairing = (await pair.json()) as { pairing: { pairingId: string; approvalCode: string; deviceCode: string } };

  const approve = await fetch(`${appBase}/api/v1/vlinks/${created.vlink.vlinkId}/pairing/${pairing.pairing.pairingId}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ approvalCode: pairing.pairing.approvalCode }),
  });
  assert.equal(approve.status, 200);

  const exchange = await fetch(`${appBase}/api/v1/vlinks/${created.vlink.vlinkId}/pairing/${pairing.pairing.pairingId}/exchange`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ deviceCode: pairing.pairing.deviceCode }),
  });
  assert.equal(exchange.status, 200);
  const credential = ((await exchange.json()) as { credential: Credential }).credential;
  return { created, credential };
}

const failoverRequest = (
  vlinkId: string,
  token: string,
  options: { retrySafe?: boolean; primary?: string; secondary?: string } = {},
) => fetch(`${appBase}/failover/vlinks/${vlinkId}/v1/chat/completions`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    authorization: `Bearer ${token}`,
    "x-vlink-retry-safe": String(options.retrySafe ?? true),
    "x-vlink-primary-url": options.primary ?? primaryUrl,
    "x-vlink-secondary-url": options.secondary ?? secondaryUrl,
  },
  body: JSON.stringify({ model: "test", messages: [{ role: "user", content: "hello" }] }),
});


test("failover makes zero upstream attempts unless the caller explicitly declares retry safety", async () => {
  const { created, credential } = await createCredential();
  resetBackends("server_error");
  const response = await failoverRequest(created.vlink.vlinkId, credential.token, { retrySafe: false });
  assert.equal(response.status, 409);
  assert.equal(((await response.json()) as { error: string }).error, "failover_requires_retry_safe_request");
  assert.equal(primaryCalls, 0);
  assert.equal(secondaryCalls, 0);
});


test("healthy primary returns directly and secondary is never contacted", async () => {
  const { created, credential } = await createCredential();
  resetBackends("success");
  const response = await failoverRequest(created.vlink.vlinkId, credential.token);
  assert.equal(response.status, 200);
  assert.equal(((await response.json()) as { backend: string }).backend, "primary");
  assert.equal(primaryCalls, 1);
  assert.equal(secondaryCalls, 0);
  assert.equal(response.headers.get("x-vlink-failover-engaged"), "false");
  assert.equal(response.headers.get("x-vlink-failover-attempts"), "1");
});


test("primary 4xx is treated as an application response and is never retried on secondary", async () => {
  const { created, credential } = await createCredential();
  resetBackends("client_error");
  const response = await failoverRequest(created.vlink.vlinkId, credential.token);
  assert.equal(response.status, 422);
  assert.equal(primaryCalls, 1);
  assert.equal(secondaryCalls, 0);
  assert.equal(response.headers.get("x-vlink-primary-outcome"), "upstream_4xx");
  assert.equal(response.headers.get("x-vlink-failover-engaged"), "false");
});


test("primary 5xx triggers exactly one secondary attempt and returns secondary success", async () => {
  const { created, credential } = await createCredential();
  resetBackends("server_error", "success");
  const response = await failoverRequest(created.vlink.vlinkId, credential.token);
  assert.equal(response.status, 200);
  assert.equal(((await response.json()) as { backend: string }).backend, "secondary");
  assert.equal(primaryCalls, 1);
  assert.equal(secondaryCalls, 1);
  assert.equal(response.headers.get("x-vlink-failover-engaged"), "true");
  assert.equal(response.headers.get("x-vlink-failover-recovered"), "true");
  assert.equal(response.headers.get("x-vlink-primary-outcome"), "upstream_5xx");
  assert.equal(response.headers.get("x-vlink-secondary-outcome"), "success");
  assert.equal(response.headers.get("x-vlink-failover-attempts"), "2");
});


test("primary timeout triggers one secondary attempt and records measured timeout recovery", async () => {
  const { created, credential } = await createCredential();
  resetBackends("delay", "success");
  const response = await failoverRequest(created.vlink.vlinkId, credential.token);
  assert.equal(response.status, 200);
  assert.equal(primaryCalls, 1);
  assert.equal(secondaryCalls, 1);
  assert.equal(response.headers.get("x-vlink-primary-outcome"), "timeout");
  assert.equal(response.headers.get("x-vlink-failover-recovered"), "true");
  const measured = Number(response.headers.get("x-vlink-total-latency-ms"));
  assert.ok(Number.isFinite(measured));
  assert.ok(measured >= 25);
});


test("primary transport failure triggers one secondary attempt", async () => {
  const { created, credential } = await createCredential();
  resetBackends("drop", "success");
  const response = await failoverRequest(created.vlink.vlinkId, credential.token);
  assert.equal(response.status, 200);
  assert.equal(primaryCalls, 1);
  assert.equal(secondaryCalls, 1);
  assert.equal(response.headers.get("x-vlink-primary-outcome"), "transport_error");
  assert.equal(response.headers.get("x-vlink-failover-recovered"), "true");
});


test("secondary 5xx is not falsely reported as recovered and final evidence names the secondary attempt", async () => {
  const { created, credential } = await createCredential();
  resetBackends("server_error", "server_error");
  const response = await failoverRequest(created.vlink.vlinkId, credential.token);
  assert.equal(response.status, 503);
  assert.equal(primaryCalls, 1);
  assert.equal(secondaryCalls, 1);
  assert.equal(response.headers.get("x-vlink-failover-recovered"), "false");
  assert.equal(response.headers.get("x-vlink-secondary-outcome"), "upstream_5xx");

  const event = registry.activity(created.vlink.vlinkId)[0];
  assert.equal(event.metadata.failoverEngaged, true);
  assert.equal(event.metadata.failoverRecovered, false);
  assert.equal(event.metadata.attemptCount, 2);
  assert.equal(event.backend, new URL(secondaryUrl).host);
});


test("both transport failures return bounded failover exhausted after exactly two attempts", async () => {
  const { created, credential } = await createCredential();
  resetBackends("drop", "drop");
  const response = await failoverRequest(created.vlink.vlinkId, credential.token);
  assert.equal(response.status, 502);
  assert.equal(((await response.json()) as { error: string }).error, "failover_exhausted");
  assert.equal(primaryCalls, 1);
  assert.equal(secondaryCalls, 1);
  assert.equal(response.headers.get("x-vlink-failover-attempts"), "2");
  assert.equal(response.headers.get("x-vlink-failover-recovered"), "false");
});


test("VLink access token is required and cannot be replayed across VLinks before any upstream attempt", async () => {
  const first = await createCredential();
  const second = await createCredential();
  resetBackends("success");
  const response = await failoverRequest(second.created.vlink.vlinkId, first.credential.token);
  assert.equal(response.status, 401);
  assert.equal(primaryCalls, 0);
  assert.equal(secondaryCalls, 0);
});


test("same primary and secondary target is rejected before execution", async () => {
  const { created, credential } = await createCredential();
  resetBackends("success");
  const response = await failoverRequest(created.vlink.vlinkId, credential.token, { secondary: primaryUrl });
  assert.equal(response.status, 400);
  assert.equal(((await response.json()) as { error: string }).error, "failover_targets_must_differ");
  assert.equal(primaryCalls, 0);
  assert.equal(secondaryCalls, 0);
});


test("non-allowlisted failover targets are rejected before execution", async () => {
  const { created, credential } = await createCredential();
  resetBackends("success");
  const response = await failoverRequest(created.vlink.vlinkId, credential.token, {
    primary: "http://localhost:65530/chat",
  });
  assert.equal(response.status, 400);
  assert.equal(((await response.json()) as { error: string }).error, "invalid_failover_target");
  assert.equal(primaryCalls, 0);
  assert.equal(secondaryCalls, 0);
});


test("VLink bearer credential is not forwarded to primary or secondary during failover", async () => {
  const { created, credential } = await createCredential();
  resetBackends("server_error", "success");
  const response = await failoverRequest(created.vlink.vlinkId, credential.token);
  assert.equal(response.status, 200);
  assert.equal(primaryAuthorization, undefined);
  assert.equal(secondaryAuthorization, undefined);
  const event = registry.activity(created.vlink.vlinkId)[0];
  assert.equal(event.metadata.vlinkAccessTokenForwardedUpstream, false);
});


test("successful recovery is recorded in a signed receipt that verifies independently through VLink", async () => {
  const { created, credential } = await createCredential();
  resetBackends("server_error", "success");
  const response = await failoverRequest(created.vlink.vlinkId, credential.token);
  assert.equal(response.status, 200);

  const event = registry.activity(created.vlink.vlinkId)[0];
  assert.equal(event.metadata.evidenceType, "bounded-failover-attempt");
  assert.equal(event.metadata.failoverRecovered, true);
  assert.equal(event.metadata.primaryOutcome, "upstream_5xx");
  assert.equal(event.metadata.secondaryOutcome, "success");
  assert.equal(event.metadata.requestBodyStored, false);
  assert.equal(event.metadata.responseBodyStored, false);

  const receipt = receiptSupport.receipts(created.vlink.vlinkId)[0];
  assert.equal(receipt.payload.eventId, event.eventId);
  const verify = await fetch(`${appBase}/receipts/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ receipt }),
  });
  assert.equal(verify.status, 200);
  assert.equal(((await verify.json()) as { valid: boolean }).valid, true);
});
