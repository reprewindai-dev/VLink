import assert from "node:assert/strict";
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign as ed25519Sign, verify as ed25519Verify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { createApp } from "../src/server/app";
import { VLinkDeviceClient } from "../src/client/deviceClient";
import { createLeaseSealer } from "../src/server/leaseSealer";
import { deviceProofPayload, deviceRequestProofPayload } from "../src/server/pairingProof";
import { makeDeviceRequestProofHeader } from "../src/server/requestProof";
import { FileBackedVLinkRegistry } from "../src/server/fileBackedRegistry";
import { canonicalizeVLinkJson } from "../src/server/receiptSigner";
import { installReceiptSupport } from "../src/server/receiptSupport";
import { InMemoryVLinkRegistry } from "../src/server/vlinkRegistry";
import type { VLinkDeviceBootstrapView, VLinkSignedReceipt } from "../src/types/vlink";

const TEST_OWNER_TOKEN = "test-owner-ws-test";
const TEST_OTHER_OWNER_TOKEN = "test-owner-ws-other";
const TEST_NO_MFA_TOKEN = "test-owner-ws-test-no-mfa";
const registry = new InMemoryVLinkRegistry();
const { app } = createApp({
  registry,
  leaseSealer: createLeaseSealer("ab".repeat(32)),
  enableAnonymousBootstrap: true,
  publicOrigin: "https://connect.example.test",
  pairingOrigin: "https://app.example.test",
  workspaceAuthenticator: async (token, context) => {
    const mfaVerified = context?.requireMfa === true && context.mfaCode === "123456";
    if (token === TEST_OWNER_TOKEN) return { workspaceId: "ws-test", mfaVerified };
    if (token === TEST_OTHER_OWNER_TOKEN) return { workspaceId: "ws-other", mfaVerified };
    if (token === TEST_NO_MFA_TOKEN) return { workspaceId: "ws-test", mfaVerified: false };
    return undefined;
  },
  enableDemoResponses: true,
  accessTokenTtlSeconds: 3600,
  enrollmentGrantTtlSeconds: 900,
});
const receiptSupport = installReceiptSupport(app, registry);
app.get("*", (_req, res) => res.status(200).type("text/plain").send("ui-fallback"));

let base = "";
let server: ReturnType<typeof app.listen>;
let targetBase = "";
let targetAuthorization: string | undefined;
const targetServer = createServer((req, res) => {
  targetAuthorization = req.headers.authorization;
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ ok: true }));
});

before(async () => {
  server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  targetServer.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => targetServer.once("listening", () => resolve()));
  targetBase = `http://127.0.0.1:${(targetServer.address() as AddressInfo).port}`;
});

test("health reports the configured registry persistence adapter", async () => {
  const memoryResponse = await fetch(`${base}/api/health`);
  assert.equal(memoryResponse.status, 200);
  const memoryHealth = await memoryResponse.json() as { persistence: string };
  assert.equal(memoryHealth.persistence, "memory");

  const stateDir = mkdtempSync(path.join(tmpdir(), "vlink-health-persistence-"));
  const fileApp = createApp({
    registry: new FileBackedVLinkRegistry({
      statePath: path.join(stateDir, "state.json"),
      leaseSealer: createLeaseSealer("cd".repeat(32)),
    }),
    leaseSealer: createLeaseSealer("cd".repeat(32)),
  }).app;
  const fileServer = fileApp.listen(0, "127.0.0.1");
  try {
    await new Promise<void>((resolve) => fileServer.once("listening", resolve));
    const address = fileServer.address() as AddressInfo;
    const fileResponse = await fetch(`http://127.0.0.1:${address.port}/api/health`);
    assert.equal(fileResponse.status, 200);
    const fileHealth = await fileResponse.json() as { persistence: string };
    assert.equal(fileHealth.persistence, "file");
  } finally {
    await new Promise<void>((resolve, reject) => fileServer.close((error) => error ? reject(error) : resolve()));
    rmSync(stateDir, { recursive: true, force: true });
  }
});

after(async () => {
  await Promise.all([
    new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve()))),
    new Promise<void>((resolve, reject) => targetServer.close((err) => (err ? reject(err) : resolve()))),
  ]);
});

type CreatedVLink = {
  vlink: { vlinkId: string; mode: string; endpoints: { openaiCompatibleBaseUrl: string } };
  enrollmentGrant: { grantId: string; vlinkId: string; token: string; issuedAt: string; expiresAt: string };
};

type Pairing = {
  pairingId: string;
  vlinkId: string;
  approvalCode: string;
  deviceCode: string;
  pairingUrl: string;
  qrPayload: string;
  status: string;
  expiresAt: string;
};

type Credential = {
  credentialId: string;
  vlinkId: string;
  token: string;
  issuedAt: string;
  expiresAt: string;
};

async function createVLink(sourceType = "ai-client"): Promise<CreatedVLink> {
  const response = await fetch(`${base}/api/v1/vlinks`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      workspaceId: "ws-test",
      environment: "development",
      displayName: `Test Link ${Date.now()}`,
      sourceType,
    }),
  });
  assert.equal(response.status, 201);
  assert.equal(response.headers.get("cache-control"), "no-store");
  return (await response.json()) as CreatedVLink;
}

async function createPairing(created: CreatedVLink): Promise<Pairing> {
  const response = await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/pairing`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${created.enrollmentGrant.token}`,
    },
    body: JSON.stringify({ ttlSeconds: 600 }),
  });
  assert.equal(response.status, 201);
  assert.equal(response.headers.get("cache-control"), "no-store");
  return ((await response.json()) as { pairing: Pairing }).pairing;
}

async function approveAndExchange(created: CreatedVLink): Promise<{ pairing: Pairing; credential: Credential }> {
  const pairing = await createPairing(created);
  const approve = await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/pairing/${pairing.pairingId}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TEST_OWNER_TOKEN}` },
    body: JSON.stringify({ approvalCode: pairing.approvalCode, mfaCode: "123456" }),
  });
  assert.equal(approve.status, 200);

  const exchange = await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/pairing/${pairing.pairingId}/exchange`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ deviceCode: pairing.deviceCode }),
  });
  assert.equal(exchange.status, 200);
  assert.equal(exchange.headers.get("cache-control"), "no-store");
  const body = (await exchange.json()) as { credential: Credential };
  return { pairing, credential: body.credential };
}

type DevicePairingSession = {
  pairingId: string;
  vlinkId: string;
  pairingUrl: string;
  nonce: string;
  expiresAt: string;
  privateKey: KeyObject;
  publicKeyPem: string;
  keyThumbprint: string;
};

async function startDevicePairing(vlinkId: string): Promise<DevicePairingSession> {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const response = await fetch(`${base}/api/v1/vlinks/${vlinkId}/device-pairings`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ publicKeyPem, ttlSeconds: 600 }),
  });
  assert.equal(response.status, 201);
  const body = (await response.json()) as {
    pairing: { pairingId: string; vlinkId: string; pairingUrl: string; expiresAt: string; deviceKeyThumbprint: string };
    challenge: { nonce: string };
    consequenceAuthority: string;
  };
  assert.equal(body.consequenceAuthority, "none");
  return {
    pairingId: body.pairing.pairingId,
    vlinkId,
    pairingUrl: body.pairing.pairingUrl,
    nonce: body.challenge.nonce,
    expiresAt: body.pairing.expiresAt,
    privateKey,
    publicKeyPem,
    keyThumbprint: body.pairing.deviceKeyThumbprint,
  };
}

const signDeviceProof = (
  device: DevicePairingSession,
  purpose: "bootstrap" | "exchange",
  nonce: string,
) => ed25519Sign(null, deviceProofPayload({
  purpose,
  vlinkId: device.vlinkId,
  pairingId: device.pairingId,
  keyThumbprint: device.keyThumbprint,
  nonce,
}), device.privateKey).toString("base64url");

const signUnboundDeviceProof = (input: {
  privateKey: KeyObject;
  pairingId: string;
  keyThumbprint: string;
  nonce: string;
  purpose?: "unbound-bootstrap" | "bootstrap";
}) => ed25519Sign(null, deviceProofPayload({
  purpose: input.purpose ?? "unbound-bootstrap",
  vlinkId: null,
  pairingId: input.pairingId,
  keyThumbprint: input.keyThumbprint,
  nonce: input.nonce,
}), input.privateKey).toString("base64url");

const signedDeviceRequestHeader = (
  device: DevicePairingSession,
  credential: Credential,
  input: { method: string; url: string; body?: string; timestampMs?: number },
) => {
  const url = new URL(input.url);
  const timestampMs = input.timestampMs ?? Date.now();
  const nonce = randomBytes(32).toString("base64url");
  const bodyHash = createHash("sha256").update(input.body ?? "").digest("hex");
  const signature = ed25519Sign(null, deviceRequestProofPayload({
    vlinkId: device.vlinkId,
    credentialId: credential.credentialId,
    tokenHash: createHash("sha256").update(credential.token, "utf8").digest("hex"),
    method: input.method.toUpperCase(),
    target: `${url.pathname}${url.search}`,
    host: url.host.toLowerCase(),
    bodyHash,
    timestampMs,
    nonce,
  }), device.privateKey).toString("base64url");
  return makeDeviceRequestProofHeader({ timestampMs, nonce, signature });
};

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

async function createSignedTestReceipt() {
  const created = await createVLink();
  const { credential } = await approveAndExchange(created);
  const response = await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/test`, {
    method: "POST",
    headers: { "content-type": "application/json", ...bearer(credential.token) },
    body: "{}",
  });
  assert.equal(response.status, 200);
  const receipts = receiptSupport.receipts(created.vlink.vlinkId);
  assert.ok(receipts.length > 0);
  return { created, credential, receipt: receipts[0] };
}


test("browser routes fall through to the UI layer while API misses stay fail-closed", async () => {
  const root = await fetch(`${base}/`);
  assert.equal(root.status, 200);
  assert.equal(await root.text(), "ui-fallback");

  const pairingPage = await fetch(`${base}/pair/vlk_example/pair_example`);
  assert.equal(pairingPage.status, 200);
  assert.equal(await pairingPage.text(), "ui-fallback");

  const missingApi = await fetch(`${base}/api/not-a-real-route`);
  assert.equal(missingApi.status, 404);
  assert.equal(((await missingApi.json()) as { error: string }).error, "not_found");
});


test("VLink creation returns a short-lived enrollment grant but does not put it on the VLink record", async () => {
  const created = await createVLink();
  assert.match(created.vlink.vlinkId, /^vlk_[a-f0-9]{16}$/);
  assert.match(created.enrollmentGrant.token, /^vle_[a-f0-9]{16}\.[A-Za-z0-9_-]+$/);
  assert.equal(created.enrollmentGrant.vlinkId, created.vlink.vlinkId);
  assert.equal(created.vlink.mode, "observe");
  assert.equal(JSON.stringify(created.vlink).includes(created.enrollmentGrant.token), false);
});


test("production workspace auth binds VLink to LockerPhycer workspace and ignores forged workspaceId", async () => {
  const isolated = createApp({
    allowUnauthenticatedCreate: false,
    workspaceAuthenticator: async (token) =>
      token === "workspace-session"
        ? { userId: "user-1", email: "user@example.com", workspaceId: "ws-canonical" }
        : undefined,
  });
  const isolatedServer = isolated.app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => isolatedServer.once("listening", () => resolve()));
  const isolatedBase = `http://127.0.0.1:${(isolatedServer.address() as AddressInfo).port}`;
  try {
    const response = await fetch(`${isolatedBase}/api/v1/vlinks`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer workspace-session",
      },
      body: JSON.stringify({
        workspaceId: "ws-forged",
        environment: "production",
        displayName: "Workspace-bound",
        sourceType: "ai-client",
      }),
    });
    assert.equal(response.status, 201);
    const body = (await response.json()) as { vlink: { workspaceId: string } };
    assert.equal(body.vlink.workspaceId, "ws-canonical");
  } finally {
    await new Promise<void>((resolve, reject) => isolatedServer.close((err) => (err ? reject(err) : resolve())));
  }
});


test("production workspace auth rejects invalid bearer and unbound sessions", async () => {
  const isolated = createApp({
    allowUnauthenticatedCreate: false,
    workspaceAuthenticator: async (token) => {
      if (token === "unbound-session") throw new Error("LockerPhycer session is authenticated but is not bound to a workspace");
      return undefined;
    },
  });
  const isolatedServer = isolated.app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => isolatedServer.once("listening", () => resolve()));
  const isolatedBase = `http://127.0.0.1:${(isolatedServer.address() as AddressInfo).port}`;
  try {
    const invalid = await fetch(`${isolatedBase}/api/v1/vlinks`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer bad-session" },
      body: JSON.stringify({ workspaceId: "ws", environment: "production", displayName: "blocked", sourceType: "ai-client" }),
    });
    assert.equal(invalid.status, 401);
    assert.equal(((await invalid.json()) as { error: string }).error, "invalid_workspace_session");

    const unbound = await fetch(`${isolatedBase}/api/v1/vlinks`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer unbound-session" },
      body: JSON.stringify({ workspaceId: "ws", environment: "production", displayName: "blocked", sourceType: "ai-client" }),
    });
    assert.equal(unbound.status, 409);
    assert.equal(((await unbound.json()) as { error: string }).error, "workspace_binding_required");
  } finally {
    await new Promise<void>((resolve, reject) => isolatedServer.close((err) => (err ? reject(err) : resolve())));
  }
});


test("production-style configuration refuses unauthenticated VLink creation", async () => {
  const isolated = createApp({ allowUnauthenticatedCreate: false });
  const isolatedServer = isolated.app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => isolatedServer.once("listening", () => resolve()));
  const isolatedBase = `http://127.0.0.1:${(isolatedServer.address() as AddressInfo).port}`;
  try {
    const response = await fetch(`${isolatedBase}/api/v1/vlinks`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ workspaceId: "ws", environment: "production", displayName: "blocked", sourceType: "ai-client" }),
    });
    assert.equal(response.status, 401);
    assert.equal(((await response.json()) as { error: string }).error, "workspace_auth_required");
  } finally {
    await new Promise<void>((resolve, reject) => isolatedServer.close((err) => (err ? reject(err) : resolve())));
  }
});


test("manifest is self-binding and contains no enrollment, pairing, or access secrets", async () => {
  const created = await createVLink();
  const response = await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/manifest`);
  assert.equal(response.status, 200);
  const text = await response.text();
  for (const forbidden of ["vle_", "vlt_", "approvalcode", "devicecode", created.enrollmentGrant.token.toLowerCase()]) {
    assert.equal(text.toLowerCase().includes(forbidden), false, forbidden);
  }
  const body = JSON.parse(text);
  assert.equal(body.endpoints.openaiCompatibleBaseUrl, `https://connect.example.test/vlinks/${created.vlink.vlinkId}/v1`);
  assert.equal(body.access.scheme, "bearer");
  assert.equal(body.access.temporaryCredentials, true);
  assert.equal(body.access.tokenPublishedInManifest, false);
});


test("pairing creation requires the enrollment grant", async () => {
  const created = await createVLink();
  const response = await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/pairing`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  assert.equal(response.status, 401);
  assert.equal(((await response.json()) as { error: string }).error, "enrollment_grant_required");
});


test("pairing approval requires the authenticated LockerPhycer owner of the VLink workspace", async () => {
  const created = await createVLink();
  const pairing = await createPairing(created);
  assert.equal(new URL(pairing.pairingUrl).origin, "https://app.example.test");
  assert.equal(new URL(created.vlink.endpoints.openaiCompatibleBaseUrl).origin, "https://connect.example.test");

  const approve = (authorization?: string, mfaCode = "123456") => fetch(
    `${base}/api/v1/vlinks/${created.vlink.vlinkId}/pairing/${pairing.pairingId}/approve`,
    {
      method: "POST",
      headers: { "content-type": "application/json", ...(authorization ? { authorization } : {}) },
      body: JSON.stringify({ approvalCode: pairing.approvalCode, mfaCode }),
    },
  );

  const anonymous = await approve();
  assert.equal(anonymous.status, 401);
  assert.equal(((await anonymous.json()) as { error: string }).error, "workspace_session_required");

  const wrongWorkspace = await approve(`Bearer ${TEST_OTHER_OWNER_TOKEN}`);
  assert.equal(wrongWorkspace.status, 403);
  assert.equal(((await wrongWorkspace.json()) as { error: string }).error, "workspace_access_denied");

  const pending = await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/pairing/${pairing.pairingId}`);
  assert.equal(((await pending.json()) as { pairing: { status: string } }).pairing.status, "pending");

  const noMfa = await approve(`Bearer ${TEST_NO_MFA_TOKEN}`);
  assert.equal(noMfa.status, 403);
  assert.equal(((await noMfa.json()) as { error: string }).error, "mfa_required");

  const owner = await approve(`Bearer ${TEST_OWNER_TOKEN}`);
  assert.equal(owner.status, 200);
  assert.equal(((await owner.json()) as { pairing: { status: string } }).pairing.status, "approved");
});


test("an enrollment grant is bound to one VLink", async () => {
  const first = await createVLink();
  const second = await createVLink();
  const response = await fetch(`${base}/api/v1/vlinks/${second.vlink.vlinkId}/pairing`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${first.enrollmentGrant.token}`,
    },
    body: "{}",
  });
  assert.equal(response.status, 401);
  assert.equal(((await response.json()) as { error: string }).error, "invalid_or_expired_enrollment_grant");
});


test("pairing QR exposes only browser approval while device exchange code stays off the QR", () => {
  const record = registry.create(
    { workspaceId: "ws", environment: "dev", displayName: "Pair", sourceType: "local-project" },
    "https://connect.example.test",
  );
  const pairing = registry.createPairing(record.vlinkId, "https://connect.example.test", 600)!;
  assert.equal(pairing.pairingUrl, `https://connect.example.test/pair/${record.vlinkId}/${pairing.pairingId}`);
  assert.ok(pairing.qrPayload.startsWith(`${pairing.pairingUrl}#approval=`));
  assert.equal(pairing.pairingUrl.includes(pairing.approvalCode), false);
  assert.equal(pairing.pairingUrl.includes(pairing.deviceCode), false);
  assert.equal(pairing.qrPayload.includes(pairing.deviceCode), false);
});


test("public pairing status exposes neither approval code, device code, nor QR payload", async () => {
  const created = await createVLink();
  const pairing = await createPairing(created);
  const response = await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/pairing/${pairing.pairingId}`);
  const text = await response.text();
  assert.equal(response.status, 200);
  assert.equal(text.includes(pairing.approvalCode), false);
  assert.equal(text.includes(pairing.deviceCode), false);
  assert.equal(text.includes("qrPayload"), false);
});


test("production anonymous bootstrap requires a canonical HTTPS origin and stable admission key", () => {
  const previous = {
    nodeEnv: process.env.NODE_ENV,
    enabled: process.env.VLINK_ANONYMOUS_BOOTSTRAP_ENABLED,
    rateLimitKey: process.env.VLINK_BOOTSTRAP_RATE_LIMIT_KEY,
    publicOrigin: process.env.VLINK_PUBLIC_ORIGIN,
    pairingOrigin: process.env.VLINK_PAIRING_ORIGIN,
  };
  process.env.NODE_ENV = "production";
  process.env.VLINK_ANONYMOUS_BOOTSTRAP_ENABLED = "true";
  delete process.env.VLINK_BOOTSTRAP_RATE_LIMIT_KEY;
  delete process.env.VLINK_PUBLIC_ORIGIN;
  delete process.env.VLINK_PAIRING_ORIGIN;
  try {
    assert.throws(
      () => createApp({ enableAnonymousBootstrap: true, bootstrapRateLimitKey: "a".repeat(32), publicOrigin: "http://connect.example.test" }),
      /canonical HTTPS origin/,
    );
    assert.throws(
      () => createApp({ enableAnonymousBootstrap: true, publicOrigin: "https://connect.example.test" }),
      /VLINK_BOOTSTRAP_RATE_LIMIT_KEY/,
    );
  } finally {
    if (previous.nodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous.nodeEnv;
    if (previous.enabled === undefined) delete process.env.VLINK_ANONYMOUS_BOOTSTRAP_ENABLED;
    else process.env.VLINK_ANONYMOUS_BOOTSTRAP_ENABLED = previous.enabled;
    if (previous.rateLimitKey === undefined) delete process.env.VLINK_BOOTSTRAP_RATE_LIMIT_KEY;
    else process.env.VLINK_BOOTSTRAP_RATE_LIMIT_KEY = previous.rateLimitKey;
    if (previous.publicOrigin === undefined) delete process.env.VLINK_PUBLIC_ORIGIN;
    else process.env.VLINK_PUBLIC_ORIGIN = previous.publicOrigin;
    if (previous.pairingOrigin === undefined) delete process.env.VLINK_PAIRING_ORIGIN;
    else process.env.VLINK_PAIRING_ORIGIN = previous.pairingOrigin;
  }
});


test("LockerPhycer owner and MFA endpoints, not auth/me claims, authorize unbound bootstrap", async () => {
  const seen = { ownerPath: "", mfaCalls: 0 };
  const lockerServer = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const bodyText = Buffer.concat(chunks).toString("utf8");
      res.setHeader("content-type", "application/json");
      if (req.url === "/api/v1/auth/me" && req.method === "GET") {
        res.end(JSON.stringify({ id: "human-1", email: "owner@example.test", workspace_id: "ws-live", mfa_verified: true }));
        return;
      }
      if (req.url === "/api/v1/workspace/ws-live/vlink-authorization" && req.method === "GET") {
        seen.ownerPath = req.url;
        res.end(JSON.stringify({ authorized: true, workspace_id: "ws-live" }));
        return;
      }
      if (req.url === "/api/v1/auth/mfa/verify" && req.method === "POST") {
        seen.mfaCalls += 1;
        const supplied = (JSON.parse(bodyText) as { code?: string }).code;
        if (supplied !== "123456") {
          res.statusCode = 401;
          res.end(JSON.stringify({ detail: "Invalid MFA code" }));
          return;
        }
        res.end(JSON.stringify({ verified: true }));
        return;
      }
      res.statusCode = 404;
      res.end(JSON.stringify({ error: "not found" }));
    });
  });
  lockerServer.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => lockerServer.once("listening", resolve));
  const lockerUrl = `http://127.0.0.1:${(lockerServer.address() as AddressInfo).port}`;
  const testRegistry = new InMemoryVLinkRegistry();
  const { app: isolatedApp } = createApp({
    registry: testRegistry,
    lockerPhycerBaseUrl: lockerUrl,
    leaseSealer: createLeaseSealer("ef".repeat(32)),
    allowUnauthenticatedCreate: false,
    enableAnonymousBootstrap: true,
  });
  const isolatedServer = isolatedApp.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => isolatedServer.once("listening", resolve));
  const isolatedBase = `http://127.0.0.1:${(isolatedServer.address() as AddressInfo).port}`;
  try {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const createdResponse = await fetch(`${isolatedBase}/api/v1/device/bootstrap`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ publicKeyPem, displayName: "live-owner-check", environment: "test", sourceType: "container" }),
    });
    assert.equal(createdResponse.status, 201);
    const created = (await createdResponse.json()) as { bootstrap: VLinkDeviceBootstrapView; challenge: { nonce: string } };
    const proofResponse = await fetch(`${isolatedBase}/api/v1/device/bootstrap/${created.bootstrap.pairingId}/proof`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        nonce: created.challenge.nonce,
        signature: signUnboundDeviceProof({
          privateKey,
          pairingId: created.bootstrap.pairingId,
          keyThumbprint: created.bootstrap.deviceKeyThumbprint,
          nonce: created.challenge.nonce,
        }),
      }),
    });
    assert.equal(proofResponse.status, 200);

    const approve = (mfaCode: string) => fetch(`${isolatedBase}/api/v1/device/bootstrap/${created.bootstrap.pairingId}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer live-locker-session" },
      body: JSON.stringify({ mfaCode }),
    });
    const invalid = await approve("000000");
    assert.equal(invalid.status, 403);
    assert.equal(((await invalid.json()) as { error: string }).error, "mfa_required");
    assert.equal(testRegistry.list().length, 0);

    const valid = await approve("123456");
    assert.equal(valid.status, 200);
    assert.equal(((await valid.json()) as { vlink: { workspaceId: string } }).vlink.workspaceId, "ws-live");
    assert.equal(seen.ownerPath, "/api/v1/workspace/ws-live/vlink-authorization");
    assert.equal(seen.mfaCalls, 2);
    assert.equal(testRegistry.list().length, 1);
  } finally {
    await Promise.all([
      new Promise<void>((resolve, reject) => isolatedServer.close((error) => error ? reject(error) : resolve())),
      new Promise<void>((resolve, reject) => lockerServer.close((error) => error ? reject(error) : resolve())),
    ]);
  }
});


test("anonymous device bootstrap has no enrollment grant or consequence authority and proves its own key", async () => {
  const created = await createVLink();
  const device = await startDevicePairing(created.vlink.vlinkId);
  const beforeProof = await fetch(`${base}/api/v1/vlinks/${device.vlinkId}/pairing/${device.pairingId}`);
  const publicStatus = (await beforeProof.json()) as { pairing: { status: string; deviceKeyThumbprint: string; deviceProofVerified: boolean } };
  assert.equal(publicStatus.pairing.status, "pending");
  assert.equal(publicStatus.pairing.deviceKeyThumbprint, device.keyThumbprint);
  assert.equal(publicStatus.pairing.deviceProofVerified, false);

  const approvalBeforeProof = await fetch(`${base}/api/v1/vlinks/${device.vlinkId}/pairing/${device.pairingId}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TEST_OWNER_TOKEN}` },
    body: "{}",
  });
  assert.equal(approvalBeforeProof.status, 409);
  assert.equal(((await approvalBeforeProof.json()) as { error: string }).error, "device_proof_required");

  const signature = signDeviceProof(device, "bootstrap", device.nonce);
  const proof = await fetch(`${base}/api/v1/vlinks/${device.vlinkId}/pairing/${device.pairingId}/device-proof`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce: device.nonce, signature }),
  });
  assert.equal(proof.status, 200);
  assert.equal(((await proof.json()) as { pairing: { deviceProofVerified: boolean } }).pairing.deviceProofVerified, true);

  const replayedProof = await fetch(`${base}/api/v1/vlinks/${device.vlinkId}/pairing/${device.pairingId}/device-proof`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce: device.nonce, signature }),
  });
  assert.equal(replayedProof.status, 400);
});


test("unknown machine bootstraps without a VLink, then owner approval binds it and exchange is recoverable", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const initialVlinkCount = registry.list().length;
  const createdResponse = await fetch(`${base}/api/v1/device/bootstrap`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      publicKeyPem,
      displayName: "new-worker",
      environment: "production",
      sourceType: "container",
      workspaceId: "attacker-chosen-workspace",
    }),
  });
  assert.equal(createdResponse.status, 201);
  const created = (await createdResponse.json()) as {
    bootstrap: VLinkDeviceBootstrapView;
    challenge: { nonce: string };
    consequenceAuthority: string;
  };
  assert.equal(created.consequenceAuthority, "none");
  assert.equal("vlinkId" in created.bootstrap, false);
  assert.equal("enrollmentGrant" in created, false);
  assert.equal("credential" in created, false);
  assert.match(created.bootstrap.approvalUrl, new RegExp(`/pair/bootstrap/${created.bootstrap.pairingId}$`));

  const proofUrl = `${base}/api/v1/device/bootstrap/${created.bootstrap.pairingId}/proof`;
  const wrongDomainProof = await fetch(proofUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      nonce: created.challenge.nonce,
      signature: signUnboundDeviceProof({
        privateKey,
        pairingId: created.bootstrap.pairingId,
        keyThumbprint: created.bootstrap.deviceKeyThumbprint,
        nonce: created.challenge.nonce,
        purpose: "bootstrap",
      }),
    }),
  });
  assert.equal(wrongDomainProof.status, 400);

  const proof = await fetch(proofUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      nonce: created.challenge.nonce,
      signature: signUnboundDeviceProof({
        privateKey,
        pairingId: created.bootstrap.pairingId,
        keyThumbprint: created.bootstrap.deviceKeyThumbprint,
        nonce: created.challenge.nonce,
      }),
    }),
  });
  assert.equal(proof.status, 200);

  const approveUrl = `${base}/api/v1/device/bootstrap/${created.bootstrap.pairingId}/approve`;
  const missingMfa = await fetch(approveUrl, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TEST_OWNER_TOKEN}` },
    body: "{}",
  });
  assert.equal(missingMfa.status, 403);
  assert.equal(registry.list().length, initialVlinkCount);

  const wrongMfa = await fetch(approveUrl, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TEST_OWNER_TOKEN}` },
    body: JSON.stringify({ mfaCode: "000000" }),
  });
  assert.equal(wrongMfa.status, 403);
  assert.equal(registry.list().length, initialVlinkCount);

  const approvedResponse = await fetch(approveUrl, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TEST_OWNER_TOKEN}` },
    body: JSON.stringify({ mfaCode: "123456" }),
  });
  assert.equal(approvedResponse.status, 200);
  const approved = (await approvedResponse.json()) as {
    bootstrap: VLinkDeviceBootstrapView;
    vlink: { vlinkId: string; workspaceId: string };
    enrollmentGrant: { grantId: string; vlinkId: string; token: string; expiresAt: string };
    consequenceAuthority: string;
  };
  assert.equal(approved.consequenceAuthority, "none");
  assert.equal(approved.vlink.workspaceId, "ws-test");
  assert.notEqual(approved.vlink.workspaceId, "attacker-chosen-workspace");
  assert.equal(approved.bootstrap.vlinkId, approved.vlink.vlinkId);
  assert.equal(approved.enrollmentGrant.vlinkId, approved.vlink.vlinkId);
  assert.ok(registry.authenticateEnrollment(approved.vlink.vlinkId, approved.enrollmentGrant.token));
  assert.equal(registry.list().length, initialVlinkCount + 1);

  const publicStatus = await fetch(`${base}/api/v1/device/bootstrap/${created.bootstrap.pairingId}`);
  assert.equal(publicStatus.status, 200);
  const publicStatusText = await publicStatus.text();
  assert.equal(publicStatusText.includes(approved.enrollmentGrant.token), false);
  assert.equal(publicStatusText.includes("enrollmentGrant"), false);

  const wrongOwnerRetry = await fetch(approveUrl, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TEST_OTHER_OWNER_TOKEN}` },
    body: JSON.stringify({ mfaCode: "123456" }),
  });
  assert.equal(wrongOwnerRetry.status, 403);

  const retryWithoutMfa = await fetch(approveUrl, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TEST_OWNER_TOKEN}` },
    body: "{}",
  });
  assert.equal(retryWithoutMfa.status, 403);

  const retryApproval = await fetch(approveUrl, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TEST_OWNER_TOKEN}` },
    body: JSON.stringify({ mfaCode: "123456" }),
  });
  assert.equal(retryApproval.status, 200);
  const retriedApproval = await retryApproval.json() as {
    vlink: { vlinkId: string };
    enrollmentGrant: { token: string };
  };
  assert.equal(retriedApproval.vlink.vlinkId, approved.vlink.vlinkId);
  assert.equal(retriedApproval.enrollmentGrant.token, approved.enrollmentGrant.token);
  assert.equal(registry.list().length, initialVlinkCount + 1);

  const challengeResponse = await fetch(`${base}/api/v1/vlinks/${approved.vlink.vlinkId}/pairing/${created.bootstrap.pairingId}/exchange-challenge`, { method: "POST" });
  assert.equal(challengeResponse.status, 200);
  const challenge = (await challengeResponse.json()) as { challenge: { nonce: string } };
  const device: DevicePairingSession = {
    pairingId: created.bootstrap.pairingId,
    vlinkId: approved.vlink.vlinkId,
    pairingUrl: created.bootstrap.approvalUrl,
    nonce: challenge.challenge.nonce,
    expiresAt: created.bootstrap.expiresAt,
    privateKey,
    publicKeyPem,
    keyThumbprint: created.bootstrap.deviceKeyThumbprint,
  };
  const exchangeResponse = await fetch(`${base}/api/v1/vlinks/${device.vlinkId}/pairing/${device.pairingId}/exchange`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce: device.nonce, signature: signDeviceProof(device, "exchange", device.nonce) }),
  });
  assert.equal(exchangeResponse.status, 200);
  assert.equal(registry.exportSnapshot().credentials.filter((item) => item.vlinkId === device.vlinkId).length, 1);
});


test("device client completes anonymous bootstrap, recovers a lost exchange response, and signs a protected request", async () => {
  const credentialCountBefore = registry.exportSnapshot().credentials.length;
  let loseFirstExchangeResponse = true;
  const device = new VLinkDeviceClient({
    apiBaseUrl: base,
    fetchImpl: async (input, init) => {
      const response = await fetch(input, init);
      if (
        loseFirstExchangeResponse &&
        init?.method === "POST" &&
        new URL(String(input)).pathname.endsWith("/exchange")
      ) {
        loseFirstExchangeResponse = false;
        throw new TypeError("Injected response loss after the VLink server processed exchange");
      }
      return response;
    },
  });

  const started = await device.beginPairing({
    displayName: "device-client-e2e",
    environment: "development",
    sourceType: "local-project",
  });
  assert.equal(started.consequenceAuthority, "none");
  assert.equal(started.bootstrap.deviceProofVerified, true);
  assert.equal(started.bootstrap.deviceKeyThumbprint, device.deviceKeyThumbprint);
  assert.equal("vlinkId" in started.bootstrap, false);
  assert.equal(device.credential, undefined);
  assert.equal(registry.exportSnapshot().credentials.length, credentialCountBefore);

  const approved = await fetch(`${base}/api/v1/device/bootstrap/${started.bootstrap.pairingId}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TEST_OWNER_TOKEN}` },
    body: JSON.stringify({ mfaCode: "123456" }),
  });
  assert.equal(approved.status, 200);
  const approval = await approved.json() as { vlink: { vlinkId: string; workspaceId: string }; consequenceAuthority: string };
  assert.equal(approval.consequenceAuthority, "none");
  assert.equal(approval.vlink.workspaceId, "ws-test");

  await assert.rejects(device.recoverCredential(), /Injected response loss/);
  assert.equal(registry.exportSnapshot().credentials.filter((item) => item.vlinkId === approval.vlink.vlinkId).length, 1);

  const recovered = await device.recoverCredential();
  assert.equal(recovered.vlinkId, approval.vlink.vlinkId);
  const credentialCount = registry.exportSnapshot().credentials.filter((item) => item.vlinkId === approval.vlink.vlinkId).length;
  assert.equal(credentialCount, 1);

  const activity = await device.request(`/api/v1/vlinks/${encodeURIComponent(approval.vlink.vlinkId)}/activity`);
  assert.equal(activity.status, 200);
  assert.equal(((await activity.json()) as { vlinkId: string }).vlinkId, approval.vlink.vlinkId);
});


test("owner approval is workspace- and MFA-gated, then proof-of-possession exchange recovers one identical credential", async () => {
  const created = await createVLink();
  const device = await startDevicePairing(created.vlink.vlinkId);
  const proof = await fetch(`${base}/api/v1/vlinks/${device.vlinkId}/pairing/${device.pairingId}/device-proof`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce: device.nonce, signature: signDeviceProof(device, "bootstrap", device.nonce) }),
  });
  assert.equal(proof.status, 200);

  const wrongWorkspace = await fetch(`${base}/api/v1/vlinks/${device.vlinkId}/pairing/${device.pairingId}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TEST_OTHER_OWNER_TOKEN}` },
    body: JSON.stringify({ mfaCode: "123456" }),
  });
  assert.equal(wrongWorkspace.status, 403);
  const noMfa = await fetch(`${base}/api/v1/vlinks/${device.vlinkId}/pairing/${device.pairingId}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TEST_NO_MFA_TOKEN}` },
    body: "{}",
  });
  assert.equal(noMfa.status, 403);

  const ownerApproval = await fetch(`${base}/api/v1/vlinks/${device.vlinkId}/pairing/${device.pairingId}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TEST_OWNER_TOKEN}` },
    body: JSON.stringify({ mfaCode: "123456" }),
  });
  assert.equal(ownerApproval.status, 200);
  const approvedView = (await ownerApproval.json()) as { pairing: { deviceKeyThumbprint: string; deviceProofVerified: boolean } };
  assert.equal(approvedView.pairing.deviceKeyThumbprint, device.keyThumbprint);
  assert.equal(approvedView.pairing.deviceProofVerified, true);

  const requestChallenge = () => fetch(`${base}/api/v1/vlinks/${device.vlinkId}/pairing/${device.pairingId}/exchange-challenge`, {
    method: "POST",
  });
  const firstChallengeResponse = await requestChallenge();
  assert.equal(firstChallengeResponse.status, 200);
  const firstChallenge = (await firstChallengeResponse.json()) as { challenge: { nonce: string } };
  const exchange = (nonce: string) => fetch(`${base}/api/v1/vlinks/${device.vlinkId}/pairing/${device.pairingId}/exchange`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce, signature: signDeviceProof(device, "exchange", nonce) }),
  });
  const firstExchange = await exchange(firstChallenge.challenge.nonce);
  assert.equal(firstExchange.status, 200);
  const first = (await firstExchange.json()) as { credential: Credential; pairing: { status: string } };
  assert.equal(first.pairing.status, "exchanged");

  const retryChallengeResponse = await requestChallenge();
  assert.equal(retryChallengeResponse.status, 200);
  const retryChallenge = (await retryChallengeResponse.json()) as { challenge: { nonce: string } };
  const retryResponse = await exchange(retryChallenge.challenge.nonce);
  assert.equal(retryResponse.status, 200);
  const retry = (await retryResponse.json()) as { credential: Credential };
  assert.deepEqual(retry.credential, first.credential);
  assert.equal(registry.exportSnapshot().credentials.filter((item) => item.vlinkId === device.vlinkId).length, 1);

  const replayResponse = await exchange(firstChallenge.challenge.nonce);
  assert.equal(replayResponse.status, 400);
});


test("device-bound access requires request proof, binds exact HTTP request, and rejects replay", async () => {
  const created = await createVLink();
  const device = await startDevicePairing(created.vlink.vlinkId);
  const deviceProof = await fetch(`${base}/api/v1/vlinks/${device.vlinkId}/pairing/${device.pairingId}/device-proof`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce: device.nonce, signature: signDeviceProof(device, "bootstrap", device.nonce) }),
  });
  assert.equal(deviceProof.status, 200);
  const approval = await fetch(`${base}/api/v1/vlinks/${device.vlinkId}/pairing/${device.pairingId}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TEST_OWNER_TOKEN}` },
    body: JSON.stringify({ mfaCode: "123456" }),
  });
  assert.equal(approval.status, 200);
  const challengeResponse = await fetch(`${base}/api/v1/vlinks/${device.vlinkId}/pairing/${device.pairingId}/exchange-challenge`, { method: "POST" });
  const challenge = (await challengeResponse.json()) as { challenge: { nonce: string } };
  const credentialResponse = await fetch(`${base}/api/v1/vlinks/${device.vlinkId}/pairing/${device.pairingId}/exchange`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce: challenge.challenge.nonce, signature: signDeviceProof(device, "exchange", challenge.challenge.nonce) }),
  });
  assert.equal(credentialResponse.status, 200);
  const credential = ((await credentialResponse.json()) as { credential: Credential }).credential;
  const target = `${base}/api/v1/vlinks/${device.vlinkId}/test`;
  const body = "{}";
  const send = (proof?: string, requestBody = body) => fetch(target, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...bearer(credential.token),
      ...(proof ? { "x-vlink-device-proof": proof } : {}),
    },
    body: requestBody,
  });

  const missingProof = await send();
  assert.equal(missingProof.status, 401);
  assert.equal(registry.activity(device.vlinkId).filter((event) => event.route === "/api/v1/vlinks/:vlinkId/test").length, 0);

  const proof = signedDeviceRequestHeader(device, credential, { method: "POST", url: target, body });
  const accepted = await send(proof);
  assert.equal(accepted.status, 200);

  const replay = await send(proof);
  assert.equal(replay.status, 401);
  assert.equal(registry.activity(device.vlinkId).filter((event) => event.route === "/api/v1/vlinks/:vlinkId/test").length, 1);

  const bodySubstitutionProof = signedDeviceRequestHeader(device, credential, { method: "POST", url: target, body });
  const bodySubstitution = await send(bodySubstitutionProof, "{\"different\":true}");
  assert.equal(bodySubstitution.status, 401);

  const pathSubstitutionProof = signedDeviceRequestHeader(device, credential, {
    method: "POST",
    url: `${base}/api/v1/vlinks/${device.vlinkId}/test?different=1`,
    body,
  });
  const pathSubstitution = await send(pathSubstitutionProof);
  assert.equal(pathSubstitution.status, 401);

  const staleProof = signedDeviceRequestHeader(device, credential, {
    method: "POST",
    url: target,
    body,
    timestampMs: Date.now() - 61_000,
  });
  const stale = await send(staleProof);
  assert.equal(stale.status, 401);
});


test("file-backed registry recovers the exact exchanged credential after process-style restart", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "vlink-recoverable-pairing-"));
  const statePath = path.join(stateDir, "registry.json");
  const sealer = createLeaseSealer("cd".repeat(32));
  assert.ok(sealer);
  let runningServer: Server | undefined;

  const start = async (durableRegistry: FileBackedVLinkRegistry) => {
    const isolated = createApp({
      registry: durableRegistry,
      publicOrigin: "https://connect.example.test",
      pairingOrigin: "https://app.example.test",
      leaseSealer: sealer,
      allowUnauthenticatedCreate: false,
      workspaceAuthenticator: async (token) => token === "durable-owner"
        ? { workspaceId: "durable-workspace", mfaVerified: true }
        : undefined,
    });
    runningServer = isolated.app.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => runningServer!.once("listening", resolve));
    return `http://127.0.0.1:${(runningServer.address() as AddressInfo).port}`;
  };
  const stop = async () => {
    const serverToClose = runningServer;
    runningServer = undefined;
    if (serverToClose) await new Promise<void>((resolve, reject) => serverToClose.close((error) => error ? reject(error) : resolve()));
  };

  try {
    const firstRegistry = new FileBackedVLinkRegistry({ statePath, leaseSealer: sealer });
    const vlink = firstRegistry.create({
      workspaceId: "durable-workspace",
      environment: "test",
      displayName: "Durable pairing",
      sourceType: "container",
    }, "https://connect.example.test");
    let root = await start(firstRegistry);

    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const createdResponse = await fetch(`${root}/api/v1/vlinks/${vlink.vlinkId}/device-pairings`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ publicKeyPem }),
    });
    assert.equal(createdResponse.status, 201);
    const created = (await createdResponse.json()) as {
      pairing: { pairingId: string; deviceKeyThumbprint: string };
      challenge: { nonce: string };
    };
    const pairingId = created.pairing.pairingId;
    const device: DevicePairingSession = {
      pairingId,
      vlinkId: vlink.vlinkId,
      pairingUrl: "",
      nonce: created.challenge.nonce,
      expiresAt: "",
      privateKey,
      publicKeyPem,
      keyThumbprint: created.pairing.deviceKeyThumbprint,
    };
    const proof = await fetch(`${root}/api/v1/vlinks/${vlink.vlinkId}/pairing/${pairingId}/device-proof`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ nonce: device.nonce, signature: signDeviceProof(device, "bootstrap", device.nonce) }),
    });
    assert.equal(proof.status, 200);
    const approval = await fetch(`${root}/api/v1/vlinks/${vlink.vlinkId}/pairing/${pairingId}/approve`, {
      method: "POST", headers: { "content-type": "application/json", authorization: "Bearer durable-owner" }, body: JSON.stringify({ mfaCode: "123456" }),
    });
    assert.equal(approval.status, 200);
    const firstChallengeResponse = await fetch(`${root}/api/v1/vlinks/${vlink.vlinkId}/pairing/${pairingId}/exchange-challenge`, { method: "POST" });
    const firstChallenge = (await firstChallengeResponse.json()) as { challenge: { nonce: string } };
    const signature = signDeviceProof(device, "exchange", firstChallenge.challenge.nonce);
    const firstExchange = await fetch(`${root}/api/v1/vlinks/${vlink.vlinkId}/pairing/${pairingId}/exchange`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ nonce: firstChallenge.challenge.nonce, signature }),
    });
    assert.equal(firstExchange.status, 200);
    const original = ((await firstExchange.json()) as { credential: Credential }).credential;
    await stop();

    const secondRegistry = new FileBackedVLinkRegistry({ statePath, leaseSealer: sealer });
    root = await start(secondRegistry);
    const retryChallengeResponse = await fetch(`${root}/api/v1/vlinks/${vlink.vlinkId}/pairing/${pairingId}/exchange-challenge`, { method: "POST" });
    assert.equal(retryChallengeResponse.status, 200);
    const retryChallenge = (await retryChallengeResponse.json()) as { challenge: { nonce: string } };
    const recoveredResponse = await fetch(`${root}/api/v1/vlinks/${vlink.vlinkId}/pairing/${pairingId}/exchange`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({
        nonce: retryChallenge.challenge.nonce,
        signature: signDeviceProof(device, "exchange", retryChallenge.challenge.nonce),
      }),
    });
    assert.equal(recoveredResponse.status, 200);
    const recovered = ((await recoveredResponse.json()) as { credential: Credential }).credential;
    assert.deepEqual(recovered, original);
    const durableText = readFileSync(statePath, "utf8");
    const durableState = JSON.parse(durableText) as { credentials?: unknown[] };
    assert.equal(durableState.credentials?.length, 1);
    assert.equal(durableText.includes(original.token), false);
    assert.equal(durableText.includes(device.nonce), false);
    assert.equal(durableText.includes(retryChallenge.challenge.nonce), false);
    assert.equal(durableText.includes(privateKey.export({ type: "pkcs8", format: "pem" }).toString()), false);
  } finally {
    await stop();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("anonymous bootstrap recovers the same device credential after response loss and VLink restart", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "vlink-anonymous-recovery-"));
  const statePath = path.join(stateDir, "registry.json");
  const sealer = createLeaseSealer("de".repeat(32));
  assert.ok(sealer);
  const bootstrapRateLimitKey = "anonymous-bootstrap-recovery-test-key-32-bytes";
  let runningServer: Server | undefined;
  let loseApprovalResponse = true;
  let loseExchangeResponse = true;
  let baseUrl = "";

  const start = async (durableRegistry: FileBackedVLinkRegistry, injectResponseLoss: boolean) => {
    const isolated = createApp({
      registry: durableRegistry,
      enableAnonymousBootstrap: true,
      bootstrapRateLimitKey,
      publicOrigin: "https://connect.example.test",
      pairingOrigin: "https://app.example.test",
      leaseSealer: sealer,
      allowUnauthenticatedCreate: false,
      workspaceAuthenticator: async (token, context) => token === "durable-owner"
        ? {
            workspaceId: "durable-workspace",
            mfaVerified: context?.requireMfa === true && context.mfaCode === "123456",
          }
        : undefined,
    });
    runningServer = isolated.app.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => runningServer!.once("listening", resolve));
    baseUrl = `http://127.0.0.1:${(runningServer.address() as AddressInfo).port}`;
    return new VLinkDeviceClient({
      apiBaseUrl: baseUrl,
      ...(injectResponseLoss ? {
        fetchImpl: async (input, init) => {
          const response = await fetch(input, init);
          if (
            loseExchangeResponse &&
            init?.method === "POST" &&
            new URL(String(input)).pathname.endsWith("/exchange")
          ) {
            loseExchangeResponse = false;
            throw new TypeError("Injected response loss after durable exchange commit");
          }
          return response;
        },
      } : {}),
    });
  };
  const stop = async () => {
    const serverToClose = runningServer;
    runningServer = undefined;
    if (serverToClose) {
      await new Promise<void>((resolve, reject) => serverToClose.close((error) => error ? reject(error) : resolve()));
    }
  };

  try {
    const firstRegistry = new FileBackedVLinkRegistry({ statePath, leaseSealer: sealer });
    const device = await start(firstRegistry, true);
    const started = await device.beginPairing({
      displayName: "restart-recovery-worker",
      environment: "production",
      sourceType: "container",
    });
    assert.equal(started.consequenceAuthority, "none");
    assert.equal("vlinkId" in started.bootstrap, false);

    const approve = async () => {
      const response = await fetch(`${baseUrl}/api/v1/device/bootstrap/${started.bootstrap.pairingId}/approve`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: "Bearer durable-owner" },
        body: JSON.stringify({ mfaCode: "123456" }),
      });
      if (loseApprovalResponse) {
        loseApprovalResponse = false;
        throw new TypeError("Injected response loss after durable owner approval");
      }
      return response;
    };
    await assert.rejects(approve(), /Injected response loss after durable owner approval/);
    const approvedBootstrap = await device.getBootstrapStatus();
    assert.equal(approvedBootstrap.status, "approved");
    assert.ok(approvedBootstrap.vlinkId);
    const approvedVlinkId = approvedBootstrap.vlinkId;

    await assert.rejects(device.recoverCredential(), /Injected response loss after durable exchange commit/);
    const persistedCredentialCount = () => {
      const persisted = JSON.parse(readFileSync(statePath, "utf8")) as { credentials: unknown[] };
      return persisted.credentials.length;
    };
    assert.equal(persistedCredentialCount(), 1);
    const privateKeyPem = device.exportPrivateKeyPem();
    const pairingId = device.pairingId;
    assert.ok(pairingId);
    await stop();

    const restartedRegistry = new FileBackedVLinkRegistry({ statePath, leaseSealer: sealer });
    await start(restartedRegistry, false);
    const recoveredApprovalResponse = await approve();
    assert.equal(recoveredApprovalResponse.status, 200);
    const recoveredApproval = await recoveredApprovalResponse.json() as {
      bootstrap: VLinkDeviceBootstrapView;
      vlink: { vlinkId: string; workspaceId: string };
      enrollmentGrant: { token: string; vlinkId: string };
      consequenceAuthority: string;
    };
    assert.equal(recoveredApproval.consequenceAuthority, "none");
    assert.equal(recoveredApproval.vlink.vlinkId, approvedVlinkId);
    assert.equal(recoveredApproval.vlink.workspaceId, "durable-workspace");
    assert.equal(recoveredApproval.bootstrap.vlinkId, approvedVlinkId);
    assert.equal(recoveredApproval.enrollmentGrant.vlinkId, approvedVlinkId);
    assert.ok(restartedRegistry.authenticateEnrollment(approvedVlinkId, recoveredApproval.enrollmentGrant.token));
    const durableStateText = readFileSync(statePath, "utf8");
    assert.equal(durableStateText.includes(recoveredApproval.enrollmentGrant.token), false);
    assert.ok(JSON.parse(durableStateText).deviceBootstraps[0].enrollmentGrantSealed);

    // Model a device process restart: restore only its protected local key and pairing handle.
    const resumed = new VLinkDeviceClient({ apiBaseUrl: baseUrl, privateKeyPem, pairingId });
    const recovered = await resumed.recoverCredential();
    assert.equal(recovered.vlinkId, approvedVlinkId);
    assert.equal(persistedCredentialCount(), 1);
    assert.equal(restartedRegistry.getDeviceBootstrap(pairingId)?.status, "approved");

    const readback = await resumed.request(`/api/v1/vlinks/${encodeURIComponent(approvedVlinkId)}/activity`);
    assert.equal(readback.status, 200);
    const again = await resumed.recoverCredential();
    assert.deepEqual(again, recovered);
    assert.equal(persistedCredentialCount(), 1);
    await stop();
  } finally {
    await stop();
    rmSync(stateDir, { recursive: true, force: true });
  }
});


test("anonymous bootstrap admission limits persist across restart and ignore spoofed forwarding headers", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "vlink-bootstrap-admission-"));
  const statePath = path.join(stateDir, "registry.json");
  const rateLimitKey = "bootstrap-test-key-32-bytes-minimum-000";
  const { publicKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  let runningServer: Server | undefined;

  const start = async () => {
    const registry = new FileBackedVLinkRegistry({ statePath });
    const isolated = createApp({
      registry,
      enableAnonymousBootstrap: true,
      bootstrapRateLimitKey: rateLimitKey,
      bootstrapAdmissionPolicy: {
        perSourceLimit: 2,
        perSourceWindowSeconds: 600,
        globalLimit: 20,
        globalWindowSeconds: 3600,
      },
      publicOrigin: "https://connect.example.test",
      pairingOrigin: "https://app.example.test",
    });
    runningServer = isolated.app.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => runningServer!.once("listening", resolve));
    return `http://127.0.0.1:${(runningServer.address() as AddressInfo).port}`;
  };
  const stop = async () => {
    const serverToClose = runningServer;
    runningServer = undefined;
    if (serverToClose) await new Promise<void>((resolve, reject) => serverToClose.close((error) => error ? reject(error) : resolve()));
  };
  const requestBootstrap = (root: string, forwardedFor: string) => fetch(`${root}/api/v1/device/bootstrap`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": forwardedFor },
    body: JSON.stringify({
      publicKeyPem,
      displayName: "rate-limit-test-device",
      environment: "test",
      sourceType: "container",
    }),
  });

  try {
    let root = await start();
    assert.equal((await requestBootstrap(root, "198.51.100.1")).status, 201);
    assert.equal((await requestBootstrap(root, "203.0.113.2")).status, 201);
    const limited = await requestBootstrap(root, "192.0.2.3");
    assert.equal(limited.status, 429);
    assert.ok(Number(limited.headers.get("retry-after")) > 0);
    await stop();

    root = await start();
    const afterRestart = await requestBootstrap(root, "203.0.113.99");
    assert.equal(afterRestart.status, 429);
    const durableText = readFileSync(statePath, "utf8");
    const durableState = JSON.parse(durableText) as { bootstrapAdmissionWindows?: Array<{ bucket: string; attempts: number }> };
    assert.equal(durableState.bootstrapAdmissionWindows?.length, 2);
    assert.ok(durableState.bootstrapAdmissionWindows?.some((item) => item.bucket === "global" && item.attempts === 2));
    assert.equal(durableText.includes("127.0.0.1"), false);
    assert.equal(durableText.includes("198.51.100.1"), false);
  } finally {
    await stop();
    rmSync(stateDir, { recursive: true, force: true });
  }
});


test("device exchange is impossible before browser approval", async () => {
  const created = await createVLink();
  const pairing = await createPairing(created);
  const response = await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/pairing/${pairing.pairingId}/exchange`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ deviceCode: pairing.deviceCode }),
  });
  assert.equal(response.status, 409);
  assert.equal(((await response.json()) as { error: string }).error, "pairing_not_approved");
});


test("recoverable device exchange fails closed when credential sealing is unavailable", async () => {
  const isolatedRegistry = new InMemoryVLinkRegistry();
  const vlink = isolatedRegistry.create({
    workspaceId: "unsealed-workspace",
    environment: "test",
    displayName: "Unsealed exchange",
    sourceType: "container",
  }, "https://connect.example.test");
  const isolated = createApp({
    registry: isolatedRegistry,
    leaseSealer: null,
    allowUnauthenticatedCreate: false,
    workspaceAuthenticator: async (token) => token === "owner"
      ? { workspaceId: "unsealed-workspace", mfaVerified: true }
      : undefined,
  });
  const isolatedServer = isolated.app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => isolatedServer.once("listening", resolve));
  const root = `http://127.0.0.1:${(isolatedServer.address() as AddressInfo).port}`;

  try {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const bootstrap = await fetch(`${root}/api/v1/vlinks/${vlink.vlinkId}/device-pairings`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ publicKeyPem }),
    });
    assert.equal(bootstrap.status, 201);
    const bootstrapBody = (await bootstrap.json()) as {
      pairing: { pairingId: string; deviceKeyThumbprint: string };
      challenge: { nonce: string };
    };
    const device: DevicePairingSession = {
      pairingId: bootstrapBody.pairing.pairingId,
      vlinkId: vlink.vlinkId,
      pairingUrl: "",
      nonce: bootstrapBody.challenge.nonce,
      expiresAt: "",
      privateKey,
      publicKeyPem,
      keyThumbprint: bootstrapBody.pairing.deviceKeyThumbprint,
    };
    const proof = await fetch(`${root}/api/v1/vlinks/${vlink.vlinkId}/pairing/${device.pairingId}/device-proof`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ nonce: device.nonce, signature: signDeviceProof(device, "bootstrap", device.nonce) }),
    });
    assert.equal(proof.status, 200);
    const approval = await fetch(`${root}/api/v1/vlinks/${vlink.vlinkId}/pairing/${device.pairingId}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer owner" },
      body: JSON.stringify({ mfaCode: "123456" }),
    });
    assert.equal(approval.status, 200);

    const challenge = await fetch(`${root}/api/v1/vlinks/${vlink.vlinkId}/pairing/${device.pairingId}/exchange-challenge`, {
      method: "POST",
    });
    assert.equal(challenge.status, 503);
    assert.equal(((await challenge.json()) as { error: string }).error, "recoverable_exchange_unavailable");
  } finally {
    await new Promise<void>((resolve, reject) => isolatedServer.close((error) => error ? reject(error) : resolve()));
  }
});


test("browser approval is one-time and does not itself mint a workload credential", async () => {
  const created = await createVLink();
  const pairing = await createPairing(created);
  const approve = () => fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/pairing/${pairing.pairingId}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TEST_OWNER_TOKEN}` },
    body: JSON.stringify({ approvalCode: pairing.approvalCode, mfaCode: "123456" }),
  });
  const first = await approve();
  assert.equal(first.status, 200);
  const firstText = await first.text();
  assert.equal(firstText.includes("vlt_"), false);
  assert.equal((await approve()).status, 400);
});


test("wrong device code cannot exchange an approved pairing", async () => {
  const created = await createVLink();
  const pairing = await createPairing(created);
  await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/pairing/${pairing.pairingId}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TEST_OWNER_TOKEN}` },
    body: JSON.stringify({ approvalCode: pairing.approvalCode, mfaCode: "123456" }),
  });
  const response = await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/pairing/${pairing.pairingId}/exchange`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ deviceCode: "wrong-device-code" }),
  });
  assert.equal(response.status, 400);
  assert.equal(((await response.json()) as { error: string }).error, "invalid_device_code");
});


test("approved pairing exchanges exactly once for an opaque temporary VLink access token", async () => {
  const created = await createVLink();
  const pairing = await createPairing(created);
  await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/pairing/${pairing.pairingId}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TEST_OWNER_TOKEN}` },
    body: JSON.stringify({ approvalCode: pairing.approvalCode, mfaCode: "123456" }),
  });
  const exchange = () => fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/pairing/${pairing.pairingId}/exchange`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ deviceCode: pairing.deviceCode }),
  });
  const first = await exchange();
  assert.equal(first.status, 200);
  assert.equal(first.headers.get("cache-control"), "no-store");
  const body = (await first.json()) as { credential: Credential; pairing: { status: string } };
  assert.match(body.credential.token, /^vlt_[a-f0-9]{16}\.[A-Za-z0-9_-]+$/);
  assert.equal(body.credential.vlinkId, created.vlink.vlinkId);
  assert.equal(body.pairing.status, "exchanged");
  assert.equal((await exchange()).status, 400);
});


test("VLink-specific OpenAI route requires a valid temporary access token", async () => {
  const created = await createVLink();
  const missing = await fetch(`${base}/vlinks/${created.vlink.vlinkId}/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "demo", messages: [{ role: "user", content: "no token" }] }),
  });
  assert.equal(missing.status, 401);
  assert.equal(((await missing.json()) as { error: string }).error, "vlink_access_token_required");

  const { credential } = await approveAndExchange(created);
  const allowed = await fetch(`${base}/vlinks/${created.vlink.vlinkId}/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json", ...bearer(credential.token) },
    body: JSON.stringify({ model: "demo", messages: [{ role: "user", content: "authenticated" }] }),
  });
  assert.equal(allowed.status, 200);
  const body = (await allowed.json()) as { metadata: { vlinkId: string; credentialId: string; executionMode: string } };
  assert.equal(body.metadata.vlinkId, created.vlink.vlinkId);
  assert.equal(body.metadata.credentialId, credential.credentialId);
  assert.equal(body.metadata.executionMode, "demo");
});


test("a VLink access token cannot be replayed against another VLink", async () => {
  const first = await createVLink();
  const second = await createVLink();
  const { credential } = await approveAndExchange(first);
  const response = await fetch(`${base}/vlinks/${second.vlink.vlinkId}/v1/models`, {
    headers: bearer(credential.token),
  });
  assert.equal(response.status, 401);
  assert.equal(((await response.json()) as { error: string }).error, "invalid_or_expired_vlink_access_token");
});


test("revoked access token loses authority immediately", async () => {
  const created = await createVLink();
  const { credential } = await approveAndExchange(created);
  const revoke = await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/access/revoke`, {
    method: "POST",
    headers: { "content-type": "application/json", ...bearer(credential.token) },
    body: "{}",
  });
  assert.equal(revoke.status, 200);
  const revoked = (await revoke.json()) as { revoked: { status: string } };
  assert.equal(revoked.revoked.status, "revoked");

  const afterRevoke = await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/access-test`, {
    method: "POST",
    headers: { "content-type": "application/json", ...bearer(credential.token) },
    body: "{}",
  });
  assert.equal(afterRevoke.status, 401);
});


test("expired enrollment grants and expired workload tokens fail closed", () => {
  const local = new InMemoryVLinkRegistry();
  const started = new Date("2026-08-30T20:00:00Z");
  const vlink = local.create({ workspaceId: "ws", environment: "dev", displayName: "TTL", sourceType: "ai-client" }, "https://connect.example.test");
  const grant = local.issueEnrollmentGrant(vlink.vlinkId, 1, started)!;
  assert.equal(local.authenticateEnrollment(vlink.vlinkId, grant.token, new Date("2026-08-30T20:00:02Z")), undefined);

  const pairing = local.createPairing(vlink.vlinkId, "https://connect.example.test", 30, started)!;
  local.approvePairing(vlink.vlinkId, pairing.pairingId, pairing.approvalCode, started);
  const credential = local.exchangePairing(vlink.vlinkId, pairing.pairingId, pairing.deviceCode, 1, started)!;
  assert.equal(local.authenticate(vlink.vlinkId, credential.token, new Date("2026-08-30T20:00:02Z")), undefined);
});


test("expired pairing cannot be approved or exchanged", () => {
  const local = new InMemoryVLinkRegistry();
  const started = new Date("2026-08-30T20:00:00Z");
  const vlink = local.create({ workspaceId: "ws", environment: "dev", displayName: "Expired", sourceType: "local-project" }, "https://connect.example.test");
  const pairing = local.createPairing(vlink.vlinkId, "https://connect.example.test", 1, started)!;
  const later = new Date("2026-08-30T20:00:02Z");
  assert.equal(local.approvePairing(vlink.vlinkId, pairing.pairingId, pairing.approvalCode, later), undefined);
  assert.equal(local.getPairingStatus(vlink.vlinkId, pairing.pairingId, later)?.status, "expired");
  assert.equal(local.exchangePairing(vlink.vlinkId, pairing.pairingId, pairing.deviceCode, 60, later), undefined);
});


test("endpoint URL identity conflict and unknown IDs are rejected before execution", async () => {
  const first = await createVLink();
  const second = await createVLink();
  const conflict = await fetch(`${base}/vlinks/${first.vlink.vlinkId}/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-vlink-id": second.vlink.vlinkId },
    body: "{}",
  });
  assert.equal(conflict.status, 400);
  assert.equal(((await conflict.json()) as { error: string }).error, "vlink_binding_conflict");

  const unknown = await fetch(`${base}/vlinks/vlk_unknown/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  assert.equal(unknown.status, 404);
  assert.equal(((await unknown.json()) as { error: string }).error, "invalid_vlink_id");
});


test("unbound global OpenAI compatibility is disabled by default", async () => {
  const response = await fetch(`${base}/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "demo", messages: [] }),
  });
  assert.equal(response.status, 400);
  assert.equal(((await response.json()) as { error: string }).error, "vlink_required");
});


test("global OpenAI compatibility still works with an explicit VLink binding plus access token", async () => {
  const created = await createVLink();
  const { credential } = await approveAndExchange(created);
  const response = await fetch(`${base}/v1/chat/completions`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-vlink-id": created.vlink.vlinkId,
      ...bearer(credential.token),
    },
    body: JSON.stringify({ model: "demo", messages: [{ role: "user", content: "compatibility" }] }),
  });
  assert.equal(response.status, 200);
  const body = (await response.json()) as { metadata: { executionMode: string; credentialId: string } };
  assert.equal(body.metadata.executionMode, "demo");
  assert.equal(body.metadata.credentialId, credential.credentialId);
});


test("authenticated connection test and activity never serialize the bearer token", async () => {
  const created = await createVLink();
  const { credential } = await approveAndExchange(created);
  const testResponse = await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/test`, {
    method: "POST",
    headers: { "content-type": "application/json", ...bearer(credential.token) },
    body: "{}",
  });
  assert.equal(testResponse.status, 200);

  const activityResponse = await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/activity`, {
    headers: bearer(credential.token),
  });
  const text = await activityResponse.text();
  assert.equal(activityResponse.status, 200);
  assert.equal(text.includes(credential.token), false);
  const body = JSON.parse(text);
  assert.equal(body.events[0].metadata.credentialId, credential.credentialId);
  assert.equal(body.events[0].metadata.cryptographicReceipt, false);
});


test("webhook ingress requires VLink access and records metadata without storing the request body", async () => {
  const created = await createVLink("webhook");
  const missing = await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/webhook`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ secretPayload: "do-not-store" }),
  });
  assert.equal(missing.status, 401);

  const { credential } = await approveAndExchange(created);
  const ok = await fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/webhook`, {
    method: "POST",
    headers: { "content-type": "application/json", ...bearer(credential.token) },
    body: JSON.stringify({ secretPayload: "do-not-store" }),
  });
  assert.equal(ok.status, 202);
  const events = registry.activity(created.vlink.vlinkId);
  assert.equal(events[0].metadata.bodyStored, false);
  assert.equal(JSON.stringify(events[0]).includes("do-not-store"), false);
  assert.equal(JSON.stringify(events[0]).includes(credential.token), false);
});


test("VLink bearer token is never forwarded to an allowlisted custom target", async () => {
  const created = await createVLink();
  const { credential } = await approveAndExchange(created);
  const previous = process.env.VLINK_ALLOWED_TARGET_HOSTS;
  process.env.VLINK_ALLOWED_TARGET_HOSTS = "127.0.0.1";
  targetAuthorization = undefined;
  try {
    const response = await fetch(`${base}/vlinks/${created.vlink.vlinkId}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-target-url": `${targetBase}/chat`,
        ...bearer(credential.token),
      },
      body: JSON.stringify({ model: "custom", messages: [] }),
    });
    assert.equal(response.status, 200);
    assert.equal(targetAuthorization, undefined);
    const events = registry.activity(created.vlink.vlinkId);
    assert.equal(events[0].metadata.vlinkAccessTokenForwardedUpstream, false);
  } finally {
    if (previous === undefined) delete process.env.VLINK_ALLOWED_TARGET_HOSTS;
    else process.env.VLINK_ALLOWED_TARGET_HOSTS = previous;
  }
});


test("every real VLink activity produces an Ed25519 signed receipt with matching event identity", async () => {
  const { created, receipt } = await createSignedTestReceipt();
  assert.equal(receipt.version, "vlink-receipt/v1");
  assert.equal(receipt.algorithm, "Ed25519");
  assert.equal(receipt.digestAlgorithm, "SHA-256");
  assert.equal(receipt.vlinkId, created.vlink.vlinkId);
  assert.equal(receipt.eventId, receipt.payload.eventId);
  assert.match(receipt.payloadHash, /^sha256:[a-f0-9]{64}$/);
  assert.match(receipt.keyId, /^vkey_sha256_[a-f0-9]{64}$/);
  assert.ok(receipt.signature.length > 40);
});


test("a receipt verifies independently with raw Node Ed25519 using only the embedded public key", async () => {
  const { receipt } = await createSignedTestReceipt();
  const { signature, ...unsigned } = receipt;
  const publicKey = createPublicKey({ key: receipt.publicKeyJwk as never, format: "jwk" });
  const valid = ed25519Verify(
    null,
    Buffer.from(canonicalizeVLinkJson(unsigned)),
    publicKey,
    Buffer.from(signature, "base64url"),
  );
  assert.equal(valid, true);
});


test("mutating a signed receipt payload makes verification fail", async () => {
  const { receipt } = await createSignedTestReceipt();
  const tampered = structuredClone(receipt) as VLinkSignedReceipt;
  tampered.payload.status = tampered.payload.status === "completed" ? "failed" : "completed";

  const response = await fetch(`${base}/receipts/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ receipt: tampered }),
  });
  assert.equal(response.status, 200);
  const verification = await response.json() as { valid: boolean; payloadHashValid: boolean; signatureValid: boolean };
  assert.equal(verification.valid, false);
  assert.equal(verification.payloadHashValid, false);
  assert.equal(verification.signatureValid, false);
});


test("changing the public key fingerprint or pinning the wrong key fails verification", async () => {
  const { receipt } = await createSignedTestReceipt();
  const wrongFingerprint = structuredClone(receipt) as VLinkSignedReceipt;
  wrongFingerprint.keyId = `vkey_sha256_${"0".repeat(64)}`;

  const changedKey = await fetch(`${base}/receipts/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ receipt: wrongFingerprint }),
  });
  const changedKeyResult = await changedKey.json() as { valid: boolean; keyIdValid: boolean };
  assert.equal(changedKeyResult.valid, false);
  assert.equal(changedKeyResult.keyIdValid, false);

  const wrongPin = await fetch(`${base}/receipts/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ receipt, expectedKeyId: `vkey_sha256_${"f".repeat(64)}` }),
  });
  const wrongPinResult = await wrongPin.json() as { valid: boolean; expectedKeyMatched: boolean };
  assert.equal(wrongPinResult.valid, false);
  assert.equal(wrongPinResult.expectedKeyMatched, false);
});


test("receipt key descriptor matches receipts and explicitly discloses ephemeral trust when no operator key is configured", async () => {
  const { receipt } = await createSignedTestReceipt();
  const response = await fetch(`${base}/.well-known/vlink-receipt-key.json`);
  assert.equal(response.status, 200);
  const descriptor = await response.json() as { keyId: string; algorithm: string; persistence: string; trustNote: string };
  assert.equal(descriptor.keyId, receipt.keyId);
  assert.equal(descriptor.algorithm, "Ed25519");
  assert.equal(descriptor.persistence, "ephemeral");
  assert.ok(descriptor.trustNote.includes("ephemeral"));
});


test("receipt retrieval requires VLink authority and signed receipts never contain the bearer token", async () => {
  const { created, credential, receipt } = await createSignedTestReceipt();
  const denied = await fetch(`${base}/receipts/vlinks/${created.vlink.vlinkId}`);
  assert.equal(denied.status, 401);

  const allowed = await fetch(`${base}/receipts/vlinks/${created.vlink.vlinkId}`, {
    headers: bearer(credential.token),
  });
  assert.equal(allowed.status, 200);
  const text = await allowed.text();
  assert.equal(text.includes(credential.token), false);
  assert.equal(text.includes(receipt.receiptId), true);
  assert.equal(JSON.stringify(receipt).includes(credential.token), false);
});
