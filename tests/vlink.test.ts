import assert from "node:assert/strict";
import { createPublicKey, verify as ed25519Verify } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { createApp } from "../src/server/app";
import { canonicalizeVLinkJson } from "../src/server/receiptSigner";
import { installReceiptSupport } from "../src/server/receiptSupport";
import { InMemoryVLinkRegistry } from "../src/server/vlinkRegistry";
import type { VLinkSignedReceipt } from "../src/types/vlink";

const registry = new InMemoryVLinkRegistry();
const { app } = createApp({
  registry,
  publicOrigin: "https://connect.example.test",
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
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ approvalCode: pairing.approvalCode }),
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
    assert.equal(response.status, 403);
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


test("browser approval is one-time and does not itself mint a workload credential", async () => {
  const created = await createVLink();
  const pairing = await createPairing(created);
  const approve = () => fetch(`${base}/api/v1/vlinks/${created.vlink.vlinkId}/pairing/${pairing.pairingId}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ approvalCode: pairing.approvalCode }),
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
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ approvalCode: pairing.approvalCode }),
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
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ approvalCode: pairing.approvalCode }),
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
