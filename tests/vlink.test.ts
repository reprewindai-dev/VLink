import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import type { AddressInfo } from "node:net";
import { createApp } from "../src/server/app";
import { InMemoryVLinkRegistry } from "../src/server/vlinkRegistry";

const registry = new InMemoryVLinkRegistry();
const { app } = createApp({ registry, publicOrigin: "https://connect.example.test", enableDemoResponses: true });
let base = "";
let server: ReturnType<typeof app.listen>;

before(async () => {
  server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
});

async function createVLink() {
  const response = await fetch(`${base}/api/v1/vlinks`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ workspaceId: "ws-test", environment: "development", displayName: "Test Link", sourceType: "ai-client" }),
  });
  assert.equal(response.status, 201);
  return (await response.json()).vlink as { vlinkId: string };
}

test("VLink creation and retrieval", async () => {
  const created = await createVLink();
  const response = await fetch(`${base}/api/v1/vlinks/${created.vlinkId}`);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.vlink.vlinkId, created.vlinkId);
  assert.equal(body.vlink.mode, "observe");
});

test("manifest contains no reusable secrets", async () => {
  const created = await createVLink();
  const response = await fetch(`${base}/api/v1/vlinks/${created.vlinkId}/manifest`);
  const text = await response.text();
  assert.equal(response.status, 200);
  for (const forbidden of ["api_key", "apikey", "bearer ", "oneTimeCode", "privateKey", "secret"]) {
    assert.equal(text.toLowerCase().includes(forbidden.toLowerCase()), false, forbidden);
  }
});

test("expired pairing cannot complete", () => {
  const record = registry.create({ workspaceId: "ws", environment: "dev", displayName: "Expired", sourceType: "local-project" }, "https://connect.example.test");
  const started = new Date("2026-08-30T20:00:00Z");
  const pairing = registry.createPairing(record.vlinkId, "https://connect.example.test", 1, started)!;
  const result = registry.completePairing(record.vlinkId, pairing.pairingId, pairing.oneTimeCode, new Date("2026-08-30T20:00:02Z"));
  assert.equal(result, undefined);
  assert.equal(registry.getPairing(record.vlinkId, pairing.pairingId, new Date("2026-08-30T20:00:02Z"))?.status, "expired");
});

test("invalid VLink ID cannot attach to OpenAI activity", async () => {
  const response = await fetch(`${base}/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-vlink-id": "vlk_does_not_exist" },
    body: JSON.stringify({ model: "demo", messages: [{ role: "user", content: "hello" }] }),
  });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, "invalid_vlink_id");
});

test("test action creates a VLink-bound activity event", async () => {
  const created = await createVLink();
  const testResponse = await fetch(`${base}/api/v1/vlinks/${created.vlinkId}/test`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  assert.equal(testResponse.status, 200);
  const activityResponse = await fetch(`${base}/api/v1/vlinks/${created.vlinkId}/activity`);
  const body = await activityResponse.json();
  assert.equal(body.events.length, 1);
  assert.equal(body.events[0].vlinkId, created.vlinkId);
  assert.equal(body.events[0].metadata.cryptographicReceipt, false);
});

test("OpenAI-compatible demo route still works and is explicitly labeled demo", async () => {
  const created = await createVLink();
  const response = await fetch(`${base}/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-vlink-id": created.vlinkId },
    body: JSON.stringify({ model: "demo", messages: [{ role: "user", content: "hello" }] }),
  });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.object, "chat.completion");
  assert.equal(body.metadata.executionMode, "demo");
  const events = registry.activity(created.vlinkId);
  assert.equal(events[0].route, "/v1/chat/completions");
});

test("existing webhook route works and validates optional VLink binding", async () => {
  const created = await createVLink();
  const ok = await fetch(`${base}/api/v1/webhooks/zapier-test`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-vlink-id": created.vlinkId },
    body: JSON.stringify({ hello: "world" }),
  });
  assert.equal(ok.status, 202);
  assert.equal((await ok.json()).vlinkId, created.vlinkId);

  const bad = await fetch(`${base}/api/v1/webhooks/zapier-test`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-vlink-id": "vlk_invalid" },
    body: "{}",
  });
  assert.equal(bad.status, 400);
});
