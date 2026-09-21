import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { request, type Server } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { createApp } from "../src/server/app";
import { FileBackedVLinkRegistry } from "../src/server/fileBackedRegistry";
import { createLeaseSealer } from "../src/server/leaseSealer";
import { InMemoryVLinkRegistry } from "../src/server/vlinkRegistry";

const key = "11".repeat(32);

type HttpResult = { status: number; body: Record<string, any> };

const httpJson = (server: Server, requestPath: string, init: { method?: string; headers?: Record<string, string>; body?: unknown } = {}) =>
  new Promise<HttpResult>((resolve, reject) => {
    const address = server.address();
    if (!address || typeof address === "string") return reject(new Error("server is not listening"));
    const req = request(
      {
        host: "127.0.0.1",
        port: address.port,
        path: requestPath,
        method: init.method ?? "GET",
        headers: {
          ...(init.body === undefined ? {} : { "content-type": "application/json" }),
          ...(init.body === undefined ? {} : { "content-length": Buffer.byteLength(JSON.stringify(init.body)) }),
          ...(init.headers ?? {}),
        },
      },
      (response: import("node:http").IncomingMessage) => {
        let payload = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => (payload += chunk));
        response.on("end", () => resolve({ status: response.statusCode ?? 0, body: payload ? JSON.parse(payload) : {} }));
      },
    );
    req.on("error", reject);
    if (init.body !== undefined) req.write(JSON.stringify(init.body));
    req.end();
  });

const listen = async (app: ReturnType<typeof createApp>) => {
  const server = app.app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return server;
};

const setup = async (fileBacked = false, sealing = true) => {
  if (sealing) process.env.VLINK_LEASE_SEALING_KEY = key;
  else delete process.env.VLINK_LEASE_SEALING_KEY;
  process.env.VLINK_CAPI_BASE_URL = "http://capi.test";
  const dir = fileBacked ? mkdtempSync(path.join(tmpdir(), "vlink-lease-test-")) : undefined;
  const registry = fileBacked
    ? new FileBackedVLinkRegistry({ statePath: path.join(dir!, "state.json") })
    : new InMemoryVLinkRegistry();
  const app = createApp({ registry, allowUnauthenticatedCreate: true });
  const server = await listen(app);
  const vlink = registry.create(
    { workspaceId: "workspace-1", environment: "test", displayName: "Lease test", sourceType: "container" },
    "http://vlink.test",
  );
  const enrollment = registry.issueEnrollmentGrant(vlink.vlinkId)!;
  const pairing = registry.createPairing(vlink.vlinkId, "http://vlink.test")!;
  registry.approvePairing(vlink.vlinkId, pairing.pairingId, pairing.approvalCode);
  const access = registry.exchangePairing(vlink.vlinkId, pairing.pairingId, pairing.deviceCode)!;
  const close = async () => {
    await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    if (dir) rmSync(dir, { recursive: true, force: true });
  };
  return { app, server, registry, vlink, enrollment, access, close, statePath: dir && path.join(dir, "state.json") };
};

const leaseInput = {
  mountId: "mount-1",
  tokenId: "token-1",
  nonce: "nonce-1",
  holderCredential: "vlm_mount-1.secret",
  packageRef: "veklom.governed-counter@v1",
  workspace: "workspace-1",
  project: "project-1",
  targetRef: "activation.governed-counter",
  allowedActions: ["counter.increment"],
  blockedActions: ["counter.reset"],
  expiresAt: "2099-01-01T00:00:00.000Z",
};

const bind = async (h: Awaited<ReturnType<typeof setup>>) =>
  httpJson(h.server, `/api/v1/vlinks/${h.vlink.vlinkId}/leases`, {
    method: "POST",
    headers: { authorization: `Bearer ${h.enrollment.token}` },
    body: leaseInput,
  });

test("lease binding requires enrollment and configured sealing without disclosing the holder credential", async () => {
  const h = await setup(true);
  try {
    const bound = await bind(h);
    assert.equal(bound.status, 201);
    assert.equal(bound.body.lease.holderCredentialDisclosed, false);
    assert.equal(JSON.stringify(bound.body).includes("vlm_mount-1.secret"), false);
    const raw = readFileSync(h.statePath!, "utf8");
    assert.equal(raw.includes("vlm_mount-1.secret"), false);
    const restarted = new FileBackedVLinkRegistry({ statePath: h.statePath! });
    restarted.configureLeaseSealer(createLeaseSealer());
    assert.equal(restarted.listLeases(h.vlink.vlinkId)[0]?.leaseId, bound.body.lease.leaseId);

    const denied = await httpJson(h.server, `/api/v1/vlinks/${h.vlink.vlinkId}/leases`, {
      method: "POST",
      headers: { authorization: `Bearer ${h.access.token}` },
      body: leaseInput,
    });
    assert.equal(denied.status, 401);
  } finally {
    await h.close();
  }

  const previous = process.env.VLINK_LEASE_SEALING_KEY;
  const noSeal = await setup(false, false);
  try {
    const result = await bind(noSeal);
    assert.equal(result.status, 503);
    assert.equal(result.body.error, "lease_sealing_unconfigured");
  } finally {
    await noSeal.close();
    if (previous) process.env.VLINK_LEASE_SEALING_KEY = previous;
  }
});

test("machine actions relay the holder credential and exact Interlink path", async () => {
  const h = await setup();
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    calls.push({ url: String(input), init });
    return new Response(JSON.stringify({ decision: "allow", reason: "allowed" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  try {
    const bound = await bind(h);
    const result = await httpJson(h.server, `/api/v1/vlinks/${h.vlink.vlinkId}/leases/${bound.body.lease.leaseId}/actions`, {
      method: "POST",
      headers: { authorization: `Bearer ${h.access.token}` },
      body: { action: "counter.increment", resource: "counter" },
    });
    assert.equal(result.status, 200);
    assert.equal(calls[0]?.url, "http://capi.test/api/v1/capi/interlink/capability/mounts/mount-1/actions");
    assert.equal(new Headers(calls[0]?.init?.headers).get("authorization"), "Bearer vlm_mount-1.secret");
  } finally {
    globalThis.fetch = originalFetch;
    await h.close();
  }
});

test("execute allow terminates the lease and records CAPPO anchoring", async () => {
  const h = await setup();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ decision: "allow", reason: "allowed", anchoring: { status: "confirmed" }, receipt: { content_hash: "sha256:abc" } }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  try {
    const bound = await bind(h);
    const result = await httpJson(h.server, `/api/v1/vlinks/${h.vlink.vlinkId}/leases/${bound.body.lease.leaseId}/execute`, {
      method: "POST",
      headers: { authorization: `Bearer ${h.access.token}` },
      body: { action: "counter.increment", resource: "counter", arguments: {} },
    });
    assert.equal(result.body.lease.status, "terminated");
    assert.equal(h.registry.activity(h.vlink.vlinkId)[0]?.metadata.evidenceType, "cappo-governed-consequence");
    assert.deepEqual(h.registry.activity(h.vlink.vlinkId)[0]?.metadata.anchoring, { status: "confirmed" });
  } finally {
    globalThis.fetch = originalFetch;
    await h.close();
  }
});

test("state readback remains relayable after execute termination", async () => {
  const h = await setup();
  const calls: string[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    calls.push(String(input));
    return new Response(JSON.stringify({ state: { value: 1 } }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  try {
    const bound = await bind(h);
    const result = await httpJson(h.server, `/api/v1/vlinks/${h.vlink.vlinkId}/leases/${bound.body.lease.leaseId}/state?resource=counter`, {
      headers: { authorization: `Bearer ${h.access.token}` },
    });
    assert.equal(result.status, 200);
    assert.equal(calls[0], "http://capi.test/api/v1/capi/interlink/capability/targets/activation.governed-counter/state?resource=counter&mount_id=mount-1");
  } finally {
    globalThis.fetch = originalFetch;
    await h.close();
  }
});

test("revoke relays terminate and marks the lease terminated", async () => {
  const h = await setup();
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    calls.push({ url: String(input), init });
    return new Response(JSON.stringify({ decision: "allow" }), { status: 200, headers: { "content-type": "application/json" } });
  };
  try {
    const bound = await bind(h);
    const result = await httpJson(h.server, `/api/v1/vlinks/${h.vlink.vlinkId}/leases/${bound.body.lease.leaseId}/revoke`, {
      method: "POST",
      headers: { authorization: `Bearer ${h.enrollment.token}` },
    });
    assert.equal(result.status, 200);
    assert.equal(result.body.lease.status, "terminated");
    assert.equal(calls[0]?.url, "http://capi.test/api/v1/capi/interlink/capability/mounts/mount-1/terminate");
    assert.deepEqual(JSON.parse(String(calls[0]?.init?.body)), { reason: "explicit_terminate" });
  } finally {
    globalThis.fetch = originalFetch;
    await h.close();
  }
});

test("CAPPO holder revocation response flips the lease status", async () => {
  const h = await setup();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ error: "HOLDER_CREDENTIAL_REVOKED" }), {
      status: 401,
      headers: { "content-type": "application/json" },
    });
  try {
    const bound = await bind(h);
    const result = await httpJson(h.server, `/api/v1/vlinks/${h.vlink.vlinkId}/leases/${bound.body.lease.leaseId}/actions`, {
      method: "POST",
      headers: { authorization: `Bearer ${h.access.token}` },
      body: { action: "counter.increment", resource: "counter" },
    });
    assert.equal(result.status, 401);
    assert.equal(result.body.lease.status, "terminated");
  } finally {
    globalThis.fetch = originalFetch;
    await h.close();
  }
});
