import assert from "node:assert/strict";
import test from "node:test";
import { readAccountToken, resolveOwnedWorkspace, resolveWorkspaceWallet, shortWalletAddress } from "../src/account-session";

test("account token uses the canonical frontend key and keeps the compatibility key", () => {
  const values = new Map([
    ["veklom.access_token", "canonical-token"],
    ["veklom_token", "compatibility-token"],
  ]);
  assert.equal(readAccountToken({ getItem: (key) => values.get(key) ?? null }), "canonical-token");
  values.delete("veklom.access_token");
  assert.equal(readAccountToken({ getItem: (key) => values.get(key) ?? null }), "compatibility-token");
});

test("workspace resolution calls LockerPhycer's implemented same-origin route with the account bearer", async () => {
  let observedUrl = "";
  let observedAuthorization = "";
  const request: typeof fetch = async (input, init) => {
    observedUrl = String(input);
    observedAuthorization = new Headers(init?.headers).get("authorization") ?? "";
    return new Response(JSON.stringify({ id: "workspace-1", name: "Primary workspace" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  const workspace = await resolveOwnedWorkspace("account-token", request);
  assert.deepEqual(workspace, { id: "workspace-1", name: "Primary workspace" });
  assert.equal(observedUrl, "/api/v1/workspace/me");
  assert.equal(observedAuthorization, "Bearer account-token");
});

test("workspace resolution fails closed when onboarding has not bound a workspace", async () => {
  const request: typeof fetch = async () => new Response(
    JSON.stringify({ detail: "No workspace bound to this operator" }),
    { status: 404, headers: { "content-type": "application/json" } },
  );

  await assert.rejects(
    resolveOwnedWorkspace("account-token", request),
    /No workspace bound to this operator/,
  );
});

test("workspace resolution rejects malformed success payloads", async () => {
  const request: typeof fetch = async () => new Response(
    JSON.stringify({ workspaces: [{ id: "wrong-shape" }] }),
    { status: 200, headers: { "content-type": "application/json" } },
  );

  await assert.rejects(resolveOwnedWorkspace("account-token", request), /Workspace response is invalid/);
});

test("wallet lookup reuses the workspace wallet from LockerPhycer's same-origin route", async () => {
  let observedUrl = "";
  let observedAuthorization = "";
  const request: typeof fetch = async (input, init) => {
    observedUrl = String(input);
    observedAuthorization = new Headers(init?.headers).get("authorization") ?? "";
    return new Response(JSON.stringify({
      workspace_id: "workspace-1", network: "base-sepolia", chain_id: 84532, name: "Base Sepolia", testnet: true,
      wallet: { address: "0x1234567890abcdef1234567890abcdef12345678", chain_id: 84532, source: "created" },
    }), { status: 200, headers: { "content-type": "application/json" } });
  };
  const lookup = await resolveWorkspaceWallet("account-token", request);
  assert.equal(observedUrl, "/api/v1/wallet");
  assert.equal(observedAuthorization, "Bearer account-token");
  assert.deepEqual(lookup, {
    status: "bound",
    wallet: { address: "0x1234567890abcdef1234567890abcdef12345678", chainId: 84532, networkName: "Base Sepolia", testnet: true, source: "created" },
  });
  assert.equal(shortWalletAddress("0x1234567890abcdef1234567890abcdef12345678"), "0x1234…5678");
});

test("wallet lookup reports none without blocking, and degrades on errors", async () => {
  const none: typeof fetch = async () => new Response(
    JSON.stringify({ name: "Base", testnet: false, wallet: null }), { status: 200, headers: { "content-type": "application/json" } });
  assert.deepEqual(await resolveWorkspaceWallet("t", none), { status: "none", networkName: "Base", testnet: false });

  const missing: typeof fetch = async () => new Response(
    JSON.stringify({ error: "Route not found in proxy table" }), { status: 404, headers: { "content-type": "application/json" } });
  assert.deepEqual(await resolveWorkspaceWallet("t", missing), { status: "unavailable", reason: "Route not found in proxy table" });

  const down: typeof fetch = async () => { throw new TypeError("fetch failed"); };
  assert.deepEqual(await resolveWorkspaceWallet("t", down), { status: "unavailable", reason: "Wallet service unreachable" });

  const malformed: typeof fetch = async () => new Response(
    JSON.stringify({ wallet: { address: "not-an-address", chain_id: 1 } }), { status: 200, headers: { "content-type": "application/json" } });
  assert.equal((await resolveWorkspaceWallet("t", malformed)).status, "unavailable");
});
