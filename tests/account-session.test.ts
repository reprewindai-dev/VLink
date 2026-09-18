import assert from "node:assert/strict";
import test from "node:test";
import { readAccountToken, resolveOwnedWorkspace } from "../src/account-session";

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
