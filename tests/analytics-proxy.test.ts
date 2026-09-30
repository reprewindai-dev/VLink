import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import express from "express";
import { installAnalyticsProxy } from "../src/server/analyticsProxy";

async function withServer(
  fetchImpl: typeof fetch,
  base: string,
  run: (origin: string) => Promise<void>,
) {
  const app = express();
  app.use(express.json({ limit: "2mb" }));
  installAnalyticsProxy(app, { lockerPhycerBaseUrl: base, fetchImpl });
  const server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  try {
    await run(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test("relays analytics beacons without cookies or origin, keeping privacy headers", async () => {
  const seen: Array<{ url: string; init: RequestInit }> = [];
  const fetchImpl = (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    return new Response(JSON.stringify({ accepted: 1, dropped: 0, mode: "aggregate" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;

  await withServer(fetchImpl, "http://lockerphycer-api:8092/", async (origin) => {
    const body = JSON.stringify({ v: 1, host: "vlink", events: [{ name: "page_view", path: "/" }] });
    const res = await fetch(`${origin}/api/v1/analytics/events`, {
      method: "POST",
      body,
      headers: {
        "content-type": "text/plain;charset=UTF-8",
        cookie: "veklom.session=present",
        origin: "https://vlink.veklom.com",
        "sec-gpc": "1",
        "cf-ipcountry": "US",
      },
    });
    assert.equal(res.status, 200);
    assert.equal((await res.json()).mode, "aggregate");
    const cfg = await fetch(`${origin}/api/v1/analytics/config?consent=granted`);
    assert.equal(cfg.status, 200);
  });

  assert.equal(seen[0].url, "http://lockerphycer-api:8092/api/v1/analytics/events");
  const headers = seen[0].init.headers as Record<string, string>;
  assert.equal(headers["sec-gpc"], "1");
  assert.equal(headers["cf-ipcountry"], "US");
  assert.equal(headers.cookie, undefined);
  assert.equal(headers.origin, undefined);
  assert.equal(seen[0].init.body, JSON.stringify({ v: 1, host: "vlink", events: [{ name: "page_view", path: "/" }] }));
  assert.equal(seen[1].url, "http://lockerphycer-api:8092/api/v1/analytics/config?consent=granted");
});

test("answers 503 when LockerPhycer is not configured", async () => {
  const fetchImpl = (async () => {
    throw new Error("must not be called");
  }) as unknown as typeof fetch;
  await withServer(fetchImpl, "", async (origin) => {
    const res = await fetch(`${origin}/api/v1/analytics/events`, { method: "POST", body: "{}" });
    assert.equal(res.status, 503);
  });
});
