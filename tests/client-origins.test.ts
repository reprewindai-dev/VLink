import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveAccountOrigin, resolveApiOrigin } from "../src/client/origins";

test("API origin keeps the veklom.com defaults when nothing is configured", () => {
  assert.equal(resolveApiOrigin("veklom.com"), "https://vlink.veklom.com");
  assert.equal(resolveApiOrigin("www.veklom.com"), "https://vlink.veklom.com");
  assert.equal(resolveApiOrigin("vlink.veklom.com"), "");
  assert.equal(resolveApiOrigin("localhost"), "");
});

test("API origin honours a configured VLINK_PUBLIC_ORIGIN on every host", () => {
  assert.equal(resolveApiOrigin("veklom.com", "https://vlink.staging.example.test/"), "https://vlink.staging.example.test");
  assert.equal(resolveApiOrigin("localhost", "http://127.0.0.1:3000"), "http://127.0.0.1:3000");
  assert.equal(resolveApiOrigin("veklom.com", "   "), "https://vlink.veklom.com", "blank configuration falls back to the default");
});

test("account origin keeps its default and honours VLINK_ACCOUNT_ORIGIN", () => {
  assert.equal(resolveAccountOrigin("vlink.veklom.com"), "https://veklom.com");
  assert.equal(resolveAccountOrigin("veklom.com"), "");
  assert.equal(resolveAccountOrigin("localhost"), "");
  assert.equal(resolveAccountOrigin("localhost", "https://app.staging.example.test/"), "https://app.staging.example.test");
  assert.equal(resolveAccountOrigin("vlink.veklom.com", ""), "https://veklom.com");
});
