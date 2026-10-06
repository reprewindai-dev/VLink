import assert from "node:assert/strict";
import { test } from "node:test";
import { disabledOptionalFeatures, missingProductionConfig } from "../src/server/startupConfig";

const productionReady = {
  NODE_ENV: "production",
  VLINK_STATE_PATH: "/app/data/vlink-state.json",
  VLINK_LOCKERPHYCER_URL: "https://locker.example.test",
  VLINK_LEASE_SEALING_KEY: "ab".repeat(32),
};

test("production startup fails closed on each required setting with a message naming it", () => {
  const missing = missingProductionConfig({ NODE_ENV: "production" });
  assert.equal(missing.length, 3);
  assert.match(missing[0], /^VLINK_STATE_PATH is required in production/);
  assert.match(missing[1], /^VLINK_LOCKERPHYCER_URL \(or LOCKERPHYCER_URL\) is required in production/);
  assert.match(missing[2], /^VLINK_LEASE_SEALING_KEY must be a valid 32-byte base64 or 64-character hex key/);

  assert.deepEqual(missingProductionConfig(productionReady), []);
  assert.deepEqual(missingProductionConfig({ ...productionReady, VLINK_LOCKERPHYCER_URL: "", LOCKERPHYCER_URL: "https://locker.example.test" }), []);
  assert.equal(missingProductionConfig({ ...productionReady, VLINK_STATE_PATH: "   " }).length, 1);
  assert.equal(missingProductionConfig({ ...productionReady, VLINK_LEASE_SEALING_KEY: "too-short" }).length, 1);
});

test("the device-flow key stays optional and its absence is reported as a disabled feature", () => {
  assert.deepEqual(missingProductionConfig(productionReady), [], "no VLINK_DEVICE_FLOW_ENCRYPTION_KEY must not block startup");
  const disabled = disabledOptionalFeatures(productionReady);
  const deviceFlow = disabled.filter((line) => line.includes("VLINK_DEVICE_FLOW_ENCRYPTION_KEY"));
  assert.equal(deviceFlow.length, 1);
  assert.match(deviceFlow[0], /^device authorization flow disabled: .*503/);
  assert.equal(disabledOptionalFeatures({ ...productionReady, VLINK_DEVICE_FLOW_ENCRYPTION_KEY: "x".repeat(32) }).some((line) => line.includes("VLINK_DEVICE_FLOW_ENCRYPTION_KEY")), false);
});

test("every disabled optional feature is reported on its own line naming its variable", () => {
  const disabled = disabledOptionalFeatures({ NODE_ENV: "production" });
  for (const name of [
    "VLINK_DEVICE_FLOW_ENCRYPTION_KEY",
    "VLINK_LEASE_SEALING_KEY",
    "VLINK_CAPI_BASE_URL",
    "VLINK_RECEIPT_PRIVATE_KEY_PEM",
    "VLINK_ANONYMOUS_BOOTSTRAP_ENABLED",
    "VLINK_ALLOWED_TARGET_HOSTS",
    "GEMINI_API_KEY",
  ]) {
    assert.equal(disabled.filter((line) => line.includes(name)).length, 1, name);
  }
  assert.ok(disabled.every((line) => !line.includes("\n")));
  const everythingOn = disabledOptionalFeatures({
    ...productionReady,
    VLINK_DEVICE_FLOW_ENCRYPTION_KEY: "x".repeat(32),
    VLINK_CAPI_BASE_URL: "http://capi.internal:3003",
    VLINK_RECEIPT_PRIVATE_KEY_PEM: "-----BEGIN PRIVATE KEY-----",
    VLINK_ANONYMOUS_BOOTSTRAP_ENABLED: "true",
    VLINK_ALLOWED_TARGET_HOSTS: "api.example.test",
    GEMINI_API_KEY: "key",
  });
  assert.deepEqual(everythingOn, []);
});
