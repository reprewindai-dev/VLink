import { createLeaseSealer } from "./leaseSealer";

type Env = Record<string, string | undefined>;

const isSet = (env: Env, name: string) => Boolean(env[name]?.trim());

/**
 * Settings without which a production VLink must not start. Each entry is a complete,
 * operator-facing sentence naming the variable and why it is required.
 */
export const missingProductionConfig = (env: Env): string[] => {
  const missing: string[] = [];
  if (!isSet(env, "VLINK_STATE_PATH")) {
    missing.push("VLINK_STATE_PATH is required in production so VLink identity and access state survive process restarts");
  }
  if (!isSet(env, "VLINK_LOCKERPHYCER_URL") && !isSet(env, "LOCKERPHYCER_URL")) {
    missing.push("VLINK_LOCKERPHYCER_URL (or LOCKERPHYCER_URL) is required in production for workspace identity and approval");
  }
  if (!createLeaseSealer(env.VLINK_LEASE_SEALING_KEY)) {
    missing.push("VLINK_LEASE_SEALING_KEY must be a valid 32-byte base64 or 64-character hex key in production for recoverable device exchange");
  }
  return missing;
};

/**
 * Optional capabilities that are switched off by the current environment, one line each,
 * so a deployment log states exactly which runtime 503s/fallbacks are expected.
 */
export const disabledOptionalFeatures = (env: Env): string[] => {
  const disabled: string[] = [];
  if (!isSet(env, "VLINK_DEVICE_FLOW_ENCRYPTION_KEY")) {
    disabled.push("device authorization flow disabled: VLINK_DEVICE_FLOW_ENCRYPTION_KEY is not set (/api/v1/device/authorizations answers 503)");
  }
  if (!isSet(env, "VLINK_LEASE_SEALING_KEY")) {
    disabled.push("recoverable device exchange and governed leases disabled: VLINK_LEASE_SEALING_KEY is not set");
  }
  if (!isSet(env, "VLINK_CAPI_BASE_URL")) {
    disabled.push("governed CAPPO lease relay disabled: VLINK_CAPI_BASE_URL is not set");
  }
  if (!isSet(env, "VLINK_RECEIPT_PRIVATE_KEY_PEM")) {
    disabled.push("stable receipt signing identity disabled: VLINK_RECEIPT_PRIVATE_KEY_PEM is not set (an ephemeral process key signs receipts)");
  }
  if (env.NODE_ENV === "production" && env.VLINK_ANONYMOUS_BOOTSTRAP_ENABLED !== "true") {
    disabled.push("anonymous device bootstrap disabled: VLINK_ANONYMOUS_BOOTSTRAP_ENABLED is not \"true\"");
  }
  if (!isSet(env, "VLINK_ALLOWED_TARGET_HOSTS")) {
    disabled.push("custom and failover HTTP targets disabled: VLINK_ALLOWED_TARGET_HOSTS is empty");
  }
  if (!isSet(env, "GEMINI_API_KEY")) {
    disabled.push("live Gemini chat completions disabled: GEMINI_API_KEY is not set");
  }
  return disabled;
};
