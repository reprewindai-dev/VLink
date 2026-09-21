export interface RelayResult {
  status: number;
  body: unknown;
}

export interface ActionRelayInput {
  token_id: string;
  nonce: string;
  action: string;
  resource: string;
}

export interface ExecuteRelayInput {
  token_id: string;
  nonce: string;
  action: string;
  target_ref: string;
  resource: string;
  arguments?: Record<string, unknown>;
  operation_id?: string;
}

export interface TerminateRelayInput {
  token_id: string;
  nonce: string;
}

const relay = async (
  path: string,
  holderCredential: string,
  init: RequestInit,
): Promise<RelayResult> => {
  const configured = process.env.VLINK_CAPI_BASE_URL?.trim().replace(/\/$/, "");
  if (!configured) return { status: 503, body: { error: "capi_unconfigured" } };

  const controller = new AbortController();
  let timedOut = false;
  const timeoutId = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, 10_000);
  try {
    const response = await fetch(`${configured}/api/v1/capi/interlink/capability${path}`, {
      ...init,
      signal: controller.signal,
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${holderCredential}`,
        ...(init.headers ?? {}),
      },
    });
    const contentType = response.headers.get("content-type") ?? "";
    const body = contentType.includes("application/json") ? await response.json() : await response.text();
    return { status: response.status, body };
  } catch (error) {
    if (timedOut || (error instanceof DOMException && error.name === "AbortError")) {
      return { status: 504, body: { error: "cappo_timeout" } };
    }
    return { status: 503, body: { error: "cappo_unreachable" } };
  } finally {
    clearTimeout(timeoutId);
  }
};

const post = (path: string, holderCredential: string, body: unknown) =>
  relay(path, holderCredential, { method: "POST", body: JSON.stringify(body) });

export const evaluateAction = (
  mountId: string,
  holderCredential: string,
  input: ActionRelayInput,
) => post(`/mounts/${encodeURIComponent(mountId)}/actions`, holderCredential, input);

export const execute = (
  mountId: string,
  holderCredential: string,
  input: ExecuteRelayInput,
) => post(`/mounts/${encodeURIComponent(mountId)}/execute`, holderCredential, input);

export const readState = (mountId: string, holderCredential: string, targetRef: string, resource: string) => {
  const query = new URLSearchParams({ resource, mount_id: mountId });
  return relay(
    `/targets/${encodeURIComponent(targetRef)}/state?${query.toString()}`,
    holderCredential,
    { method: "GET" },
  );
};

export const terminate = (mountId: string, holderCredential: string, input: TerminateRelayInput) => {
  void input;
  return post(`/mounts/${encodeURIComponent(mountId)}/terminate`, holderCredential, { reason: "explicit_terminate" });
};
