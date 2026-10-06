export type OwnedWorkspace = {
  id: string;
  name: string;
};

type TokenStorage = Pick<Storage, "getItem">;

export function readAccountToken(storage: TokenStorage): string | null {
  return storage.getItem("veklom.access_token") || storage.getItem("veklom_token");
}

function errorMessage(payload: unknown, status: number): string {
  if (payload && typeof payload === "object") {
    const body = payload as Record<string, unknown>;
    for (const key of ["detail", "message", "error"]) {
      if (typeof body[key] === "string" && body[key]) return body[key];
    }
  }
  return `HTTP ${status}`;
}

export async function resolveOwnedWorkspace(
  token: string,
  request: typeof fetch = fetch,
): Promise<OwnedWorkspace> {
  const response = await request("/api/v1/workspace/me", {
    headers: { authorization: `Bearer ${token}` },
  });
  const payload: unknown = await response.json();
  if (!response.ok) throw new Error(errorMessage(payload, response.status));
  if (!payload || typeof payload !== "object") throw new Error("Workspace response is invalid");

  const workspace = payload as Record<string, unknown>;
  if (typeof workspace.id !== "string" || !workspace.id || typeof workspace.name !== "string" || !workspace.name) {
    throw new Error("Workspace response is invalid");
  }
  return { id: workspace.id, name: workspace.name };
}

export type WorkspaceWallet = {
  address: string;
  chainId: number;
  networkName: string;
  testnet: boolean;
  source: "created" | "connected";
};

export type WorkspaceWalletLookup =
  | { status: "bound"; wallet: WorkspaceWallet }
  | { status: "none"; networkName: string; testnet: boolean }
  | { status: "unavailable"; reason: string };

/**
 * The wallet is bound once to the workspace in Capability OS (LockerPhycer
 * /api/v1/wallet). VLink only reads it, so onboarding never repeats per
 * connection. A lookup failure never blocks connecting: a wallet is required
 * only before paid or externally settled actions.
 */
export async function resolveWorkspaceWallet(
  token: string,
  request: typeof fetch = fetch,
): Promise<WorkspaceWalletLookup> {
  let response: Response;
  try {
    response = await request("/api/v1/wallet", { headers: { authorization: `Bearer ${token}` } });
  } catch {
    return { status: "unavailable", reason: "Wallet service unreachable" };
  }
  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) return { status: "unavailable", reason: errorMessage(payload, response.status) };
  if (!payload || typeof payload !== "object") return { status: "unavailable", reason: "Wallet response is invalid" };
  const body = payload as Record<string, unknown>;
  const networkName = typeof body.name === "string" ? body.name : "Base";
  const testnet = body.testnet === true;
  const wallet = body.wallet as Record<string, unknown> | null | undefined;
  if (!wallet) return { status: "none", networkName, testnet };
  if (typeof wallet.address !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(wallet.address) || typeof wallet.chain_id !== "number") {
    return { status: "unavailable", reason: "Wallet response is invalid" };
  }
  return {
    status: "bound",
    wallet: {
      address: wallet.address,
      chainId: wallet.chain_id,
      networkName,
      testnet,
      source: wallet.source === "created" ? "created" : "connected",
    },
  };
}

export function shortWalletAddress(address: string): string {
  return address.length > 12 ? `${address.slice(0, 6)}…${address.slice(-4)}` : address;
}
