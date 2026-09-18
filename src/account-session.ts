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
