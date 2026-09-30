import { useEffect, useMemo, useState } from "react";
import QRCode from "qrcode";
import { CheckCircle2, Copy, Link2, Play, QrCode, ShieldCheck, Unplug } from "lucide-react";
import { readAccountToken, resolveOwnedWorkspace, type OwnedWorkspace } from "./account-session";
import type {
  VLinkAccessCredential,
  VLinkActivityEvent,
  VLinkEnrollmentGrant,
  VLinkPairingRequest,
  VLinkPairingStatusView,
  VLinkRecord,
  VLinkSourceType,
} from "./types/vlink";

const sourceOptions: Array<{ value: VLinkSourceType; label: string }> = [
  { value: "ai-client", label: "AI model client" },
  { value: "agent-mcp", label: "Automation / MCP tool" },
  { value: "api-service", label: "API or backend service" },
  { value: "webhook", label: "Webhook workflow" },
  { value: "local-project", label: "Local project" },
  { value: "cicd", label: "CI/CD pipeline" },
  { value: "container", label: "Docker / Kubernetes workload" },
];

const apiOrigin = ["veklom.com", "www.veklom.com"].includes(window.location.hostname)
  ? "https://vlink.veklom.com"
  : "";

// Sign-in and signup live on the veklom.com frontend; on vlink.veklom.com a relative
// link would land in this app's own catch-all instead.
const accountOrigin = window.location.hostname === "vlink.veklom.com" ? "https://veklom.com" : "";

const api = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const headers = new Headers(init?.headers);
  headers.set("content-type", "application/json");
  if (!headers.has("authorization")) {
    const accountToken = readAccountToken(window.localStorage);
    if (accountToken) headers.set("authorization", `Bearer ${accountToken}`);
  }
  const response = await fetch(`${apiOrigin}${path}`, {
    ...init,
    headers,
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.detail || payload.message || payload.error || `HTTP ${response.status}`);
  return payload as T;
};

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

export default function App() {
  const [displayName, setDisplayName] = useState("My first VLink");
  const [workspace, setWorkspace] = useState<OwnedWorkspace | null>(null);
  const [workspaceState, setWorkspaceState] = useState<"loading" | "ready" | "signed-out" | "missing" | "failed">("loading");
  const [environment, setEnvironment] = useState("development");
  const [sourceType, setSourceType] = useState<VLinkSourceType>("ai-client");
  const [vlink, setVlink] = useState<VLinkRecord | null>(null);
  const [enrollmentGrant, setEnrollmentGrant] = useState<VLinkEnrollmentGrant | null>(null);
  const [credential, setCredential] = useState<VLinkAccessCredential | null>(null);
  const [activity, setActivity] = useState<VLinkActivityEvent[]>([]);
  const [pairing, setPairing] = useState<VLinkPairingRequest | null>(null);
  const [pairingStatus, setPairingStatus] = useState<VLinkPairingStatusView | null>(null);
  const [qr, setQr] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [exchanging, setExchanging] = useState(false);
  const [pairingInfo, setPairingInfo] = useState<VLinkPairingStatusView | null>(null);
  const [pairingApproval, setPairingApproval] = useState<"idle" | "approved" | "failed">("idle");
  const [deviceAuthorization, setDeviceAuthorization] = useState<{
    machineIdentity: { value: string; assurance: "client-asserted" };
    displayName: string;
    sourceType: VLinkSourceType;
    requestedScope: string;
    status: "pending" | "authorized" | "denied" | "expired";
    expiresAt: string;
  } | null>(null);
  const [deviceAuthorizationDecision, setDeviceAuthorizationDecision] = useState<"idle" | "approved" | "denied" | "failed">("idle");

  useEffect(() => {
    const accountToken = readAccountToken(window.localStorage);
    if (!accountToken) {
      setWorkspaceState("signed-out");
      return;
    }
    resolveOwnedWorkspace(accountToken)
      .then((resolvedWorkspace) => {
        setWorkspace(resolvedWorkspace);
        setWorkspaceState("ready");
      })
      .catch((cause: unknown) => {
        const message = cause instanceof Error ? cause.message : "Workspace lookup failed";
        setWorkspaceState(/no workspace bound/i.test(message) ? "missing" : "failed");
        setError(message);
      });
  }, []);

  const pairingTarget = useMemo(() => {
    const match = window.location.pathname.match(/^\/pair\/([^/]+)\/([^/]+)$/);
    if (!match) return null;
    const approvalCode = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("approval");
    return { vlinkId: decodeURIComponent(match[1]), pairingId: decodeURIComponent(match[2]), approvalCode };
  }, []);

  const deviceAuthorizationTarget = useMemo(() => {
    if (!window.location.pathname.endsWith("/authorize")) return null;
    const userCode = new URLSearchParams(window.location.search).get("user_code");
    return userCode ? userCode.replace(/[\s-]/g, "").toUpperCase() : "";
  }, []);

  useEffect(() => {
    if (!deviceAuthorizationTarget) return;
    api<{ authorization: NonNullable<typeof deviceAuthorization> }>(
      `/api/v1/device/authorizations/${encodeURIComponent(deviceAuthorizationTarget)}`,
    ).then((result) => setDeviceAuthorization(result.authorization)).catch((cause: unknown) => {
      setDeviceAuthorization(null);
      setError(cause instanceof Error ? cause.message : "Could not load this authorization request");
    });
  }, [deviceAuthorizationTarget]);

  useEffect(() => {
    if (!pairing?.qrPayload) {
      setQr("");
      return;
    }
    QRCode.toDataURL(pairing.qrPayload, { margin: 1, width: 220 }).then(setQr).catch(() => setQr(""));
  }, [pairing]);

  useEffect(() => {
    if (!pairingTarget) return;
    api<{ pairing: VLinkPairingStatusView }>(
      `/api/v1/vlinks/${pairingTarget.vlinkId}/pairing/${pairingTarget.pairingId}`,
    ).then((result) => setPairingInfo(result.pairing)).catch(() => setPairingInfo(null));
  }, [pairingTarget]);

  useEffect(() => {
    if (!pairing || !vlink || credential || exchanging) return;
    let stopped = false;

    const check = async () => {
      try {
        const result = await api<{ pairing: VLinkPairingStatusView }>(
          `/api/v1/vlinks/${vlink.vlinkId}/pairing/${pairing.pairingId}`,
        );
        if (stopped) return;
        setPairingStatus(result.pairing);
        if (result.pairing.status !== "approved") return;

        setExchanging(true);
        const exchanged = await api<{ credential: VLinkAccessCredential; pairing: VLinkPairingStatusView }>(
          `/api/v1/vlinks/${vlink.vlinkId}/pairing/${pairing.pairingId}/exchange`,
          {
            method: "POST",
            body: JSON.stringify({ deviceCode: pairing.deviceCode }),
          },
        );
        if (stopped) return;
        setCredential(exchanged.credential);
        setPairingStatus(exchanged.pairing);
        setEnrollmentGrant(null);
      } catch (e) {
        if (!stopped) setError(e instanceof Error ? e.message : "Could not complete pairing");
      } finally {
        if (!stopped) setExchanging(false);
      }
    };

    void check();
    const interval = window.setInterval(() => void check(), 1500);
    return () => {
      stopped = true;
      window.clearInterval(interval);
    };
  }, [pairing, vlink, credential, exchanging]);

  const snippet = useMemo(() => {
    if (!vlink) return "";
    if (!credential) {
      if (vlink.sourceType === "webhook" || vlink.sourceType === "api-service") {
        return `${vlink.endpoints.webhookIngressUrl}\n\nPair this VLink to receive the temporary Bearer token.`;
      }
      return `OPENAI_BASE_URL=${vlink.endpoints.openaiCompatibleBaseUrl}\nOPENAI_API_KEY=<pair-this-vlink-first>`;
    }

    if (vlink.sourceType === "webhook" || vlink.sourceType === "api-service") {
      return `curl -X POST ${vlink.endpoints.webhookIngressUrl} \\\n  -H 'Authorization: Bearer ${credential.token}' \\\n  -H 'Content-Type: application/json' \\\n  -d '{"event":"hello"}'`;
    }
    if (vlink.sourceType === "agent-mcp") {
      return `OPENAI_BASE_URL=${vlink.endpoints.openaiCompatibleBaseUrl}\nOPENAI_API_KEY=${credential.token}\n\nMCP endpoint: ${vlink.endpoints.mcpEndpoint}\nMCP transport is still planned.`;
    }
    if (vlink.sourceType === "cicd") {
      return `OPENAI_BASE_URL=${vlink.endpoints.openaiCompatibleBaseUrl}\nOPENAI_API_KEY=${credential.token}`;
    }
    if (vlink.sourceType === "container") {
      return `-e OPENAI_BASE_URL=${vlink.endpoints.openaiCompatibleBaseUrl} \\\n-e OPENAI_API_KEY=${credential.token}`;
    }
    return `OPENAI_BASE_URL=${vlink.endpoints.openaiCompatibleBaseUrl}\nOPENAI_API_KEY=${credential.token}`;
  }, [vlink, credential]);

  const createVLink = async () => {
    setBusy(true);
    setError("");
    try {
      const result = await api<{ vlink: VLinkRecord; enrollmentGrant: VLinkEnrollmentGrant }>("/api/v1/vlinks", {
        method: "POST",
        body: JSON.stringify({ workspaceId: workspace?.id, environment, displayName, sourceType }),
      });
      setVlink(result.vlink);
      setEnrollmentGrant(result.enrollmentGrant);
      setCredential(null);
      setActivity([]);
      setPairing(null);
      setPairingStatus(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not create VLink");
    } finally {
      setBusy(false);
    }
  };

  const runTest = async () => {
    if (!vlink || !credential) return;
    setBusy(true);
    setError("");
    try {
      await api(`/api/v1/vlinks/${vlink.vlinkId}/test`, {
        method: "POST",
        headers: bearer(credential.token),
        body: "{}",
      });
      const result = await api<{ events: VLinkActivityEvent[] }>(`/api/v1/vlinks/${vlink.vlinkId}/activity`, {
        headers: bearer(credential.token),
      });
      setActivity(result.events);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Test failed");
    } finally {
      setBusy(false);
    }
  };

  const createPairing = async () => {
    if (!vlink || !enrollmentGrant) return;
    setBusy(true);
    setError("");
    try {
      const result = await api<{ pairing: VLinkPairingRequest }>(`/api/v1/vlinks/${vlink.vlinkId}/pairing`, {
        method: "POST",
        headers: bearer(enrollmentGrant.token),
        body: JSON.stringify({ ttlSeconds: 600 }),
      });
      setPairing(result.pairing);
      setPairingStatus({
        pairingId: result.pairing.pairingId,
        vlinkId: result.pairing.vlinkId,
        pairingUrl: result.pairing.pairingUrl,
        status: result.pairing.status,
        createdAt: result.pairing.createdAt,
        expiresAt: result.pairing.expiresAt,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Pairing failed");
    } finally {
      setBusy(false);
    }
  };

  const approvePairing = async () => {
    if (!pairingTarget?.approvalCode) return;
    setBusy(true);
    setError("");
    try {
      await api(`/api/v1/vlinks/${pairingTarget.vlinkId}/pairing/${pairingTarget.pairingId}/approve`, {
        method: "POST",
        body: JSON.stringify({ approvalCode: pairingTarget.approvalCode }),
      });
      setPairingApproval("approved");
      window.history.replaceState({}, "", window.location.pathname);
    } catch (e) {
      setPairingApproval("failed");
      setError(e instanceof Error ? e.message : "Pairing approval failed");
    } finally {
      setBusy(false);
    }
  };

  const decideDeviceAuthorization = async (decision: "approve" | "deny") => {
    if (!deviceAuthorizationTarget) return;
    setBusy(true);
    setError("");
    try {
      const result = await api<{ authorization: NonNullable<typeof deviceAuthorization> }>(
        `/api/v1/device/authorizations/${encodeURIComponent(deviceAuthorizationTarget)}/${decision}`,
        { method: "POST", body: "{}" },
      );
      setDeviceAuthorization(result.authorization);
      setDeviceAuthorizationDecision(decision === "approve" ? "approved" : "denied");
      window.history.replaceState({}, "", window.location.pathname);
    } catch (cause) {
      setDeviceAuthorizationDecision("failed");
      setError(cause instanceof Error ? cause.message : "Could not update this authorization");
    } finally {
      setBusy(false);
    }
  };

  const revokeAccess = async () => {
    if (!vlink || !credential) return;
    setBusy(true);
    setError("");
    try {
      await api(`/api/v1/vlinks/${vlink.vlinkId}/access/revoke`, {
        method: "POST",
        headers: bearer(credential.token),
        body: "{}",
      });
      setCredential(null);
      setPairing(null);
      setPairingStatus(null);
      setActivity([]);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not revoke access");
    } finally {
      setBusy(false);
    }
  };

  const copy = (text: string) => navigator.clipboard?.writeText(text);

  if (pairingTarget) {
    const returnTo = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    const loginHref = `${accountOrigin}/login?returnTo=${encodeURIComponent(returnTo)}`;
    return (
      <main className="shell">
        <section className="hero">
          <div className="brand"><span className="brandMark">V</span><span>VLink</span></div>
          <h1>Approve this VLink pairing.</h1>
          <p>This browser can approve the request, but it cannot mint the workload credential. The initiating tool keeps a separate device-exchange secret and receives the temporary access token only after approval.</p>
        </section>
        <section className="card">
          <div className="eyebrow">PAIRING REQUEST</div>
          <h2>{pairingApproval === "approved" ? "Pairing approved" : "Confirm connection"}</h2>
          <div className="statusRow"><code>{pairingTarget.vlinkId}</code><code>{pairingTarget.pairingId}</code></div>
          {pairingInfo?.expiresAt && <p>Expires at {new Date(pairingInfo.expiresAt).toLocaleString()}.</p>}
          {!pairingTarget.approvalCode && <div className="error">This page has no one-time approval code. Open it from the VLink QR code.</div>}
          {workspaceState === "loading" && <p>Checking your Veklom identity and workspace…</p>}
          {workspaceState === "signed-out" && <div className="error">Sign in with the Veklom account that owns this workspace before approving. <a href={loginHref}>Sign in to Veklom</a></div>}
          {workspaceState === "missing" && <div className="error">This identity has no owned workspace to authorize the pairing.</div>}
          {workspaceState === "failed" && <div className="error">Your workspace could not be verified. Pairing approval is unavailable until the identity authority responds.</div>}
          {pairingApproval === "approved" ? <div className="truthBadge"><CheckCircle2 size={16}/> Approved. Return to the initiating device; it can now exchange its separate device code for temporary access.</div> :
            workspaceState === "ready" && <button className="primary" disabled={busy || !pairingTarget.approvalCode || pairingInfo?.status === "expired"} onClick={approvePairing}>
              <ShieldCheck size={17}/> {busy ? "Approving…" : "Approve pairing"}
            </button>}
          {pairingApproval === "failed" && error && <div className="error">{error}</div>}
        </section>
      </main>
    );
  }

  if (deviceAuthorizationTarget !== null) {
    const returnTo = `${window.location.pathname}${window.location.search}`;
    const loginHref = `${accountOrigin}/login?returnTo=${encodeURIComponent(returnTo)}`;
    return (
      <main className="shell">
        <section className="hero">
          <div className="brand"><span className="brandMark">V</span><span>VLink</span></div>
          <h1>Authorize a machine connection.</h1>
          <p>Review the machine’s declared identity and the narrow VLink connection it is requesting. Approval does not grant CAPPO capability or authority.</p>
        </section>
        <section className="card">
          <div className="eyebrow">MACHINE AUTHORIZATION</div>
          {!deviceAuthorizationTarget && <div className="error">This authorization link is missing its user code.</div>}
          {!deviceAuthorization && !error && <p>Loading authorization request…</p>}
          {deviceAuthorization && <>
            <h2>{deviceAuthorization.displayName}</h2>
            <div className="statusRow"><span className="pill observe">{deviceAuthorization.requestedScope}</span><code>{deviceAuthorization.machineIdentity.value}</code></div>
            <p>Identity assurance: <strong>client-asserted</strong>. This value is supplied by the requesting client; it is not hardware attestation.</p>
            <p>Requested connection type: <strong>{deviceAuthorization.sourceType}</strong>.</p>
            <p>Request expires: {new Date(deviceAuthorization.expiresAt).toLocaleString()}.</p>
            <div className="truthBadge"><ShieldCheck size={16}/> Approval binds this VLink to your authenticated LockerPhycer operator and workspace. It grants VLink connection access only; CAPPO authority is separate.</div>
            {workspaceState === "loading" && <p>Checking your Veklom identity and workspace…</p>}
            {workspaceState === "signed-out" && <div className="error">Sign in with your Veklom account before approving. <a href={loginHref}>Sign in to Veklom</a></div>}
            {workspaceState === "missing" && <div className="error">This identity has no owned workspace to authorize the connection.</div>}
            {workspaceState === "failed" && <div className="error">Your workspace could not be verified. Authorization is unavailable until identity authority responds.</div>}
            {deviceAuthorization.status !== "pending" && <p>Request state: <strong>{deviceAuthorization.status}</strong>.</p>}
            {deviceAuthorizationDecision === "approved" && <div className="truthBadge"><CheckCircle2 size={16}/> Approved. Return to the machine; it can now poll for its VLink-scoped credential.</div>}
            {deviceAuthorizationDecision === "denied" && <div className="truthBadge">Request denied. No machine access was granted.</div>}
            {workspaceState === "ready" && deviceAuthorization.status === "pending" && deviceAuthorizationDecision === "idle" && <div className="actions">
              <button className="primary" disabled={busy} onClick={() => void decideDeviceAuthorization("approve")}><ShieldCheck size={17}/> {busy ? "Saving…" : "Approve VLink access"}</button>
              <button disabled={busy} onClick={() => void decideDeviceAuthorization("deny")}>Deny</button>
            </div>}
          </>}
          {error && <div className="error">{error}</div>}
        </section>
      </main>
    );
  }

  return (
    <main className="shell">
      <section className="hero">
        <div className="brand"><span className="brandMark">V</span><span>VLink</span></div>
        <h1>Connect first. Observe reality. Govern what matters.</h1>
        <p>VLink is the portable connection layer into Veklom. Create one link, approve it once, then use a normal OpenAI-compatible base URL plus a short-lived API token. The VLink ID identifies the connection; it is never treated as authority by itself.</p>
        <div className="truthBadge"><ShieldCheck size={16}/> Activity records are metadata, not cryptographic receipts.</div>
      </section>

      <section className="grid two">
        <article className="card">
          <div className="eyebrow">1 · CREATE</div>
          <h2>Create a VLink</h2>
          <label>Name<input value={displayName} onChange={(e) => setDisplayName(e.target.value)} /></label>
          <div className="grid two compact">
            <label>Workspace<input
              value={workspaceState === "loading" ? "Resolving your workspace…" : workspace ? workspace.name : "No authenticated workspace"}
              readOnly
              aria-busy={workspaceState === "loading"}
            /></label>
            <label>Environment<select value={environment} onChange={(e) => setEnvironment(e.target.value)}><option>development</option><option>staging</option><option>production</option></select></label>
          </div>
          {workspaceState === "signed-out" && <div className="error">Sign in before creating a VLink. <a className="manifest" href={`${accountOrigin}/login?returnTo=%2Fvlink%2Fconnect%2F`}>Sign in →</a> New here? <a className="manifest" href={`${accountOrigin}/signup?returnTo=%2Fvlink%2Fconnect%2F`}>Start your free trial →</a></div>}
          {workspaceState === "missing" && <div className="error">Finish Capability OS onboarding to bind a workspace before creating a VLink. <a className="manifest" href="/os/onboarding">Continue onboarding →</a></div>}
          {workspaceState === "failed" && <div className="error">VLink could not verify your workspace. Refresh after the identity service is available.</div>}
          <label>What are you linking?<select value={sourceType} onChange={(e) => setSourceType(e.target.value as VLinkSourceType)}>{sourceOptions.map((o) => <option value={o.value} key={o.value}>{o.label}</option>)}</select></label>
          <button className="primary" disabled={busy || workspaceState !== "ready" || !workspace} onClick={createVLink}><Link2 size={17}/> {busy ? "Working…" : workspaceState === "loading" ? "Resolving workspace…" : "Create VLink"}</button>
          {error && <div className="error">{error}</div>}
        </article>

        <article className="card">
          <div className="eyebrow">2 · CONNECT</div>
          <h2>{vlink ? (credential ? "Your VLink is connected" : "Approve this VLink") : "Connection instructions appear here"}</h2>
          {!vlink ? <p className="muted">No credentials or setup snippets are generated until you create a VLink.</p> : <>
            <div className="statusRow"><span className="pill observe">OBSERVE</span><code>{vlink.vlinkId}</code></div>
            <div className="snippet"><pre>{snippet}</pre><button onClick={() => copy(snippet)} aria-label="Copy setup instructions"><Copy size={15}/></button></div>
            <div className="actions">
              {!credential && <button onClick={createPairing} disabled={busy || !enrollmentGrant || Boolean(pairing)}><QrCode size={16}/> {pairing ? "Waiting for approval…" : "Pair & get access"}</button>}
              <button onClick={runTest} disabled={busy || !credential}><Play size={16}/> Run authenticated test</button>
              {credential && <button onClick={revokeAccess} disabled={busy}><Unplug size={16}/> Revoke token</button>}
            </div>
            {credential && <div className="truthBadge"><CheckCircle2 size={16}/> Temporary access active until {new Date(credential.expiresAt).toLocaleString()}. The token exists only in this page memory unless you copy it into your client.</div>}
            <a className="manifest" href={`/api/v1/vlinks/${vlink.vlinkId}/manifest`} target="_blank" rel="noreferrer">Open secret-free machine-readable manifest ↗</a>
          </>}
        </article>
      </section>

      {pairing && !credential && <section className="card pairing">
        <div>
          <div className="eyebrow">PAIRING</div>
          <h2>{exchanging ? "Issuing temporary access…" : pairingStatus?.status === "approved" ? "Approved — exchanging on this device" : "Scan and approve"}</h2>
          <p>Expires at {new Date(pairing.expiresAt).toLocaleTimeString()}. The QR contains only the browser approval secret. A separate device code stays in this initiating page and is required to receive the workload token.</p>
          <code>{pairing.pairingId}</code>
          {pairingStatus && <div className="truthBadge"><ShieldCheck size={16}/> Pairing state: {pairingStatus.status}</div>}
        </div>
        {qr && <img src={qr} alt="VLink pairing QR code"/>}
      </section>}

      <section className="card">
        <div className="eyebrow">3 · VERIFY</div>
        <h2>Authenticated VLink activity</h2>
        {!credential ? <p className="muted">Pair the VLink first. A VLink identifier by itself cannot create activity through protected routes.</p> : activity.length === 0 ? <p className="muted">Run the authenticated connection test to create the first VLink-bound activity event.</p> : activity.map((event) => <div className="event" key={event.eventId}>
          <CheckCircle2 size={18}/><div><strong>Authenticated connection event</strong><span>{event.route} · {event.mode} · {event.status} · {event.latencyMs} ms</span><small>{event.timestamp}</small></div>
        </div>)}
      </section>
    </main>
  );
}
