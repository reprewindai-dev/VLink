import { useEffect, useMemo, useState } from "react";
import QRCode from "qrcode";
import { CheckCircle2, Copy, Link2, Play, QrCode, ShieldCheck, Unplug, Wallet } from "lucide-react";
import {
  readAccountToken,
  resolveOwnedWorkspace,
  resolveWorkspaceWallet,
  shortWalletAddress,
  type OwnedWorkspace,
  type WorkspaceWalletLookup,
} from "./account-session";
import { noteSignedIn, track } from "./analytics/tracker";
import type {
  VLinkAccessCredential,
  VLinkActivityEvent,
  VLinkDeviceBootstrapView,
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
const accountToken = () => window.localStorage.getItem("veklom.access_token")?.trim() || "";
const PENDING_APPROVAL_KEY = "veklom.vlink.pending_pairing_approval";

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
  const [bootstrapInfo, setBootstrapInfo] = useState<VLinkDeviceBootstrapView | null>(null);
  const [bootstrapEnrollmentGrant, setBootstrapEnrollmentGrant] = useState<VLinkEnrollmentGrant | null>(null);
  const [mfaCode, setMfaCode] = useState("");

  const bootstrapTarget = useMemo(() => {
    const match = window.location.pathname.match(/^\/pair\/bootstrap\/([^/]+)$/);
    return match ? { pairingId: decodeURIComponent(match[1]) } : null;
  }, []);
  const [deviceAuthorization, setDeviceAuthorization] = useState<{
    machineIdentity: { value: string; assurance: "client-asserted" };
    displayName: string;
    sourceType: VLinkSourceType;
    requestedScope: string;
    status: "pending" | "authorized" | "denied" | "expired";
    expiresAt: string;
  } | null>(null);
  const [deviceAuthorizationDecision, setDeviceAuthorizationDecision] = useState<"idle" | "approved" | "denied" | "failed">("idle");
  const [walletLookup, setWalletLookup] = useState<WorkspaceWalletLookup | null>(null);

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
        // Reuse the workspace wallet; onboarding is never repeated per connection.
        return resolveWorkspaceWallet(accountToken).then(setWalletLookup);
      })
      .catch((cause: unknown) => {
        const message = cause instanceof Error ? cause.message : "Workspace lookup failed";
        setWorkspaceState(/no workspace bound/i.test(message) ? "missing" : "failed");
        setError(message);
      });
  }, []);

  // Funnel analytics: the connect screen was reached (once per page load), and a
  // signed-in tab links its anonymous analytics id to the workspace.
  const isConnectScreen =
    !/^\/pair\/[^/]+\/[^/]+$/.test(window.location.pathname) && !window.location.pathname.endsWith("/authorize");
  const [connectViewTracked, setConnectViewTracked] = useState(false);
  useEffect(() => {
    if (!isConnectScreen || connectViewTracked || workspaceState === "loading") return;
    setConnectViewTracked(true);
    track("vlink_connect_viewed", {
      state: workspaceState === "ready" ? "signed_in" : workspaceState === "signed-out" ? "signed_out" : "unknown",
    });
    if (workspaceState === "ready") noteSignedIn(readAccountToken(window.localStorage));
  }, [isConnectScreen, connectViewTracked, workspaceState]);

  const pairingTarget = useMemo(() => {
    const match = window.location.pathname.match(/^\/pair\/([^/]+)\/([^/]+)$/);
    if (!match) return null;
    const vlinkId = decodeURIComponent(match[1]);
    const pairingId = decodeURIComponent(match[2]);
    const approvalCode = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("approval");
    if (approvalCode) return { vlinkId, pairingId, approvalCode };
    try {
      const pending = JSON.parse(window.sessionStorage.getItem(PENDING_APPROVAL_KEY) || "null") as
        | { vlinkId?: string; pairingId?: string; approvalCode?: string }
        | null;
      if (pending?.vlinkId === vlinkId && pending.pairingId === pairingId && pending.approvalCode) {
        return { vlinkId, pairingId, approvalCode: pending.approvalCode };
      }
    } catch {
      window.sessionStorage.removeItem(PENDING_APPROVAL_KEY);
    }
    return { vlinkId, pairingId, approvalCode: null };
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
    if (!pairingTarget?.approvalCode) return;
    window.sessionStorage.setItem(PENDING_APPROVAL_KEY, JSON.stringify(pairingTarget));
    if (window.location.hash) window.history.replaceState({}, "", `${window.location.pathname}${window.location.search}`);
  }, [pairingTarget]);

  useEffect(() => {
    if (!pairing?.qrPayload) {
      setQr("");
      return;
    }
    QRCode.toDataURL(pairing.qrPayload, { margin: 1, width: 220 }).then(setQr).catch(() => setQr(""));
  }, [pairing]);

  useEffect(() => {
    if (!pairingTarget) return;
    let stopped = false;
    let terminal = false;
    const refresh = async () => {
      if (stopped || terminal) return;
      try {
        const result = await api<{ pairing: VLinkPairingStatusView }>(
          `/api/v1/vlinks/${pairingTarget.vlinkId}/pairing/${pairingTarget.pairingId}`,
        );
        if (stopped) return;
        setPairingInfo(result.pairing);
        terminal = result.pairing.status !== "pending";
      } catch {
        if (!stopped) setPairingInfo(null);
      }
    };
    void refresh();
    const interval = window.setInterval(() => void refresh(), 1500);
    return () => {
      stopped = true;
      window.clearInterval(interval);
    };
  }, [pairingTarget]);

  useEffect(() => {
    if (!bootstrapTarget) return;
    let stopped = false;
    let terminal = false;
    const refresh = async () => {
      if (stopped || terminal) return;
      try {
        const result = await api<{ bootstrap: VLinkDeviceBootstrapView }>(
          `/api/v1/device/bootstrap/${bootstrapTarget.pairingId}`,
        );
        if (stopped) return;
        setBootstrapInfo(result.bootstrap);
        terminal = result.bootstrap.status !== "pending";
      } catch {
        if (!stopped) setBootstrapInfo(null);
      }
    };
    void refresh();
    const interval = window.setInterval(() => void refresh(), 1500);
    return () => {
      stopped = true;
      window.clearInterval(interval);
    };
  }, [bootstrapTarget]);

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
    if (!pairingTarget) return;
    if (!pairingTarget.approvalCode && !pairingInfo?.deviceKeyThumbprint) return;
    if (pairingInfo?.deviceKeyThumbprint && pairingInfo.deviceProofVerified !== true) return;
    const sessionToken = accountToken();
    if (!sessionToken) {
      setError("Sign in with the workspace-owning Veklom account before approving this pairing.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      await api(`/api/v1/vlinks/${pairingTarget.vlinkId}/pairing/${pairingTarget.pairingId}/approve`, {
        method: "POST",
        headers: bearer(sessionToken),
        body: JSON.stringify({
          ...(pairingTarget.approvalCode ? { approvalCode: pairingTarget.approvalCode } : {}),
          mfaCode,
        }),
      });
      setPairingApproval("approved");
      setMfaCode("");
      setPairingInfo((current) => current ? { ...current, status: "approved" } : current);
      window.sessionStorage.removeItem(PENDING_APPROVAL_KEY);
    } catch (e) {
      setPairingApproval("failed");
      const message = e instanceof Error ? e.message : "Pairing approval failed";
      setError(message === "mfa_required"
        ? "Complete a recent LockerPhycer MFA challenge, then return here to approve this device."
        : message);
    } finally {
      setBusy(false);
    }
  };

  const approveDeviceBootstrap = async () => {
    if (!bootstrapTarget || !bootstrapInfo || bootstrapInfo.status === "expired" || !bootstrapInfo.deviceProofVerified) return;
    const sessionToken = accountToken();
    if (!sessionToken) {
      setError("Sign in with the workspace-owning Veklom account before approving this device.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const result = await api<{ bootstrap: VLinkDeviceBootstrapView; enrollmentGrant: VLinkEnrollmentGrant }>(
        `/api/v1/device/bootstrap/${bootstrapTarget.pairingId}/approve`,
        {
          method: "POST",
          headers: bearer(sessionToken),
          body: JSON.stringify({ mfaCode }),
        },
      );
      setBootstrapInfo(result.bootstrap);
      setBootstrapEnrollmentGrant(result.enrollmentGrant);
      setMfaCode("");
    } catch (e) {
      const message = e instanceof Error ? e.message : "Device approval failed";
      setError(message === "mfa_required"
        ? "Enter a current LockerPhycer MFA code to approve this device."
        : message);
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

  if (bootstrapTarget) {
    const returnTo = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    const loginHref = `${accountOrigin}/login?returnTo=${encodeURIComponent(returnTo)}`;
    return (
      <main className="shell">
        <section className="hero">
          <div className="brand"><span className="brandMark">V</span><span>VLink</span></div>
          <h1>Review an unknown device.</h1>
          <p>This machine has no VLink yet. Its request grants no credential or consequence authority. Approval creates a workspace-bound VLink only after you verify its key and complete MFA.</p>
        </section>
        <section className="card">
          <div className="eyebrow">ANONYMOUS DEVICE BOOTSTRAP</div>
          {!bootstrapInfo ? <p className="muted">Loading the short-lived request…</p> : <>
            <h2>{bootstrapInfo.status === "approved" ? "Device approved" : bootstrapInfo.status === "expired" ? "Request expired" : "Confirm this machine"}</h2>
            <div className="statusRow"><span>{bootstrapInfo.displayName}</span><code>{bootstrapInfo.environment} · {bootstrapInfo.sourceType}</code></div>
            <p>Requested {new Date(bootstrapInfo.createdAt).toLocaleString()}; expires {new Date(bootstrapInfo.expiresAt).toLocaleString()}.</p>
            <div className="snippet"><div><strong>Device key fingerprint</strong><pre>{bootstrapInfo.deviceKeyThumbprint}</pre></div></div>
            <div className="truthBadge"><ShieldCheck size={16}/>{bootstrapInfo.deviceProofVerified ? "The device proved possession of this key. Compare the fingerprint with the initiating machine before approving." : "Waiting for proof that the initiating device possesses its private key."}</div>
            {bootstrapInfo.status === "approved" && bootstrapInfo.vlinkId && <div className="truthBadge"><CheckCircle2 size={16}/>Bound to VLink <code>{bootstrapInfo.vlinkId}</code>. The device must finish its signed exchange to receive its temporary access credential.</div>}
            {bootstrapEnrollmentGrant && <>
              <div className="snippet"><div><strong>Workspace enrollment grant — keep private</strong><pre>{bootstrapEnrollmentGrant.token}</pre></div><button onClick={() => copy(bootstrapEnrollmentGrant.token)} aria-label="Copy enrollment grant"><Copy size={15}/></button></div>
              <p className="muted">This short-lived owner grant can initiate pairing and bind a CAPPO lease. It is not CAPPO consequence authority. It is held only in this page’s memory; if the response was lost, re-authenticate with MFA to recover it.</p>
            </>}
            {bootstrapInfo.status === "expired" && <div className="error">This request expired. The device must create a new bootstrap request.</div>}
            {workspaceState === "loading" && <p>Checking your Veklom identity and workspace…</p>}
            {workspaceState === "signed-out" && <div className="error">Sign in to the owning Veklom workspace before approval. <a href={loginHref}>Sign in to Veklom</a></div>}
            {workspaceState === "missing" && <div className="error">This identity has no owned workspace to approve this device.</div>}
            {workspaceState === "failed" && <div className="error">Your workspace could not be verified. Device approval is unavailable until the identity authority responds.</div>}
            {(bootstrapInfo.status === "pending" || (bootstrapInfo.status === "approved" && !bootstrapEnrollmentGrant)) && workspaceState === "ready" && <>
              <label>LockerPhycer MFA code<input value={mfaCode} onChange={(event) => setMfaCode(event.target.value)} inputMode="numeric" autoComplete="one-time-code" maxLength={12} /></label>
              <button className="primary" disabled={busy || !bootstrapInfo.deviceProofVerified || !mfaCode.trim()} onClick={approveDeviceBootstrap}>
                <ShieldCheck size={17}/> {busy ? "Verifying…" : bootstrapInfo.status === "pending" ? "Verify key and approve" : "Recover enrollment grant"}
              </button>
            </>}
            {error && <div className="error">{error}</div>}
          </>}
        </section>
      </main>
    );
  }

  if (pairingTarget) {
    const returnTo = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    const loginHref = `${accountOrigin}/login?returnTo=${encodeURIComponent(returnTo)}`;
    return (
      <main className="shell">
        <section className="hero">
          <div className="brand"><span className="brandMark">V</span><span>VLink</span></div>
          <h1>Review this VLink device request.</h1>
          <p>Unknown devices may request pairing, but bootstrap grants no consequence authority. Approval requires the owning workspace and recent MFA; the device receives access only after proving possession of its private key.</p>
        </section>
        <section className="card">
          <div className="eyebrow">PAIRING REQUEST</div>
          <h2>{pairingApproval === "approved" ? "Pairing approved" : "Confirm connection"}</h2>
          <div className="statusRow"><code>{pairingTarget.vlinkId}</code><code>{pairingTarget.pairingId}</code></div>
          {pairingInfo?.expiresAt && <p>Expires at {new Date(pairingInfo.expiresAt).toLocaleString()}.</p>}
          {pairingInfo?.deviceKeyThumbprint && <div className="snippet"><div><strong>Device key fingerprint</strong><pre>{pairingInfo.deviceKeyThumbprint}</pre></div></div>}
          {pairingInfo?.deviceKeyThumbprint && <div className="truthBadge"><ShieldCheck size={16}/>{pairingInfo.deviceProofVerified ? "Device proved possession. Compare this fingerprint with the one shown by the initiating machine before approving." : "Waiting for the device to prove possession of its key."}</div>}
          {!pairingTarget.approvalCode && !pairingInfo?.deviceKeyThumbprint && <div className="error">This legacy pairing page has no one-time approval code. Open it from the VLink QR code.</div>}
          {pairingInfo?.status === "expired" && <div className="error">This pairing request expired. Start a new request from the device.</div>}
          {workspaceState === "loading" && <p>Checking your Veklom identity and workspace…</p>}
          {workspaceState === "signed-out" && <div className="error">Sign in with the Veklom account that owns this workspace before approving. <a href={loginHref}>Sign in to Veklom</a></div>}
          {workspaceState === "missing" && <div className="error">This identity has no owned workspace to authorize the pairing.</div>}
          {workspaceState === "failed" && <div className="error">Your workspace could not be verified. Pairing approval is unavailable until the identity authority responds.</div>}
          {pairingInfo?.status === "pending" && workspaceState === "ready" && <label>LockerPhycer MFA code<input value={mfaCode} onChange={(event) => setMfaCode(event.target.value)} inputMode="numeric" autoComplete="one-time-code" maxLength={12} /></label>}
          {pairingApproval === "approved" ? <div className="truthBadge"><CheckCircle2 size={16}/> Approved. Return to the initiating device; it can now prove key possession and recover its temporary VLink access credential.</div> :
            workspaceState === "ready" && <button className="primary" disabled={busy || !mfaCode.trim() || pairingInfo?.status === "expired" || (pairingTarget.approvalCode ? false : !pairingInfo?.deviceKeyThumbprint || pairingInfo.deviceProofVerified !== true)} onClick={approvePairing}>
              <ShieldCheck size={17}/> {busy ? "Approving…" : "Approve this device"}
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

      <ol className="flowSteps" aria-label="VLink flow">
        {[
          { label: "Connect", done: Boolean(vlink) },
          { label: "Wallet", done: walletLookup?.status === "bound" },
          { label: "Authorize", done: Boolean(credential) },
          { label: "Execute", done: activity.length > 0 },
          { label: "Receipt", done: activity.length > 0 },
        ].map((stage, index) => (
          <li key={stage.label} className={stage.done ? "done" : undefined}>
            {stage.done ? <CheckCircle2 size={14}/> : <span className="stepIndex">{index + 1}</span>} {stage.label}
          </li>
        ))}
      </ol>

      <section className="grid two">
        <article className="card">
          <div className="eyebrow">1 · CONNECT</div>
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
          {workspaceState === "signed-out" && <div className="error">Sign in before creating a VLink. <a className="manifest" data-analytics-cta="vlink-sign-in" href={`${accountOrigin}/login?returnTo=%2Fvlink%2Fconnect%2F`}>Sign in →</a> New here? <a className="manifest" data-analytics-cta="vlink-start-free-trial" href={`${accountOrigin}/signup?returnTo=%2Fvlink%2Fconnect%2F`}>Start your free trial →</a></div>}
          {workspaceState === "missing" && <div className="error">Finish Capability OS onboarding to bind a workspace before creating a VLink. <a className="manifest" href="/os/onboarding">Continue onboarding →</a></div>}
          {workspaceState === "failed" && <div className="error">VLink could not verify your workspace. Refresh after the identity service is available.</div>}
          <label>What are you linking?<select value={sourceType} onChange={(e) => setSourceType(e.target.value as VLinkSourceType)}>{sourceOptions.map((o) => <option value={o.value} key={o.value}>{o.label}</option>)}</select></label>
          <button className="primary" disabled={busy || workspaceState !== "ready" || !workspace} onClick={createVLink}><Link2 size={17}/> {busy ? "Working…" : workspaceState === "loading" ? "Resolving workspace…" : "Create VLink"}</button>
          {error && <div className="error">{error}</div>}
        </article>

        <article className="card">
          <div className="eyebrow">3 · AUTHORIZE → 4 · EXECUTE</div>
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

      <section className="card walletCard">
        <div className="eyebrow">2 · WALLET</div>
        <h2><Wallet size={18}/> Your Veklom Wallet</h2>
        <p>Carries funding and execution authority for governed actions. You can keep connecting and testing without funding it; funding is required before paid or externally settled actions.</p>
        {workspaceState !== "ready" ? <p className="muted">Your workspace wallet appears here after sign-in.</p>
          : !walletLookup ? <p className="muted">Checking your workspace wallet…</p>
          : walletLookup.status === "bound" ? <div className="truthBadge"><CheckCircle2 size={16}/> Reusing <code>{shortWalletAddress(walletLookup.wallet.address)}</code> on {walletLookup.wallet.networkName}{walletLookup.wallet.testnet ? " (testnet)" : ""}. Nothing to set up for this connection.</div>
          : walletLookup.status === "none" ? <p className="muted">No wallet on this workspace yet. <a className="manifest" href={`${accountOrigin}/os/onboarding?step=wallet`}>Create or connect one in Capability OS →</a> It is set up once and reused by every connection.</p>
          : <p className="muted">Wallet status unavailable ({walletLookup.reason}). Connecting is not blocked.</p>}
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
        <div className="eyebrow">5 · RECEIPT</div>
        <h2>Authenticated VLink activity</h2>
        {!credential ? <p className="muted">Pair the VLink first. A VLink identifier by itself cannot create activity through protected routes.</p> : activity.length === 0 ? <p className="muted">Run the authenticated connection test to create the first VLink-bound activity event.</p> : activity.map((event) => <div className="event" key={event.eventId}>
          <CheckCircle2 size={18}/><div><strong>Authenticated connection event</strong><span>{event.route} · {event.mode} · {event.status} · {event.latencyMs} ms</span><small>{event.timestamp}</small></div>
        </div>)}
      </section>
    </main>
  );
}
