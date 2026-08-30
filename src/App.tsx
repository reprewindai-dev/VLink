import { useEffect, useMemo, useState } from "react";
import QRCode from "qrcode";
import { CheckCircle2, Copy, Link2, Play, QrCode, ShieldCheck } from "lucide-react";
import type { VLinkActivityEvent, VLinkPairingRequest, VLinkRecord, VLinkSourceType } from "./types/vlink";

const sourceOptions: Array<{ value: VLinkSourceType; label: string }> = [
  { value: "ai-client", label: "AI model client" },
  { value: "agent-mcp", label: "Agent / MCP tool" },
  { value: "api-service", label: "API or backend service" },
  { value: "webhook", label: "Webhook workflow" },
  { value: "local-project", label: "Local project" },
  { value: "cicd", label: "CI/CD pipeline" },
  { value: "container", label: "Docker / Kubernetes workload" },
];

const api = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const response = await fetch(path, {
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.message || payload.error || `HTTP ${response.status}`);
  return payload as T;
};

export default function App() {
  const [displayName, setDisplayName] = useState("My first VLink");
  const [workspaceId, setWorkspaceId] = useState("default");
  const [environment, setEnvironment] = useState("development");
  const [sourceType, setSourceType] = useState<VLinkSourceType>("ai-client");
  const [vlink, setVlink] = useState<VLinkRecord | null>(null);
  const [activity, setActivity] = useState<VLinkActivityEvent[]>([]);
  const [pairing, setPairing] = useState<VLinkPairingRequest | null>(null);
  const [qr, setQr] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [pairingInfo, setPairingInfo] = useState<Partial<VLinkPairingRequest> | null>(null);
  const [pairingApproval, setPairingApproval] = useState<"idle" | "approved" | "failed">("idle");

  const pairingTarget = useMemo(() => {
    const match = window.location.pathname.match(/^\/pair\/([^/]+)\/([^/]+)$/);
    if (!match) return null;
    const code = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("code");
    return { vlinkId: decodeURIComponent(match[1]), pairingId: decodeURIComponent(match[2]), code };
  }, []);

  useEffect(() => {
    if (!pairing?.qrPayload) {
      setQr("");
      return;
    }
    QRCode.toDataURL(pairing.qrPayload, { margin: 1, width: 220 }).then(setQr).catch(() => setQr(""));
  }, [pairing]);

  useEffect(() => {
    if (!pairingTarget) return;
    api<{ pairing: Partial<VLinkPairingRequest> }>(
      `/api/v1/vlinks/${pairingTarget.vlinkId}/pairing/${pairingTarget.pairingId}`,
    ).then((result) => setPairingInfo(result.pairing)).catch(() => setPairingInfo(null));
  }, [pairingTarget]);

  const snippet = useMemo(() => {
    if (!vlink) return "";
    if (vlink.sourceType === "webhook" || vlink.sourceType === "api-service") {
      return vlink.endpoints.webhookIngressUrl;
    }
    if (vlink.sourceType === "agent-mcp") {
      return `OpenAI-compatible now: ${vlink.endpoints.openaiCompatibleBaseUrl}\nMCP endpoint (planned transport): ${vlink.endpoints.mcpEndpoint}`;
    }
    if (vlink.sourceType === "cicd") return `OPENAI_BASE_URL=${vlink.endpoints.openaiCompatibleBaseUrl}`;
    if (vlink.sourceType === "container") return `-e OPENAI_BASE_URL=${vlink.endpoints.openaiCompatibleBaseUrl}`;
    return `OPENAI_BASE_URL=${vlink.endpoints.openaiCompatibleBaseUrl}`;
  }, [vlink]);

  const createVLink = async () => {
    setBusy(true);
    setError("");
    try {
      const result = await api<{ vlink: VLinkRecord }>("/api/v1/vlinks", {
        method: "POST",
        body: JSON.stringify({ workspaceId, environment, displayName, sourceType }),
      });
      setVlink(result.vlink);
      setActivity([]);
      setPairing(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not create VLink");
    } finally {
      setBusy(false);
    }
  };

  const runTest = async () => {
    if (!vlink) return;
    setBusy(true);
    setError("");
    try {
      await api(`/api/v1/vlinks/${vlink.vlinkId}/test`, { method: "POST", body: "{}" });
      const result = await api<{ events: VLinkActivityEvent[] }>(`/api/v1/vlinks/${vlink.vlinkId}/activity`);
      setActivity(result.events);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Test failed");
    } finally {
      setBusy(false);
    }
  };

  const createPairing = async () => {
    if (!vlink) return;
    setBusy(true);
    setError("");
    try {
      const result = await api<{ pairing: VLinkPairingRequest }>(`/api/v1/vlinks/${vlink.vlinkId}/pairing`, {
        method: "POST",
        body: JSON.stringify({ ttlSeconds: 600 }),
      });
      setPairing(result.pairing);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Pairing failed");
    } finally {
      setBusy(false);
    }
  };

  const approvePairing = async () => {
    if (!pairingTarget?.code) return;
    setBusy(true);
    setError("");
    try {
      await api(`/api/v1/vlinks/${pairingTarget.vlinkId}/pairing/${pairingTarget.pairingId}/complete`, {
        method: "POST",
        body: JSON.stringify({ oneTimeCode: pairingTarget.code }),
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

  const copy = (text: string) => navigator.clipboard?.writeText(text);

  if (pairingTarget) {
    return (
      <main className="shell">
        <section className="hero">
          <div className="brand"><span className="brandMark">V</span><span>VLink</span></div>
          <h1>Approve this VLink pairing.</h1>
          <p>This is a one-time enrollment request. Approval marks this browser/device as paired to the requested VLink; it does not create a permanent API key.</p>
        </section>
        <section className="card">
          <div className="eyebrow">PAIRING REQUEST</div>
          <h2>{pairingApproval === "approved" ? "Pairing approved" : "Confirm connection"}</h2>
          <div className="statusRow"><code>{pairingTarget.vlinkId}</code><code>{pairingTarget.pairingId}</code></div>
          {pairingInfo?.expiresAt && <p>Expires at {new Date(pairingInfo.expiresAt).toLocaleString()}.</p>}
          {!pairingTarget.code && <div className="error">This page has no one-time enrollment code. Open it from the VLink QR code.</div>}
          {pairingApproval === "approved" ? <div className="truthBadge"><CheckCircle2 size={16}/> Paired successfully. The one-time code cannot be reused.</div> :
            <button className="primary" disabled={busy || !pairingTarget.code || pairingInfo?.status === "expired"} onClick={approvePairing}>
              <ShieldCheck size={17}/> {busy ? "Approving…" : "Approve pairing"}
            </button>}
          {pairingApproval === "failed" && error && <div className="error">{error}</div>}
        </section>
      </main>
    );
  }

  return (
    <main className="shell">
      <section className="hero">
        <div className="brand"><span className="brandMark">V</span><span>VLink</span></div>
        <h1>Connect first. Observe reality. Govern what matters.</h1>
        <p>VLink is the portable connection layer into Veklom. Create one link, choose what you are connecting, use the generated VLink-specific endpoint or pairing flow, and verify the first activity event. No custom VLink header is required when you use the generated connection URL.</p>
        <div className="truthBadge"><ShieldCheck size={16}/> Activity records are metadata, not cryptographic receipts.</div>
      </section>

      <section className="grid two">
        <article className="card">
          <div className="eyebrow">1 · CREATE</div>
          <h2>Create a VLink</h2>
          <label>Name<input value={displayName} onChange={(e) => setDisplayName(e.target.value)} /></label>
          <div className="grid two compact">
            <label>Workspace<input value={workspaceId} onChange={(e) => setWorkspaceId(e.target.value)} /></label>
            <label>Environment<select value={environment} onChange={(e) => setEnvironment(e.target.value)}><option>development</option><option>staging</option><option>production</option></select></label>
          </div>
          <label>What are you linking?<select value={sourceType} onChange={(e) => setSourceType(e.target.value as VLinkSourceType)}>{sourceOptions.map((o) => <option value={o.value} key={o.value}>{o.label}</option>)}</select></label>
          <button className="primary" disabled={busy} onClick={createVLink}><Link2 size={17}/> {busy ? "Working…" : "Create VLink"}</button>
          {error && <div className="error">{error}</div>}
        </article>

        <article className="card">
          <div className="eyebrow">2 · CONNECT</div>
          <h2>{vlink ? "Your VLink is ready" : "Connection instructions appear here"}</h2>
          {!vlink ? <p className="muted">No credentials or setup snippets are generated until you create a VLink.</p> : <>
            <div className="statusRow"><span className="pill observe">OBSERVE</span><code>{vlink.vlinkId}</code></div>
            <div className="snippet"><pre>{snippet}</pre><button onClick={() => copy(snippet)} aria-label="Copy setup instructions"><Copy size={15}/></button></div>
            <div className="actions">
              <button onClick={runTest} disabled={busy}><Play size={16}/> Run connection test</button>
              <button onClick={createPairing} disabled={busy}><QrCode size={16}/> Pair a device</button>
            </div>
            <a className="manifest" href={`/api/v1/vlinks/${vlink.vlinkId}/manifest`} target="_blank" rel="noreferrer">Open machine-readable manifest ↗</a>
          </>}
        </article>
      </section>

      {pairing && <section className="card pairing">
        <div><div className="eyebrow">PAIRING</div><h2>Short-lived one-time enrollment</h2><p>Expires at {new Date(pairing.expiresAt).toLocaleTimeString()}. Scan the QR to open a browser approval page. Its one-time code lives only in the URL fragment and is not a reusable API key.</p><code>{pairing.pairingId}</code></div>
        {qr && <img src={qr} alt="VLink pairing QR code"/>}
      </section>}

      <section className="card">
        <div className="eyebrow">3 · VERIFY</div>
        <h2>VLink activity</h2>
        {activity.length === 0 ? <p className="muted">Run the connection test to create the first real VLink-bound activity event.</p> : activity.map((event) => <div className="event" key={event.eventId}>
          <CheckCircle2 size={18}/><div><strong>Connection test received</strong><span>{event.route} · {event.mode} · {event.status} · {event.latencyMs} ms</span><small>{event.timestamp}</small></div>
        </div>)}
      </section>
    </main>
  );
}
