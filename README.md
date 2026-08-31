# VLink

> Link existing tools, models, workflows, and services to Veklom without rewriting application logic.

VLink is the low-friction connection primitive into Veklom. It creates a portable, self-describing connection object that a model client, workflow, service, local project, CI job, container, or future MCP client can use without adopting a large SDK.

The current product flow is:

**Create → Pair → Receive temporary access → Connect → Test/Execute → Observe activity → Verify signed receipt → optionally use bounded retry-safe failover → later attach deeper governance.**

## What is implemented now

- Versioned `VLink` TypeScript contract (`vlink/v1`).
- Replaceable registry interface with restart-safe local file persistence when `VLINK_STATE_PATH` is configured.
- Production startup fails closed if `VLINK_STATE_PATH` is missing instead of silently using volatile connection/access state.
- Durable snapshots retain VLink identity, hashed enrollment grants, hashed pairing secrets, hashed/revoked workload credentials, and the bounded activity history.
- Durable writes use a same-directory temporary file, file sync, and rename; a failed durable write restores the previous in-memory snapshot rather than returning a successful mutation that was not committed.
- Durable-state loading validates format/schema, rejects duplicate identities and orphaned cross-VLink state, and fails closed on corrupt or unsupported state.
- VLink create/list/read endpoints.
- Secret-free machine-readable manifests at `/.well-known/vlink.json` and `/api/v1/vlinks/:vlinkId/manifest`.
- A self-binding OpenAI-compatible base URL for every VLink: `/vlinks/<vlink-id>/v1`.
- A short-lived enrollment grant returned only at VLink creation. The VLink ID alone cannot initiate pairing.
- Browser/device pairing with **two independent secrets**: a browser approval secret in the QR URL fragment and a separate device-exchange secret retained by the initiating tool/device.
- Approval and credential issuance are separate operations. Browser approval cannot mint a workload token by itself.
- One-time device exchange for an opaque, short-lived VLink bearer token.
- Enrollment grants and workload tokens stored hashed server-side rather than retained in usable form.
- VLink access tokens bound to one VLink with cross-VLink replay denial, TTL expiry, and immediate revocation.
- Protected VLink-specific OpenAI-compatible, webhook, test, activity, receipt, and bounded-failover routes.
- Unbound global `/v1` compatibility disabled by default.
- Live Gemini execution when `GEMINI_API_KEY` and a model are configured.
- Explicit demo responses only when `VLINK_ENABLE_DEMO_RESPONSES=true`.
- Custom HTTP targets restricted to hosts listed in `VLINK_ALLOWED_TARGET_HOSTS`.
- VLink bearer credentials consumed at the VLink boundary and **not forwarded** upstream.
- Webhook request bodies not persisted in activity records.
- **Ed25519-signed VLink receipts for real recorded activity events.**
- SHA-256 payload digests and SHA-256 fingerprints of the Ed25519 verification key.
- Public receipt key descriptor at `/.well-known/vlink-receipt-key.json`.
- Protected receipt export at `/receipts/vlinks/<vlink-id>` and `/receipts/<receipt-id>`.
- Public receipt verification endpoint at `/receipts/verify`.
- Receipts embed the public JWK required for independent mathematical verification.
- Explicit signing-key posture: `configured` or `ephemeral`.
- **Bounded failover for explicitly retry-safe requests** at `/failover/vlinks/<vlink-id>/v1/chat/completions`.
- Failover attempts the primary exactly once and may attempt one secondary only after primary transport failure, timeout, or HTTP 5xx.
- Primary HTTP 4xx responses are returned as application responses and are never replayed to the secondary.
- Failover is disabled unless the caller explicitly sends `X-VLink-Retry-Safe: true`.
- Primary and secondary targets must differ and both must be allowlisted.
- Each failover event records measured per-attempt outcomes and latencies, final backend, recovery state, and total latency without storing request/response bodies or forwarding the VLink bearer token.
- Failover evidence passes through the signed-receipt path.
- React UI for Create → QR approval → automatic device exchange → temporary token → authenticated test/activity.

## Proof gates

The bounded-failover milestone previously passed:

- **42 tests passed, 0 failed**
- `tsc --noEmit`
- production Vite + server build

The durable-state work adds seven falsifiers covering:

1. VLink identity, enrollment, pairing, workload access, activity, and revocation surviving a process-style registry recreation;
2. plaintext enrollment, approval, device, and access secrets never appearing in the durable state file;
3. expired pairing state remaining expired after reload;
4. activity retention remaining bounded to 100 records across reload;
5. corrupt or unsupported state failing closed instead of silently starting an empty registry;
6. orphaned cross-VLink credential state being rejected during load;
7. a durable clear not resurrecting prior runtime state.

CI runs the full suite, typecheck, and production build on Ubuntu and runs the durable-state falsifiers plus typecheck on Windows. The Windows job exists because the canonical local deployment target uses Windows filesystem semantics.

## What the durable-state claim means

With `VLINK_STATE_PATH` configured, VLink has a **single-node restart-safe local state store for VLink identity, hashed enrollment/pairing/access state, revocation state, and bounded activity metadata**.

This is intentionally not described as a clustered database, multi-host replication, or malicious-local-tamper-proof storage. The state file must be placed on persistent storage and protected with host filesystem permissions. Container deployments must mount the state path from persistent host/volume storage rather than leaving it on an ephemeral container filesystem.

Signed receipt objects are currently stored by the receipt support layer in process memory. Activity facts that drive those receipts can be durable, but this release does **not** claim durable local retention of the signed receipt objects themselves. Stable receipt signing identity also still requires `VLINK_RECEIPT_PRIVATE_KEY_PEM`.

## What the failover claim means

VLink can truthfully claim **bounded request-level failover for explicitly retry-safe HTTP workloads under a defined two-target contract**.

This is deliberately narrower than “zero downtime.” VLink does not claim zero-millisecond switching, zero packet loss, exactly-once semantics for arbitrary consequences, or universal provider equivalence. The caller must explicitly declare the request safe to retry, and VLink performs at most one primary attempt plus one secondary attempt. Recovery latency is measured rather than invented.

For consequential operations, provider-specific idempotency, reconciliation, or compensation must be proven separately before retry/failover is considered safe.

## What the receipt claim means

VLink can truthfully claim **tamper-evident, independently verifiable signed receipts for the activity facts that VLink itself recorded**.

That does **not** yet mean full non-repudiation. A verifier that wants a stronger authorship/trust statement must know which VLink signing key it trusts. The receipt includes a public key and deterministic key fingerprint, and VLink publishes the current key descriptor. A future external pin/anchor, Veklom evidence service binding, COSE receipt profile, SCITT transparency service, or equivalent witness can strengthen the trust layer.

An ephemeral process key still produces mathematically verifiable receipts, but the operator identity of that key is not durable across restart. For a stable signing identity, configure `VLINK_RECEIPT_PRIVATE_KEY_PEM` and pin or externally anchor its published key fingerprint.

## Not claimed / not implemented yet

VLink does **not** currently claim any of the following:

- Multi-node/clustered database persistence or replicated state.
- Durable local retention of signed receipt objects; the receipt store is still process-local even when VLink activity state is durable.
- External anchoring/witnessing of the VLink signing key or receipt stream.
- Formal non-repudiation.
- Production SPIFFE/SPIRE workload identity issuance or verification.
- Veklom account/workspace authentication for management routes.
- Hardware attestation or enclave verification.
- Zero-downtime, zero-loss, or transparent failover for arbitrary consequential operations.
- Multi-target health orchestration, automatic backend promotion, or provider semantic equivalence.
- General zero-data-loss rollback. Compensation semantics must be defined and verified per consequence type/provider.
- Full MCP transport. `/mcp/v1` is an explicit `501 planned` placeholder.
- Full Veklom Capability OS policy/capability enforcement.

The OmniConnect prototype contains additional candidate capabilities—delegation, compensation/rollback, shadow evaluation, backend promotion, MCP tooling, no-code integrations, control sockets, and connection UX. They remain implementation targets, not discarded ideas: each capability must be implemented against a falsifiable contract and earn its claim independently. The prototype itself is not the canonical VLink implementation and must not overwrite the stronger canonical repository.

## Run locally

```bash
npm install
npm run dev
```

Then open `http://localhost:3000`.

Quality checks:

```bash
npm test
npm run lint
npm run build
```

For restart-safe local state, configure a persistent path:

```text
VLINK_STATE_PATH=.runtime/vlink-state.json
```

Production mode requires a non-empty `VLINK_STATE_PATH`.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `PORT` | HTTP port. Default `3000`. |
| `VLINK_PUBLIC_ORIGIN` | Canonical public origin used in generated manifests/endpoints. |
| `VLINK_CORS_ORIGIN` | Allowed browser origin. Default `*` for local/prototype use; set explicitly in production. |
| `VLINK_STATE_PATH` | Required in production. Persistent single-node registry state for VLink identity, hashed access/pairing state, revocation, and bounded activity metadata. |
| `VLINK_ENROLLMENT_TTL_SECONDS` | Enrollment-grant lifetime. Default `900`, clamped to at most one hour. |
| `VLINK_ACCESS_TOKEN_TTL_SECONDS` | Temporary workload-token lifetime. Default `3600`, clamped to at most one day. |
| `VLINK_ALLOW_UNBOUND_COMPAT` | Deliberately enable unbound global compatibility traffic. Defaults off. |
| `VLINK_ALLOW_UNAUTHENTICATED_CREATE` | Explicit override allowing unauthenticated VLink creation in production. Defaults off in production. |
| `VLINK_RECEIPT_PRIVATE_KEY_PEM` | Optional Ed25519 private key PEM for stable receipt signing. If absent, VLink uses an explicitly disclosed ephemeral process key. |
| `VLINK_FAILOVER_TIMEOUT_MS` | Per-backend timeout for bounded failover. Default `4000`; clamped to 25–30000 ms. |
| `GEMINI_API_KEY` | Enables live Gemini-backed chat completion execution. |
| `GEMINI_MODEL` | Gemini model identifier used for live execution. |
| `VLINK_ENABLE_DEMO_RESPONSES` | Set `true` only for deliberately labeled demo chat responses. Defaults off. |
| `VLINK_ALLOWED_TARGET_HOSTS` | Comma-separated hostname allowlist for custom and failover targets. |

## Connection protocol

### 1. Create the VLink

```bash
curl -X POST http://localhost:3000/api/v1/vlinks \
  -H 'content-type: application/json' \
  -d '{
    "workspaceId":"default",
    "environment":"development",
    "displayName":"invoice-worker",
    "sourceType":"ai-client"
  }'
```

The creation response contains the non-secret VLink record, an expiring `vle_...` enrollment grant, and the manifest location. The enrollment grant authorizes **pairing initiation only**; it is not workload authority.

### 2. Initiate pairing

```bash
curl -X POST http://localhost:3000/api/v1/vlinks/<vlink-id>/pairing \
  -H 'content-type: application/json' \
  -H 'Authorization: Bearer <vle-enrollment-grant>' \
  -d '{"ttlSeconds":600}'
```

The initiating device receives an approval QR plus a separate `deviceCode`. The QR contains only the browser approval secret; the device code is retained separately by the initiating device.

### 3. Approve and exchange

Browser approval changes pairing state but returns no workload token. The initiating device exchanges its separate device code exactly once and receives the temporary `vlt_...` access token.

### 4. Use ordinary OpenAI-compatible configuration

```text
OPENAI_BASE_URL=http://localhost:3000/vlinks/<vlink-id>/v1
OPENAI_API_KEY=<vlt-temporary-vlink-token>
```

### 5. Retrieve and verify receipts

```bash
curl http://localhost:3000/receipts/vlinks/<vlink-id> \
  -H 'Authorization: Bearer <vlt-temporary-vlink-token>'
```

Public key descriptor:

```bash
curl http://localhost:3000/.well-known/vlink-receipt-key.json
```

Caller-supplied verification:

```bash
curl -X POST http://localhost:3000/receipts/verify \
  -H 'content-type: application/json' \
  -d '{"receipt":{...}}'
```

### 6. Use bounded failover only for a retry-safe request

```bash
curl -X POST http://localhost:3000/failover/vlinks/<vlink-id>/v1/chat/completions \
  -H 'Authorization: Bearer <vlt-temporary-vlink-token>' \
  -H 'Content-Type: application/json' \
  -H 'X-VLink-Retry-Safe: true' \
  -H 'X-VLink-Primary-Url: https://primary.example.com/chat' \
  -H 'X-VLink-Secondary-Url: https://secondary.example.com/chat' \
  -d '{"model":"example","messages":[{"role":"user","content":"hello"}]}'
```

Both target hostnames must be present in `VLINK_ALLOWED_TARGET_HOSTS`. VLink attempts the primary once. A transport error, timeout, or HTTP 5xx may trigger exactly one secondary attempt. A primary 4xx never triggers failover.

Response headers expose the measured routing result:

```text
X-VLink-Failover-Engaged
X-VLink-Failover-Recovered
X-VLink-Failover-Attempts
X-VLink-Primary-Outcome
X-VLink-Secondary-Outcome
X-VLink-Total-Latency-Ms
```

The same outcome is recorded as VLink activity and signed into a VLink receipt without storing the request or response body.

## Security posture of this release

- **VLink ID = connection identifier, not authority.**
- **Enrollment grant = short-lived permission to initiate pairing, not execute workloads.**
- **Browser approval = human/device approval, not a workload credential.**
- **VLink access token = short-lived authority for one VLink.**
- Access credentials are hashed server-side, expire, are revocable, and cannot be replayed across VLinks.
- VLink bearer credentials are never forwarded as upstream authorization on supported custom/failover routes.
- Manifests never publish enrollment, pairing, or workload credentials.
- Unknown or contradictory VLink bindings fail before execution/activity creation.
- Request/response bodies are not copied into VLink activity/failover evidence by these routes.
- Signed receipts cover the exact stored activity event and key identity; alteration breaks verification.
- Bounded failover requires explicit retry-safety declaration and never exceeds two total attempts.
- Production VLink connection/access/activity state must use `VLINK_STATE_PATH`; startup fails closed if that path is omitted.
- Durable state contains hashes rather than usable enrollment/pairing/access secrets and is rejected if corrupt, unsupported, duplicated, or cross-linked to unknown VLinks.
- The durable state file is a single-node operational store, not a substitute for external evidence anchoring or replicated storage.

## Architecture boundary

```text
Veklom Capability OS
        │
        └── VLink
              ├── portable connection object
              ├── self-binding connection URL
              ├── secret-free discovery manifest
              ├── short-lived enrollment grant
              ├── browser approval + device exchange
              ├── temporary VLink access token
              ├── restart-safe local connection/access/activity state
              ├── OpenAI-compatible ingress
              ├── webhook ingress
              ├── bounded retry-safe failover
              ├── activity events
              ├── Ed25519 signed receipts (receipt retention still process-local)
              └── future identity / capability / policy / external evidence bindings
```
