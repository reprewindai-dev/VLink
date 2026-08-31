# VLink

> Link existing tools, models, workflows, and services to Veklom without rewriting application logic.

VLink is the low-friction connection primitive into Veklom. It creates a portable, self-describing connection object that a model client, workflow, service, local project, CI job, container, or future MCP client can use without adopting a large SDK.

The current product flow is:

**Create → Pair → Receive temporary access → Connect → Test → Observe activity → later attach governance.**

## What is implemented now

- Versioned `VLink` TypeScript contract (`vlink/v1`).
- In-memory registry behind a replaceable interface.
- VLink create/list/read endpoints.
- Secret-free machine-readable manifests at `/.well-known/vlink.json` and `/api/v1/vlinks/:vlinkId/manifest`.
- A self-binding OpenAI-compatible base URL for every VLink: `/vlinks/<vlink-id>/v1`.
- A short-lived enrollment grant returned only at VLink creation. The VLink ID alone cannot initiate pairing.
- Browser/device pairing with **two independent secrets**:
  - an approval secret placed only in the QR/browser URL fragment;
  - a device-exchange secret retained by the initiating tool/device and never placed in the QR.
- Approval and credential issuance are separate operations. Browser approval cannot mint a workload token by itself.
- One-time device exchange for an opaque, short-lived VLink bearer token.
- Enrollment grants and workload tokens are stored hashed server-side rather than retained in usable form.
- VLink access tokens are bound to one VLink and reject cross-VLink replay.
- Immediate access-token revocation and TTL expiry.
- Protected VLink-specific OpenAI-compatible, webhook, test, and activity routes.
- Unbound global `/v1` compatibility disabled by default; explicit VLink binding plus a valid access token is required unless compatibility is deliberately enabled.
- Live Gemini execution when `GEMINI_API_KEY` and a model are configured.
- Explicit demo responses only when `VLINK_ENABLE_DEMO_RESPONSES=true`.
- Custom HTTP target forwarding only to hosts explicitly listed in `VLINK_ALLOWED_TARGET_HOSTS`.
- VLink bearer credentials are consumed at the VLink boundary and are **not forwarded** to an upstream custom target.
- Webhook request bodies are not persisted in activity records.
- React UI for Create → QR approval → automatic device exchange → temporary token → authenticated test/activity.
- Browser routes fall through to the SPA while missing API routes stay fail-closed JSON 404s.

## Proof gate

The current short-lived-access branch has passed a clean GitHub Actions gate with:

- **23 tests passed, 0 failed**
- `tsc --noEmit`
- production Vite + server build

The adversarial suite covers VLink-ID-only denial, enrollment-grant binding, production creation fail-closed behavior, secret-free manifests, QR/device-secret separation, approval/exchange separation, wrong-device denial, one-time exchange, access-token binding, cross-VLink replay denial, expiry, revocation, unbound-route denial, authenticated activity, webhook body non-persistence, and prevention of VLink bearer-token forwarding to an upstream target.

## Not claimed / not implemented yet

VLink does **not** currently claim any of the following:

- Cryptographically signed or independently verifiable receipts.
- Durable database persistence.
- Production SPIFFE/SPIRE workload identity issuance or verification.
- Veklom account/workspace authentication for management routes. Production-style configuration therefore disables unauthenticated VLink creation rather than inventing account authority.
- Hardware attestation or enclave verification.
- Formal non-repudiation.
- Verified multi-provider failover or zero-downtime switching.
- General zero-data-loss rollback. Compensation semantics must be defined and verified per consequence type/provider.
- Full MCP transport. `/mcp/v1` is an explicit `501 planned` placeholder.
- Full Veklom Capability OS policy/capability enforcement. The VLink record reserves references for that integration but this repo does not pretend the boundary is already attached.

Activity entries are therefore still called **activity events**, not cryptographic receipts.

The OmniConnect prototype contains additional candidate capabilities—signed receipts, delegation, compensation/rollback, shadow evaluation, backend promotion/failover, MCP tooling, no-code integrations, control sockets, and connection UX. Those are treated as implementation targets, not discarded ideas: each capability must be implemented against a falsifiable contract and earn its claim independently.

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

## Environment variables

| Variable | Purpose |
| --- | --- |
| `PORT` | HTTP port. Default `3000`. |
| `VLINK_PUBLIC_ORIGIN` | Canonical public origin used in generated manifests/endpoints. |
| `VLINK_CORS_ORIGIN` | Allowed browser origin. Default `*` for local/prototype use; set explicitly in production. |
| `VLINK_ENROLLMENT_TTL_SECONDS` | Enrollment-grant lifetime. Default `900`, clamped to at most one hour. |
| `VLINK_ACCESS_TOKEN_TTL_SECONDS` | Temporary workload-token lifetime. Default `3600`, clamped to at most one day. |
| `VLINK_ALLOW_UNBOUND_COMPAT` | Deliberately enable unbound global compatibility traffic. Defaults off. |
| `VLINK_ALLOW_UNAUTHENTICATED_CREATE` | Explicit override allowing unauthenticated VLink creation in production. Defaults off in production. |
| `GEMINI_API_KEY` | Enables live Gemini-backed chat completion execution. |
| `GEMINI_MODEL` | Gemini model identifier used for live execution. |
| `VLINK_ENABLE_DEMO_RESPONSES` | Set `true` only for deliberately labeled demo chat responses. Defaults off. |
| `VLINK_ALLOWED_TARGET_HOSTS` | Comma-separated hostname allowlist for `X-Target-Url`. Arbitrary target URLs are rejected. |

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

The creation response contains:

- the non-secret VLink record;
- an expiring `vle_...` enrollment grant;
- the manifest location.

The enrollment grant authorizes **pairing initiation only**. It is not accepted as workload authority.

### 2. Initiate pairing

```bash
curl -X POST http://localhost:3000/api/v1/vlinks/<vlink-id>/pairing \
  -H 'content-type: application/json' \
  -H 'Authorization: Bearer <vle-enrollment-grant>' \
  -d '{"ttlSeconds":600}'
```

The initiating device receives an approval QR plus a separate `deviceCode`. The QR opens:

```text
/pair/<vlink-id>/<pairing-id>#approval=<one-time-approval-secret>
```

The approval secret is in the URL fragment, so the browser does not send it in the HTTP request path/query. The `deviceCode` is **not** present in the QR.

### 3. Approve in the browser

The browser calls the approval endpoint with the one-time approval secret. Approval changes the pairing state but returns no workload token.

### 4. Exchange on the initiating device

After approval, the initiating device exchanges its separate device code exactly once:

```bash
curl -X POST http://localhost:3000/api/v1/vlinks/<vlink-id>/pairing/<pairing-id>/exchange \
  -H 'content-type: application/json' \
  -d '{"deviceCode":"<device-code>"}'
```

The response returns a temporary `vlt_...` VLink access token. Secret-bearing creation/pairing/exchange responses use `Cache-Control: no-store`.

### 5. Use ordinary OpenAI-compatible configuration

```text
OPENAI_BASE_URL=http://localhost:3000/vlinks/<vlink-id>/v1
OPENAI_API_KEY=<vlt-temporary-vlink-token>
```

No custom VLink header is needed on the self-binding URL.

Example:

```bash
curl -X POST http://localhost:3000/vlinks/<vlink-id>/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'Authorization: Bearer <vlt-temporary-vlink-token>' \
  -d '{"model":"your-model","messages":[{"role":"user","content":"hello"}]}'
```

Without a configured live provider, model execution returns `503` unless demo responses were deliberately enabled.

## Security posture of this release

- **VLink ID = connection identifier, not authority.**
- **Enrollment grant = short-lived permission to initiate pairing, not execute workloads.**
- **Browser approval = human/device approval, not a workload credential.**
- **VLink access token = short-lived authority for one VLink.**
- Enrollment grants and access tokens are stored as hashes server-side.
- Approval secret and device-exchange secret are independent.
- Approval and device exchange are one-time transitions.
- Access tokens expire and can be revoked immediately.
- Access tokens cannot be replayed against another VLink.
- VLink bearer tokens are never forwarded as upstream authorization when using an allowlisted custom target.
- Manifests never publish enrollment, pairing, or workload credentials.
- Unknown or contradictory VLink bindings fail before execution/activity creation.
- Request/response bodies are not copied into VLink activity events by these routes.
- In-memory state is lost on restart. Durable persistence remains required before production service claims.

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
              ├── OpenAI-compatible ingress
              ├── webhook ingress
              ├── activity events
              └── future identity / capability / policy / evidence bindings
```

VLink is not the whole Capability OS. It is the connection primitive that makes the rest of Veklom reachable with minimum integration friction.
