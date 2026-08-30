# VLink

> Link existing tools, models, workflows, and services to Veklom without rewriting application logic.

VLink is a Veklom connection module extracted from the OmniConnect prototype. Its job is deliberately narrow: create a portable, self-describing connection object that a model client, workflow, service, local project, CI job, container, or future MCP client can use to connect to Veklom with low setup friction.

The first release follows one product flow:

**Create → Connect → Test → Observe activity → later attach governance.**

## What is implemented now

- Versioned `VLink` TypeScript contract (`vlink/v1`).
- In-memory registry behind an interface that can be replaced by persistent storage later.
- VLink create/list/read endpoints.
- Non-secret machine-readable manifests at `/.well-known/vlink.json` and `/api/v1/vlinks/:vlinkId/manifest`.
- A self-binding OpenAI-compatible base URL for every VLink: `/vlinks/<vlink-id>/v1`. Normal compatible clients can change one base URL without adding a custom VLink header.
- Short-lived, one-time browser pairing requests. QR codes open an approval page and keep the approval code in the URL fragment so it is not sent in the browser request path/query.
- Pairing status responses strip the one-time code, and successful approval cannot be replayed.
- A real internal connection-test route that creates a VLink-bound activity event.
- VLink activity timeline endpoint.
- Dedicated VLink webhook ingress plus compatibility with the prototype webhook route.
- Optional legacy `X-VLink-Id` binding on the global OpenAI-compatible and webhook routes, with existence validation.
- OpenAI-compatible model and chat-completion routes.
- Live Gemini execution when `GEMINI_API_KEY` and a model are configured.
- Explicit demo responses only when `VLINK_ENABLE_DEMO_RESPONSES=true`.
- Custom HTTP target forwarding only to hosts explicitly listed in `VLINK_ALLOWED_TARGET_HOSTS`.
- React UI for Create VLink, one-URL setup text, pairing QR/browser approval, connection test, and activity display.
- Browser routes deliberately fall through to the Vite/static SPA while missing API routes remain fail-closed JSON 404s.

## Not claimed / not implemented yet

VLink does **not** currently claim any of the following:

- Cryptographically signed or independently verifiable receipts.
- Durable database persistence.
- Production SPIFFE/SPIRE workload identity issuance or verification.
- Production authentication/authorization for VLink management or execution traffic.
- A post-pairing workload access credential. The current pairing flow proves one-time user approval; credential issuance/exchange is the next security slice.
- Hardware attestation or enclave verification.
- Formal non-repudiation.
- Verified multi-cloud failover or zero-downtime switching.
- Full MCP transport. `/mcp/v1` is an explicit `501 planned` placeholder.
- Full Veklom capability/policy enforcement. The VLink record reserves opaque references for future integration, but this repo does not pretend those services exist here.

Activity entries are therefore called **activity events**, not cryptographic receipts.

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

The current boundary suite covers VLink creation, secret-free manifests, endpoint-swap binding, conflicting/unknown IDs, one-time browser pairing, pairing expiry/replay, UI-route fallthrough, API fail-closed behavior, VLink-bound activity, and prototype OpenAI/webhook compatibility.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `PORT` | HTTP port. Default `3000`. |
| `VLINK_PUBLIC_ORIGIN` | Canonical public origin used in generated manifests/endpoints. |
| `VLINK_CORS_ORIGIN` | Allowed browser origin. Default `*` for local/prototype use; set explicitly in production. |
| `GEMINI_API_KEY` | Enables live Gemini-backed chat completion execution. |
| `GEMINI_MODEL` | Gemini model identifier used for live execution. |
| `VLINK_ENABLE_DEMO_RESPONSES` | Set `true` only when you intentionally want clearly labeled demo chat responses. Defaults off. |
| `VLINK_ALLOWED_TARGET_HOSTS` | Comma-separated host allowlist for `X-Target-Url` forwarding. Arbitrary target URLs are rejected. |

## Core API

Create a VLink:

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

The returned VLink contains a base URL like:

```text
http://localhost:3000/vlinks/vlk_abc123/v1
```

Use that as the client's OpenAI-compatible base URL. The connection URL itself binds traffic to the VLink, so no `X-VLink-Id` header is required:

```bash
curl -X POST http://localhost:3000/vlinks/<vlink-id>/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"your-model","messages":[{"role":"user","content":"hello"}]}'
```

The global `/v1` compatibility route remains available and can still be explicitly bound with `X-VLink-Id` for clients that need that pattern.

Read the machine-readable manifest:

```bash
curl http://localhost:3000/api/v1/vlinks/<vlink-id>/manifest
```

Run the internal connection test:

```bash
curl -X POST http://localhost:3000/api/v1/vlinks/<vlink-id>/test \
  -H 'content-type: application/json' -d '{}'
```

Read activity:

```bash
curl http://localhost:3000/api/v1/vlinks/<vlink-id>/activity
```

Start browser pairing:

```bash
curl -X POST http://localhost:3000/api/v1/vlinks/<vlink-id>/pairing \
  -H 'content-type: application/json' \
  -d '{"ttlSeconds":600}'
```

The creator receives an expiring QR payload. Scanning it opens `/pair/<vlink-id>/<pairing-id>#code=<one-time-code>`. The fragment is processed by the browser UI and is not part of the HTTP request URL sent to the server. Approval is explicit and one-time.

Without a configured live provider, model execution returns `503` unless demo responses were deliberately enabled.

## Security posture of this release

- **A VLink ID is a connection identifier, not authentication or authority.** Putting it in the URL makes connection binding frictionless; it does not make possession of the URL sufficient authorization for a production deployment.
- Manifests contain connection metadata only; pairing secrets are not published in manifests.
- Pairing approval codes are short-lived and one-time use.
- Pairing approval codes live in a browser URL fragment, not the server-visible path or query string.
- Public pairing-status responses strip the approval code and QR payload.
- Unknown user-supplied VLink IDs are rejected before events are recorded.
- A VLink-specific URL rejects a contradictory `X-VLink-Id`/query binding rather than silently reassigning the activity.
- Webhook request bodies are accepted by the ingress route but are **not persisted** by the in-memory activity store; activity records store metadata such as payload size.
- Arbitrary SSRF-style `X-Target-Url` forwarding is disabled by default and requires a hostname allowlist.
- Registry, pairing, and activity state are lost when the process restarts. Production deployment requires persistent storage and an authentication/authorization layer before exposing management or execution routes publicly.

## Architecture boundary

```text
Veklom Capability OS
        │
        └── VLink
              ├── portable connection object
              ├── self-binding connection URL
              ├── non-secret discovery manifest
              ├── short-lived browser approval / pairing
              ├── OpenAI-compatible ingress
              ├── webhook ingress
              ├── activity events
              └── future identity / capability / policy / evidence bindings
```

VLink is not the whole Capability OS. It is the low-friction connection primitive that makes the rest of Veklom reachable.
