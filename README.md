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
- Short-lived, one-time pairing requests. QR payloads contain an expiring enrollment code, never a reusable API key.
- A real internal connection-test route that creates a VLink-bound activity event.
- VLink activity timeline endpoint.
- Dedicated VLink webhook ingress plus compatibility with the prototype webhook route.
- Optional `X-VLink-Id` binding on OpenAI-compatible and webhook traffic, with existence validation.
- OpenAI-compatible `/v1/models` and `/v1/chat/completions` routes.
- Live Gemini execution when `GEMINI_API_KEY` and a model are configured.
- Explicit demo responses only when `VLINK_ENABLE_DEMO_RESPONSES=true`.
- Custom HTTP target forwarding only to hosts explicitly listed in `VLINK_ALLOWED_TARGET_HOSTS`.
- React UI for Create VLink, generated setup text, pairing QR, connection test, and activity display.

## Not claimed / not implemented yet

VLink does **not** currently claim any of the following:

- Cryptographically signed or independently verifiable receipts.
- Durable database persistence.
- Production SPIFFE/SPIRE workload identity issuance or verification.
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

Read its manifest:

```bash
curl http://localhost:3000/api/v1/vlinks/<vlink-id>/manifest
```

Run the connection test:

```bash
curl -X POST http://localhost:3000/api/v1/vlinks/<vlink-id>/test \
  -H 'content-type: application/json' -d '{}'
```

Read activity:

```bash
curl http://localhost:3000/api/v1/vlinks/<vlink-id>/activity
```

Bind an OpenAI-compatible request to the VLink:

```bash
curl -X POST http://localhost:3000/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'X-VLink-Id: <vlink-id>' \
  -d '{"model":"your-model","messages":[{"role":"user","content":"hello"}]}'
```

Without a configured live provider, this returns `503` unless demo responses were deliberately enabled.

## Security posture of this release

- Manifests contain connection metadata only; pairing secrets are not published in manifests.
- Pairing codes are short-lived and one-time use.
- Unknown user-supplied VLink IDs are rejected before events are recorded.
- Webhook request bodies are accepted by the ingress route but are **not persisted** by the in-memory activity store; activity records store metadata such as payload size.
- Arbitrary SSRF-style `X-Target-Url` forwarding is disabled by default and requires a hostname allowlist.
- Registry, pairing, and activity state are lost when the process restarts. Production deployment requires persistent storage and an authentication/authorization layer before exposing management routes publicly.

## Architecture boundary

```text
Veklom Capability OS
        │
        └── VLink
              ├── portable connection object
              ├── non-secret discovery manifest
              ├── short-lived enrollment / pairing
              ├── OpenAI-compatible ingress
              ├── webhook ingress
              ├── activity events
              └── future identity / capability / policy / evidence bindings
```

VLink is not the whole Capability OS. It is the low-friction connection primitive that makes the rest of Veklom reachable.
