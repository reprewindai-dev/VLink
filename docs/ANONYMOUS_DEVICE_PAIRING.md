# Anonymous device pairing (local implementation)

This flow lets a completely unknown device initiate pairing without a VLink, account credential, or enrollment grant. Bootstrap creates a pending request only; it issues no VLink credential and no consequence authority. The device-side Node client is implemented in `src/client/deviceClient.ts`.

## Protocol

1. Create a device client and start bootstrap. The client generates an Ed25519 key pair locally, retains the private key in memory, and sends only the SPKI public key to:

   `POST /api/v1/device/bootstrap`

   The response contains a `pairingId`, owner-review URL, public-key SHA-256 thumbprint, short-lived bootstrap challenge, and `consequenceAuthority: "none"`. Bootstrap does not accept or trust a caller-supplied workspace ID. The client signs the bootstrap challenge and submits proof of possession.

2. The human opens the returned approval URL, signs in through LockerPhycer, confirms the owning workspace, completes recent MFA, and compares the displayed key thumbprint with the initiating device. The owner approves the request; only then does VLink bind the device key to the owner's workspace and create the VLink identity. The authenticated owner receives a short-lived `vle_...` enrollment grant for VLink administration (including pairing and CAPPO lease binding), not CAPPO consequence authority. If the approval response is lost, the same owner can re-authenticate with MFA and recover the same unexpired grant; its token is sealed at rest and omitted from public status responses.

3. After approval, the device calls `recoverCredential()`. It reads approval status, obtains a fresh exchange challenge, signs it, and exchanges it for a device-bound temporary credential. If the exchange response is lost, calling `recoverCredential()` again returns the same credential while it remains active; it does not mint another identity or credential.

4. Protected VLink calls use `device.request(path, init)`. The client signs each request with the device key and adds the proof header. Use the exact serialized request body when signing; the helper accepts a string or byte array so the signed bytes are the sent bytes.

Example:

```ts
import { VLinkDeviceClient } from "./src/client/deviceClient";

const device = new VLinkDeviceClient({ apiBaseUrl: process.env.VLINK_URL! });
const { bootstrap } = await device.beginPairing({
  displayName: "build-runner-01",
  environment: "development",
  sourceType: "cicd",
});
console.log(`Approve this device: ${bootstrap.approvalUrl}`);
console.log(`Verify device key: ${device.deviceKeyThumbprint}`);

// After the owner approves in Veklom:
const credential = await device.recoverCredential();
const activity = await device.request(`/api/v1/vlinks/${credential.vlinkId}/activity`);
```

The helper does not persist secrets automatically. If a device must resume after process restart, store `exportPrivateKeyPem()` and `pairingId` in an OS-protected secret store, then pass both to a new `VLinkDeviceClient`. Never print or commit the private key or returned credential.

## Current limits (do not overclaim)

- Device-bound credentials also require an Ed25519 proof on each protected HTTP request. The proof binds the VLink and credential IDs, bearer-token hash, HTTP method, exact origin-form path/query, lowercase Host, SHA-256 of the exact request-body bytes, timestamp, and one-use random nonce. The credential alone is not enough.
- `X-VLink-Device-Proof` contains unpadded base64url JSON with exactly `timestampMs`, `nonce`, and `signature`. The signature is Ed25519 over the UTF-8 JSON serialization of this exact array:

  `["vlink-device-request-proof/v1", vlinkId, credentialId, sha256(token), METHOD, target, host, sha256(rawBody), timestampMs, nonce]`

  `METHOD` is uppercase; `target` is the exact path plus query sent to VLink; `host` is the request Host in lowercase; an absent body is the empty byte string. The timestamp may be at most 60 seconds old or 5 seconds in the future. The nonce is 32 random bytes encoded as unpadded base64url. The server remembers its hash for 120 seconds, and the same proof is rejected on replay, including after a single-process file-backed restart.
- Replay records are bounded to 50,000 outstanding nonces; authentication fails closed while the bound is full. The file-backed registry remains a single-process/single-writer store, not a horizontally scaled replay coordinator.
- The Node device client supports bootstrap, exchange recovery, and signed protected HTTP requests. The React UI is the human approval surface; ordinary OpenAI-compatible SDKs have not yet been integrated with the signing client. Existing legacy code/device-code credentials remain bearer-compatible. Do not claim frictionless support for arbitrary OpenAI SDKs until an SDK adapter exists and is tested.
- VLink pairing is not CAPPO consequence authority. CAPPO remains the final authority boundary.
- Physical machine attestation is not implemented by this flow.
- The included persistence test covers one file-backed process stopping and restarting. The file-backed registry is not a multi-process transaction coordinator; do not run multiple writers against one state file or claim horizontally scaled idempotency from this test.
- Anonymous bootstrap creation is throttled by a persisted per-source window (default 10 per 10 minutes) and a persisted instance-wide window (default 100 per hour). The registry stores HMAC fingerprints, not source IPs. The state file remains a single-process/single-writer store; do not mount it into multiple VLink writers.
- Recoverable owner-grant and device-credential exchange requires a stable `VLINK_LEASE_SEALING_KEY`; without it, approval/exchange fails closed rather than returning a non-recoverable credential.
- Express trusts no forwarded client-address header by default. If VLink sits behind a reverse proxy and per-client rather than aggregate proxy-peer throttling is required, configure only the exact proxy CIDRs through `VLINK_TRUST_PROXY_CIDRS`. The edge should also have its own request-size and volumetric controls before anonymous bootstrap is exposed broadly.
- Production anonymous bootstrap remains opt-in and requires a stable `VLINK_BOOTSTRAP_RATE_LIMIT_KEY` of at least 32 bytes. Rotating that key resets per-source buckets (the instance-wide bucket remains persisted).
