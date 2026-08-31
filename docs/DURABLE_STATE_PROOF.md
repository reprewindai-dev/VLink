# VLink Durable State Proof

**Status:** VERIFIED_CI

**Scope:** Single-node restart-safe local persistence for canonical VLink identity, hashed enrollment/pairing/access state, revocation state, and bounded activity metadata.

## Implemented boundary

- Production requires `VLINK_STATE_PATH`; startup fails closed if it is missing.
- Durable state is written outside source control under a configured persistent path.
- Enrollment grants, browser approval secrets, device exchange secrets, and workload access tokens are persisted only as SHA-256 hashes.
- Mutations are committed to a same-directory temporary file, synced through a writable file descriptor, and renamed into place.
- If durable persistence fails, the in-memory registry is restored to its previous snapshot and the mutation fails rather than reporting success.
- Loading fails closed on corrupt/unsupported state, duplicate identities, invalid hashes, and orphaned cross-VLink references.
- Activity retention remains bounded to 100 records per VLink across reload.

## Adversarial tests

Seven persistence falsifiers verify:

1. VLink identity, enrollment, pairing, workload access, activity, and revocation survive process-style registry recreation.
2. Plaintext enrollment, approval, device, and workload access secrets never appear in the durable state file.
3. Pairing expiry remains expired across reload.
4. Activity retention remains bounded across reload.
5. Corrupt and unsupported state fail closed.
6. Orphaned cross-VLink credential state is rejected before use.
7. Durable clear does not resurrect deleted runtime state.

## Cross-platform proof

GitHub Actions run `33350737043` passed both jobs on commit `896c75e89130e9e320562045ec13a453d591c3d5`:

- `verify` on Ubuntu: full test suite, TypeScript/lint gate, production build — PASS.
- `windows-durable-state` on Windows: seven persistence falsifiers and TypeScript/lint gate — PASS.

The Windows gate previously falsified the first implementation because `fsync` on a read-only file descriptor returned `EPERM`. The implementation was repaired to create/write/sync the temporary file through a writable descriptor; the same Windows gate then passed.

## Claim boundary

This proof earns:

> VLink provides restart-safe single-node local persistence for VLink identity, hashed enrollment/pairing/access state, revocation state, and bounded activity metadata when `VLINK_STATE_PATH` points to persistent storage.

It does **not** claim:

- multi-node or replicated database durability;
- malicious-local-admin tamper resistance;
- durable signed-receipt object retention;
- external evidence anchoring;
- zero data loss under physical disk failure.

Signed VLink receipt objects remain process-local in the current receipt support layer. Stable signing identity separately requires a configured persistent Ed25519 signing key.
