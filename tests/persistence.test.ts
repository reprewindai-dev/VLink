import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { FileBackedVLinkRegistry } from "../src/server/fileBackedRegistry";

const withStatePath = (fn: (statePath: string) => void) => {
  const dir = mkdtempSync(path.join(tmpdir(), "vlink-state-test-"));
  try {
    fn(path.join(dir, "vlink-state.json"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};

const createLink = (registry: FileBackedVLinkRegistry) =>
  registry.create(
    {
      workspaceId: "workspace-durable",
      environment: "production",
      displayName: "Durable VLink",
      sourceType: "api-service",
    },
    "https://vlink.example.test",
  );

test("VLink identity, pairing, access, activity, and revocation survive process-style registry recreation", () => {
  withStatePath((statePath) => {
    const first = new FileBackedVLinkRegistry({ statePath });
    const vlink = createLink(first);
    const enrollment = first.issueEnrollmentGrant(vlink.vlinkId, 900, new Date("2026-08-30T20:00:00Z"));
    assert.ok(enrollment);
    assert.ok(first.authenticateEnrollment(vlink.vlinkId, enrollment.token, new Date("2026-08-30T20:01:00Z")));

    const pairing = first.createPairing(
      vlink.vlinkId,
      "https://vlink.example.test",
      600,
      new Date("2026-08-30T20:00:00Z"),
    );
    assert.ok(pairing);
    assert.equal(
      first.approvePairing(vlink.vlinkId, pairing.pairingId, pairing.approvalCode, new Date("2026-08-30T20:01:00Z"))?.status,
      "approved",
    );
    const credential = first.exchangePairing(
      vlink.vlinkId,
      pairing.pairingId,
      pairing.deviceCode,
      3600,
      new Date("2026-08-30T20:02:00Z"),
    );
    assert.ok(credential);

    first.addActivity(
      {
        vlinkId: vlink.vlinkId,
        sourceType: "api-service",
        route: "/v1/chat/completions",
        method: "POST",
        mode: "observe",
        status: "completed",
        latencyMs: 12,
        metadata: { durable: true },
      },
      new Date("2026-08-30T20:03:00Z"),
    );

    const second = new FileBackedVLinkRegistry({ statePath });
    assert.equal(second.get(vlink.vlinkId)?.displayName, "Durable VLink");
    assert.ok(second.authenticateEnrollment(vlink.vlinkId, enrollment.token, new Date("2026-08-30T20:04:00Z")));
    assert.equal(second.authenticate(vlink.vlinkId, credential.token, new Date("2026-08-30T20:04:00Z"))?.status, "active");
    assert.equal(second.activity(vlink.vlinkId).length, 1);

    assert.equal(
      second.revokeCredential(vlink.vlinkId, credential.credentialId, new Date("2026-08-30T20:05:00Z"))?.status,
      "revoked",
    );

    const third = new FileBackedVLinkRegistry({ statePath });
    assert.equal(third.authenticate(vlink.vlinkId, credential.token, new Date("2026-08-30T20:06:00Z")), undefined);
    assert.equal(
      third.revokeCredential(vlink.vlinkId, credential.credentialId, new Date("2026-08-30T20:06:00Z"))?.status,
      "revoked",
    );
  });
});

test("durable state never persists plaintext enrollment, approval, device, or access secrets", () => {
  withStatePath((statePath) => {
    const registry = new FileBackedVLinkRegistry({ statePath });
    const vlink = createLink(registry);
    const enrollment = registry.issueEnrollmentGrant(vlink.vlinkId)!;
    const pairing = registry.createPairing(vlink.vlinkId, "https://vlink.example.test")!;
    registry.approvePairing(vlink.vlinkId, pairing.pairingId, pairing.approvalCode);
    const credential = registry.exchangePairing(vlink.vlinkId, pairing.pairingId, pairing.deviceCode)!;

    const raw = readFileSync(statePath, "utf8");
    for (const secret of [enrollment.token, pairing.approvalCode, pairing.deviceCode, credential.token]) {
      assert.equal(raw.includes(secret), false, `durable state leaked secret ${secret.slice(0, 8)}...`);
    }
    assert.equal(raw.includes("tokenHash"), true);
    assert.equal(raw.includes("approvalCodeHash"), true);
    assert.equal(raw.includes("deviceCodeHash"), true);
  });
});

test("expired pairing state is persisted after a restart-visible status check", () => {
  withStatePath((statePath) => {
    const first = new FileBackedVLinkRegistry({ statePath });
    const vlink = createLink(first);
    const pairing = first.createPairing(
      vlink.vlinkId,
      "https://vlink.example.test",
      1,
      new Date("2026-08-30T20:00:00Z"),
    )!;

    const second = new FileBackedVLinkRegistry({ statePath });
    assert.equal(
      second.getPairingStatus(vlink.vlinkId, pairing.pairingId, new Date("2026-08-30T20:00:02Z"))?.status,
      "expired",
    );

    const third = new FileBackedVLinkRegistry({ statePath });
    assert.equal(third.getPairingStatus(vlink.vlinkId, pairing.pairingId)?.status, "expired");
    assert.equal(third.get(vlink.vlinkId)?.enrollmentStatus, "expired");
  });
});

test("activity retention remains bounded to 100 records across durable reload", () => {
  withStatePath((statePath) => {
    const registry = new FileBackedVLinkRegistry({ statePath });
    const vlink = createLink(registry);
    for (let i = 0; i < 105; i += 1) {
      registry.addActivity({
        vlinkId: vlink.vlinkId,
        sourceType: "api-service",
        route: `/event/${i}`,
        method: "POST",
        mode: "observe",
        status: "completed",
        latencyMs: i,
        metadata: { index: i },
      });
    }
    const reloaded = new FileBackedVLinkRegistry({ statePath });
    const events = reloaded.activity(vlink.vlinkId);
    assert.equal(events.length, 100);
    assert.equal(events[0]?.route, "/event/104");
    assert.equal(events[99]?.route, "/event/5");
  });
});

test("corrupt or unsupported durable state fails closed instead of silently starting empty", () => {
  withStatePath((statePath) => {
    writeFileSync(statePath, "{ definitely-not-json", "utf8");
    assert.throws(() => new FileBackedVLinkRegistry({ statePath }), /could not be parsed/);

    writeFileSync(statePath, JSON.stringify({ format: "vlink-registry/v999", vlinks: [] }), "utf8");
    assert.throws(() => new FileBackedVLinkRegistry({ statePath }), /unsupported format/);
  });
});

test("orphaned cross-VLink credential state is rejected before the registry becomes usable", () => {
  withStatePath((statePath) => {
    const registry = new FileBackedVLinkRegistry({ statePath });
    const vlink = createLink(registry);
    const pairing = registry.createPairing(vlink.vlinkId, "https://vlink.example.test")!;
    registry.approvePairing(vlink.vlinkId, pairing.pairingId, pairing.approvalCode);
    registry.exchangePairing(vlink.vlinkId, pairing.pairingId, pairing.deviceCode);

    const state = JSON.parse(readFileSync(statePath, "utf8")) as {
      credentials: Array<{ vlinkId: string }>;
    };
    assert.ok(state.credentials.length > 0);
    state.credentials[0]!.vlinkId = "vlk_0000000000000000";
    writeFileSync(statePath, JSON.stringify(state), "utf8");

    assert.throws(() => new FileBackedVLinkRegistry({ statePath }), /orphan credential\.vlinkId/);
  });
});

test("clear is durable and does not resurrect deleted runtime state", () => {
  withStatePath((statePath) => {
    const registry = new FileBackedVLinkRegistry({ statePath });
    createLink(registry);
    assert.equal(registry.list().length, 1);
    registry.clear();
    assert.equal(new FileBackedVLinkRegistry({ statePath }).list().length, 0);
  });
});
