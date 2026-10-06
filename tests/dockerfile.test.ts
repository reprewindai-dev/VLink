import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";

const dockerfile = readFileSync(path.join(process.cwd(), "Dockerfile"), "utf8").split(/\r?\n/);
const lineIndex = (pattern: RegExp) => dockerfile.findIndex((line) => pattern.test(line));

test("runtime image owns /app/data before dropping to the vlink user", () => {
  const userMatch = dockerfile.map((line) => /^USER\s+(\S+)/.exec(line)).find(Boolean);
  assert.ok(userMatch, "runner stage must drop privileges with USER");
  const runtimeUser = userMatch![1];
  const groupMatch = dockerfile.map((line) => /addgroup\s+--system\s+--gid\s+\d+\s+(\S+)/.exec(line)).find(Boolean);
  assert.ok(groupMatch, "runner stage must create a system group for the runtime user");

  const stateDir = lineIndex(new RegExp(`^RUN mkdir -p /app/data && chown ${runtimeUser}:${groupMatch![1]} /app/data$`));
  const dropPrivileges = lineIndex(new RegExp(`^USER\s+${runtimeUser}$`));
  assert.notEqual(stateDir, -1, "Dockerfile must create /app/data owned by the runtime user");
  assert.ok(stateDir < dropPrivileges, "/app/data must be prepared while still root, before USER");
});
