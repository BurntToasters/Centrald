import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);

test("package.json contains deps:rust:update, test:cargo-safe-update, and check:cargo-update-policy", () => {
  const pkg = JSON.parse(
    readFileSync(path.join(repoRoot, "package.json"), "utf8"),
  );
  assert.equal(
    pkg.scripts["deps:rust:update"],
    "node scripts/cargo-safe-update.mjs --manifest-path Cargo.toml",
  );
  assert.equal(
    pkg.scripts["test:cargo-safe-update"],
    "node --test scripts/cargo-safe-update.test.mjs scripts/check-cargo-update-policy.test.mjs",
  );
  assert.equal(
    pkg.scripts["check:cargo-update-policy"],
    "node scripts/check-cargo-update-policy.mjs",
  );
});

test("scripts/qa.js wires in test:cargo-safe-update and check:cargo-update-policy", () => {
  const qaScript = readFileSync(path.join(repoRoot, "scripts/qa.js"), "utf8");
  assert.match(qaScript, /test:cargo-safe-update/);
  assert.match(qaScript, /check:cargo-update-policy/);
});

test("cargo-update-policy scanner passes cleanly", () => {
  const output = execFileSync(
    process.execPath,
    [path.join(repoRoot, "scripts/check-cargo-update-policy.mjs")],
    { cwd: repoRoot, encoding: "utf8" },
  );
  assert.match(output, /no unguarded cargo dependency mutation found/);
});
