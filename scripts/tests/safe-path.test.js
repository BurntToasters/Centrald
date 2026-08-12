import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  cleanGeneratedDirectory,
  ensureGeneratedDirectory,
  resolveGeneratedTarget,
} from "../lib/safe-path.js";

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "centrald-safe-path-"));
  return {
    root,
    dispose() {
      fs.rmSync(root, { recursive: true, force: true });
    },
  };
}

test("rejects broad and escaping cleanup targets", () => {
  const testRoot = fixture();
  try {
    for (const target of [
      "",
      ".",
      "..",
      "../outside",
      "src",
      path.parse(testRoot.root).root,
    ]) {
      assert.throws(() => resolveGeneratedTarget(testRoot.root, target));
    }
  } finally {
    testRoot.dispose();
  }
});

test("requires marker before recursive cleanup", () => {
  const testRoot = fixture();
  try {
    fs.mkdirSync(path.join(testRoot.root, "dist"));
    assert.throws(() => cleanGeneratedDirectory(testRoot.root, "dist"));
    fs.writeFileSync(path.join(testRoot.root, "dist", "keep.txt"), "keep");
    assert.equal(
      fs.existsSync(path.join(testRoot.root, "dist", "keep.txt")),
      true,
    );
  } finally {
    testRoot.dispose();
  }
});

test("cleans only a marked allowlisted directory", () => {
  const testRoot = fixture();
  try {
    const target = ensureGeneratedDirectory(testRoot.root, "release");
    fs.writeFileSync(path.join(target, "artifact"), "test");
    assert.equal(cleanGeneratedDirectory(testRoot.root, "release"), true);
    assert.equal(fs.existsSync(target), false);
  } finally {
    testRoot.dispose();
  }
});


test("rejects a symlinked generated-output ancestor", (t) => {
  if (process.platform === "win32") {
    t.skip("junction behavior is covered by the native Windows CI smoke test");
    return;
  }
  const testRoot = fixture();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "centrald-safe-outside-"));
  try {
    fs.symlinkSync(outside, path.join(testRoot.root, "dist"), "dir");
    assert.throws(() => ensureGeneratedDirectory(testRoot.root, "dist/nested"));
    assert.equal(fs.existsSync(path.join(outside, "nested")), false);
  } finally {
    testRoot.dispose();
    fs.rmSync(outside, { recursive: true, force: true });
  }
});
