import test from "node:test";
import assert from "node:assert/strict";
import {
  MIN_PUBLISH_AGE_MS,
  crateIndexPath,
  isPublishAgeAllowed,
  parseArguments,
  parsePublishTime,
} from "./cargo-safe-update.mjs";

const now = Date.parse("2026-08-20T12:00:00Z");

test("enforces 72-hour publish age exactly", () => {
  assert.equal(isPublishAgeAllowed(now - MIN_PUBLISH_AGE_MS, now), true);
  assert.equal(isPublishAgeAllowed(now - MIN_PUBLISH_AGE_MS + 1, now), false);
});

test("rejects missing and malformed timestamps", () => {
  assert.equal(parsePublishTime(undefined), null);
  assert.equal(parsePublishTime("invalid"), null);
  assert.equal(isPublishAgeAllowed(null, now), false);
});

test("uses crates.io sparse index layout", () => {
  assert.equal(crateIndexPath("serde"), "se/rd/serde");
  assert.equal(crateIndexPath("ab"), "2/ab");
  assert.equal(crateIndexPath("a"), "1/a");
});

test("requires exact emergency override reason", () => {
  assert.throws(() => parseArguments(["--allow-git", "foo@abc"]), /--reason/);
  const parsed = parseArguments([
    "--allow-git",
    "foo@abc",
    "--reason",
    "reviewed",
    "--manifest-path",
    "Cargo.toml",
  ]);
  assert.deepEqual(parsed.cargoArgs, ["--manifest-path", "Cargo.toml"]);
  assert.equal(parsed.allowGit.has("foo@abc"), true);
});
