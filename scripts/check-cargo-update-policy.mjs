#!/usr/bin/env node
// Enforces the Cargo dependency policy on the committed Cargo.lock: every
// registry package version that is new compared with a base revision must
// have been published at least 72 hours ago, and no new git source may
// appear. It checks the lock itself, so it does not matter which command
// changed it.
//
// Usage: node scripts/check-cargo-update-policy.mjs [--base <git-rev>]
//   --base defaults to HEAD (checks uncommitted lock changes). CI passes the
//   pull request base or the previous commit on main.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { validateCandidate } from "./cargo-safe-update.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");

/** Packages from a Cargo.lock (v3/v4): name, version, source. */
export function parseLock(text) {
  return text
    .split(/^\[\[package\]\]$/mu)
    .slice(1)
    .map((block) => {
      const field = (key) =>
        block.match(new RegExp(`^${key} = "([^"]*)"$`, "mu"))?.[1];
      return {
        name: field("name"),
        version: field("version"),
        source: field("source") ?? null,
      };
    })
    .filter((pkg) => pkg.name && pkg.version);
}

function baseLock(base) {
  try {
    return execFileSync("git", ["show", `${base}:Cargo.lock`], {
      cwd: ROOT,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    throw new Error(`cannot read Cargo.lock at ${base}: ${error.message}`, {
      cause: error,
    });
  }
}

async function main() {
  const argv = process.argv.slice(2);
  const at = argv.indexOf("--base");
  let base = at >= 0 ? argv[at + 1] : "HEAD";
  if (!base || /^0+$/u.test(base)) base = "HEAD~1";
  const baseline = parseLock(baseLock(base));
  const candidate = parseLock(
    readFileSync(path.join(ROOT, "Cargo.lock"), "utf8"),
  );
  const { newlySelected, approved } = await validateCandidate(
    baseline,
    candidate,
    { allowYoung: new Set(), allowGit: new Set() },
  );
  for (const line of approved) console.log(line);
  const registry = newlySelected.filter((pkg) => pkg.source).length;
  console.log(
    `cargo dependency policy: ${registry} new package version(s) since ${base}, all at least 72 hours old.`,
  );
}

main().catch((error) => {
  console.error(
    error.message.replace(/\n\nCargo\.lock was not modified\.$/u, ""),
  );
  console.error(
    "\nUpdate with `npm run deps:rust:update` (72-hour minimum crate age).",
  );
  process.exitCode = 1;
});
