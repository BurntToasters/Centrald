import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";
import { parseSemver } from "./lib/release-metadata.js";

const root = process.cwd();
const candidate = process.argv[2];
if (!candidate) {
  throw new Error("Usage: node scripts/bump-version.js <new-version>");
}

try {
  parseSemver(candidate);
} catch (error) {
  throw new Error(
    `Version ${JSON.stringify(candidate)} is not valid strict SemVer.`,
    { cause: error },
  );
}
const nextVersion = candidate.trim();

const packageJsonPath = path.join(root, "package.json");
const cargoPath = path.join(root, "Cargo.toml");
const tauriPath = path.join(root, "apps/admin/src-tauri/tauri.conf.json");

const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));
const cargo = fs.readFileSync(cargoPath, "utf8");
const tauri = JSON.parse(fs.readFileSync(tauriPath, "utf8"));

const currentVersion = packageJson.version;
if (nextVersion === currentVersion) {
  throw new Error(`Version is already ${nextVersion}; nothing to bump.`);
}

const expectedTag = `v${nextVersion}`;
try {
  const existing = execFileSync(
    "git",
    ["ls-remote", "--tags", "origin", expectedTag],
    { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
  ).trim();
  if (existing) {
    throw new Error(
      `Refusing to bump to ${nextVersion}: tag ${expectedTag} already exists on origin.`,
    );
  }
} catch (error) {
  if (error.message?.includes("Refusing")) throw error;
  // A missing origin or ls-remote failure must not block a local bump; the
  // release flow re-verifies tag existence before publishing.
}

if (!cargo.includes(`version = "${currentVersion}"`)) {
  throw new Error(
    `Cargo.toml does not contain version = "${currentVersion}" as expected.`,
  );
}
if (tauri.version !== currentVersion) {
  throw new Error(
    `tauri.conf.json version is "${tauri.version}", expected "${currentVersion}".`,
  );
}

packageJson.version = nextVersion;
tauri.version = nextVersion;
const nextCargo = cargo.replace(
  `version = "${currentVersion}"`,
  `version = "${nextVersion}"`,
);

fs.writeFileSync(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`, {
  encoding: "utf8",
  mode: 0o644,
});
fs.writeFileSync(cargoPath, nextCargo, { encoding: "utf8", mode: 0o644 });
fs.writeFileSync(tauriPath, `${JSON.stringify(tauri, null, 2)}\n`, {
  encoding: "utf8",
  mode: 0o644,
});

// Cargo.lock pins every workspace member's version; a stale lock breaks all
// --locked builds (CI and the release flow) until the next lock update. Skip
// trees without a lockfile (e.g. temp-dir tests); the real repo always has one.
const lockPath = path.join(root, "Cargo.lock");
if (fs.existsSync(lockPath)) {
  try {
    execFileSync("cargo", ["generate-lockfile"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch (error) {
    fs.unlinkSync(cargoPath);
    fs.unlinkSync(packageJsonPath);
    fs.unlinkSync(tauriPath);
    throw new Error(
      "Cargo.lock could not be regenerated; version files were restored.",
      { cause: error },
    );
  }
} else {
  console.warn(
    "No Cargo.lock found; skipped lockfile regeneration. Run `cargo generate-lockfile` before any --locked build.",
  );
}

console.log(
  `Bumped version ${currentVersion} -> ${nextVersion} in package.json, Cargo.toml, tauri.conf.json, and Cargo.lock.`,
);
console.log(`Release tag will be ${expectedTag}.`);
