// Licence notices for the third-party code compiled into the binaries:
// every crate in Cargo.lock (all platforms) and the npm packages bundled
// into the web app (non-dev entries of package-lock.json). Identical
// licence texts are printed once with the packages that use them.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";

const LICENSE_FILE = /^(licen[cs]e|copying|notice)/i;

function licenseTexts(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((name) => LICENSE_FILE.test(name))
    .sort()
    .map((name) => readFileSync(path.join(dir, name), "utf8").trim())
    .filter(Boolean);
}

function crates(root) {
  const metadata = JSON.parse(
    execFileSync("cargo", ["metadata", "--locked", "--format-version", "1"], {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 256 * 1024 * 1024,
    }),
  );
  const members = new Set(metadata.workspace_members);
  return metadata.packages
    .filter((pkg) => !members.has(pkg.id))
    .map((pkg) => ({
      name: `${pkg.name} ${pkg.version}`,
      license: pkg.license ?? "see licence text",
      texts: licenseTexts(path.dirname(pkg.manifest_path)),
    }));
}

function npmPackages(root) {
  const lock = JSON.parse(
    readFileSync(path.join(root, "package-lock.json"), "utf8"),
  );
  return Object.entries(lock.packages)
    .filter(([key, entry]) => key && !entry.dev)
    .map(([key, entry]) => {
      const dir = path.join(root, key);
      if (!existsSync(dir)) {
        throw new Error(`${key} is not installed; run npm ci first`);
      }
      return {
        name: `${key.replace(/^.*node_modules\//, "")} ${entry.version} (npm)`,
        license: entry.license ?? "see licence text",
        texts: licenseTexts(dir),
      };
    });
}

/** Returns the notices file as one string. */
export function thirdPartyNotices(root) {
  const packages = [...crates(root), ...npmPackages(root)].sort((a, b) =>
    a.name.localeCompare(b.name),
  );
  const groups = new Map();
  const bare = [];
  for (const pkg of packages) {
    if (pkg.texts.length === 0) {
      bare.push(pkg);
      continue;
    }
    const text = pkg.texts.join("\n\n----\n\n");
    const key = createHash("sha256").update(text).digest("hex");
    if (!groups.has(key)) groups.set(key, { text, users: [] });
    groups.get(key).users.push(pkg);
  }
  const rule = "=".repeat(72);
  const out = [
    "CentralD includes the following third-party software.",
    "",
    ...packages.map((pkg) => `  ${pkg.name}: ${pkg.license}`),
    "",
  ];
  for (const { text, users } of groups.values()) {
    out.push(rule, ...users.map((pkg) => pkg.name), rule, "", text, "");
  }
  if (bare.length) {
    out.push(
      rule,
      "Packages that ship no licence file; their SPDX licence applies:",
      ...bare.map((pkg) => `  ${pkg.name}: ${pkg.license}`),
      "",
    );
  }
  return out.join("\n");
}
