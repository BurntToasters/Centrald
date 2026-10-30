import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { commandExists, run } from "./command.js";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const pinnedNode = readFileSync(join(repoRoot, ".node-version"), "utf8").trim();

const args = new Set(process.argv.slice(2));
const windows = args.has("--windows") || process.platform === "win32";
const yes = args.has("--yes");

function compareVersions(left, right) {
  const parse = (value) =>
    value.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const a = parse(left);
  const b = parse(right);
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

function requireTool(name, install) {
  if (commandExists(name)) return;
  if (!yes) {
    throw new Error(
      `${name} is missing. Re-run with --yes to install, or run: ${install.join(" ")}`,
    );
  }
  run(install[0], install.slice(1));
}

requireTool("git", ["winget", "install", "--id", "Git.Git", "--exact"]);
requireTool("node", [
  "winget",
  "install",
  "--id",
  "OpenJS.NodeJS.LTS",
  "--exact",
]);

const runningNode = execFileSync("node", ["--version"], { encoding: "utf8" })
  .trim()
  .replace(/^v/, "");
if (compareVersions(runningNode, pinnedNode) < 0) {
  throw new Error(
    `Node.js ${runningNode} is older than the pinned toolchain (${pinnedNode}). Install Node.js >= ${pinnedNode} and retry.`,
  );
}

requireTool("rustup", [
  "winget",
  "install",
  "--id",
  "Rustlang.Rustup",
  "--exact",
]);

run("rustup", ["toolchain", "install", "stable", "--profile", "minimal"]);
run("rustup", ["component", "add", "clippy", "rustfmt"]);
if (windows) {
  run("rustup", [
    "target",
    "add",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
  ]);
}
run("npm", ["install"]);
run("npm", ["--prefix", "site", "ci"]);
console.log("CentralD workspace setup complete.");
