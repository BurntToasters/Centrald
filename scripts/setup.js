import process from "node:process";
import { commandExists, run } from "./command.js";

const args = new Set(process.argv.slice(2));
const windows = args.has("--windows") || process.platform === "win32";
const yes = args.has("--yes");

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
console.log("CentralD workspace setup complete.");
