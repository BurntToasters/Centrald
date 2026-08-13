import { execFileSync } from "node:child_process";
import fs from "node:fs";
import process from "node:process";
import { commandExists, run } from "./command.js";
import {
  dockerExecutable,
  dockerOstype,
  ensureDockerEngine,
  waitForDockerEngine,
} from "./lib/docker-engine.js";

// CentralD Docker setup. Sets up everything the release flow needs:
// the Docker engine, the Windows containers feature, both engine modes,
// pre-pulled base images, and (with --build-images) warmed builder images.
//
// Flags:
//   --yes                        install Docker Desktop / npm upgrades without asking
//   --skip-images                do not pre-pull base images or warm builder images
//   --build-images               also build both builder images (slow first run)
//   --skip-windows-containers    skip the Windows containers feature check/enable

const args = new Set(process.argv.slice(2));
const yes = args.has("--yes");
const skipImages = args.has("--skip-images");
const buildImages = args.has("--build-images");
const skipWindowsContainers = args.has("--skip-windows-containers");

const DOCKER_DESKTOP_PATH =
  "C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe";
const REQUIRED_NPM = "12.0.1";

if (process.platform === "win32") setupWindowsHost();
else setupUnixHost();

function setupWindowsHost() {
  console.log("CentralD Docker setup (Windows host)");
  ensureNpmVersion();
  ensureDockerDesktop();
  startDockerEngineIfNeeded();
  waitForDockerEngine(240);
  if (!skipWindowsContainers) ensureWindowsContainersFeature();
  verifyEngineSwitching();
  if (!skipImages) {
    pullBaseImages();
    if (buildImages) warmBuilderImages();
  }
  printSummary();
}

function setupUnixHost() {
  console.log("CentralD Docker setup (Unix host)");
  if (!dockerInstalled()) {
    throw new Error(
      "Docker is missing. Install docker or docker-ce for your distribution and retry.",
    );
  }
  waitForDockerEngine(120);
  if (!skipImages) {
    run(dockerExecutable(), ["pull", "node:22.16.0-bookworm-slim"]);
    run(dockerExecutable(), ["pull", "rust:bookworm"]);
    run(dockerExecutable(), ["pull", "ubuntu:24.04"]);
    if (buildImages) {
      run(dockerExecutable(), [
        "build",
        "--file",
        "docker/linux-builder.Dockerfile",
        "--tag",
        "centrald-linux-builder:latest",
        ".",
      ]);
    }
  }
  console.log("Docker setup complete for the Linux builder.");
}

/// Whether a docker CLI resolves: either on PATH or at the known Docker
/// Desktop install location (a fresh install is not on PATH until the user
/// logs out and back in).
function dockerInstalled() {
  if (commandExists("docker", ["--version"])) return true;
  if (process.platform === "win32") {
    return fs.existsSync(
      "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe",
    );
  }
  return false;
}

function ensureNpmVersion() {
  if (!commandExists("npm", ["--version"])) {
    throw new Error(
      "npm is missing. Install Node.js >= 22.12 (bundles npm) and retry.",
    );
  }
  let version;
  try {
    // Read-only version query resolved through the shell so it reflects the
    // npm the user actually invokes, not Node's bundled npm CLI.
    version = execFileSync("npm", ["--version"], {
      encoding: "utf8",
      shell: true,
    }).trim();
  } catch {
    throw new Error("Could not read the npm version.");
  }
  if (compareVersions(version, REQUIRED_NPM) < 0) {
    const upgrade = ["npm", "install", "-g", `npm@12.0.2`];
    if (!yes) {
      throw new Error(
        `npm ${version} is older than the required ${REQUIRED_NPM}. Run ${upgrade.join(" ")} (or re-run with --yes).`,
      );
    }
    run(upgrade[0], upgrade.slice(1));
    console.log("npm upgraded to 12.0.2.");
  }
}
function ensureDockerDesktop() {
  if (!dockerInstalled()) {
    if (!fs.existsSync(DOCKER_DESKTOP_PATH)) {
      if (!commandExists("winget", ["--version"])) {
        throw new Error(
          "Docker Desktop is not installed and winget is unavailable. Install Docker Desktop manually from https://www.docker.com/products/docker-desktop/.",
        );
      }
      if (!isAdministrator()) {
        throw new Error(
          "Docker Desktop is not installed and installing it needs an elevated shell. Open an Administrator terminal and run: winget install --id Docker.DockerDesktop --exact --accept-source-agreements --accept-package-agreements",
        );
      }
      console.log(
        "Installing Docker Desktop via winget (this takes several minutes)...",
      );
      run("winget", [
        "install",
        "--id",
        "Docker.DockerDesktop",
        "--exact",
        "--accept-source-agreements",
        "--accept-package-agreements",
      ]);
      console.log(
        "Docker Desktop installed. If prompted, sign out and back in so the docker-users group applies.",
      );
    }
    if (!fs.existsSync(DOCKER_DESKTOP_PATH)) {
      throw new Error(
        `Docker Desktop was not found at ${DOCKER_DESKTOP_PATH} after installation. Reboot and retry.`,
      );
    }
  }
}

/// Launches Docker Desktop when it is installed but the engine is not
/// responding, then lets waitForDockerEngine poll until it is ready.
function startDockerEngineIfNeeded() {
  if (dockerOstype()) return;
  if (!fs.existsSync(DOCKER_DESKTOP_PATH)) {
    throw new Error(
      "Docker Desktop is not installed; install it first (npm run setup:docker from an elevated shell).",
    );
  }
  console.log("Starting Docker Desktop...");
  execFileSync("powershell", [
    "-NoProfile",
    "-Command",
    `Start-Process '${DOCKER_DESKTOP_PATH}'`,
  ]);
}

function isAdministrator() {
  try {
    const result = execFileSync(
      "powershell",
      [
        "-NoProfile",
        "-Command",
        "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
      ],
      { encoding: "utf8" },
    ).trim();
    return result === "True";
  } catch {
    return false;
  }
}

/// Windows containers need the "Containers" Windows feature. Check and enable
/// it when possible; a reboot may still be required.
function ensureWindowsContainersFeature() {
  try {
    const state = execFileSync(
      "powershell",
      [
        "-NoProfile",
        "-Command",
        "(Get-WindowsOptionalFeature -Online -FeatureName Containers).State",
      ],
      { encoding: "utf8" },
    ).trim();
    if (state === "Enabled") return;
    if (state !== "Disabled") {
      console.log(
        `Windows Containers feature state is "${state || "unknown"}"; verify it is enabled.`,
      );
      return;
    }
    if (!isAdministrator()) {
      console.log(
        "The Windows 'Containers' feature is disabled. Enable it in an Administrator terminal:",
      );
      console.log(
        "  Enable-WindowsOptionalFeature -Online -FeatureName Containers -All -NoRestart",
      );
      console.log("  (reboot if prompted, then re-run setup)");
      return;
    }
    console.log("Enabling the Windows 'Containers' feature...");
    run("powershell", [
      "-NoProfile",
      "-Command",
      "Enable-WindowsOptionalFeature -Online -FeatureName Containers -All -NoRestart",
    ]);
    const restartNeeded = execFileSync(
      "powershell",
      [
        "-NoProfile",
        "-Command",
        "(Get-WindowsOptionalFeature -Online -FeatureName Containers).RestartNeeded",
      ],
      { encoding: "utf8" },
    ).trim();
    if (restartNeeded === "True") {
      console.log(
        "A reboot is required for Windows containers. Reboot and re-run npm run setup:docker.",
      );
    }
  } catch (error) {
    console.log(
      `Could not inspect the Windows Containers feature (${error.message}); verify it manually.`,
    );
  }
}

function verifyEngineSwitching() {
  console.log(
    "Verifying the Docker engine can run both Linux and Windows containers...",
  );
  ensureDockerEngine("linux", "Linux builder");
  console.log("Linux containers mode: OK");
  ensureDockerEngine("windows", "Windows container builder");
  console.log("Windows containers mode: OK");
  console.log(
    "Leaving the engine in Linux containers mode (the Docker Desktop default).",
  );
  ensureDockerEngine("linux", "restore default engine mode");
}

function pullBaseImages() {
  console.log("Pre-pulling builder base images...");
  ensureDockerEngine("linux", "Linux base images");
  run(dockerExecutable(), ["pull", "node:22.16.0-bookworm-slim"]);
  run(dockerExecutable(), ["pull", "rust:bookworm"]);
  run(dockerExecutable(), ["pull", "ubuntu:24.04"]);
  ensureDockerEngine("windows", "Windows base image");
  run(dockerExecutable(), [
    "pull",
    "mcr.microsoft.com/windows/servercore:ltsc2022",
  ]);
  console.log("Leaving the engine in Linux containers mode.");
  ensureDockerEngine("linux", "restore default engine mode");
}

function warmBuilderImages() {
  console.log(
    "Warming the builder images (first run downloads several GB and takes a while)...",
  );
  ensureDockerEngine("linux", "Linux builder image");
  run(dockerExecutable(), [
    "build",
    "--file",
    "docker/linux-builder.Dockerfile",
    "--tag",
    "centrald-linux-builder:latest",
    ".",
  ]);
  ensureDockerEngine("windows", "Windows builder image");
  run(dockerExecutable(), [
    "build",
    "--file",
    "docker/windows-builder.Dockerfile",
    "--tag",
    "centrald-windows-builder:latest",
    ".",
  ]);
  ensureDockerEngine("linux", "restore default engine mode");
}

function printSummary() {
  console.log("");
  console.log("CentralD Docker setup complete.");
  console.log("Release flow is now usable: npm run release");
  console.log(
    "Remaining release prerequisites on this host: minisign, gh CLI (gh auth login), and the keys documented in .env.example.",
  );
}

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
