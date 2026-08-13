import { execFileSync } from "node:child_process";
import fs from "node:fs";
import process from "node:process";
import { run } from "../command.js";

const DOCKER_DESKTOP_CLI = "C:\\Program Files\\Docker\\Docker\\DockerCli.exe";
const DOCKER_BINARY =
  "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe";

/// The docker executable. A freshly installed Docker Desktop is not on the
/// current process PATH until the user logs out and back in, so the known
/// install location is preferred on Windows when it exists.
export function dockerExecutable() {
  if (process.platform === "win32" && fs.existsSync(DOCKER_BINARY)) {
    return DOCKER_BINARY;
  }
  return "docker";
}

/// Returns the Docker engine's OSType ("linux" or "windows") or an empty
/// string when Docker is unavailable or not running.
export function dockerOstype() {
  try {
    return execFileSync(
      dockerExecutable(),
      ["info", "--format", "{{.OSType}}"],
      {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      },
    )
      .trim()
      .toLowerCase();
  } catch {
    return "";
  }
}

/// Blocks until the Docker engine responds, or throws after the timeout.
export function waitForDockerEngine(timeoutSeconds = 180) {
  const deadline = Date.now() + timeoutSeconds * 1000;
  while (Date.now() < deadline) {
    if (dockerOstype()) return;
    sleepSeconds(5);
  }
  throw new Error(
    `Docker engine did not start within ${timeoutSeconds} seconds. Start Docker Desktop manually and retry.`,
  );
}

/// Ensures the Docker engine is running the expected OS type. Docker Desktop
/// supports one engine mode at a time; when the engine reports the other mode
/// the switch command restarts the engine.
export function ensureDockerEngine(expected, operation) {
  const current = dockerOstype();
  if (current === expected) return;
  if (!current) {
    throw new Error(
      `${operation} requires Docker; install Docker Desktop and start the engine before running release builds (npm run setup:docker).`,
    );
  }
  if (!fs.existsSync(DOCKER_DESKTOP_CLI)) {
    throw new Error(
      `${operation} requires the ${expected} Docker engine mode, but the engine is in ${current} mode. Switch Docker Desktop to ${expected} containers and retry.`,
    );
  }
  console.log(
    `Switching the Docker engine to ${expected} containers (this restarts the engine)...`,
  );
  run(DOCKER_DESKTOP_CLI, [
    expected === "windows"
      ? "-SwitchWindowsContainers"
      : "-SwitchLinuxContainers",
  ]);
  const deadline = Date.now() + 180 * 1000;
  while (Date.now() < deadline) {
    if (dockerOstype() === expected) return;
    sleepSeconds(10);
  }
  throw new Error(
    `Docker engine did not switch to ${expected} mode within 180 seconds. Switch it manually in Docker Desktop and retry.`,
  );
}

export function sleepSeconds(seconds) {
  const shared = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(shared, 0, 0, seconds * 1000);
}
