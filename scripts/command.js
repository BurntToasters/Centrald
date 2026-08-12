import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

const WINDOWS_COMMAND_SHIMS = new Set(["npm", "npx"]);

export function platformInvocation(command, args) {
  if (process.platform === "win32" && WINDOWS_COMMAND_SHIMS.has(command)) {
    const npmCli =
      process.env.npm_execpath ??
      path.join(
        path.dirname(process.execPath),
        "node_modules",
        "npm",
        "bin",
        "npm-cli.js",
      );
    const cli =
      command === "npm"
        ? npmCli
        : path.join(path.dirname(npmCli), "npx-cli.js");
    return { command: process.execPath, args: [cli, ...args] };
  }
  return { command, args };
}

export function commandExists(command, args = ["--version"]) {
  const invocation = platformInvocation(command, args);
  const result = spawnSync(invocation.command, invocation.args, {
    encoding: "utf8",
    shell: false,
    stdio: "ignore",
  });
  return result.status === 0;
}

export function run(command, args, options = {}) {
  const invocation = platformInvocation(command, args);
  const result = spawnSync(invocation.command, invocation.args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    shell: false,
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} exited with status ${result.status}`);
  }
}
