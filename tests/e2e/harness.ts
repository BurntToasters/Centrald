// Shared helpers for the E2E suite. Real binaries, real TLS, real SQLite.
import { spawn, spawnSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import path from "node:path";

export const ROOT = path.resolve(import.meta.dirname, "../..");
export const PORT = Number(process.env.CENTRALD_E2E_PORT ?? 17443);
export const BASE = `https://127.0.0.1:${PORT}`;
export const REPORT_DIR = path.join(ROOT, "e2e-report");
export const BIN_DIR = path.resolve(
  process.env.CENTRALD_E2E_BIN_DIR ?? path.join(ROOT, "target/debug"),
);
export const SERVER_BIN = path.join(BIN_DIR, "centrald-server");
export const AGENT_BIN = path.join(BIN_DIR, "centrald-agent");
export const ADMIN = { username: "admin", password: "correct horse battery" };

/** Values global setup passes to workers through the environment. */
export function runDir(): string {
  const dir = process.env.CENTRALD_E2E_RUN_DIR;
  if (!dir) throw new Error("global setup did not run");
  return dir;
}

export function setupCode(): string {
  return process.env.CENTRALD_E2E_SETUP_CODE ?? "";
}

/** Runs `centrald-agent enroll --key-stdin` with an isolated config file. */
export function enroll(code: string, name: string, monitorOnly = false) {
  const args = ["enroll", "--key-stdin"];
  if (monitorOnly) args.push("--monitor-only");
  return spawnSync(AGENT_BIN, args, {
    input: `${code}\n`,
    env: agentEnv(name),
    encoding: "utf8",
    timeout: 30_000,
  });
}

export function agentEnv(name: string): NodeJS.ProcessEnv {
  return {
    ...process.env,
    CENTRALD_AGENT_CONFIG: path.join(runDir(), `${name}.toml`),
    CENTRALD_SKIP_SERVICE: "1",
    CENTRALD_LOG: "info",
  };
}

/** Starts `centrald-agent run`; global teardown kills every recorded pid. */
export function startAgent(name: string, binary = AGENT_BIN) {
  const log = path.join(runDir(), `${name}.log`);
  const child = spawn("sh", ["-c", 'exec "$0" run >>"$1" 2>&1', binary, log], {
    env: agentEnv(name),
    stdio: "ignore",
    detached: false,
  });
  if (child.pid) appendFileSync(path.join(runDir(), "pids"), `${child.pid}\n`);
  return { child, log };
}

export function readLog(file: string): string {
  return existsSync(file) ? readFileSync(file, "utf8") : "";
}

/** RFC 6238 TOTP (SHA-1, 30 s, 6 digits); `stepOffset` picks a later window. */
export function totp(secretBase32: string, stepOffset = 0): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of secretBase32.replace(/=+$/, "").toUpperCase()) {
    const value = alphabet.indexOf(char);
    if (value < 0) throw new Error("bad base32");
    bits += value.toString(2).padStart(5, "0");
  }
  const key = Buffer.from(
    bits.match(/.{8}/g)?.map((byte) => parseInt(byte, 2)) ?? [],
  );
  const counter = Buffer.alloc(8);
  counter.writeBigInt64BE(
    BigInt(Math.floor(Date.now() / 1000 / 30) + stepOffset),
  );
  const digest = createHmac("sha1", key).update(counter).digest();
  const offset = digest[19] & 0x0f;
  const value = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(value % 1_000_000).padStart(6, "0");
}
