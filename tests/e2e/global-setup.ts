// Starts one real server on a throwaway data directory for the whole run.
import { spawn } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  AGENT_BIN,
  BASE,
  PORT,
  REPORT_DIR,
  SERVER_BIN,
  readLog,
} from "./harness";

export default async function globalSetup() {
  for (const binary of [SERVER_BIN, AGENT_BIN]) {
    if (!existsSync(binary)) {
      throw new Error(
        `${binary} is missing. Run \`npm run build:web && CENTRALD_REQUIRE_UI=1 cargo build --workspace --locked\` first.`,
      );
    }
  }
  rmSync(REPORT_DIR, { recursive: true, force: true });
  mkdirSync(path.join(REPORT_DIR, "screenshots"), { recursive: true });

  const dir = mkdtempSync(path.join(tmpdir(), "centrald-e2e-"));
  const agents = path.join(dir, "agents");
  mkdirSync(agents);
  const arch = process.arch === "arm64" ? "aarch64" : "x86_64";
  copyFileSync(AGENT_BIN, path.join(agents, `centrald-agent-linux-${arch}`));

  const log = path.join(dir, "server.log");
  const server = spawn(
    "sh",
    ["-c", 'exec "$0" run >"$1" 2>&1', SERVER_BIN, log],
    {
      env: {
        ...process.env,
        CENTRALD_DATA_DIR: path.join(dir, "data"),
        CENTRALD_AGENT_DIR: agents,
        CENTRALD_LISTEN: `127.0.0.1:${PORT}`,
        CENTRALD_LOG: "info",
      },
      stdio: "ignore",
    },
  );

  let code = "";
  for (let i = 0; i < 100 && !code; i++) {
    await new Promise((resolve) => setTimeout(resolve, 100));
    code = /setup code: ([A-Z0-9-]+)/.exec(readLog(log))?.[1] ?? "";
    if (server.exitCode !== null) break;
  }
  if (!code) {
    server.kill();
    throw new Error(`server did not start on ${BASE}:\n${readLog(log)}`);
  }

  process.env.CENTRALD_E2E_RUN_DIR = dir;
  process.env.CENTRALD_E2E_SETUP_CODE = code;

  return async () => {
    const pids = path.join(dir, "pids");
    if (existsSync(pids)) {
      for (const pid of readFileSync(pids, "utf8").split("\n")) {
        try {
          if (pid) process.kill(Number(pid));
        } catch {
          // Already exited.
        }
      }
    }
    server.kill();
    await new Promise((resolve) => setTimeout(resolve, 300));
    // Keep logs with the report so failures can be diagnosed later.
    for (const file of ["server.log", "agent-full.log", "agent-monitor.log"]) {
      const source = path.join(dir, file);
      if (existsSync(source)) {
        copyFileSync(source, path.join(REPORT_DIR, file));
      }
    }
    rmSync(dir, { recursive: true, force: true });
  };
}
