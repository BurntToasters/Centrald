// Starts one real server on a throwaway data directory for the whole run.
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
  AGENT_ARCH,
  AGENT_BIN,
  BASE,
  REPORT_DIR,
  SERVER_BIN,
  readLog,
  signBuild,
  startServer,
} from "./harness";
import { updateKey } from "./minisign";

export default async function globalSetup() {
  for (const binary of [SERVER_BIN, AGENT_BIN]) {
    if (!existsSync(binary)) {
      throw new Error(
        `${binary} is missing. Run \`npm run e2e\` (it builds with the E2E update key).`,
      );
    }
  }
  // Update tests sign builds with a throwaway key the agent must trust.
  if (!readFileSync(AGENT_BIN).includes(updateKey().publicKey)) {
    throw new Error(
      `${AGENT_BIN} was not built with the E2E update key. Run \`npm run e2e\`.`,
    );
  }
  rmSync(REPORT_DIR, { recursive: true, force: true });
  mkdirSync(path.join(REPORT_DIR, "screenshots"), { recursive: true });

  const dir = mkdtempSync(path.join(tmpdir(), "centrald-e2e-"));
  const agents = path.join(dir, "agents");
  mkdirSync(agents);
  const served = path.join(agents, `centrald-agent-linux-${AGENT_ARCH}`);
  copyFileSync(AGENT_BIN, served);
  signBuild(served);

  const { server, log } = startServer(dir);
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
    // Every agent and server pid, including servers restarted by tests.
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
    for (const file of [
      "server.log",
      "agent-full.log",
      "agent-monitor.log",
      "agent-reconcile.log",
    ]) {
      const source = path.join(dir, file);
      if (existsSync(source)) {
        copyFileSync(source, path.join(REPORT_DIR, file));
      }
    }
    rmSync(dir, { recursive: true, force: true });
  };
}
