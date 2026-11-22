// Negative paths against the live server left behind by flow.spec.ts.
//
// Ways this can fail (each is asserted below):
// - API data or WebSockets reachable without a session
// - a cross-site page can make state-changing requests with the cookie
// - the session cookie is readable by scripts or sent over plain HTTP
// - a join code works twice, after revocation, or after tampering
// - an agent connects with a guessed or wrong credential
// - the install command downloads from a server with a different key
// - the served agent does not match its published checksum
// - a monitor-only device opens a terminal
// - plain HTTP serves content instead of redirecting
// - pages lack the security headers that block framing and injection
// - `centrald-agent update` installs a build that fails its checks, or
//   leaves a half-written binary behind
// - password guessing is not slowed down
// - parallel wrong passwords are all checked before any is counted
// - a client that hangs up mid-hash leaves no audit row or limiter count
// - one address holds enough sockets to starve everyone else, or idle
//   connections are never closed
// - the streamed agent download differs from the published build
// - a foreign Host name (DNS rebinding) gets pages or install scripts
// - unknown API paths, other methods, or CONNECT get the web app
// - malformed API requests get errors that are not JSON
// - a borrowed session turns on two-factor sign-in without the password
// - a right password with a missing code leaves no audit trace
// - a planted duplicate session cookie shadows the real one
// - a second server on the same data directory changes the first's state
// - `centrald-server status` fails next to the server or into a closed pipe
// - a missing or damaged CA, key, database, or data directory starts as a
//   fresh install instead of refusing
import {
  expect,
  test,
  type APIRequestContext,
  type PlaywrightWorkerArgs,
} from "@playwright/test";
import { execFile, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  copyFileSync,
  cpSync,
  mkdirSync,
  readFileSync,
  rmSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { connect as netConnect } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import path from "node:path";
import {
  AGENT_BIN,
  BASE,
  PORT,
  SERVER_BIN,
  agentEnv,
  enroll,
  runDir,
  totp,
} from "./harness";

test.describe.configure({ mode: "serial" });

let api: APIRequestContext;
let cookie = "";

const WS_HEADERS = [
  "-H",
  "Connection: Upgrade",
  "-H",
  "Upgrade: websocket",
  "-H",
  "Sec-WebSocket-Version: 13",
  "-H",
  "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
];

/** curl over HTTP/1.1; returns the status code (or curl's exit code) and body. */
function curl(args: string[]) {
  const result = spawnSync(
    "curl",
    ["-sk", "--http1.1", "--max-time", "10", "-w", "\n%{http_code}", ...args],
    { encoding: "utf8" },
  );
  const lines = result.stdout.split("\n");
  const status = Number(lines.pop());
  return { status, body: lines.join("\n"), exit: result.status };
}

test.beforeAll(async ({ playwright }) => {
  const storageState = path.join(runDir(), "operator.json");
  api = await playwright.request.newContext({
    baseURL: BASE,
    ignoreHTTPSErrors: true,
    storageState,
    extraHTTPHeaders: { Origin: BASE },
  });
  const state = JSON.parse(readFileSync(storageState, "utf8"));
  const session = state.cookies.find(
    (c: { name: string }) => c.name === "__Host-centrald",
  );
  cookie = `${session.name}=${session.value}`;
});

test.afterAll(async () => {
  await api.dispose();
});

test("no session means no data", async ({ request }) => {
  for (const url of ["/api/devices", "/api/runs", "/api/audit", "/api/users"]) {
    const response = await request.get(url);
    expect(response.status(), url).toBe(401);
  }
  const events = curl([
    ...WS_HEADERS,
    "-H",
    `Origin: ${BASE}`,
    `${BASE}/api/events`,
  ]);
  expect(events.status).toBe(401);
});

test("the session cookie is locked down", async () => {
  const state = await api.storageState();
  const session = state.cookies.find((c) => c.name === "__Host-centrald");
  expect(session?.secure).toBe(true);
  expect(session?.httpOnly).toBe(true);
  expect(session?.sameSite).toBe("Strict");
  expect(session?.path).toBe("/");
});

test("cross-site requests are refused even with the cookie", async () => {
  const body = JSON.stringify({
    name: "x",
    serverAddress: `127.0.0.1:${PORT}`,
  });
  const base = [
    "-b",
    cookie,
    "-H",
    "content-type: application/json",
    "-d",
    body,
  ];
  const evil = curl([
    ...base,
    "-H",
    "Origin: https://evil.example",
    `${BASE}/api/join-tokens`,
  ]);
  expect(evil.status).toBe(403);
  const none = curl([...base, `${BASE}/api/join-tokens`]);
  expect(none.status).toBe(403);
  const terminal = curl([
    ...WS_HEADERS,
    "-b",
    cookie,
    "-H",
    "Origin: https://evil.example",
    `${BASE}/api/events`,
  ]);
  expect(terminal.status).toBe(403);
  const same = curl([
    ...base,
    "-H",
    `Origin: ${BASE}`,
    `${BASE}/api/join-tokens`,
  ]);
  expect(same.status).toBe(201);
});

test("join codes work once and cannot be revived or forged", async () => {
  await test.step("a used code is refused", async () => {
    const used = readFileSync(path.join(runDir(), "used-code"), "utf8");
    const result = enroll(used, "reuse");
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("already used");
  });

  const created = await api.post("/api/join-tokens", {
    data: { name: "revoked", serverAddress: `127.0.0.1:${PORT}` },
  });
  expect(created.status()).toBe(201);
  const token = await created.json();

  await test.step("a tampered code is rejected before contacting anyone", async () => {
    const chars = token.code.split("");
    const index = chars.length - 6;
    chars[index] = chars[index] === "A" ? "B" : "A";
    const result = enroll(chars.join(""), "tampered");
    expect(result.status).not.toBe(0);
  });

  await test.step("a revoked code is refused", async () => {
    const revoke = await api.delete(`/api/join-tokens/${token.id}`);
    expect(revoke.ok()).toBe(true);
    const result = enroll(token.code, "revoked");
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/revoked|already used|expired|not valid/i);
  });
});

test("agents need their exact credential", async () => {
  const url = `${BASE}/api/agent/connect`;
  const missing = curl([...WS_HEADERS, url]);
  expect(missing.status).toBe(401);
  const config = readFileSync(
    path.join(runDir(), "agent-monitor.toml"),
    "utf8",
  );
  const device = /device_id\s*=\s*"([^"]+)"/.exec(config)?.[1];
  expect(device).toBeTruthy();
  const wrong = curl([
    ...WS_HEADERS,
    "-H",
    `Authorization: Bearer ${device}.${"A".repeat(43)}`,
    url,
  ]);
  expect(wrong.status).toBe(401);
});

test("install commands only trust this server's key", async () => {
  const created = await api.post("/api/join-tokens", {
    data: { name: "pin-check", serverAddress: `127.0.0.1:${PORT}` },
  });
  const { linuxCommand } = await created.json();
  const pin = /--pinnedpubkey '([^']+)'/.exec(linuxCommand)?.[1] ?? "";
  expect(pin).toMatch(/^sha256\/\/[A-Za-z0-9+/]{43}=$/);

  const good = curl(["--pinnedpubkey", pin, `${BASE}/install.sh`]);
  expect(good.status).toBe(200);
  expect(good.body).toContain("CentralD agent installer");
  expect(good.body).toContain(pin);

  const wrongPin = `sha256//${"A".repeat(43)}=`;
  const bad = curl(["--pinnedpubkey", wrongPin, `${BASE}/install.sh`]);
  expect(bad.exit).toBe(90); // CURLE_SSL_PINNEDPUBKEYNOTMATCH

  const arch = process.arch === "arm64" ? "aarch64" : "x86_64";
  const published = curl([
    "--pinnedpubkey",
    pin,
    `${BASE}/download/agent/linux/${arch}.sha256`,
  ]);
  const actual = createHash("sha256")
    .update(readFileSync(AGENT_BIN))
    .digest("hex");
  expect(published.body.trim()).toBe(actual);
});

test("a monitor-only device never opens a terminal", async () => {
  const devices = await (await api.get("/api/devices")).json();
  const watch = devices.find((d: { name: string }) => d.name === "watch-only");
  expect(watch.allowCommands).toBe(false);
  const result = curl([
    ...WS_HEADERS,
    "-b",
    cookie,
    "-H",
    `Origin: ${BASE}`,
    `${BASE}/api/devices/${watch.id}/terminal`,
  ]);
  expect(result.status).toBe(409);
  expect(result.body).toMatch(/monitor-only/i);
});

test("plain HTTP is redirected and pages carry security headers", async ({
  request,
}) => {
  const plain = spawnSync(
    "curl",
    [
      "-s",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code} %{redirect_url}",
      `http://127.0.0.1:${PORT}/devices`,
    ],
    { encoding: "utf8" },
  );
  expect(plain.stdout).toBe(`301 https://127.0.0.1:${PORT}/devices`);

  const page = await request.get("/");
  const headers = page.headers();
  expect(headers["content-security-policy"]).toContain(
    "frame-ancestors 'none'",
  );
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["x-frame-options"]).toBe("DENY");
  expect(headers["referrer-policy"]).toBe("no-referrer");
  // No HSTS: it would make the built-in CA's browser warning unskippable.
  expect(headers["strict-transport-security"]).toBeUndefined();
  const apiResponse = await request.get("/api/state");
  expect(apiResponse.headers()["cache-control"]).toContain("no-store");
});

test("agents update only to a verified build from their server", async () => {
  const arch = process.arch === "arm64" ? "aarch64" : "x86_64";
  const served = path.join(runDir(), "agents", `centrald-agent-linux-${arch}`);
  const installed = path.join(runDir(), "bin", "centrald-agent");
  mkdirSync(path.dirname(installed), { recursive: true });
  copyFileSync(AGENT_BIN, installed);
  const hash = (file: string) =>
    createHash("sha256").update(readFileSync(file)).digest("hex");
  const update = () =>
    spawnSync(installed, ["update"], {
      env: agentEnv("agent-monitor"),
      encoding: "utf8",
      timeout: 60_000,
    });

  try {
    await test.step("an identical build is left alone", async () => {
      const result = update();
      expect(result.stdout + result.stderr).toContain("Already up to date");
      expect(result.status).toBe(0);
    });

    await test.step("a newer build replaces the binary", async () => {
      // Trailing bytes change the hash but keep the program runnable.
      appendFileSync(served, Buffer.from("centrald-e2e"));
      const result = update();
      expect(result.stdout).toContain("Updated the agent");
      expect(result.status).toBe(0);
      expect(hash(installed)).toBe(hash(served));
    });

    await test.step("a build that does not run is refused", async () => {
      const before = hash(installed);
      writeFileSync(served, "this is not a program");
      const result = update();
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain("nothing was changed");
      expect(hash(installed)).toBe(before);
      const leftovers = spawnSync("ls", ["-A", path.dirname(installed)], {
        encoding: "utf8",
      }).stdout.trim();
      expect(leftovers).toBe("centrald-agent");
    });
  } finally {
    copyFileSync(AGENT_BIN, served);
  }
});

/** curl as a promise, for requests that must run at the same time. */
function curlAsync(args: string[]) {
  return new Promise<{ status: number; body: string }>((resolve) => {
    execFile(
      "curl",
      ["-sk", "--http1.1", "--max-time", "30", "-w", "\n%{http_code}", ...args],
      { encoding: "utf8" },
      (_error, stdout) => {
        const lines = String(stdout).split("\n");
        const status = Number(lines.pop());
        resolve({ status, body: lines.join("\n") });
      },
    );
  });
}

const sleep = (ms: number) => new Promise((done) => setTimeout(done, ms));

/** Creates an operator and signs it in from its own context. */
async function operatorContext(
  playwright: PlaywrightWorkerArgs["playwright"],
  username: string,
  password: string,
) {
  const created = await api.post("/api/users", {
    data: { username, password },
  });
  expect(created.status()).toBe(201);
  const context: APIRequestContext = await playwright.request.newContext({
    baseURL: BASE,
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: { Origin: BASE },
  });
  const login = await context.post("/api/login", {
    data: { username, password },
  });
  expect(login.status()).toBe(200);
  return context;
}

test("parallel wrong passwords are counted before any is checked", async () => {
  // Own source address and an unknown user, so later tests are unaffected.
  const attempts = await Promise.all(
    Array.from({ length: 20 }, (_, i) =>
      curlAsync([
        "--interface",
        "127.0.0.2",
        "-H",
        `Origin: ${BASE}`,
        "-H",
        "content-type: application/json",
        "-d",
        JSON.stringify({ username: "nobody-parallel", password: `w-${i}` }),
        `${BASE}/api/login`,
      ]),
    ),
  );
  const statuses = attempts.map((a) => a.status);
  expect(statuses.filter((s) => s === 401).length).toBeLessThanOrEqual(5);
  expect(statuses.filter((s) => s === 429).length).toBeGreaterThanOrEqual(15);
  expect(statuses.every((s) => s === 401 || s === 429)).toBe(true);
});

test("sign-in outcomes are recorded even when the client hangs up", async ({
  playwright,
}) => {
  const password = "second operator pass";
  const second = await operatorContext(playwright, "second-op", password);
  try {
    await test.step("a hang-up mid-hash still leaves an audit row", async () => {
      const failures = async () =>
        (await (await api.get("/api/audit?limit=500")).json()).filter(
          (e: { action: string; target: string }) =>
            e.action === "login.failed" && e.target === "second-op",
        ).length;
      const before = await failures();
      const hung = spawnSync(
        "curl",
        [
          "-sk",
          "--http1.1",
          "--interface",
          "127.0.0.3",
          "--max-time",
          "0.3",
          "-H",
          `Origin: ${BASE}`,
          "-H",
          "content-type: application/json",
          "-d",
          JSON.stringify({ username: "second-op", password: "wrong one!!" }),
          `${BASE}/api/login`,
        ],
        { encoding: "utf8" },
      );
      expect(hung.status).toBe(28); // curl hung up before the answer
      await expect.poll(failures).toBe(before + 1);
    });

    await test.step("two-factor needs the current password to turn on", async () => {
      const setup = await (await second.post("/api/account/totp/setup")).json();
      const code = totp(setup.secret);
      const missing = await second.post("/api/account/totp/enable", {
        data: { code },
      });
      expect(missing.status()).toBe(422);
      expect(missing.headers()["content-type"]).toContain("application/json");
      expect((await missing.json()).error).toBeTruthy();
      const wrong = await second.post("/api/account/totp/enable", {
        data: { code, password: "not my password" },
      });
      expect(wrong.status()).toBe(403);
      const right = await second.post("/api/account/totp/enable", {
        data: { code, password },
      });
      expect(right.status()).toBe(200);
    });

    await test.step("a right password without the code is audited", async () => {
      // Own address: this attempt stays counted until a full sign-in.
      const asked = curl([
        "--interface",
        "127.0.0.8",
        "-H",
        `Origin: ${BASE}`,
        "-H",
        "content-type: application/json",
        "-d",
        JSON.stringify({ username: "second-op", password }),
        `${BASE}/api/login`,
      ]);
      expect(asked.status).toBe(401);
      expect(JSON.parse(asked.body).totpRequired).toBe(true);
      const entries = await (await api.get("/api/audit?limit=20")).json();
      expect(
        entries.some(
          (e: { action: string; target: string }) =>
            e.action === "login.second_factor" && e.target === "second-op",
        ),
      ).toBe(true);
    });
  } finally {
    await second.dispose();
  }
});

test("a planted duplicate session cookie does not shadow the real one", () => {
  const result = curl([
    "-H",
    `Cookie: __Host-centrald=planted-by-another-service; ${cookie}`,
    `${BASE}/api/devices`,
  ]);
  expect(result.status).toBe(200);
});

test("only this server's names are answered", () => {
  const evil = curl([
    "-H",
    `Host: rebind.example:${PORT}`,
    `${BASE}/install.sh`,
  ]);
  expect(evil.status).toBe(421);
  expect(evil.body).not.toContain("CentralD agent installer");
  const h2 = spawnSync(
    "curl",
    [
      "-sk",
      "--http2",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code} %{http_version}",
      "-H",
      `Host: rebind.example:${PORT}`,
      `${BASE}/`,
    ],
    { encoding: "utf8" },
  );
  expect(h2.stdout).toBe("421 2");
  const connect = curl([
    "-X",
    "CONNECT",
    "--request-target",
    "example.com:443",
    `${BASE}/`,
  ]);
  expect(connect.status).toBe(421);
  for (const host of [`localhost:${PORT}`, `127.0.0.1:${PORT}`]) {
    const ok = curl(["-H", `Host: ${host}`, `${BASE}/install.sh`]);
    expect(ok.status, host).toBe(200);
  }
  // Agents dial their join-code address; the CA pin protects them.
  const agent = curl([
    ...WS_HEADERS,
    "-H",
    `Host: rebind.example:${PORT}`,
    `${BASE}/api/agent/connect`,
  ]);
  expect(agent.status).toBe(401);
});

test("the web app answers only GET and HEAD of app paths", () => {
  expect(curl([`${BASE}/devices`]).status).toBe(200);
  expect(curl(["-I", `${BASE}/devices`]).status).toBe(200);
  for (const method of ["POST", "PUT", "DELETE"]) {
    const result = curl(["-X", method, `${BASE}/devices`]);
    expect(result.status, method).toBe(405);
  }
  for (const [method, url] of [
    ["GET", "/api/"],
    ["GET", "/api"],
    ["PUT", "/api/nope"],
    ["DELETE", "/api/agent/nope"],
  ]) {
    const result = curl(["-X", method, `${BASE}${url}`]);
    expect(result.status, `${method} ${url}`).toBe(404);
    expect(JSON.parse(result.body).error).toBeTruthy();
  }
  const ipConnect = curl([
    "-X",
    "CONNECT",
    "--request-target",
    "10.0.0.1:443",
    `${BASE}/`,
  ]);
  expect(ipConnect.status).toBe(405);
  const badJson = curl([
    "-H",
    `Origin: ${BASE}`,
    "-H",
    "content-type: application/json",
    "-d",
    "{not json",
    `${BASE}/api/login`,
  ]);
  expect(badJson.status).toBe(400);
  expect(JSON.parse(badJson.body).error).toBeTruthy();
  const wrongMethod = curl([
    "-X",
    "PUT",
    "-H",
    `Origin: ${BASE}`,
    `${BASE}/api/state`,
  ]);
  expect(wrongMethod.status).toBe(405);
  expect(JSON.parse(wrongMethod.body).error).toBeTruthy();
});

test("one address cannot hold every connection, and idle ones close", async () => {
  test.setTimeout(90_000);
  const sockets: TLSSocket[] = [];
  const results = await Promise.all(
    Array.from(
      { length: 140 },
      () =>
        new Promise<boolean>((resolve) => {
          const socket = tlsConnect({
            socket: netConnect({
              host: "127.0.0.1",
              port: PORT,
              localAddress: "127.0.0.6",
            }),
            rejectUnauthorized: false,
          });
          sockets.push(socket);
          socket.once("secureConnect", () => resolve(true));
          socket.once("error", () => resolve(false));
          socket.once("close", () => resolve(false));
        }),
    ),
  );
  const open = results.filter(Boolean).length;
  expect(open).toBeLessThanOrEqual(128);
  expect(open).toBeGreaterThanOrEqual(100);
  // Everyone else is still served.
  const other = curl(["--interface", "127.0.0.7", `${BASE}/api/state`]);
  expect(other.status).toBe(200);
  // HTTP/1.1 connections that never send a request are closed (20 s).
  await expect
    .poll(
      () => sockets.filter((s) => !s.destroyed && !s.readableEnded).length,
      {
        timeout: 40_000,
        intervals: [2_000],
      },
    )
    .toBe(0);
  for (const socket of sockets) socket.destroy();
});

test("the streamed agent download matches the published build", () => {
  const arch = process.arch === "arm64" ? "aarch64" : "x86_64";
  const file = path.join(runDir(), "downloaded-agent");
  const result = spawnSync(
    "curl",
    [
      "-sk",
      "-o",
      file,
      "-w",
      "%{http_code}",
      `${BASE}/download/agent/linux/${arch}`,
    ],
    { encoding: "utf8" },
  );
  expect(result.stdout).toBe("200");
  const published = curl([`${BASE}/download/agent/linux/${arch}.sha256`]);
  const actual = createHash("sha256").update(readFileSync(file)).digest("hex");
  expect(actual).toBe(published.body.trim());
});

test("a second server on the same data directory changes nothing", async () => {
  const dataDir = path.join(runDir(), "data");
  const before = readFileSync(path.join(dataDir, "tls", "server.crt"), "utf8");
  const second = spawnSync(SERVER_BIN, ["run"], {
    env: {
      ...process.env,
      CENTRALD_DATA_DIR: dataDir,
      CENTRALD_AGENT_DIR: path.join(runDir(), "agents"),
      CENTRALD_LISTEN: `127.0.0.1:${PORT + 5}`,
    },
    encoding: "utf8",
    timeout: 20_000,
  });
  expect(second.status).not.toBe(0);
  expect(second.stderr).toContain("already running");
  expect(readFileSync(path.join(dataDir, "tls", "server.crt"), "utf8")).toBe(
    before,
  );
  const state = await api.get("/api/state");
  expect(state.status()).toBe(200);
});

test("the status command works next to the server and into a closed pipe", () => {
  const env = {
    ...process.env,
    CENTRALD_DATA_DIR: path.join(runDir(), "data"),
  };
  const full = spawnSync(SERVER_BIN, ["status"], { env, encoding: "utf8" });
  expect(full.status).toBe(0);
  expect(full.stdout).toContain("Server: running");
  for (let i = 0; i < 5; i++) {
    const piped = spawnSync(
      "bash",
      ["-c", 'set -o pipefail; "$0" status | true', SERVER_BIN],
      { env, encoding: "utf8" },
    );
    expect(piped.status, piped.stderr).toBe(0);
  }
});

test("damaged or missing state refuses to start instead of starting fresh", async () => {
  test.setTimeout(120_000);
  const base = path.join(runDir(), "startup");
  const data = path.join(base, "data");
  const backup = path.join(base, "backup");
  mkdirSync(base);
  const env = {
    ...process.env,
    CENTRALD_DATA_DIR: data,
    CENTRALD_AGENT_DIR: path.join(runDir(), "agents"),
    CENTRALD_LISTEN: `127.0.0.1:${PORT + 11}`,
    CENTRALD_LOG: "info",
  };
  const refuse = (expected: string) => {
    const result = spawnSync(SERVER_BIN, ["run"], {
      env,
      encoding: "utf8",
      timeout: 20_000,
    });
    expect(result.status, result.stdout + result.stderr).not.toBe(0);
    expect(result.signal).toBeNull();
    expect(result.stderr).toContain(expected);
  };
  /** Starts, waits for the CA fingerprint line, stops; returns the log. */
  const startAndStop = async () => {
    const child = spawn(SERVER_BIN, ["run"], {
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let log = "";
    child.stdout.on("data", (chunk) => (log += chunk));
    child.stderr.on("data", (chunk) => (log += chunk));
    for (let i = 0; i < 100 && !/CA fingerprint: \S+/.test(log); i++) {
      if (child.exitCode !== null) break;
      await sleep(100);
    }
    child.kill("SIGTERM");
    await new Promise((done) => child.once("exit", done));
    return log;
  };
  const restore = () => {
    rmSync(data, { recursive: true, force: true });
    cpSync(backup, data, { recursive: true });
  };
  const fingerprint = (log: string) => /CA fingerprint: (\S+)/.exec(log)?.[1];

  await test.step("a missing data directory is not a first run", async () => {
    refuse("does not exist");
  });

  mkdirSync(data, { mode: 0o700 });
  const first = await startAndStop();
  expect(first).toContain("setup code");
  const original = fingerprint(first);
  expect(original).toBeTruthy();
  cpSync(data, backup, { recursive: true });

  await test.step("a missing CA is never replaced", async () => {
    rmSync(path.join(data, "tls"), { recursive: true });
    refuse("ca.crt is missing");
    restore();
    rmSync(path.join(data, "tls", "ca.key"));
    refuse("ca.key is missing");
    restore();
  });

  await test.step("a server key that does not match its certificate is refused", async () => {
    copyFileSync(
      path.join(data, "tls", "ca.key"),
      path.join(data, "tls", "server.key"),
    );
    refuse("server.key does not match");
    restore();
  });

  await test.step("a CA key that does not match the CA is refused", async () => {
    copyFileSync(
      path.join(data, "tls", "server.key"),
      path.join(data, "tls", "ca.key"),
    );
    refuse("does not belong to");
    restore();
  });

  await test.step("an emptied or missing database is refused", async () => {
    for (const file of ["centrald.db-wal", "centrald.db-shm"]) {
      rmSync(path.join(data, file), { force: true });
    }
    truncateSync(path.join(data, "centrald.db"), 0);
    refuse("is empty");
    restore();
    rmSync(path.join(data, "centrald.db"));
    refuse("centrald.db is missing");
    restore();
  });

  await test.step("the restored directory starts with the same CA", async () => {
    const again = await startAndStop();
    expect(fingerprint(again)).toBe(original);
  });
});

// Runs last: it locks this address out of sign-in for a while.
test("password guessing is throttled", async ({ request }) => {
  const statuses: number[] = [];
  for (let i = 0; i < 7; i++) {
    const response = await request.post("/api/login", {
      headers: { Origin: BASE },
      data: { username: "admin", password: `wrong-${i}` },
    });
    statuses.push(response.status());
  }
  expect(statuses.slice(0, 5)).toEqual([401, 401, 401, 401, 401]);
  expect(statuses.at(-1)).toBe(429);
  const correct = await request.post("/api/login", {
    headers: { Origin: BASE },
    data: { username: "admin", password: "correct horse battery" },
  });
  expect(correct.status()).toBe(429);
});
