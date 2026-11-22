// Negative paths against the live server left behind by flow.spec.ts.
//
// Ways this can fail (each is asserted below):
// - API data or WebSockets reachable without a session
// - a cross-site page can make state-changing requests with the cookie
// - the session cookie is readable by scripts or sent over plain HTTP
// - a join code works twice, after revocation, or after tampering
// - an agent connects with a guessed or wrong credential
// - bad credentials sent from the agent's address lock the real agent out
// - a device stores hidden characters (bidi, zero-width, escapes) in its
//   name, status, or error text, or unbounded counts the dashboard renders
// - a device floods status faster than the server can use it
// - a device that stops reading stays online and parks the operator's
//   terminal instead of being disconnected
// - the install command downloads from a server with a different key
// - the served agent does not match its published checksum
// - a monitor-only device opens a terminal
// - plain HTTP serves content instead of redirecting
// - pages lack the security headers that block framing and injection
// - `centrald-agent update` installs a build that fails its checks, or
//   leaves a half-written binary behind
// - password guessing is not slowed down
import { expect, test, type APIRequestContext } from "@playwright/test";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  copyFileSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import {
  AGENT_BIN,
  BASE,
  PORT,
  REPORT_DIR,
  agentEnv,
  enroll,
  runDir,
} from "./harness";
import { RawSocket } from "./rawws";

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

/** Reads `device_id` and `token` from an isolated agent config file. */
function credentialOf(name: string) {
  const config = readFileSync(path.join(runDir(), `${name}.toml`), "utf8");
  const device = /device_id\s*=\s*"([^"]+)"/.exec(config)?.[1] ?? "";
  const token = /token\s*=\s*"([^"]+)"/.exec(config)?.[1] ?? "";
  expect(device && token).toBeTruthy();
  return { device, token };
}

/** GET a JSON API path with the operator session. */
async function getJson(url: string) {
  return (await api.get(url)).json();
}

test("bad credentials from the agent's address do not lock it out", async () => {
  const url = `${BASE}/api/agent/connect`;
  const { device, token } = credentialOf("agent-monitor");
  const statuses: number[] = [];
  for (let i = 0; i < 8; i++) {
    statuses.push(curl([...WS_HEADERS, url]).status);
    const wrong = `Authorization: Bearer ${device}.${"B".repeat(42)}${i}`;
    statuses.push(curl([...WS_HEADERS, "-H", wrong, url]).status);
  }
  expect(statuses.every((s) => s === 401 || s === 429)).toBe(true);
  expect(statuses).toContain(429);
  // No Hello is sent, so the real agent's connection is left alone.
  const real = await RawSocket.open("/api/agent/connect", {
    Authorization: `Bearer ${device}.${token}`,
  });
  expect(real.status).toBe(101);
  real.socket?.close();
});

test("a hostile device cannot plant hidden text, flood, or stall", async ({
  browser,
}) => {
  const created = await api.post("/api/join-tokens", {
    data: { name: "hostile\u202eevil", serverAddress: `127.0.0.1:${PORT}` },
  });
  expect(created.status()).toBe(201);
  const enrolled = enroll((await created.json()).code, "hostile");
  expect(enrolled.status).toBe(0);
  const { device, token } = credentialOf("hostile");
  const opened = await RawSocket.open("/api/agent/connect", {
    Authorization: `Bearer ${device}.${token}`,
  });
  expect(opened.status).toBe(101);
  const agent = opened.socket as RawSocket;
  // Controls, zero-width, bidi overrides and isolates, BOM.
  const hidden =
    // eslint-disable-next-line no-control-regex
    /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/;
  const status = (cpuPercent: number) => ({
    type: "status",
    uptimeSeconds: 100,
    cpuPercent,
    cpuCount: 4,
    load: [0.1, 0.1, 0.1],
    memory: { totalBytes: 100, usedBytes: 1000 },
    swap: { totalBytes: 0, usedBytes: 0 },
    disks: Array.from({ length: 64 }, (_, i) => ({
      mount: `/d${i}\u202e`,
      filesystem: "ext4",
      totalBytes: 100,
      usedBytes: 99,
    })),
    addresses: ["10.9.9.9\u200b"],
    updates: {
      manager: "apt",
      pending: 4294967295,
      rebootRequired: true,
      checkedAt: 0,
    },
    failedUnits: Array.from(
      { length: 64 },
      (_, i) => `unit-${i}\u2066.service`,
    ),
  });

  await test.step("hello and status text is cleaned and bounded", async () => {
    agent.send({
      type: "hello",
      protocol: 1,
      agentVersion: "0.1.0",
      hostname: `evil\u202egnp.exe\u200b\u001b[31m${"x".repeat(1000)}`,
      os: {
        family: "linux",
        id: "debian",
        name: "Debian\u2066 hidden",
        version: "12",
        kernel: "6",
        arch: "x86_64",
      },
      allowCommands: true,
      packageManaged: false,
    });
    expect(await agent.next((m) => m.type === "welcome")).not.toBeNull();
    agent.send(status(11));
    // Too soon after the first report, so it is ignored.
    agent.send(status(77));
    agent.send({ type: "exec_output", id: "x".repeat(100_000), data: "" });
    await expect
      .poll(
        async () =>
          (await getJson(`/api/devices/${device}`)).status?.cpuPercent,
      )
      .toBe(11);
    await new Promise((resolve) => setTimeout(resolve, 1_000));
    const view = await getJson(`/api/devices/${device}`);
    expect(view.online).toBe(true);
    expect(view.status.cpuPercent).toBe(11);
    expect(view.hostname).not.toMatch(hidden);
    expect(Buffer.byteLength(view.hostname)).toBeLessThanOrEqual(256);
    expect(view.name).toBe("hostileevil");
    expect(view.os.name).not.toMatch(hidden);
    expect(view.status.updates.pending).toBeLessThanOrEqual(100_000);
    expect(view.status.failedUnits.length).toBeLessThanOrEqual(32);
    expect(view.status.memory.usedBytes).toBeLessThanOrEqual(
      view.status.memory.totalBytes,
    );
    for (const text of [
      ...view.status.failedUnits,
      ...view.status.addresses,
      ...view.status.disks.map((d: { mount: string }) => d.mount),
    ])
      expect(text).not.toMatch(hidden);
  });

  await test.step("the device list stays readable", async () => {
    const viewer = await browser.newPage({
      storageState: path.join(runDir(), "operator.json"),
    });
    await viewer.goto("/");
    const row = viewer
      .getByTestId("device-row")
      .filter({ hasText: "hostileevil" });
    await expect(row).toBeVisible();
    expect(await row.locator(".badge").count()).toBeLessThanOrEqual(6);
    const box = await row.boundingBox();
    expect(box?.height ?? 0).toBeLessThan(160);
    await viewer.screenshot({
      path: path.join(REPORT_DIR, "screenshots", "security-hostile-device.png"),
      fullPage: true,
    });
    await viewer.close();
  });

  await test.step("error text from the device is cleaned", async () => {
    const run = await api.post("/api/runs", {
      data: { deviceIds: [device], command: "true" },
    });
    expect(run.status()).toBe(201);
    const runId = (await run.json()).id;
    const start = await agent.next((m) => m.type === "exec_start");
    expect(start).not.toBeNull();
    agent.send({
      type: "exec_exit",
      id: start?.id,
      outcome: {
        state: "failed",
        exitCode: 1,
        error: "boom\u001b]0;pwned\u0007\u202edone\u200b",
      },
    });
    await expect
      .poll(async () => (await getJson(`/api/runs/${runId}`)).targets[0].error)
      .toBe("boom]0;pwneddone");
  });

  await test.step("a device that stops reading is disconnected", async () => {
    agent.pause();
    const terminal = await RawSocket.open(`/api/devices/${device}/terminal`, {
      Cookie: cookie,
      Origin: BASE,
    });
    expect(terminal.status).toBe(101);
    const chunk = Buffer.alloc(32 * 1024, 0x61);
    for (let i = 0; i < 1000 && !terminal.socket?.closed; i++) {
      terminal.socket?.sendBinary(chunk);
    }
    await expect
      .poll(async () => (await getJson(`/api/devices/${device}`)).online, {
        timeout: 40_000,
      })
      .toBe(false);
    terminal.socket?.close();
    agent.close();
  });
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
