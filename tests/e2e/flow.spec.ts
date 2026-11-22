// The homelab journey through the real web app, server, and agents.
//
// Ways this can fail (each is asserted below):
// - setup accepts a wrong setup code, or never lands on the dashboard
// - the install command does not enroll, or the device never shows online
// - status never arrives (no CPU/memory on the device page)
// - command output is lost, mangled, or the exit code/state is wrong
// - cancel leaves the run running
// - a timeout or cancel leaves processes behind: a background child, or a
//   child that ignores SIGTERM after its parent shell exits
// - a background child that keeps the output pipe open disarms the timeout
//   or outlives a finished run
// - commands inherit the agent's own environment instead of a clean one
// - the terminal does not echo input or relay output
// - a monitor-only device accepts commands or offers a terminal
// - two-factor setup does not persist, or sign-in skips the code
// - a removed device's agent can still connect
import { expect, test, type Page } from "@playwright/test";
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import path from "node:path";
import {
  ADMIN,
  BASE,
  REPORT_DIR,
  agentEnv,
  enroll,
  readLog,
  runDir,
  setupCode,
  startAgent,
  totp,
} from "./harness";

test.describe.configure({ mode: "serial" });

let page: Page;
let shotIndex = 0;
let deviceUrl = "";
let fullAgentLog = "";

async function shot(name: string) {
  shotIndex += 1;
  const file = `${String(shotIndex).padStart(2, "0")}-${name}.png`;
  await page.screenshot({
    path: path.join(REPORT_DIR, "screenshots", file),
    fullPage: true,
  });
}

/** The real one-liner needs root and writes /usr/local/bin; opt in only. */
const RUN_INSTALLER =
  process.getuid?.() === 0 && process.env.CENTRALD_E2E_INSTALL === "1";

test.beforeAll(async ({ browser }) => {
  page = await browser.newPage();
});

test.afterAll(async () => {
  await page.close();
});

test("first-run setup creates the first operator", async () => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Welcome" })).toBeVisible();

  await test.step("a wrong setup code is refused", async () => {
    await page.getByLabel(/^Setup code/).fill("AAAA-BBBB-CCCC");
    await page.getByLabel(/^Username/).fill(ADMIN.username);
    await page.getByLabel(/^Password/).fill(ADMIN.password);
    await page.getByLabel(/^Confirm password/).fill(ADMIN.password);
    await page.getByRole("button", { name: "Create account" }).click();
    await expect(page.getByText("That setup code is not right")).toBeVisible();
  });

  await test.step("the printed setup code creates the account", async () => {
    await page.getByLabel(/^Setup code/).fill(setupCode());
    await page.getByRole("button", { name: "Create account" }).click();
    await expect(page.getByText("No devices yet")).toBeVisible();
  });
  await shot("empty-dashboard");
});

test("a device joins with the copied install command", async () => {
  await page.getByRole("button", { name: "Add your first device" }).click();
  await expect(
    page.getByRole("heading", { name: "Add a device" }),
  ).toBeVisible();
  await page.getByLabel(/^Device name/).fill("lab-box");
  await expect(page.getByText("only works here")).toBeVisible();
  await page.getByRole("button", { name: "Create join code" }).click();

  const linux = page.getByLabel("Linux install command");
  await expect(linux).toContainText("--pinnedpubkey 'sha256//");
  await shot("install-command");

  await page.getByRole("tab", { name: "Manual" }).click();
  const code = (await page.getByLabel("Join code").textContent()) ?? "";
  expect(code).toMatch(/^cdj1\./);
  writeFileSync(path.join(runDir(), "used-code"), code);

  let binary: string | undefined;
  if (RUN_INSTALLER) {
    await test.step("run the real install one-liner", async () => {
      await page.getByRole("tab", { name: "Linux" }).click();
      const command = (await linux.textContent()) ?? "";
      const result = spawnSync("sh", ["-c", command], {
        env: agentEnv("agent-full"),
        encoding: "utf8",
        timeout: 60_000,
      });
      expect(result.stderr + result.stdout).toContain("Enrolled");
      expect(result.status).toBe(0);
      binary = "/usr/local/bin/centrald-agent";
    });
  } else {
    await test.step("enroll with the join code on stdin", async () => {
      const result = enroll(code, "agent-full");
      expect(result.stderr + result.stdout).toContain("Enrolled");
      expect(result.status).toBe(0);
    });
  }

  fullAgentLog = startAgent("agent-full", binary).log;
  await expect(page.getByText("lab-box joined.")).toBeVisible({
    timeout: 20_000,
  });
  await shot("device-joined");
  await page.getByRole("link", { name: "Open it" }).click();
  await expect(page).toHaveURL(/\/devices\/[0-9a-f-]{36}$/);
  deviceUrl = page.url();
});

test("the device page shows live status", async () => {
  await expect(page.getByText(/· online/)).toBeVisible();
  await expect(page.getByText(/CPU \(\d+ cores\)/)).toBeVisible();
  await expect(page.getByText("Memory", { exact: true })).toBeVisible();
  await shot("device-detail");

  await test.step("it is listed online on the dashboard", async () => {
    await page.getByRole("link", { name: "Devices" }).first().click();
    const row = page.getByTestId("device-row").filter({ hasText: "lab-box" });
    await expect(row).toBeVisible();
    await expect(page.getByText("1 of 1 online")).toBeVisible();
    await shot("dashboard");
  });
});

test("a command runs as root and streams its output", async () => {
  await page.goto(deviceUrl);
  await page.getByRole("button", { name: "Run command" }).click();
  await page
    .getByLabel("Command line")
    .fill('echo "hello from $(hostname)"; echo uid=$(id -u); exit 3');
  await page.getByRole("button", { name: "Run on 1 device" }).click();
  await expect(page).toHaveURL(/\/runs\/[0-9a-f-]{36}$/);

  const output = page.getByTestId("run-output");
  await expect(output).toContainText("hello from");
  await expect(output).toContainText(`uid=${process.getuid?.() ?? 0}`);
  await expect(page.getByText("exit code 3")).toBeVisible();
  await expect(page.getByText("Failed", { exact: true })).toBeVisible();
  await shot("run-output");
});

test("a running command can be canceled", async () => {
  await page.goto(deviceUrl);
  await page.getByRole("button", { name: "Run command" }).click();
  await page.getByLabel("Command line").fill("echo started; sleep 300");
  await page.getByRole("button", { name: "Run on 1 device" }).click();
  await expect(page.getByTestId("run-output")).toContainText("started");
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByText("Canceled", { exact: true })).toBeVisible();
});

/** Starts a command on lab-box through the API and returns the run id. */
async function apiRun(command: string, timeoutSeconds = 300) {
  const response = await page.request.post("/api/runs", {
    headers: { Origin: BASE },
    data: {
      deviceIds: [deviceUrl.split("/").pop()],
      command,
      timeoutSeconds,
    },
  });
  expect(response.status()).toBe(201);
  return (await response.json()).id as string;
}

async function target(runId: string) {
  const run = await (await page.request.get(`/api/runs/${runId}`)).json();
  const first = run.targets[0];
  return {
    state: first.state as string,
    output: Buffer.from(first.output ?? "", "base64").toString(),
  };
}

/** True while any process on this machine has `pattern` in its arguments. */
function running(pattern: string) {
  return spawnSync("pgrep", ["-f", pattern]).status === 0;
}

test("timeouts and cancel stop every process a command started", async () => {
  await test.step("a timeout stops the command and its background child", async () => {
    const run = await apiRun("sleep 31301 & echo started; sleep 31302", 2);
    await expect
      .poll(async () => (await target(run)).state, { timeout: 20_000 })
      .toBe("timed_out");
    expect(running("sleep 3130[12]")).toBe(false);
  });

  await test.step("a background child holding the output open ends with the run", async () => {
    const run = await apiRun("sleep 31303 & echo started", 300);
    await expect
      .poll(async () => (await target(run)).state, { timeout: 15_000 })
      .toBe("succeeded");
    expect((await target(run)).output).toContain("started");
    expect(running("sleep 31303")).toBe(false);
  });

  await test.step("cancel stops a child that ignores SIGTERM", async () => {
    const run = await apiRun(
      `sh -c 'trap "" TERM; echo started; sleep 31304' & wait`,
    );
    await expect
      .poll(async () => (await target(run)).output, { timeout: 15_000 })
      .toContain("started");
    const cancel = await page.request.post(`/api/runs/${run}/cancel`, {
      headers: { Origin: BASE },
    });
    expect(cancel.ok()).toBe(true);
    await expect
      .poll(async () => (await target(run)).state, { timeout: 30_000 })
      .toBe("canceled");
    expect(running("sleep 31304")).toBe(false);
  });
});

test("commands start from a clean environment", async () => {
  const run = await apiRun("env");
  await expect
    .poll(async () => (await target(run)).state, { timeout: 15_000 })
    .toBe("succeeded");
  const env = (await target(run)).output;
  expect(env).toContain("PATH=/usr/local/sbin:/usr/local/bin:");
  expect(env).toContain("LANG=C.UTF-8");
  // The agent runs with these; commands must not see them.
  expect(env).not.toContain("CENTRALD_AGENT_CONFIG");
  expect(env).not.toContain("CENTRALD_SKIP_SERVICE");
});

test("the terminal relays keystrokes and output", async () => {
  await page.goto(deviceUrl);
  await page.getByRole("button", { name: "Open terminal" }).click();
  const terminal = page.getByTestId("terminal");
  await expect(terminal.locator(".xterm-rows")).toBeVisible();
  await terminal.click();
  // Arithmetic proves the shell evaluated it rather than echoing input.
  await page.keyboard.type("echo terminal-$((6*7))-ok\n");
  await expect(terminal).toContainText("terminal-42-ok");
  await shot("terminal");
});

test("a monitor-only device refuses commands and terminals", async () => {
  await page.getByRole("link", { name: "Add device" }).click();
  await page.getByLabel(/^Device name/).fill("watch-only");
  await page.getByRole("radio", { name: /^Monitor only/ }).check();
  await page.getByRole("button", { name: "Create join code" }).click();
  await expect(page.getByLabel("Linux install command")).toContainText(
    "CENTRALD_MONITOR_ONLY=1",
  );
  await page.getByRole("tab", { name: "Manual" }).click();
  await expect(page.getByText("enroll --monitor-only")).toBeVisible();
  const code = (await page.getByLabel("Join code").textContent()) ?? "";
  const result = enroll(code, "agent-monitor", true);
  expect(result.status).toBe(0);
  startAgent("agent-monitor");
  await expect(page.getByText("watch-only joined.")).toBeVisible({
    timeout: 20_000,
  });
  await page.getByRole("link", { name: "Open it" }).click();

  await expect(page.getByText("enrolled as monitor-only")).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Open terminal" }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Run command" }),
  ).toBeDisabled();
  await shot("monitor-only");

  await test.step("a run aimed at it is refused", async () => {
    const id = page.url().split("/").pop();
    const response = await page.request.post("/api/runs", {
      headers: { Origin: BASE },
      data: { deviceIds: [id], command: "touch /tmp/should-not-exist" },
    });
    expect(response.status()).toBe(201);
    const run = await response.json();
    expect(run.targets[0].state).toBe("refused");
  });
});

test("two-factor sign-in can be turned on and is enforced", async () => {
  await page.getByRole("link", { name: "Settings" }).click();
  await page.getByRole("button", { name: "Set up two-factor sign-in" }).click();
  const secret =
    (await page.getByLabel("Two-factor secret").textContent()) ?? "";
  expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
  await page.getByLabel(/^Code from the app/).fill(totp(secret));
  await page.getByRole("button", { name: "Turn on" }).click();
  await expect(page.getByText("Signing in asks for a code")).toBeVisible();
  await shot("settings");

  await test.step("sign out and back in with a code", async () => {
    await page.getByRole("button", { name: "Sign out" }).click();
    await page.getByLabel(/^Username/).fill(ADMIN.username);
    await page.getByLabel(/^Password/).fill(ADMIN.password);
    await page.getByRole("button", { name: "Sign in" }).click();
    const field = page.getByLabel(/^Authentication code/);
    await expect(field).toBeVisible();
    await field.fill("000000");
    await page.getByRole("button", { name: "Verify" }).click();
    await expect(page.getByRole("alert")).toBeVisible();
    // The enable step used this window's code; replay is refused, so use the next.
    await field.fill(totp(secret, 1));
    await page.getByRole("button", { name: "Verify" }).click();
    await expect(page.getByText(/of 2 online/)).toBeVisible();
  });
  // Later suites reuse this signed-in session.
  await page
    .context()
    .storageState({ path: path.join(runDir(), "operator.json") });
});

test("removing a device revokes its agent", async () => {
  await page.goto(deviceUrl);
  await page.getByRole("button", { name: "Remove device" }).click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Remove device" })
    .click();
  await expect(page.getByText(/of 1 online/)).toBeVisible();
  await expect
    .poll(() => readLog(fullAgentLog), { timeout: 30_000 })
    .toContain("rejected this device's credential");
  await shot("after-removal");
});
