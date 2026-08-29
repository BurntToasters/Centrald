import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { run } from "./command.js";

/**
 * Builds Linux server/client binaries, packs .deb files, installs them, and
 * verifies unit files and binaries landed with the expected hardening markers.
 * Intended for CI on Ubuntu runners (requires apt/dpkg). The install step
 * uses `apt-get install` on the built .deb files so PostgreSQL is pulled in
 * the same way as `sudo apt install ./centrald-server_*.deb`. After install it
 * runs non-interactive `initial-setup` with the recommended local PostgreSQL
 * path so the packaged first-run becomes a usable server.
 */
const root = process.cwd();
const targetDir = path.join(root, "target", "debug");
const output = path.join(root, "dist", "ci-linux-debs");

run("cargo", [
  "build",
  "--locked",
  "-p",
  "centrald-server",
  "-p",
  "centrald-client",
]);
run("node", [
  "scripts/package-linux.js",
  "--target-dir",
  targetDir,
  "--output",
  path.relative(root, output).replaceAll("\\", "/"),
  "--debs-only",
]);

const version = JSON.parse(
  fs.readFileSync(path.join(root, "package.json"), "utf8"),
).version;
const serverDeb = path.join(
  output,
  `centrald-server_${version}_linux_x86_64.deb`,
);
const clientDeb = path.join(
  output,
  `centrald-client_${version}_linux_x86_64.deb`,
);
for (const artifact of [serverDeb, clientDeb]) {
  if (!fs.existsSync(artifact)) {
    throw new Error(`missing package artifact: ${artifact}`);
  }
}

const installLog = runCaptured("sudo", [
  "apt-get",
  "install",
  "-y",
  serverDeb,
  clientDeb,
]);
if (
  !installLog.includes(
    "CentralD server is installed. Next: sudo centrald-server initial-setup",
  )
) {
  throw new Error("apt install did not print the server first-run command");
}
if (
  !installLog.includes(
    "CentralD client is installed. Next: sudo centrald-client enroll",
  )
) {
  throw new Error("apt install did not print the client enroll command");
}

run("dpkg-query", ["-W", "postgresql"]);

const requiredFiles = [
  "/usr/bin/centrald-server",
  "/usr/bin/centrald-client",
  "/lib/systemd/system/centrald-server.service",
  "/lib/systemd/system/centrald-client.service",
  "/lib/systemd/system/centrald-broker.service",
  "/usr/lib/tmpfiles.d/centrald-server.conf",
  "/usr/lib/tmpfiles.d/centrald-client.conf",
];
for (const file of requiredFiles) {
  if (!fs.existsSync(file)) {
    throw new Error(`package install missing ${file}`);
  }
}

const clientUnit = fs.readFileSync(
  "/lib/systemd/system/centrald-client.service",
  "utf8",
);
if (clientUnit.includes("RuntimeDirectory=centrald")) {
  throw new Error(
    "client unit must not own shared /run/centrald via RuntimeDirectory",
  );
}
if (
  !clientUnit.includes("ReadWritePaths=") ||
  !clientUnit.includes("/run/centrald")
) {
  throw new Error("client unit missing ReadWritePaths=/run/centrald");
}

const serverUnit = fs.readFileSync(
  "/lib/systemd/system/centrald-server.service",
  "utf8",
);
if (!serverUnit.includes("RuntimeDirectory=centrald")) {
  throw new Error("server unit missing RuntimeDirectory=centrald");
}
if (!/^User=root$/m.test(serverUnit)) {
  throw new Error("server unit must run as root in this release");
}

const brokerUnit = fs.readFileSync(
  "/lib/systemd/system/centrald-broker.service",
  "utf8",
);
if (/WantedBy=/.test(brokerUnit) === false) {
  // Install section may exist; enablement must still be absent from packaging.
}
run("bash", [
  "-lc",
  "systemctl is-enabled centrald-broker.service >/dev/null 2>&1 && exit 1 || exit 0",
]);

const serverPostinst = controlScript(serverDeb, "postinst");
if (
  !serverPostinst.includes(
    "CentralD server is installed. Next: sudo centrald-server initial-setup",
  )
) {
  throw new Error("server package postinst is missing the first-run command");
}
const clientPostinst = controlScript(clientDeb, "postinst");
if (
  !clientPostinst.includes(
    "CentralD client is installed. Next: sudo centrald-client enroll",
  )
) {
  throw new Error("client package postinst is missing the enroll command");
}

const serverHelp = commandOutput("centrald-server", ["--help"]);
for (const command of ["initial-setup", "config", "run", "channel"]) {
  if (!serverHelp.includes(command)) {
    throw new Error(
      `centrald-server --help is missing public command ${command}`,
    );
  }
}
if (
  /\benroll-client\b/.test(serverHelp) ||
  /\benroll-admin\b/.test(serverHelp)
) {
  throw new Error("centrald-server --help leaked a hidden enrollment command");
}

const clientHelp = commandOutput("centrald-client", ["--help"]);
for (const command of ["enroll", "restart", "reenroll", "rescue"]) {
  if (!clientHelp.includes(command)) {
    throw new Error(
      `centrald-client --help is missing public command ${command}`,
    );
  }
}
if (/\bdaemon\b/.test(clientHelp) || /\bprivileged-broker\b/.test(clientHelp)) {
  throw new Error("centrald-client --help leaked an internal daemon command");
}

const setupLog = runCaptured("sudo", [
  "env",
  "-u",
  "CENTRALD_DATABASE_URL",
  "-u",
  "PGHOST",
  "-u",
  "PGPORT",
  "-u",
  "PGUSER",
  "-u",
  "PGDATABASE",
  "-u",
  "PGPASSWORD",
  "-u",
  "PGSERVICE",
  "centrald-server",
  "initial-setup",
  "--non-interactive",
  "--public-host",
  "ci.centrald.test",
  "--admin-name",
  "CI Admin",
  "--recovery-key-output",
  "/root/centrald-root-recovery.pem",
]);
run("sudo", ["test", "-f", "/etc/centrald/server.toml"]);
if (!setupLog.includes("Initial Admin access key")) {
  throw new Error("initial-setup did not print the Admin access key banner");
}
if (!setupLog.includes("Paste this single key into CentralD Admin")) {
  throw new Error(
    "initial-setup did not tell the operator to enroll Admin next",
  );
}
if (!setupLog.includes("READY:")) {
  const status = optionalCommandOutput("sudo", [
    "systemctl",
    "status",
    "centrald-server",
    "--no-pager",
  ]);
  const journal = optionalCommandOutput("sudo", [
    "journalctl",
    "-u",
    "centrald-server",
    "-n",
    "80",
    "--no-pager",
  ]);
  throw new Error(
    `packaged initial-setup did not leave a usable systemd service:\n${setupLog}\n--- systemctl status ---\n${status}\n--- journalctl ---\n${journal}`,
  );
}

console.log("Linux package install smoke OK");

function controlScript(deb, name) {
  const extract = path.join(output, `${path.basename(deb)}.control`);
  fs.mkdirSync(extract, { recursive: true });
  run("dpkg-deb", ["-e", deb, extract]);
  const script = path.join(extract, name);
  if (!fs.existsSync(script)) {
    throw new Error(`package ${deb} is missing DEBIAN/${name}`);
  }
  return fs.readFileSync(script, "utf8");
}

function commandOutput(command, args) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    shell: false,
  });
  if (result.error) throw result.error;
  const text = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed:\n${text}`);
  }
  return text;
}

function optionalCommandOutput(command, args) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    shell: false,
  });
  return `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
}

function runCaptured(command, args) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    shell: false,
  });
  if (result.error) throw result.error;
  const text = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  process.stdout.write(text);
  if (!text.endsWith("\n")) process.stdout.write("\n");
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed:\n${text}`);
  }
  return text;
}
