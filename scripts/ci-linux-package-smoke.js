import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { run } from "./command.js";

/**
 * Builds Linux server/client binaries, packs .deb files, installs them, and
 * verifies unit files and binaries landed with the expected hardening markers.
 * Intended for CI on Ubuntu runners (requires dpkg).
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

run("sudo", ["dpkg", "-i", serverDeb, clientDeb]);

const requiredFiles = [
  "/usr/bin/centrald-server",
  "/usr/bin/centrald-client",
  "/lib/systemd/system/centrald-server.service",
  "/lib/systemd/system/centrald-client.service",
  "/lib/systemd/system/centrald-broker.service",
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
if (!clientUnit.includes("RuntimeDirectory=centrald")) {
  throw new Error("client unit missing RuntimeDirectory=centrald");
}
if (!clientUnit.includes("RuntimeDirectoryMode=0755")) {
  throw new Error("client unit missing RuntimeDirectoryMode=0755");
}

const serverUnit = fs.readFileSync(
  "/lib/systemd/system/centrald-server.service",
  "utf8",
);
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

console.log("Linux package install smoke OK");
