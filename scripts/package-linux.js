import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { run } from "./command.js";
import {
  cleanGeneratedDirectory,
  ensureGeneratedDirectory,
} from "./lib/safe-path.js";

const root = process.cwd();
const options = parseArguments(process.argv.slice(2));
const packageJson = JSON.parse(
  fs.readFileSync(path.join(root, "package.json"), "utf8"),
);
const version = packageJson.version;
const debianVersion = version.replace("-", "~");
const targetDir = path.resolve(root, options.targetDir);
const outputRelative = path
  .relative(root, path.resolve(root, options.output))
  .replaceAll("\\", "/");

if (process.platform !== "linux") {
  throw new Error("Linux packages must be assembled on Linux.");
}
if (!fs.existsSync(targetDir)) {
  throw new Error(`Rust target directory does not exist: ${targetDir}`);
}

cleanGeneratedDirectory(root, outputRelative);
const output = ensureGeneratedDirectory(root, outputRelative);
const serverBinary = requireRegularFile(
  path.join(targetDir, "centrald-server"),
  "centrald-server binary",
);
const clientBinary = requireRegularFile(
  path.join(targetDir, "centrald-client"),
  "centrald-client binary",
);

const serverArtifact = path.join(
  output,
  `centrald-server_${version}_linux_x86_64.deb`,
);
const clientArtifact = path.join(
  output,
  `centrald-client_${version}_linux_x86_64.deb`,
);

buildDebianPackage({
  artifact: serverArtifact,
  binary: serverBinary,
  binaryName: "centrald-server",
  control: controlFile({
    packageName: "centrald-server",
    version: debianVersion,
    description:
      "CentralD homelab management server for Ubuntu Server 24.04 and newer",
    dependencies: ["ca-certificates", "coreutils", "postgresql", "systemd", "util-linux"],
  }),
  postinst: `#!/bin/sh\nset -eu\ninstall -d -m 0700 -o root -g root /etc/centrald /var/lib/centrald\nif command -v systemctl >/dev/null 2>&1; then\n  systemctl daemon-reload || true\n  if systemctl is-active --quiet centrald-server.service; then\n    systemctl try-restart centrald-server.service || echo "warning: centrald-server.service did not restart cleanly; inspect with systemctl status centrald-server" >&2\n  fi\nfi\n`,
  service: path.join(root, "deploy/systemd/centrald-server.service"),
});

buildDebianPackage({
  artifact: clientArtifact,
  binary: clientBinary,
  binaryName: "centrald-client",
  control: controlFile({
    packageName: "centrald-client",
    version: debianVersion,
    description: "Outbound-only CentralD managed client for Debian and Ubuntu",
    dependencies: ["adduser", "ca-certificates", "systemd"],
  }),
  postinst: `#!/bin/sh\nset -eu\nif ! getent group centrald >/dev/null 2>&1; then addgroup --system centrald >/dev/null; fi\nif ! getent passwd centrald >/dev/null 2>&1; then adduser --system --ingroup centrald --home /var/lib/centrald-client --no-create-home --shell /usr/sbin/nologin centrald >/dev/null; fi\nfor path in /var/lib/centrald-client /var/lib/centrald-client/identities /var/lib/centrald-client/configurations /var/lib/centrald-client.lock; do\n  if [ -L "$path" ]; then echo "refusing symbolic-link CentralD client state: $path" >&2; exit 1; fi\ndone\ninstall -d -m 0750 -o root -g centrald /var/lib/centrald-client\ninstall -d -m 0750 -o root -g centrald /var/lib/centrald-client/identities\ninstall -d -m 0700 -o centrald -g centrald /var/lib/centrald-client/configurations\nif [ -e /var/lib/centrald-client.lock ]; then\n  if [ ! -f /var/lib/centrald-client.lock ]; then echo "CentralD client state lock is not a regular file" >&2; exit 1; fi\n  chown centrald:centrald /var/lib/centrald-client.lock\n  chmod 0600 /var/lib/centrald-client.lock\nelse\n  install -m 0600 -o centrald -g centrald /dev/null /var/lib/centrald-client.lock\nfi\nif command -v systemctl >/dev/null 2>&1; then\n  systemctl daemon-reload || true\n  if systemctl is-active --quiet centrald-client.service; then\n    systemctl try-restart centrald-client.service || echo "warning: centrald-client.service did not restart cleanly; inspect with systemctl status centrald-client" >&2\n  fi\nfi\n`,
  service: path.join(root, "deploy/systemd/centrald-client.service"),
});

const appImage = findSingleArtifact(
  options.appImage ? path.resolve(root, options.appImage) : targetDir,
  (file) => file.endsWith(".AppImage"),
  "CentralD Admin AppImage",
);
const adminArtifact = path.join(
  output,
  `centrald-admin_${version}_linux_x86_64.AppImage`,
);
copyArtifact(appImage, adminArtifact, 0o755);
copySignatureIfPresent(appImage, adminArtifact);

console.log(`Created ${serverArtifact}`);
console.log(`Created ${clientArtifact}`);
console.log(`Created ${adminArtifact}`);

function parseArguments(args) {
  const result = {
    targetDir: "target/x86_64-unknown-linux-gnu/release",
    output: "dist/linux-x64",
    appImage: "",
  };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--target-dir") {
      result.targetDir = requiredValue(args, ++index, argument);
    } else if (argument === "--output") {
      result.output = requiredValue(args, ++index, argument);
    } else if (argument === "--appimage") {
      result.appImage = requiredValue(args, ++index, argument);
    } else {
      throw new Error(`Unknown argument ${argument}`);
    }
  }
  return result;
}

function requiredValue(args, index, option) {
  const value = args[index];
  if (!value || value.startsWith("--")) {
    throw new Error(`${option} requires a value`);
  }
  return value;
}

function controlFile({
  packageName,
  version: packageVersion,
  description,
  dependencies,
}) {
  return [
    `Package: ${packageName}`,
    `Version: ${packageVersion}`,
    "Section: admin",
    "Priority: optional",
    "Architecture: amd64",
    "Maintainer: CentralD maintainers",
    `Depends: ${dependencies.join(", ")}`,
    `Description: ${description}`,
    " CentralD is intended for private LAN and VPN deployments.",
    "",
  ].join("\n");
}

function buildDebianPackage({
  artifact,
  binary,
  binaryName,
  control,
  postinst,
  service,
}) {
  const staging = path.join(
    path.dirname(artifact),
    `.staging-${binaryName}-${process.pid}`,
  );
  if (fs.existsSync(staging)) {
    throw new Error(`Refusing existing package staging directory: ${staging}`);
  }
  try {
    fs.mkdirSync(path.join(staging, "DEBIAN"), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(staging, "usr/bin"), {
      recursive: true,
      mode: 0o755,
    });
    fs.mkdirSync(path.join(staging, "lib/systemd/system"), {
      recursive: true,
      mode: 0o755,
    });
    fs.mkdirSync(path.join(staging, `usr/share/doc/${binaryName}`), {
      recursive: true,
      mode: 0o755,
    });
    copyArtifact(binary, path.join(staging, `usr/bin/${binaryName}`), 0o755);
    copyArtifact(
      requireRegularFile(service, "systemd service"),
      path.join(staging, `lib/systemd/system/${binaryName}.service`),
      0o644,
    );
    fs.writeFileSync(path.join(staging, "DEBIAN/control"), control, {
      mode: 0o644,
    });
    fs.writeFileSync(path.join(staging, "DEBIAN/postinst"), postinst, {
      mode: 0o755,
    });
    fs.writeFileSync(
      path.join(staging, `usr/share/doc/${binaryName}/copyright`),
      "CentralD is distributed under GPL-3.0-or-later.\n",
      { mode: 0o644 },
    );
    run("dpkg-deb", ["--root-owner-group", "--build", staging, artifact]);
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
}

function requireRegularFile(file, label) {
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) {
    throw new Error(`Missing ${label}: ${file}`);
  }
  if (fs.lstatSync(file).isSymbolicLink()) {
    throw new Error(`Refusing symbolic-link ${label}: ${file}`);
  }
  return file;
}

function findSingleArtifact(start, predicate, label) {
  if (fs.existsSync(start) && fs.statSync(start).isFile()) {
    if (!predicate(start)) throw new Error(`${label} has an unexpected name: ${start}`);
    return requireRegularFile(start, label);
  }
  const matches = [];
  walk(start, matches, predicate);
  if (matches.length !== 1) {
    throw new Error(
      `Expected exactly one ${label} under ${start}; found ${matches.length}`,
    );
  }
  return requireRegularFile(matches[0], label);
}

function walk(directory, matches, predicate) {
  if (!fs.existsSync(directory) || !fs.statSync(directory).isDirectory()) return;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) walk(absolute, matches, predicate);
    else if (entry.isFile() && predicate(absolute)) matches.push(absolute);
  }
}

function copyArtifact(source, destination, mode) {
  fs.copyFileSync(source, destination);
  fs.chmodSync(destination, mode);
}

function copySignatureIfPresent(source, destination) {
  const signature = `${source}.sig`;
  if (!fs.existsSync(signature)) return;
  copyArtifact(requireRegularFile(signature, "updater signature"), `${destination}.sig`, 0o644);
}
