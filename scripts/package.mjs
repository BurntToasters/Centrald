#!/usr/bin/env node
// Builds release packages from binaries already compiled into target/:
//   target/<arch>-unknown-linux-musl/release/centrald-{server,agent}
//   target/<arch>-pc-windows-{msvc,gnu}/release/centrald-agent.exe
// Writes dist/: .deb, .rpm, Linux tarballs, Windows agents, Arch PKGBUILD,
// SHA256SUMS. Each agent's detached signature (<binary>.minisig, written by
// the release workflow) ships next to it so agents can verify updates.
// dist/ is flat: every file is uploaded under the name SHA256SUMS lists.
// Fixed argument lists only; no shells.
//
// Usage: node scripts/package.mjs [--require-all] [--no-rpm]
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { gzipSync } from "node:zlib";
import path from "node:path";
import { thirdPartyNotices } from "./third-party.mjs";

// Modes in the packages must not depend on the caller's umask.
process.umask(0o022);

const ROOT = path.resolve(import.meta.dirname, "..");
const DIST = path.join(ROOT, "dist");
const PACKAGING = path.join(ROOT, "packaging");
const VERSION = JSON.parse(
  readFileSync(path.join(ROOT, "package.json"), "utf8"),
).version;
const CARGO_VERSION = readFileSync(path.join(ROOT, "Cargo.toml"), "utf8").match(
  /^\[workspace\.package\][^[]*?^version = "([^"]+)"/m,
)?.[1];
// "0.2.0-rc.1" must sort before "0.2.0": dpkg and rpm use "~", pacman
// a letter straight after the digits. File names keep the plain version.
const DEB_VERSION = VERSION.replace("-", "~");
const RPM_VERSION = DEB_VERSION;
const PACMAN_VERSION = VERSION.replace("-", "").replace(/-/g, ".");
const REPO = "https://github.com/BurntToasters/centrald";
const MAINTAINER = "CentralD contributors <noreply@centrald.dev>";
const ARCHES = ["x86_64", "aarch64"];
const DEB_ARCH = { x86_64: "amd64", aarch64: "arm64" };

const args = new Set(process.argv.slice(2));
const requireAll = args.has("--require-all");
const skipRpm = args.has("--no-rpm");

function run(command, argv, options = {}) {
  execFileSync(command, argv, { stdio: "inherit", ...options });
}

function sha256(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function sourceDateEpoch() {
  if (process.env.SOURCE_DATE_EPOCH) return process.env.SOURCE_DATE_EPOCH;
  try {
    return execFileSync("git", ["log", "-1", "--format=%ct"], {
      cwd: ROOT,
      encoding: "utf8",
    }).trim();
  } catch {
    throw new Error(
      "no git history; set SOURCE_DATE_EPOCH to the release's commit time",
    );
  }
}
const EPOCH = sourceDateEpoch();
const ENV = { ...process.env, SOURCE_DATE_EPOCH: EPOCH };

function install(source, target, mode) {
  mkdirSync(path.dirname(target), { recursive: true });
  copyFileSync(source, target);
  chmodSync(target, mode);
}

function linuxBinary(arch, name) {
  const file = path.join(
    ROOT,
    "target",
    `${arch}-unknown-linux-musl`,
    "release",
    name,
  );
  return existsSync(file) ? file : null;
}

function windowsAgent(arch) {
  for (const abi of ["msvc", "gnu", "gnullvm"]) {
    const file = path.join(
      ROOT,
      "target",
      `${arch}-pc-windows-${abi}`,
      "release",
      "centrald-agent.exe",
    );
    if (existsSync(file)) return file;
  }
  return null;
}

/** Every agent build the server will offer, keyed by its served name. */
function agentBuilds() {
  const builds = {};
  for (const arch of ARCHES) {
    const linux = linuxBinary(arch, "centrald-agent");
    if (linux) builds[`centrald-agent-linux-${arch}`] = linux;
    const windows = windowsAgent(arch);
    if (windows) builds[`centrald-agent-windows-${arch}.exe`] = windows;
  }
  return builds;
}

/** Copies an agent build and its signature, if any, into `dir`. */
function installAgent(file, dir, name) {
  install(file, path.join(dir, name), 0o755);
  if (existsSync(`${file}.minisig`)) {
    install(`${file}.minisig`, path.join(dir, `${name}.minisig`), 0o644);
  }
}

/** A temporary directory removed after `body` returns or throws. */
function withTemp(prefix, body) {
  const dir = mkdtempSync(path.join(tmpdir(), prefix));
  try {
    return body(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

let notices = null;
function installDocs(root, name) {
  const doc = path.join(root, "usr/share/doc", name);
  install(path.join(ROOT, "LICENSE"), path.join(doc, "copyright"), 0o644);
  install(notices, path.join(doc, "THIRD-PARTY-NOTICES.txt"), 0o644);
}

/** Lays out the files of one package under `root` (a filesystem image). */
function stageServer(root, agents, serverBin) {
  install(serverBin, path.join(root, "usr/bin/centrald-server"), 0o755);
  install(
    path.join(PACKAGING, "systemd/centrald-server.service"),
    path.join(root, "usr/lib/systemd/system/centrald-server.service"),
    0o644,
  );
  install(
    path.join(PACKAGING, "systemd/centrald.sysusers"),
    path.join(root, "usr/lib/sysusers.d/centrald.conf"),
    0o644,
  );
  install(
    path.join(PACKAGING, "server-maint"),
    path.join(root, "usr/lib/centrald/server-maint"),
    0o755,
  );
  install(
    path.join(PACKAGING, "server.toml"),
    path.join(root, "etc/centrald/server.toml"),
    0o644,
  );
  for (const [name, file] of Object.entries(agents)) {
    installAgent(file, path.join(root, "usr/share/centrald/agents"), name);
  }
  installDocs(root, "centrald-server");
}

function stageAgent(root, agentBin) {
  install(agentBin, path.join(root, "usr/bin/centrald-agent"), 0o755);
  install(
    path.join(PACKAGING, "systemd/centrald-agent.service"),
    path.join(root, "usr/lib/systemd/system/centrald-agent.service"),
    0o644,
  );
  install(
    path.join(PACKAGING, "agent-maint"),
    path.join(root, "usr/lib/centrald/agent-maint"),
    0o755,
  );
  installDocs(root, "centrald-agent");
}

const DESCRIPTIONS = {
  "centrald-server":
    "Remote management for home labs (server)\n" +
    " Web app and API for checking the health of your machines, running\n" +
    " commands, and opening terminals on them.",
  "centrald-agent":
    "Remote management for home labs (agent)\n" +
    " Connects this machine to a CentralD server so it can report its health\n" +
    " and, unless enrolled as monitor-only, run commands from operators.",
};

function buildDeb(name, arch, stage) {
  withTemp(`${name}-deb-`, (root) => buildDebIn(root, name, arch, stage));
}

function buildDebIn(root, name, arch, stage) {
  chmodSync(root, 0o755);
  stage(root);
  const debian = path.join(root, "DEBIAN");
  mkdirSync(debian);
  const control = [
    `Package: ${name}`,
    `Version: ${DEB_VERSION}`,
    `Architecture: ${DEB_ARCH[arch]}`,
    `Maintainer: ${MAINTAINER}`,
    "Section: admin",
    "Priority: optional",
    `Homepage: ${REPO}`,
    `Description: ${DESCRIPTIONS[name]}`,
    "",
  ];
  writeFileSync(path.join(debian, "control"), control.join("\n"));
  if (name === "centrald-server") {
    writeFileSync(
      path.join(debian, "conffiles"),
      "/etc/centrald/server.toml\n",
    );
  }
  const scripts = path.join(PACKAGING, "debian", name.replace("centrald-", ""));
  for (const script of readdirSync(scripts)) {
    install(path.join(scripts, script), path.join(debian, script), 0o755);
  }
  const output = path.join(DIST, `${name}_${VERSION}_${DEB_ARCH[arch]}.deb`);
  run("dpkg-deb", ["--root-owner-group", "-Zxz", "--build", root, output], {
    env: ENV,
  });
}

function listFiles(root, dir = root) {
  return readdirSync(dir).flatMap((entry) => {
    const full = path.join(dir, entry);
    return statSync(full).isDirectory()
      ? listFiles(root, full)
      : [`/${path.relative(root, full)}`];
  });
}

function listDirs(root, dir = root) {
  return readdirSync(dir).flatMap((entry) => {
    const full = path.join(dir, entry);
    return statSync(full).isDirectory()
      ? [`/${path.relative(root, full)}`, ...listDirs(root, full)]
      : [];
  });
}

function buildRpm(name, arch, stage) {
  withTemp(`${name}-rpm-`, (top) => buildRpmIn(top, name, arch, stage));
}

function buildRpmIn(top, name, arch, stage) {
  const image = path.join(top, "image");
  stage(image);
  const maint = name === "centrald-server" ? "server-maint" : "agent-maint";
  // Own the package's directories so an erase removes them.
  const dirs = listDirs(image)
    .filter((dir) => dir.includes("centrald"))
    .sort()
    .map((dir) => `%dir ${dir}`);
  const files = listFiles(image)
    .sort()
    .map((file) =>
      file === "/etc/centrald/server.toml"
        ? `%config(noreplace) ${file}`
        : file.startsWith("/usr/share/doc/")
          ? `%license ${file}`
          : file,
    );
  const [summary, ...body] = DESCRIPTIONS[name].split("\n");
  // No BuildArch: `--target` sets it, and BuildArch for a foreign
  // architecture makes rpmbuild refuse to build on this host.
  const spec = `
Name: ${name}
Version: ${RPM_VERSION}
Release: 1
Summary: ${summary}
License: GPL-3.0-or-later
URL: ${REPO}
AutoReqProv: no
%global debug_package %{nil}
%global __strip /bin/true
%global _build_id_links none

%description
${body.map((line) => line.trim()).join("\n")}

%install
cp -a ${image}/. %{buildroot}/

%post
if [ "$1" -eq 1 ]; then /usr/lib/centrald/${maint} configure install; else /usr/lib/centrald/${maint} configure upgrade; fi

%preun
if [ "$1" -eq 0 ]; then /usr/lib/centrald/${maint} remove; /usr/lib/centrald/${maint} disable; fi

%postun
if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi

%files
${[...dirs, ...files].join("\n")}
`;
  const specFile = path.join(top, `${name}.spec`);
  writeFileSync(specFile, spec);
  const rpmdir = path.join(top, "rpms");
  const result = spawnSync(
    "rpmbuild",
    [
      "-bb",
      "--target",
      arch,
      "--define",
      `_topdir ${top}`,
      "--define",
      `_rpmdir ${rpmdir}`,
      "--define",
      "_build_name_fmt %%{NAME}.rpm",
      "--define",
      "_buildhost centrald",
      "--define",
      "_binary_payload w19.zstdio",
      "--define",
      "use_source_date_epoch_as_buildtime 1",
      "--define",
      "clamp_mtime_to_source_date_epoch 1",
      specFile,
    ],
    { env: ENV, encoding: "utf8" },
  );
  if (result.status !== 0) {
    process.stderr.write(result.stdout + result.stderr);
    throw new Error(`rpmbuild failed for ${name} ${arch}`);
  }
  // "~" in a file name is renamed by GitHub; the name keeps the plain version.
  copyFileSync(
    path.join(rpmdir, `${name}.rpm`),
    path.join(DIST, `${name}-${VERSION}-1.${arch}.rpm`),
  );
}

const TARBALL_README = (arch) => `CentralD ${VERSION} for Linux ${arch}

Static binaries for any Linux distribution with systemd. Packages for
Debian/Ubuntu (.deb), Fedora (.rpm), and Arch (PKGBUILD) are easier and
handle upgrades; see https://centrald.dev/docs/quickstart

Agents: agents/ holds every agent build the server offers. To manage a
machine (this one included), use the install command from the web app; it
puts the agent in /usr/local/bin, where it can update itself.

Install the server (as root, from this directory):
  install -m 0755 centrald-server /usr/bin/
  install -d /usr/share/centrald/agents
  install -m 0755 agents/centrald-agent-* /usr/share/centrald/agents/
  chmod 0644 /usr/share/centrald/agents/*.minisig
  install -m 0644 centrald-server.service /usr/lib/systemd/system/
  install -m 0644 centrald.sysusers /usr/lib/sysusers.d/centrald.conf
  install -d -m 0755 /etc/centrald
  [ -e /etc/centrald/server.toml ] || install -m 0644 server.toml /etc/centrald/
  systemd-sysusers
  systemctl daemon-reload
  systemctl enable --now centrald-server
  sleep 10; centrald-server status

Upgrade: repeat the install lines except server.toml, then
  systemctl daemon-reload && systemctl restart centrald-server

Remove:
  systemctl disable --now centrald-server
  rm -f /usr/bin/centrald-server /usr/lib/systemd/system/centrald-server.service
  rm -f /usr/lib/sysusers.d/centrald.conf
  rm -rf /usr/share/centrald
  rm -rf /var/lib/centrald /etc/centrald/server.toml   # deletes all data
`;

function buildTarball(arch, agents, serverBin) {
  return withTemp("centrald-tar-", (top) =>
    buildTarballIn(top, arch, agents, serverBin),
  );
}

function buildTarballIn(top, arch, agents, serverBin) {
  const name = `centrald-${VERSION}-linux-${arch}`;
  const root = path.join(top, name);
  install(serverBin, path.join(root, "centrald-server"), 0o755);
  for (const file of [
    "systemd/centrald-server.service",
    "systemd/centrald-agent.service",
    "systemd/centrald.sysusers",
    "server.toml",
  ]) {
    install(
      path.join(PACKAGING, file),
      path.join(root, path.basename(file)),
      0o644,
    );
  }
  for (const [agent, file] of Object.entries(agents)) {
    installAgent(file, path.join(root, "agents"), agent);
  }
  install(path.join(ROOT, "LICENSE"), path.join(root, "LICENSE"), 0o644);
  install(notices, path.join(root, "THIRD-PARTY-NOTICES.txt"), 0o644);
  writeFileSync(path.join(root, "README.txt"), TARBALL_README(arch));
  chmodSync(path.join(root, "README.txt"), 0o644);
  const tarFile = path.join(top, `${name}.tar`);
  run("tar", [
    "--sort=name",
    `--mtime=@${EPOCH}`,
    "--owner=0",
    "--group=0",
    "--numeric-owner",
    "-cf",
    tarFile,
    "-C",
    top,
    name,
  ]);
  // zlib writes no name or timestamp into the gzip header.
  const output = path.join(DIST, `${name}.tar.gz`);
  writeFileSync(output, gzipSync(readFileSync(tarFile), { level: 9 }));
  return output;
}

function buildPkgbuild(tarballs) {
  const arches = Object.keys(tarballs);
  const lines = [
    "# Maintainer: CentralD contributors",
    "# Keep this file, centrald-server.install, and centrald-agent.install",
    "# together; check all three against the signed SHA256SUMS first.",
    "pkgbase=centrald",
    "pkgname=(centrald-server centrald-agent)",
    `pkgver=${PACMAN_VERSION}`,
    "_version=" + VERSION,
    "pkgrel=1",
    'pkgdesc="Remote management for home labs"',
    `arch=(${arches.join(" ")})`,
    'url="https://centrald.dev"',
    "license=(GPL-3.0-or-later)",
    "options=(!strip !debug)",
    ...arches.flatMap((arch) => [
      `source_${arch}=("${REPO}/releases/download/v$_version/centrald-$_version-linux-${arch}.tar.gz")`,
      `sha256sums_${arch}=('${sha256(tarballs[arch])}')`,
    ]),
    "",
    "_docs() {",
    '  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$1/LICENSE"',
    '  install -Dm644 THIRD-PARTY-NOTICES.txt "$pkgdir/usr/share/licenses/$1/THIRD-PARTY-NOTICES.txt"',
    "}",
    "",
    "package_centrald-server() {",
    '  pkgdesc="Remote management for home labs (server)"',
    "  backup=(etc/centrald/server.toml)",
    "  install=centrald-server.install",
    '  cd "centrald-$_version-linux-$CARCH"',
    '  install -Dm755 centrald-server "$pkgdir/usr/bin/centrald-server"',
    '  install -Dm644 centrald-server.service "$pkgdir/usr/lib/systemd/system/centrald-server.service"',
    '  install -Dm644 centrald.sysusers "$pkgdir/usr/lib/sysusers.d/centrald.conf"',
    '  install -Dm644 server.toml "$pkgdir/etc/centrald/server.toml"',
    '  install -d "$pkgdir/usr/share/centrald/agents"',
    "  local file",
    "  for file in agents/*; do",
    '    case "$file" in',
    '    *.minisig) install -m644 "$file" "$pkgdir/usr/share/centrald/agents/" ;;',
    '    *) install -m755 "$file" "$pkgdir/usr/share/centrald/agents/" ;;',
    "    esac",
    "  done",
    "  _docs centrald-server",
    "}",
    "",
    "package_centrald-agent() {",
    '  pkgdesc="Remote management for home labs (agent)"',
    "  install=centrald-agent.install",
    '  cd "centrald-$_version-linux-$CARCH"',
    '  install -Dm755 "agents/centrald-agent-linux-$CARCH" "$pkgdir/usr/bin/centrald-agent"',
    '  install -Dm644 centrald-agent.service "$pkgdir/usr/lib/systemd/system/centrald-agent.service"',
    "  _docs centrald-agent",
    "}",
    "",
  ];
  writeFileSync(path.join(DIST, "PKGBUILD"), lines.join("\n"));
  for (const file of ["centrald-server.install", "centrald-agent.install"]) {
    install(path.join(PACKAGING, "arch", file), path.join(DIST, file), 0o644);
  }
}

function main() {
  if (CARGO_VERSION !== VERSION) {
    throw new Error(
      `package.json is ${VERSION} but Cargo.toml is ${CARGO_VERSION}; bump both`,
    );
  }
  rmSync(DIST, { recursive: true, force: true });
  mkdirSync(DIST, { recursive: true });
  const agents = agentBuilds();
  const expected = ARCHES.flatMap((arch) => [
    `centrald-agent-linux-${arch}`,
    `centrald-agent-windows-${arch}.exe`,
  ]);
  const missing = expected.filter((name) => !agents[name]);
  if (missing.length) {
    const message = `agent builds missing: ${missing.join(", ")}`;
    if (requireAll) throw new Error(message);
    console.warn(`warning: ${message}`);
  }
  const unsigned = Object.entries(agents)
    .filter(([, file]) => !existsSync(`${file}.minisig`))
    .map(([name]) => name);
  if (unsigned.length) {
    const message = `agent builds without a .minisig (agents will not update from them): ${unsigned.join(", ")}`;
    if (requireAll) throw new Error(message);
    console.warn(`warning: ${message}`);
  }
  const rpm = !skipRpm && spawnSync("rpmbuild", ["--version"]).status === 0;
  if (!skipRpm && !rpm) {
    if (requireAll) throw new Error("rpmbuild is required for --require-all");
    console.warn("warning: rpmbuild not found; skipping .rpm packages");
  }

  withTemp("centrald-notices-", (dir) => {
    notices = path.join(dir, "THIRD-PARTY-NOTICES.txt");
    writeFileSync(notices, thirdPartyNotices(ROOT));
    const tarballs = {};
    for (const arch of ARCHES) {
      const serverBin = linuxBinary(arch, "centrald-server");
      const agentBin = linuxBinary(arch, "centrald-agent");
      if (!serverBin || !agentBin) continue;
      console.log(`packaging linux ${arch}`);
      const server = (root) => stageServer(root, agents, serverBin);
      const agent = (root) => stageAgent(root, agentBin);
      buildDeb("centrald-server", arch, server);
      buildDeb("centrald-agent", arch, agent);
      if (rpm) {
        buildRpm("centrald-server", arch, server);
        buildRpm("centrald-agent", arch, agent);
      }
      tarballs[arch] = buildTarball(arch, agents, serverBin);
    }
    if (Object.keys(tarballs).length === 0) {
      throw new Error(
        "no Linux builds found; run cargo build --release --target <arch>-unknown-linux-musl first",
      );
    }
    buildPkgbuild(tarballs);
  });
  for (const arch of ARCHES) {
    const windows = windowsAgent(arch);
    if (windows) {
      install(
        windows,
        path.join(DIST, `centrald-agent-${VERSION}-windows-${arch}.exe`),
        0o644,
      );
    }
  }

  const files = readdirSync(DIST).sort();
  // GitHub renames assets with other characters, which would break
  // `sha256sum -c SHA256SUMS` on the downloaded files.
  const unsafe = files.filter((file) => !/^[A-Za-z0-9._+-]+$/.test(file));
  if (unsafe.length) {
    throw new Error(`release asset names GitHub would rename: ${unsafe}`);
  }
  writeFileSync(
    path.join(DIST, "SHA256SUMS"),
    files.map((file) => `${sha256(path.join(DIST, file))}  ${file}\n`).join(""),
  );
  console.log(files.map((file) => `dist/${file}`).join("\n"));
}

main();
