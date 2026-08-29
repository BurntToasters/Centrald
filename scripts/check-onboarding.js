import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const read = (name) => fs.readFileSync(path.join(root, name), "utf8");
const requireText = (source, text, label) => {
  if (!source.includes(text))
    throw new Error(`${label} is missing ${JSON.stringify(text)}`);
};

const readme = read("README.md");
const quickstart = read("docs/QUICKSTART.md");
const serverMain = read("crates/centrald-server/src/main.rs");
const manage = read("crates/centrald-server/src/manage.rs");
const app = read("apps/admin/src/App.tsx");
const terminalPanel = read("apps/admin/src/TerminalPanel.tsx");
const client = read("crates/centrald-client/src/daemon.rs");
const build = read("crates/centrald-common/build.rs");
const setupRecovery = read("crates/centrald-server/src/setup_recovery.rs");
const localPostgres = read("crates/centrald-server/src/local_postgres.rs");

for (const [source, text, label] of [
  [readme, "centrald-server initial-setup", "README"],
  [
    readme,
    "sudo apt install ./centrald-server_*.deb",
    "README server package install",
  ],
  [quickstart, "centrald-server config", "quick start"],
  [
    quickstart,
    "sudo apt install ./centrald-server_*.deb",
    "quick start server package install",
  ],
  [
    quickstart,
    "sudo apt install ./centrald-client_*.deb",
    "quick start client package install",
  ],
  [quickstart, "centrald-client enroll", "quick start"],
  [quickstart, "centrald-server channel", "quick start channel switch"],
  [quickstart, "centrald-client reenroll", "quick start reenroll"],
  [quickstart, "7443", "quick start enrollment port"],
  [quickstart, "timedatectl", "quick start NTP guidance"],
  [serverMain, "enable", "server setup service activation"],
  [serverMain, "CENTRALD_SKIP_SERVICE_START", "advanced service-start opt-out"],
  [manage, "Add a client (guided)", "guided server TUI"],
  [manage, "Server settings (advanced)", "advanced TUI grouping"],
  [app, "Getting started and common tasks", "Admin onboarding checklist"],
  [
    app,
    '<details className="getting-started" open>',
    "Admin onboarding checklist stays open",
  ],
  [
    app,
    "listener port must be between 1024 and 65535",
    "Admin listener port validation",
  ],
  [
    terminalPanel,
    "Save the validated credentials in this machine's OS vault",
    "Admin vault-backed credential saving contract",
  ],
  [
    app,
    "Change the release channel from centrald-server config",
    "Admin local-only update channel",
  ],
  [app, "TERMINAL_FEATURE_AVAILABLE = false", "Admin terminal nav stays gated"],
  [serverMain, "READY:", "setup success only when daemon is healthy"],
  [
    serverMain,
    "install_rustls_crypto_provider",
    "server installs rustls crypto provider before listeners",
  ],
  [
    serverMain,
    "INCOMPLETE:",
    "setup incomplete when service fails to become healthy",
  ],
  [
    read("crates/centrald-server/src/wizard.rs"),
    "fn suggested_public_host",
    "setup suggests this host's TLS name",
  ],
  [
    read("scripts/package-linux.js"),
    "CentralD server is installed. Next: sudo centrald-server initial-setup",
    "server package prints first-run command",
  ],
  [
    read("scripts/package-linux.js"),
    "CentralD client is installed. Next: sudo centrald-client enroll",
    "client package prints enroll command",
  ],
  [
    readme,
    "You do not need the local server console before the",
    "README first-run does not require config console",
  ],
  [
    app,
    "is optional after this first enroll.",
    "Admin empty state does not require config console",
  ],
  [
    app,
    "No enrolled clients reported. Create an invitation, then on the",
    "Admin devices empty state names enroll command",
  ],
  [
    client,
    'capabilities: vec!["heartbeat".into()]',
    "heartbeat-only client Hello capabilities",
  ],
  [
    read("crates/centrald-common/src/lib.rs"),
    "pub const PRIVILEGED_OPERATIONS_ENABLED: bool = false;",
    "privileged operations stay fail-closed",
  ],
  [
    read("crates/centrald-common/src/lib.rs"),
    "pub const TERMINAL_SESSIONS_ENABLED: bool = false;",
    "terminal sessions stay fail-closed",
  ],
  [build, "raw.githubusercontent.com", "Rust prerelease update origin"],
  [setupRecovery, "begin_setup", "PostgreSQL crash journal"],
  [setupRecovery, "boot_id", "setup recovery boot identity"],
  [
    localPostgres,
    "cleanup_managed_resources",
    "managed PostgreSQL retry cleanup",
  ],
  [
    read("crates/centrald-server/src/wizard.rs"),
    "fn recommended_local_database",
    "non-interactive Ubuntu setup defaults to recommended local PostgreSQL",
  ],
  [quickstart, "Rerun the same command", "interrupted setup recovery guidance"],
  [
    quickstart,
    "C:\\Program Files\\CentralD\\centrald-client.exe",
    "quick start Windows enroll uses the install path",
  ],
  [quickstart, "libfuse2t64", "quick start Admin AppImage FUSE dependency"],
  [
    read("deploy/systemd/centrald-client.service"),
    "Do not use\n# RuntimeDirectory=",
    "client unit does not own shared /run/centrald",
  ],
])
  requireText(source, text, label);

console.log("CentralD onboarding contract OK");
