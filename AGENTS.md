# CentralD agent context

# Critical Information - Do not modify

- NEVER write unit tests after you write code.
- Highly prefer E2E tests as the sole testing mechanism. Use them to verify complex features work. At the end of E2E tests, produce a verifiable and repeatable artifact.
- If you must test a system in isolation, FIRST write all the ways it could fail, THEN write the code.
- Code comments may be included within edits, however they must remain concise. Long sentences or paragraphs are discouraged.

## Important

This file is the durable briefing for later agents. After any code or docs
change that a future agent needs in order to work correctly, update this file
in the same change. Prefer concrete paths, command names, env vars, and
fail-closed rules over slogans.

`AGENTS.md` is listed in `.prettierignore`. Wrap prose near 80 columns by hand.
Do not run Prettier on this file.

Canonical operator docs are `docs/*.md` and root `SECURITY.md`. This file does
not replace them; it tells agents how the tree is allowed to change.

All project code is GPL-3.0-or-later.

## What CentralD is

Easy, secure remote management for home labs: see the health of every machine
and run commands, terminals, updates, and reboots on them from one web app.

- **Server** (`centrald-server`): one static Linux binary. HTTPS on one port
  (default `0.0.0.0:7443`), SQLite storage, embedded React web app. Runs as
  the unprivileged `centrald` user. Never executes commands itself.
- **Agent** (`centrald-agent`): one static binary per machine, runs as root
  (Linux) or LocalSystem (Windows). Connects outbound to the server over
  WebSocket with a pinned CA. Never listens.
- **Web app** (`web/`): the only admin UI. A desktop app may come later; do
  not reintroduce Tauri without the user asking.
- Targets: Debian/Ubuntu first, then Fedora, Arch (low priority), Windows
  10/11. Linux x86_64 and ARM64 (musl), Windows x86_64 and ARM64.
- Network scope: LAN or VPN. Never present it as Internet-safe.

This is a clean rewrite at `0.1.0`. The previous Tauri Admin, PostgreSQL,
client/broker split, invitations (`centrald-invite1`), release channels, CDN
mirror, and Tauri updater were removed on purpose. Do not restore them or add
migration code for them.

## Hard do-nots

- Do not add a public CLI argument that places a join code or any bearer
  token in process arguments. Agents read join codes from a prompt,
  `--key-stdin`, `--key-file`, or the `CENTRALD_JOIN` env var (installer only).
- Do not add nested CLI command trees. Keep public commands flat.
- Do not add trust-on-first-use. Agents pin the CA fingerprint from the join
  code; install commands pin the server's public key (curl
  `--pinnedpubkey` / PowerShell certificate hash callback).
- Do not add plaintext listeners. Plain HTTP on the TLS port only gets a 301.
- Do not add HSTS: browsers would lock users out of the self-signed CA.
- Do not make the server run as root or spawn processes for operators.
- Do not let the server override monitor-only. The agent refuses
  `exec_start` and `term_open` locally when its own config says
  `monitor_only`.
- Do not run agent actions through a shell. Actions (updates, reboot) use
  fixed executable paths and fixed argument lists. Only the explicit
  "command" feature uses `/bin/sh -c` or PowerShell.
- Do not store terminal bytes. Command output is stored, capped at 1 MiB per
  device per run.
- Do not write or execute a downloaded agent update before its Minisign
  signature, target, and version are verified (`update.rs`). Never set
  `CENTRALD_UPDATE_PUBKEY` for a release build; never commit a secret key.
- Do not let commands inherit the agent's environment: `exec.rs` and
  `terminal.rs` call `env_clear()` and use `process::clean_environment()`.
- Do not log the agent's bearer credential. `main.rs` drops debug/trace from
  tungstenite, hyper, h2, and http (`quiet_library`); keep that filter.
- Do not put secrets in tracked files, Docker build args, command-line
  values, or generated packages.
- Do not hardcode `C:\ProgramData`. The agent reads `%ProgramData%` and fails
  if it is unset (workspace forbids `unsafe`, so no Known Folder FFI).
- Do not edit `site/src/content/docs/` (gitignored, generated). Edit `docs/`
  and `SECURITY.md`.
- Do not call `cargo update` directly. Use `npm run deps:rust:update`
  (72-hour minimum crate age; `-p <crate>` for a partial update). CI runs
  `scripts/check-cargo-update-policy.mjs --base <commit>`, which diffs
  `Cargo.lock` against the base and fails on any new crate version younger
  than 72 h or any new git source, whatever produced it.
- Do not pin a specific npm version. `.npmrc` keeps `min-release-age=3`.

## Workspace layout

```text
Cargo.toml               Rust workspace; lints: unsafe forbid, clippy pedantic
package.json             web build, lint, tests, e2e, packaging, site
crates/centrald-proto    wire messages, join codes, TLS pin verifier, limits
crates/centrald-server   axum server, SQLite, sessions, hub, installers
crates/centrald-agent    status, exec, PTY terminal, enroll, service, update
web/                     React 19 + Vite 7 + xterm; built to web/dist
tests/e2e/               Playwright suite against the real binaries
packaging/               systemd units, sysusers, package hooks, Arch files
scripts/                 package.mjs, package-smoke.sh, cargo policy tools
site/                    Astro docs site (syncs docs/*.md + SECURITY.md)
docs/                    canonical operator documentation
```

Node: `.node-version` (`26.13.0`); `engines.node` is
`^24.22.1 || >=26.13.0`; `.npmrc` sets `engine-strict=true` (old npm
ignores `min-release-age`). Rust edition 2024, resolver 3,
`rust-version = "1.89"` (CI `msrv` job checks with exactly that toolchain;
raise it when a dependency needs more), `rust-toolchain.toml` pins
`stable`. Workspace lints: `unsafe_code = "forbid"`, clippy `all` +
`pedantic` warn, `unwrap_used` / `expect_used` deny.

`[profile.dev]` uses `debug = "line-tables-only"` and no debug info for
dependencies. Keep it: the agent self-update download is capped at 64 MiB
and a full-debug agent (~107 MB) breaks the E2E update test.

## Server map (`crates/centrald-server/src/`)

- `main.rs` — CLI: `run` (default), `status`, `reset-password <user>
  [--password-stdin]`. Global `--config`. `run` order is fixed: check data
  dir (never created; missing = refuse) -> exclusive flock on
  `<data_dir>/lock` (refuse "already running") -> bind -> TLS -> DB ->
  `Hub::recover_on_start`. Data dir empty (ignoring `lock`) = first run;
  anything else must already hold `centrald.db`, `tls/ca.{crt,key}`,
  `tls/server.key` or the server refuses. `status` opens the DB read-only,
  prints `Server: running|not running` (brief shared flock), and ignores
  EPIPE (`status | head` must exit 0).
- `config.rs` — `/etc/centrald/server.toml` (optional) plus env overrides:
  `CENTRALD_LISTEN`, `CENTRALD_DATA_DIR`, `CENTRALD_HOSTNAMES`,
  `CENTRALD_TLS_CERT` + `CENTRALD_TLS_KEY` (together),
  `CENTRALD_AGENT_DIR`. Port 0 is refused.
- `net.rs` — own accept/serve loop (not `axum::serve`): sniffs first byte,
  301s plain HTTP, bounded handshakes, ALPN picks hyper http2 (extended
  CONNECT on, pings) or http1 (`header_read_timeout` 20 s, upgrades). Caps
  900 connections total and 128 per source (IPv6 /64); slots live with the
  socket, also after a WebSocket upgrade. Idle (no request in flight) 120 s
  -> graceful close. Inserts `ConnectInfo<ClientAddr>` per request.
- `tls.rs` — private CA (P-256, 20 years) and 397-day leaf, renewed 30 days
  before expiry or when addresses change, same key. Agents use SNI
  `centrald-server.internal` and always get the internal chain. Creates the
  CA and server key only when `fresh`; checks `ca.key`/`ca.crt`,
  `server.key`/`server.crt` and custom key/cert pairs with `keys_match`.
  `allows_host` is the Host allow-list (any IP literal, `localhost`, agent
  name, hostname and `hostname.local`, `CENTRALD_HOSTNAMES`, names the
  custom cert covers via `rustls-webpki`).
- `db.rs` — SQLite WAL, `foreign_keys=ON`, strict tables, forward-only
  in-code migrations. Blocking work off async workers. `OpenMode`: `Create`
  (first run only), `Server` (must exist, non-empty, schema >= 1,
  `quick_check`, migrates), `Tool`/`ReadOnly` (CLI; never create or
  migrate, refuse a schema mismatch).
- `auth.rs`, `session.rs` — Argon2id (max 2 concurrent), `__Host-centrald`
  cookie (`Secure`, `HttpOnly`, `SameSite=Strict`), Origin check on every
  write and WebSocket upgrade, TOTP with replay guard, rate limiter (5 free
  failures, then 30 s doubling to 15 min). Use `RateLimiter::attempt` (check
  and count in one step) BEFORE hashing, then `record_success`; keys
  `kind:<ip>` group IPv6 by /64; map capped at 4096 with eviction.
  Lockouts are in memory by design. Session cookie: every
  `__Host-centrald` value is tried (`session_cookies`).
- `state.rs` — `AppState::hashing` runs Argon2 on a spawned task that holds
  its permits until the hash ends (2 running, 32 running+queued, else 503).
  Login (`api/account.rs`) runs on a spawned task so audit + limiter are
  recorded even if the client hangs up. TOTP enable/disable need the
  current password.
- `hub.rs` — in-memory live state: agents, runs, terminals, browser event
  broadcast.
- `api/` — `account`, `devices`, `join`, `runs`, `agent`, `misc`. WebSocket
  routes are registered with `.get(...).connect(...)`; Chromium uses HTTP/2
  extended CONNECT, so dropping `.connect()` gives 405. `api/mod.rs`
  `host_guard` answers 421 to unknown Host/`:authority` (exempt:
  `/api/agent/`, `/download/agent/`); `json_errors` turns non-JSON API
  errors (axum rejections, 405) into `{ "error" }`.
- `downloads.rs` — `/install.sh`, `/install.ps1`, `/download/agent/{os}/
  {arch}` with `.sha256` and `.minisig` (the release signature, read from
  `<agent>.minisig` next to the build; 404 if absent). Builds the copy-paste
  install commands from the address the operator typed (URL single-quoted
  for IPv6/zsh). Downloads stream from disk (`stream_file`); never buffer
  whole binaries. The Windows command needs Windows PowerShell 5.1 (its
  script-block pin callback has no runspace on PowerShell 7, so the command
  throws a clear message there first). `assets/install.ps1` reads the
  machine architecture from the registry, uses `%ProgramW6432%`, and resets
  the pin callback and TLS setting in `finally`.
- `ui.rs` — rust-embed of `web/dist`. `CENTRALD_REQUIRE_UI=1` makes the build
  fail if the UI is missing (used by `npm run e2e` and release builds).
  Fallback: `/api*` -> 404 JSON, non-GET/HEAD -> 405, else the SPA.

## Agent map (`crates/centrald-agent/src/`)

Public commands: `enroll [--key-stdin|--key-file] [--server] [--monitor-only]`,
`status`, `leave`, `update [--allow-downgrade]`. Hidden: `run` (the service),
`service` (Windows SCM entry). All but `status` require root/Administrator.

- `config.rs` — `/etc/centrald/agent.toml` (root 0600; the directory is
  set to 0755 because the server, user `centrald`, reads `server.toml` from
  it; never 0700) or
  `%ProgramData%\CentralD\agent.toml` (Administrators/SYSTEM ACL).
  `deny_unknown_fields`. `CENTRALD_AGENT_CONFIG` overrides (tests).
- `connection.rs` — `wss://…/api/agent/connect`; TCP + TLS + upgrade +
  `Hello`/`Welcome` share one 30 s timeout. `Hello.runningExecs` lists live
  exec ids; the server (`api/agent.rs` `cancel_forgotten`) cancels ones it
  does not track. Status every 15 s, 90 s silence ends it, outgoing queue 256
  with a 60 s send deadline, jittered 1–60 s backoff, 10 min backoff after a
  rejected credential. On SIGTERM: close terminals, `Executor::shutdown`.
- `exec.rs`, `process.rs` — commands in their own process group, env cleared.
  A run ends only when its group is gone: timeout/cancel SIGTERM the group,
  SIGKILL 10 s later regardless of the direct child; after the main process
  exits, 2 s of output drain, then leftovers get SIGTERM, 2 s, SIGKILL.
  Agent shutdown kills shell-command groups (3 s grace) but leaves package
  actions running (`kill_on_drop(false)`) so dpkg is not cut mid-upgrade.
  `setsid` escapes the group (documented limit). Windows: `taskkill /T`,
  then `/T /F`, direct child only. Refusals, caps (8 execs, 4 terminals),
  duplicate ids, and id validity (`wire::valid_id`, 64 bytes) are checked
  before spawning; refusals use `try_send`.
- `terminal.rs` — portable-pty (openpty / ConPTY).
- `status.rs` — sysinfo plus Linux failed units, reboot-required, pending
  updates (apt-get -s, dnf check-update, pacman -Qu) every 6 h. Skips
  read-only disks.
- `service.rs`, `winservice.rs` — systemd unit / Windows service
  `CentralDAgent`. `CENTRALD_SKIP_SERVICE=1` skips service install/restart
  (tests).
- `update.rs` — downloads the build and `.minisig` over the pinned
  connection, verifies with `minisign-verify` against the key in
  `packaging/minisign.json` (or build-time `CENTRALD_UPDATE_PUBKEY`), checks
  the trusted comment `centrald-agent <version> <os>-<arch>` (own target,
  newer semver unless `--allow-downgrade`), then writes and renames. Never
  executes the download. Refuses package-managed `/usr/bin` installs. Linux
  restart via `systemd-run --on-active=5`.

## Join codes

`cdj1.` + base64url of: CA SHA-256 fingerprint, 20-byte secret, up to four
server addresses, checksum (`crates/centrald-proto/src/join.rs`). Single-use,
expire within 7 days, revocable, stored hashed. Enrollment returns a device ID
and 32-byte token; the server stores only its SHA-256. Agents send
`Authorization: Bearer <device>.<token>`.

## Default paths

| Purpose            | Path                                         |
| ------------------ | -------------------------------------------- |
| Server config      | `/etc/centrald/server.toml` (optional)       |
| Server data        | `/var/lib/centrald` (user `centrald`, 0700)  |
| Database           | `/var/lib/centrald/centrald.db`              |
| TLS + CA key       | `/var/lib/centrald/tls/`                     |
| Bundled agents     | `/usr/share/centrald/agents/`                |
| Agent config       | `/etc/centrald/agent.toml`                   |
| Agent config (Win) | `%ProgramData%\CentralD\agent.toml`          |

## Packaging and release

- `npm run package` (`scripts/package.mjs`) packages whatever exists in
  `target/<arch>-unknown-linux-musl/release` and
  `target/<arch>-pc-windows-{msvc,gnu,gnullvm}/release` into `dist/`: debs,
  rpms, tarballs, `PKGBUILD` + `centrald-{server,agent}.install`, Windows
  exes, `SHA256SUMS`. `dist/` is flat: every file name is the release asset
  name and is listed in `SHA256SUMS` (names limited to `[A-Za-z0-9._+-]`, so
  GitHub never renames one). `--require-all` insists on every platform and
  `.minisig`; `--no-rpm` skips rpm. Fails if `package.json` and `Cargo.toml`
  versions differ or no `SOURCE_DATE_EPOCH`/git history. Prerelease `X-rc.N`:
  deb/rpm version `X~rc.N`, pacman `Xrc.N`, file names keep `X-rc.N`.
  Reproducibility: `SOURCE_DATE_EPOCH`, `process.umask(0o022)`, rpm
  `_buildhost centrald`, rust-embed `deterministic-timestamps`; same rustc
  and `CARGO_HOME` path still needed. No `BuildArch` in the spec (`--target`
  sets it; `BuildArch: aarch64` fails on the x86_64 runner).
- `scripts/third-party.mjs` writes `THIRD-PARTY-NOTICES.txt` (all crates in
  `Cargo.lock` plus non-dev npm packages, licence files from the cargo
  registry and `node_modules`) into every package; needs `npm ci` first.
- The deb `Maintainer` is a placeholder
  (`CentralD contributors <noreply@centrald.dev>`) until the owner picks one.
- Server packages ship every agent build; the install commands download from
  the server, never from GitHub.
- Hooks: `packaging/server-maint` and `packaging/agent-maint` (POSIX sh,
  `configure <install|upgrade>` / `remove` / `disable`), wrapped by
  `packaging/debian/*` and the rpm scriptlets; Arch has its own
  `packaging/arch/*.install` (not the maint scripts). Rules: a systemctl
  failure never fails the transaction (warn instead); `enable` only on first
  install; upgrade restarts only an enabled unit (`try-restart` otherwise);
  deb `remove` only stops (the enable link survives so remove + reinstall
  starts again), deb purge / rpm erase drop the link. Server configure
  repairs a `/etc/centrald` the `centrald` user cannot enter. Agent
  configure takes over an install-command agent (`/usr/local/bin` binary
  and `/etc/systemd/system` unit); agent purge keeps `agent.toml` while
  `/usr/local/bin/centrald-agent` exists. Server hook prints
  `centrald-server status` and firewall hints (never changes the firewall).
- `.github/workflows/release.yml` (tag `v*`, or `workflow_dispatch` for a
  dry run with a throwaway key that uploads `release-dry-run` and publishes
  nothing). A first `check` job compares tag, `package.json`, `Cargo.toml`,
  `Cargo.lock`. Then musl Linux on x86_64/ARM64,
  MSVC Windows on x86_64/ARM64, then signs each agent build (trusted comment
  `centrald-agent <version> <os>-<arch>`, `<bin>.minisig`), packages, signs
  `SHA256SUMS` with Minisign (secrets `MINISIGN_SECRET_KEY_B64`,
  `MINISIGN_PASSWORD`) and opens a draft release. Public key in
  `packaging/minisign.json`. `package.mjs` ships each `.minisig` next to its
  agent (0644; PKGBUILD installs them 0644 too); `--require-all` fails on an
  unsigned agent. The upload is exactly the files in `SHA256SUMS` plus
  `SHA256SUMS{,.minisig}`; a re-run updates an existing draft.
- `.github/workflows/audit.yml`: `cargo audit --deny unsound --deny yanked`
  and `npm audit` (root + site) on every change and weekly.
- Actions in workflows are pinned by commit SHA.

## Testing

E2E is the main gate (`npm run e2e`): builds the web app and debug binaries,
starts the real server, enrolls real agents, drives Chromium, and probes
security with curl. Two Playwright projects: `flow` (`flow.spec.ts`) and
`security` (`security.spec.ts`, depends on `flow`), one worker, serial.

- Each spec file starts with the failure modes it covers. Add a failure mode
  there first, then the test, then the code.
- Output: `e2e-report/REPORT.md`, `report.json` (commit, dirty flag,
  platform, binary SHA-256s, per-test steps), screenshots, logs,
  `SHA256SUMS`. CI uploads it as the `e2e-report` artifact.
- `CENTRALD_E2E_INSTALL=1` as root runs the real `curl … | sh` install
  one-liner; otherwise the test enrolls with `--key-stdin`.
- Update signing: `tests/e2e/minisign.ts` makes a throwaway key in
  `target/e2e-update-key.json`; `npm run e2e` builds with
  `CENTRALD_UPDATE_PUBKEY=$(node tests/e2e/minisign.ts)`. Global setup
  refuses an agent binary without that key and signs the served agent
  (`signBuild` in `harness.ts`). A plain `cargo build` drops the key, so run
  E2E through `npm run e2e`.
- `startServer(dir)` in `harness.ts` (re)starts the server; the security
  spec kills it with SIGKILL and restarts it to test reconciliation. Every
  pid goes to `<run dir>/pids` for teardown.
- `CENTRALD_E2E_PORT` (default 17443) and `CENTRALD_E2E_BIN_DIR` (default
  `target/debug`) override the harness.
- `scripts/package-smoke.sh` (CI) installs the debs on a systemd runner and
  walks setup, install command on the server host, a command run, a server
  restart, agent package takeover, `/etc/centrald` repair, remove/reinstall,
  disabled-across-upgrade, and purge. Its header lists the failure modes;
  it needs systemd and sudo, so it only runs in CI.
- The only node unit tests are the inherited `cargo-safe-update` tests
  (`npm test`). Do not add more unit tests after writing code.

## Quality gates

```text
npm run format:check
npm run lint          # ESLint + cargo clippy -D warnings
npm run typecheck
npm test
npm run test:rust
npm run e2e
npm run site:install   # once; the site has its own lock file
npm run site:check && npm run site:build
```

Also run `cargo clippy -p centrald-agent --target x86_64-pc-windows-gnu
--locked -- -D warnings` when touching agent code (needs mingw). If a gate
cannot run locally, say so and leave it to CI; never claim it passed.

CI (`.github/workflows/ci.yml`): `checks` (also the Cargo lock-age check
and the site gates), `msrv`, `windows`, `e2e`, `package`; plus
`audit.yml`.

## Docs map

`docs/QUICKSTART.md` (first run), `docs/GUIDE.md` (user guide),
`docs/OPERATIONS.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`,
`docs/RELEASES.md`, `docs/IMPLEMENTATION_STATUS.md` (what works, what is
planned). Screenshots in `docs/images/` come from `e2e-report/screenshots/`.
`site/scripts/sync-docs.mjs` maps files to slugs and rewrites `FILE.md` links
to `/docs/<slug>`; add new docs there.

When changing first-run or UI labels, update QUICKSTART, GUIDE, README, and
the E2E selectors together. Prettier uses `proseWrap: always` on markdown.

## Agent pitfalls seen in this tree

- WebSocket routes need `.connect()` (HTTP/2 extended CONNECT).
- The install command must use the address the operator typed; the join
  code may list LAN addresses first, but a loopback fallback address in the
  install command breaks remote machines.
- Async loaders in the web app set state after `await`; the
  `react-hooks/set-state-in-effect` rule is off for that reason.
- Use `nowSeconds()` from `web/src/format.ts`, not `Date.now()` in render.
- Match arms with block bodies need trailing semicolons for clippy pedantic.
- Tracing uses ANSI only when stdout is a terminal; keep logs grep-able.
- The server never creates its data directory. The E2E global setup and
  `packaging/server-maint` (no-systemd branch) create it; systemd's
  `StateDirectory=` does on packaged installs. Scratch servers in tests
  must `mkdir` their data dir first.
- E2E tests that lock out sign-in use their own source address
  (`curl --interface 127.0.0.N`); the final throttle test needs
  `127.0.0.1` and user `admin` unlocked.
