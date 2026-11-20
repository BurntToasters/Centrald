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
- Do not put secrets in tracked files, Docker build args, command-line
  values, or generated packages.
- Do not hardcode `C:\ProgramData`. The agent reads `%ProgramData%` and fails
  if it is unset (workspace forbids `unsafe`, so no Known Folder FFI).
- Do not edit `site/src/content/docs/` (gitignored, generated). Edit `docs/`
  and `SECURITY.md`.
- Do not call `cargo update` directly. Use `npm run deps:rust:update`
  (72-hour minimum crate age). `npm run check:cargo-update-policy` enforces
  it.
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
`^24.22.1 || >=26.13.0`. Rust edition 2024, `rust-toolchain.toml` pins
`stable`. Workspace lints: `unsafe_code = "forbid"`, clippy `all` +
`pedantic` warn, `unwrap_used` / `expect_used` deny.

`[profile.dev]` uses `debug = "line-tables-only"` and no debug info for
dependencies. Keep it: the agent self-update download is capped at 64 MiB
and a full-debug agent (~107 MB) breaks the E2E update test.

## Server map (`crates/centrald-server/src/`)

- `main.rs` — CLI: `run` (default), `status`, `reset-password <user>
  [--password-stdin]`. Global `--config`.
- `config.rs` — `/etc/centrald/server.toml` (optional) plus env overrides:
  `CENTRALD_LISTEN`, `CENTRALD_DATA_DIR`, `CENTRALD_HOSTNAMES`,
  `CENTRALD_TLS_CERT` + `CENTRALD_TLS_KEY` (together),
  `CENTRALD_AGENT_DIR`. Port 0 is refused.
- `net.rs` — TLS listener; sniffs first byte, 301s plain HTTP; bounded
  handshakes. Serves HTTP/1.1 and HTTP/2.
- `tls.rs` — private CA (P-256, 20 years) and 397-day leaf, renewed 30 days
  before expiry or when addresses change, same key. Agents use SNI
  `centrald-server.internal` and always get the internal chain.
- `db.rs` — SQLite WAL, `foreign_keys=ON`, strict tables, forward-only
  in-code migrations. Blocking work off async workers.
- `auth.rs`, `session.rs` — Argon2id (max 2 concurrent), `__Host-centrald`
  cookie (`Secure`, `HttpOnly`, `SameSite=Strict`), Origin check on every
  write and WebSocket upgrade, TOTP with replay guard, rate limiter (5 free
  failures, then 30 s doubling to 15 min).
- `hub.rs` — in-memory live state: agents, runs, terminals, browser event
  broadcast.
- `api/` — `account`, `devices`, `join`, `runs`, `agent`, `misc`. WebSocket
  routes are registered with `.get(...).connect(...)`; Chromium uses HTTP/2
  extended CONNECT, so dropping `.connect()` gives 405.
- `downloads.rs` — `/install.sh`, `/install.ps1`, `/download/agent/{os}/
  {arch}` and `.sha256`. Builds the copy-paste install commands from the
  address the operator typed.
- `ui.rs` — rust-embed of `web/dist`. `CENTRALD_REQUIRE_UI=1` makes the build
  fail if the UI is missing (used by `npm run e2e` and release builds).

## Agent map (`crates/centrald-agent/src/`)

Public commands: `enroll [--key-stdin|--key-file] [--server] [--monitor-only]`,
`status`, `leave`, `update`. Hidden: `run` (the service), `service` (Windows
SCM entry). All but `status` require root/Administrator.

- `config.rs` — `/etc/centrald/agent.toml` (root 0600) or
  `%ProgramData%\CentralD\agent.toml` (Administrators/SYSTEM ACL).
  `deny_unknown_fields`. `CENTRALD_AGENT_CONFIG` overrides (tests).
- `connection.rs` — `wss://…/api/agent/connect`, `Hello`/`Welcome` within
  10 s, status every 15 s, 90 s silence ends it, jittered 1–60 s backoff,
  10 min backoff after a rejected credential.
- `exec.rs`, `process.rs` — commands in their own process group, clean env;
  timeout/cancel: SIGTERM, 10 s, SIGKILL (`taskkill /T`, then `/T /F`).
  At most 8 execs and 4 terminals.
- `terminal.rs` — portable-pty (openpty / ConPTY).
- `status.rs` — sysinfo plus Linux failed units, reboot-required, pending
  updates (apt-get -s, dnf check-update, pacman -Qu) every 6 h. Skips
  read-only disks.
- `service.rs`, `winservice.rs` — systemd unit / Windows service
  `CentralDAgent`. `CENTRALD_SKIP_SERVICE=1` skips service install/restart
  (tests).
- `update.rs` — downloads the server's build over the pinned connection,
  verifies `.sha256`, runs `--version`, renames into place. Refuses
  package-managed `/usr/bin` installs. Linux restart via
  `systemd-run --on-active=5`.

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
  rpms, tarballs, `dist/arch/PKGBUILD`, Windows exes, `SHA256SUMS`.
  `--require-all` insists on every platform; `--no-rpm` skips rpm.
  Reproducible via `SOURCE_DATE_EPOCH` from the last commit.
- The deb `Maintainer` is a placeholder
  (`CentralD contributors <noreply@centrald.dev>`) until the owner picks one.
- Server packages ship every agent build; the install commands download from
  the server, never from GitHub.
- Hooks: `packaging/server-maint` and `packaging/agent-maint` (POSIX sh,
  `configure` / `remove`), wrapped by `packaging/debian/*` and
  `packaging/arch/*.install`. Server hook creates the user, enables the unit,
  prints `centrald-server status`, and prints firewall hints (never changes
  the firewall).
- `.github/workflows/release.yml` (tag `v*`): musl Linux on x86_64/ARM64,
  MSVC Windows on x86_64/ARM64, then signs `SHA256SUMS` with Minisign
  (secrets `MINISIGN_SECRET_KEY_B64`, `MINISIGN_PASSWORD`) and opens a draft
  release. Public key in `packaging/minisign.json`.
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
- `CENTRALD_E2E_PORT` (default 17443) and `CENTRALD_E2E_BIN_DIR` (default
  `target/debug`) override the harness.
- `scripts/package-smoke.sh` (CI) installs the debs on a systemd runner and
  walks setup, install command, a command run, and purge.
- The only node unit tests are the inherited cargo policy tests
  (`npm test`). Do not add more unit tests after writing code.

## Quality gates

```text
npm run format:check
npm run lint          # ESLint + cargo clippy -D warnings
npm run typecheck
npm test
npm run test:rust
npm run e2e
npm run site:check && npm run site:build
```

Also run `cargo clippy -p centrald-agent --target x86_64-pc-windows-gnu
--locked -- -D warnings` when touching agent code (needs mingw). If a gate
cannot run locally, say so and leave it to CI; never claim it passed.

CI (`.github/workflows/ci.yml`): `checks`, `windows`, `e2e`, `package`.

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
