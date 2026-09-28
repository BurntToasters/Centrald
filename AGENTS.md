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

Canonical operator docs remain `docs/*.md` and root `SECURITY.md`. This file
does not replace them; it tells agents how the tree is allowed to change.

## Hard do-nots

- Do not restore legacy architecture, enrollment keys, trust flags, database
  schemas, or migration logic. A development install that predates this tree
  must use the destructive reset and run `initial-setup` again.
- Do not flip `PRIVILEGED_OPERATIONS_ENABLED`, `TERMINAL_SESSIONS_ENABLED`, or
  Admin `TERMINAL_FEATURE_AVAILABLE` without the matching broker, vault, wire,
  Tauri, Hello, and package-enablement acceptance tests.
- Do not add a public CLI argument that places an invitation bearer token in
  process arguments. Automation may use `--key-file` or `--key-stdin` only.
- Do not add nested CLI command trees. Keep public commands flat.
- Do not advertise a client capability or enable a GUI action until the
  complete secure execution path exists. Scaffolded broker/terminal work stays
  visibly unavailable.
- Do not restore `updater:default` in the Admin capability ACL
  (`apps/admin/src-tauri/capabilities/default.json`). Admin updates are
  Minisign-verified in Rust, then the Tauri plugin is called only if versions
  match.
- Do not spawn shells from runners, setup, firewall, or PostgreSQL helpers.
  Fixed executable paths and fixed argument lists only.
- Do not open PostgreSQL to the LAN. Recommended local PostgreSQL is
  `127.0.0.1:5432`.
- Do not enable or auto-start `centrald-broker` / `CentralDBroker`.
- Do not edit `site/src/content/docs/` (gitignored, generated). Edit `docs/`
  and `SECURITY.md`.
- Do not put secrets in `centrald.config`, tracked files, Docker build args,
  command-line values, or generated manifests.
- Do not guess Windows roots (`C:\ProgramData`, `C:\Program Files`). Use Known
  Folder APIs; failure is fatal.
- Do not chmod `/run/centrald` to `0700`. Do not give the unprivileged client
  unit `RuntimeDirectory=centrald`.
- Do not add `CAP_NET_BIND_SERVICE` merely so listeners can bind privileged
  ports. Packaged listeners stay 1024-65535.

All project code is GPL-3.0-or-later.

## Repository state

CentralD is a pre-public clean rewrite at `0.1.0` (no prerelease suffix, so the
baked channel is `stable`). There is no legacy-key or schema migration path.

GitHub: `BurntToasters/Centrald` (`https://github.com/BurntToasters/centrald`).
Site: `https://centrald.dev` (Cloudflare Pages, project root `site/`).

## Product and targets

- Server: Ubuntu Server 24.04 x86_64; keep Ubuntu Server 26.04 compatible.
  Packaged server runs as **root** (local-control peer credentials, PKI, the
  root-only database environment file). Listener ports stay unprivileged.
- Database: PostgreSQL through SQLx. Ubuntu 24.04 `postgresql` currently pulls
  PostgreSQL 16. Recommended local bind is `127.0.0.1:5432`.
- Client: Linux x86_64 and Windows x86_64/aarch64. Clients connect outbound
  and never listen.
- Admin: Tauri v2 + React + TypeScript; Linux x86_64 AppImage and Windows
  x86_64/aarch64 NSIS.
- Network scope: private LAN/VPN. Do not expose an alpha server to the public
  Internet.
- v1 scope: inventory, typed jobs, secure transient shell, service/machine
  restart, OS update operations, and operator-approved CentralD updates.
- Future scope: Windows policy/GPO and broader Linux distributions.

This alpha's live path is setup, invitations, enrollment, inventory, invitation
lifecycle, and safe remote settings. Jobs, shell, remote package install, and
privileged broker execution stay fail-closed.

## Workspace layout

```text
package.json                 setup, QA, build, package, release (JS owns these)
Cargo.toml                   Rust workspace (runtime/backend)
centrald.config              tracked public/non-secret build settings
.env.example                 documents every release secret; .env is gitignored
crates/centrald-common       shared config, enrollment, HTTPS, grants, FS
crates/centrald-protocol     protobuf/tonic v1 API
crates/centrald-pki          offline root + online issuers
crates/centrald-platform     platform helpers
crates/centrald-server       Ubuntu server binary
crates/centrald-client       Linux/Windows client + hidden broker
apps/admin                   React UI + Tauri backend
deploy/systemd               server, client, broker units
deploy/tmpfiles.d            /run/centrald 0755 root:root
deploy/windows               client ZIP installer script
scripts/                     release, package, contract tests
site/                        Astro 7 docs site (syncs from docs/)
docs/                        canonical operator documentation
```

Node `>= 22.12`, npm `>= 12.0.1`. Rust edition 2024, `rust-toolchain.toml`
pins `stable` with `cargo`, `clippy`, `rustfmt`. Workspace clippy: `all` +
`pedantic` warn, `unwrap_used` and `expect_used` deny, `unsafe_code` deny.
Server crate forbids unsafe. Unavoidable Windows FFI lives in
`crates/centrald-client/src/windows_ffi.rs` and must stay isolated and
commented.

## Crate and module map

### `centrald-common`

- `config.rs` — TOML load/validate; unknown keys fail closed; packaged server
  secret paths are fixed.
- `enrollment.rs` — `centrald-invite1` parse/generate/hash.
- `https.rs` — rustls `ring` CryptoProvider install; bounded HTTPS fetch;
  redirect policy (3 hops, HTTPS-only, refuse loopback/RFC1918/link-local/ULA
  including IPv4-mapped IPv6, fail closed on unresolvable or any non-public
  resolved address).
- `build_info.rs` — baked channel, manifest URL derivation (must stay in
  parity with `scripts/lib/build-config.js`).
- `secure_fs.rs`, `grant.rs`, `host.rs`, `release.rs`, `active_pointer.rs`.

### `centrald-server` (`crates/centrald-server/src/`)

- `main.rs` — CLI dispatch, three TLS listeners, packaged systemd start,
  rustls provider install before listeners.
- `cli.rs` — public vs hidden commands.
- `wizard.rs` — interactive/non-interactive `initial-setup` collect +
  completion banner (Admin key shown once; Firewall section from
  `firewall::FirewallApplyReport`).
- `setup.rs` — PKI, config, data-root marker; default listeners
  `0.0.0.0:7443/7444/7445`.
- `setup_recovery.rs` — non-secret crash journal, boot/process binding,
  rollback, mutation lock `/var/lib/centrald-initial-setup.lock`.
- `local_postgres.rs` — recommended local role/database; `timeout` +
  `runuser` + `env -i` + pinned `psql`; no `CREATEDB` on the service login.
- `firewall.rs` — UFW AIO for unique non-loopback listener ports.
- `db.rs` — connect/migrate; refuse existing DB; instance comment + singleton
  row. Uses `include_str!("../migrations/0001_initial.sql")`, not
  `sqlx::migrate!`.
- `manage.rs` — `centrald-server config` TUI: common tasks first, advanced
  labeled. Network save re-applies UFW. Health prints `firewall::describe_status`.
- `nuke.rs` — `--nuke --yes-i-want-to-do-this`.
- `services.rs` — enrollment/client/Admin RPC, jobs (fail-closed), updates.
- `local_control.rs` — `/run/centrald/server.sock`, root peer creds.
- `config_lock.rs` — optimistic revision, atomic replace, journals.
- `file_security.rs` — no-follow opened-descriptor reads (`O_NOFOLLOW` +
  `fstat`) at point of use.
- `local_audit.rs`, `audit_export.rs` — hash-chained audit; JSONL export.
- `shell.rs` — gated terminal RPC.

### `centrald-client`

Public: `enroll`, `restart`, `reenroll`, `rescue`. Hidden: `daemon`,
`privileged-broker`, Windows SCM entrypoints. Enrollment: `--server` may
override TCP destination only; `--key-file` / `--key-stdin` for automation.
Linux daemon user `centrald`. Windows SCM identity
`NT SERVICE\CentralDClient`.

### Admin

- `apps/admin/src/App.tsx` — UI, onboarding checklist stays `<details open>`,
  `TERMINAL_FEATURE_AVAILABLE = false` hides Terminal nav.
- `apps/admin/src/TerminalPanel.tsx` — gated; vault copy exists but saving
  stays disabled.
- `apps/admin/src-tauri/src/` — `profiles.rs` (per-profile lock, enroll,
  renew), `updates.rs` (Minisign then Tauri plugin), `shell.rs` (gated).
- Capability ACL: `core:default` only.

## Default paths

| Purpose                 | Path                                              |
| ----------------------- | ------------------------------------------------- |
| Server config           | `/etc/centrald/server.toml`                       |
| Database environment    | `/etc/centrald/server.env` (`CENTRALD_DATABASE_URL`) |
| Server data             | `/var/lib/centrald`                               |
| Data-root marker        | `/var/lib/centrald/.centrald-data-root`           |
| Local server socket     | `/run/centrald/server.sock`                       |
| Broker socket (Unix)    | `/run/centrald/broker.sock` (`root:centrald` 0660) |
| Client data             | `/var/lib/centrald-client`                        |
| Broker grant verify key | `/var/lib/centrald-broker/grant-signing-public.pem` |
| Windows broker key      | `%ProgramData%\CentralD\Broker\grant-signing-public.pem` |
| Runtime dir             | `/run/centrald` `0755` `root:root` via tmpfiles.d |

Advanced `--config` must be a clean absolute path **outside**
`/var/lib/centrald` (reset deletes that tree). Secret files are mode `0600`
on Unix. Packaged `/run/centrald` is created by `deploy/tmpfiles.d/` plus the
root-owned server/broker `RuntimeDirectory=`. The client unit may
`ReadWritePaths=` that directory but must not own it.

## Public command contracts

Server first-run and management commands:

```text
centrald-server initial-setup
centrald-server config
centrald-server run
centrald-server channel <stable|alpha|beta>
centrald-server --nuke --yes-i-want-to-do-this
```

Advanced flat commands may remain hidden from `--help`, but every persisted
setting and normal identity workflow must be reachable through
`centrald-server config`. `centrald-server channel` is the operator-facing
release-channel switch: it sets `updates.channel`, derives
`updates.manifest_url` (failing closed when no per-channel layout exists),
sets `allow_prerelease = channel != "stable"`, and persists through the same
locked/journaled save path as the guided console. Restart the server for the
change to take effect.

Public client commands:

```text
centrald-client enroll
centrald-client restart
centrald-client reenroll
centrald-client rescue
```

`centrald-client enroll` without flags is the normal wizard. Do not add a
`--key` / argv bearer. Internal daemon and broker modes stay hidden.

## Feature gates (keep false in this alpha)

Flip only together, with acceptance tests:

| Gate                            | Location                                      | Meaning                         |
| ------------------------------- | --------------------------------------------- | ------------------------------- |
| `PRIVILEGED_OPERATIONS_ENABLED` | `crates/centrald-common/src/lib.rs`           | jobs, broker runner, package ops |
| `TERMINAL_SESSIONS_ENABLED`     | `crates/centrald-common/src/lib.rs`           | PTY/ConPTY on the wire          |
| `TERMINAL_FEATURE_AVAILABLE`    | `apps/admin/src/App.tsx`                      | Admin Terminal nav              |

Client Hello currently advertises only `heartbeat`. GUI disable flags are not
the security boundary; protocol, broker, runner, and Tauri commands must
fail closed.

## Novice and advanced administration contract

Homelab first-run is all-in-one via the packaged binaries:

```text
sudo apt install ./centrald-server_*.deb
sudo centrald-server initial-setup
# paste the one-time Admin access key into Admin → Add server
sudo apt install ./centrald-client_*.deb
sudo centrald-client enroll
```

- Server `.deb` postinst prints `sudo centrald-server initial-setup` when
  `/etc/centrald/server.toml` is absent. Client `.deb` prints
  `sudo centrald-client enroll` until `current.pointer` exists.
- Server package `Depends`: `ca-certificates`, `coreutils`, `postgresql`,
  `systemd`, `ufw`, `util-linux`. `apt install ./centrald-server_*.deb` pulls
  PostgreSQL and UFW. Client `Depends` do not include UFW (outbound only).
- After `initial-setup` commits, packaged systemd activation enables and
  starts `centrald-server.service` and waits up to 60s for
  `/run/centrald/server.sock`. Success prints `READY:`. Failure prints
  `INCOMPLETE:` plus the exact recovery command. Source/custom binaries and
  non-default `--config` print the manual start action instead of pretending
  the unit started.
- `CENTRALD_SKIP_SERVICE_START` skips automatic `systemctl enable --now`
  (image bake / advanced). Not a public CLI flag.
- After `initial-setup`, the next operator step is Admin enrollment with the
  printed access key. `centrald-server config` is health, extra invitations,
  and advanced/local-only trust — not a required second command before Admin.
- `centrald-server config` puts common enrollment, health, firewall refresh,
  and recovery first. Label PKI, database, storage, listeners, and
  destructive controls as advanced/local-only. Do not drop configuration
  parity to simplify the menu.
- Admin GUI keeps an accessible onboarding/common-tasks checklist after the
  first successful connection (`<details className="getting-started" open>`).
- Keep `docs/QUICKSTART.md` and `npm run check:onboarding` aligned with the
  path above.

### UFW (host firewall) AIO

Implemented in `crates/centrald-server/src/firewall.rs`. Called after service
start from `initial_setup` (`main.rs`), after listener saves in
`configure_network`, from Health (`describe_status`), and from the common
menu item `Refresh host firewall (UFW)`.

Behavior:

- Unique non-loopback TCP ports from the persisted enrollment/client/Admin
  listen addresses (defaults `0.0.0.0:7443/7444/7445`). Loopback including
  IPv4-mapped `::ffff:127.0.0.1` is skipped. Port 0 is skipped.
- Comments are single `[A-Za-z0-9-]` tokens: `CentralD-enrollment`,
  `CentralD-client`, `CentralD-admin`. Never interpolate operator strings
  into UFW argv.
- Allow SSH **before** enable: `ufw allow OpenSSH`, fallback
  `ufw allow 22/tcp comment CentralD-ssh`. If UFW is already active and SSH
  allow fails, continue with CentralD ports rather than failing the whole
  apply (SSH is already working). If inactive, SSH failure is fatal for
  enable (would drop remote access).
- Inactive UFW: add rules, then `ufw --force enable` (Ubuntu default
  deny-incoming / allow-outgoing). Other host services (Cockpit, etc.) need
  their own rules; document that, do not auto-detect every listener.
- Already active: add missing CentralD allows and `ufw reload`. Do not reset
  policy. Do not delete old rules when ports change; only ensure current
  ports are allowed.
- Tools: `/usr/bin/timeout` wrapping `/usr/sbin/ufw`, `env_clear`,
  `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LANG=C`. Never `sh -c` or
  `Command::new("ufw")` from PATH.
- Apply never aborts committed setup: failures become an operator report
  with recovery text.
- `CENTRALD_SKIP_FIREWALL` skips all mutation.
- `CI` or `CENTRALD_SKIP_FIREWALL_ENABLE` still adds rules but does not
  `--force enable` (GitHub runners / local package smoke). Linux package
  smoke sets `CENTRALD_SKIP_FIREWALL_ENABLE=1` via `sudo env`.
- No public `--skip-firewall` CLI flag.
- Hypervisor and cloud security groups are independent of UFW. PostgreSQL
  is never opened.

## Enrollment and Admin authentication contract

Only `centrald-invite1` is supported. Do not add legacy parsing, version
fallbacks, trust-on-first-use, or an unauthenticated CA download endpoint.

A one-time invitation carries public bootstrap metadata plus its bearer
secret: server instance, role, display name, exact TLS name, all service
ports, root CA, and expiry. The server stores an Argon2id hash of the full
invitation and consumes it transactionally. Hash/verify runs off Tokio
workers behind a shared concurrency limit of 2 (including local-control
create). The client/Admin may replace the TCP destination, but must continue
to verify the invitation's TLS name and root CA.

Admin access keys are invitations, not permanent API tokens. Admin generates
an mTLS private key locally, enrolls once, and never stores the invitation.
Only the server-local console may create, rotate, or revoke Admin identities.

TLS name is the most common first-enroll failure. The wizard may suggest this
machine's hostname; other VMs often cannot resolve it. For a homelab without
DNS, the operator must enter the server's LAN IPv4. That value is baked into
the invitation and certificates. A later connection override only changes
where TCP goes.

## Architecture contracts

- Root `package.json` owns setup, QA, build, package, and release commands.
- Rust Cargo workspace owns runtime/backend behavior.
- Three TLS listeners, on distinct configurable ports:
  - enrollment server-authenticated TLS (default `7443`);
  - client mTLS (default `7444`);
  - Admin mTLS (default `7445`).
- Server-local control uses `/run/centrald/server.sock` with root
  peer-credential checks and bounded typed messages.
- PKI uses a separately stored offline root and online server/client/Admin
  issuers. Persist the online server issuer so a local TLS-name rotation does
  not require the offline root. Offline-root replacement is a journaled
  ceremony authorized only by the current recovery key; every enrolled device
  must re-enroll afterward.
- Client network daemon is unprivileged. The future privileged broker has no
  network listener and may accept only typed, short-lived, server-signed
  grants on an ACL-restricted local channel.
- Unix privileged client-state repair and root enrollment persistence must
  use fixed-root descriptor-relative, no-follow operations; never validate a
  path and then mutate that pathname as root. Windows ACL repair is
  installer-owned (`centrald-client rescue --repair` refuses it).
- Admin profile activation/renewal uses a per-profile cross-process lock.
- Admin settings updates use optimistic revision checks and atomic file
  replacement; local backup retention is bounded (10). Remote settings must
  not include secret locations, PKI mutation, Admin lifecycle, or destructive
  reset. Channel, manifest URL, and `allow_prerelease` stay server-local.
- PostgreSQL is authoritative for identities, inventory, jobs, and audit
  metadata. Shell bytes are transient and never durable.
- Recommended local PostgreSQL setup must persist non-secret crash-recovery
  state before the first cluster mutation, bind that state to the creating
  Linux process/boot, and keep it until rollback or commit is durably
  recoverable. Non-interactive Ubuntu setup without `CENTRALD_DATABASE_URL`
  uses the same recommended local path as the wizard default. The runtime
  daemon and TUI do not accept a process-level `CENTRALD_DATABASE_URL`
  override; credentials come from the root-owned environment file.
- Server, client, and Admin install rustls `ring` as the process-level
  `CryptoProvider` at startup so tonic `tls-ring` plus reqwest's aws-lc-rs
  feature cannot panic packaged `run` on outbound HTTPS.

## Interactive terminal contract

Do not fake an SSH-like terminal by running arbitrary commands as the daemon
or by storing reusable passwords in application files. The final
implementation must use a real PTY/ConPTY stream, bounded frames and
backpressure, explicit session metadata, short idle/absolute timeouts, and a
privileged local broker.

User/password prompts may be used to authenticate a requested OS account, but
saved credentials require the operating-system vault (Windows Credential
Manager/DPAPI or Linux Secret Service). Until those pieces exist, keep
terminal execution and credential saving visibly disabled.

## Environment variables

Runtime / setup (not public CLI flags):

| Variable                         | Effect                                              |
| -------------------------------- | --------------------------------------------------- |
| `CENTRALD_SKIP_SERVICE_START`    | skip `systemctl enable --now` after setup           |
| `CENTRALD_SKIP_FIREWALL`         | skip all UFW mutation                               |
| `CENTRALD_SKIP_FIREWALL_ENABLE`  | add UFW rules but do not `--force enable`           |
| `CI`                             | same enable-skip as `CENTRALD_SKIP_FIREWALL_ENABLE` |
| `CENTRALD_DATABASE_URL`          | advanced setup URL; ignored at packaged runtime     |

Release / build (`.env`, never argv, never `centrald.config`):

| Variable                              | Effect                                      |
| ------------------------------------- | ------------------------------------------- |
| `CENTRALD_RELEASE_PUBLISH=YES`        | create/push `v<version>` tag and publish    |
| `CENTRALD_GITHUB_IMMUTABLE_RELEASES`  | required with publish                       |
| `CENTRALD_RELEASE_CHANNEL`            | override baked channel for one build        |
| `CENTRALD_S3_ENDPOINT` / `_BUCKET` / `_REGION` | CDN mirror (required when `CDN_BASE_URL` is set) |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | S3/Spaces credentials                |
| `TAURI_SIGNING_PRIVATE_KEY`           | key **content**, not a path                 |
| `MINISIGN_SECRET_KEY_FILE`            | path to secret key                          |
| `MINISIGN_SECRET_KEY_B64`             | CI-only ephemeral key                       |
| `CENTRALD_MINISIGN_UNPROTECTED_KEY`   | CI `-W`; keep commented in `.env.example`   |
| `CENTRALD_ALLOW_CHANNEL_ROLLBACK=YES` | emergency channel downgrade                 |
| `CENTRALD_RELEASE_NOTES` / `_TIMESTAMP` | optional reproducible metadata            |
| `CENTRALD_TEST_DATABASE_URL`          | CI postgres migrate smoke                   |
| `GH_TOKEN`                            | GitHub release upload                       |

## Update and release contracts

- `centrald.config` is tracked and contains public/non-secret build settings
  only. Unknown keys fail closed. Current CDN:
  `CDN_BASE_URL=https://updated.centrald.dev`.
- Mutable manifests and immutable artifacts use separate URL bases.
- Clients never discover updates independently; server/Admin coordinate
  checks.
- No component installs an update without explicit operator approval.
- Every artifact has a Minisign `.minisig` verified with
  `MINISIGN_PUBLIC_KEY`.
- Admin AppImage/NSIS updater artifacts additionally have Tauri `.sig` files
  verified with `TAURI_UPDATER_PUBKEY`.
- Do not interpret a Tauri `.sig` as a general release signature.
- One release includes server Linux `.deb`, client Linux `.deb`, client
  Windows ZIP/service installer, Admin AppImage, and Admin Windows NSIS for
  both architectures.
- Release manifests use immutable version URLs. Mutable non-stable channel
  manifests live outside immutable GitHub Releases; the default GitHub layout
  publishes both manifests in one compare-and-swap commit on the
  `centrald-channels` branch.
- Every build bakes exactly one release channel; CentralD serves only
  `stable`, `alpha`, and `beta` (enforced in the build tooling, the server
  update feed, manifest validation, and the operator CLI). An install only
  follows its own channel and promotion is a new build. The channel is
  auto-detected from the package version (no prerelease suffix = stable,
  otherwise the prerelease identifier), and `--channel` on the release/build
  tools and the `CENTRALD_RELEASE_CHANNEL` environment variable override the
  tracked `centrald.config` in both the JS tooling and
  `centrald-common/build.rs` (which mirrors the detection from
  `CARGO_PKG_VERSION`).
- With `CDN_BASE_URL` set, all channels (including stable) resolve
  `<CDN_BASE_URL>/<channel>` and the release flow mirrors the signed channel
  manifests to an S3-compatible bucket as the automatic last publish step.
  Artifacts always remain on immutable GitHub tag URLs. Without
  `CDN_BASE_URL`, stable stays on `/releases/latest/download` and non-stable
  channels on the channel branch.
- Channel updates are monotonic by strict Semantic Versioning. Same-version
  byte replacement is forbidden. Emergency rollback requires the exact
  explicit `CENTRALD_ALLOW_CHANNEL_ROLLBACK=YES` environment variable.
- Release verification uses a reproducible commit-derived manifest timestamp.
  A channel-only retry downloads and verifies the immutable release
  manifests; it must never regenerate mutable pointer bytes from ambient
  environment.
- Signing private keys come only from process environment or an ephemeral
  secret file.
- `.env.example` documents every release secret; `.env` is gitignored and
  loaded by release/build scripts via `node --env-file-if-exists=.env`.
- `.npmrc` (root and `site/`) hard-enforces `min-release-age=3`; Docker
  builder images copy it before `npm ci`. Install scripts are allowed in the
  builder images with the allowlist in `package.json` (`allowScripts`). npm
  upgrades use `npm@latest` everywhere; never pin a specific npm version.
- `npm run setup:docker` is the handsfree Docker setup for release hosts.
  `--all-docker` additionally enables/checks the Windows `Containers`
  feature.
- `npm run release` builds every platform the host can produce (Windows hosts
  build Windows artifacts on the host and Linux artifacts in the Docker Linux
  engine; `--all-docker` opts into `build.js --target all --container`). With
  `CENTRALD_RELEASE_PUBLISH=YES` it creates and pushes the
  `v<package-version>` tag **after** `verify()`. Docker-built Linux AppImage
  and Windows NSIS installers are Tauri-signed on the host with
  `tauri signer sign`, never inside Docker. Host and both builder images run
  `rustup update stable` before building. Pass flags after `--`:
  `npm run release -- --channel beta`. Linux `npm run release` **fails
  closed** (`requireCompleteReleaseHost`); use
  `npm run build:linux:x64:native` only for disposable VM-test packages.
- The S3 mirror is required when `CDN_BASE_URL` is baked: publish fails
  closed without `CENTRALD_S3_ENDPOINT` (and bucket/credentials) **before**
  tagging. CI that does not publish stays green. `sync-channel.js`
  JSON-parses the `.yml` feed (JSON body), verifies Minisign, refuses
  symlinks, and rejects an empty/undetermined channel.
- `scripts/bump-version.js` keeps `package.json`, workspace `Cargo.toml`,
  `tauri.conf.json`, and `Cargo.lock` in lockstep. It captures
  `cargo metadata --locked` **before** rewriting `Cargo.toml`, then
  `cargo update --workspace --offline` (do not `generate-lockfile`; 64MiB
  `maxBuffer`). Refuses invalid SemVer, existing origin tags, and disagreeing
  version fields.
- `npm run qa` needs site dependencies (`npm ci --prefix site`). Linux
  builds need `libpam0g-dev`. Linux package smoke also needs `libclang-dev`
  (`clang-sys`). In `windows-builder.Dockerfile` the node-dir `ENV PATH`
  must be set before `npm install -g npm@latest`.

## Update feed and channel switching

Feed URL derivation lives in two places that must stay in parity:
`centrald-common/src/build_info.rs::manifest_url_for_channel` (baked via
`build.rs`) and `scripts/lib/build-config.js`. Contract tests
(`hardening-contract.test.js`, `build-config.test.js`) pin:

- CDN set -> `<CDN_BASE_URL>/<channel>/<manifest>` (CDN wins even when
  `UPDATE_BASE_URL` is also set);
- GitHub without CDN -> stable at `/releases/latest/download`, other
  channels at
  `raw.githubusercontent.com/<repo>/centrald-channels/channels/<channel>/latest`;
- generic origins -> `<repo>/<channel>/latest`.

`centrald-server channel` derives `updates.manifest_url` through that
function and **fails closed** when the build has an explicitly configured
`UPDATE_BASE_URL` without `CDN_BASE_URL`.

Clients refuse to follow any channel other than their own baked
`RELEASE_CHANNEL` (`UpdateParameters::validate`). A server channel switch
only affects installs whose baked channel matches.

Server fetches release manifests and Minisign signatures with strict bounds
(signature body capped at 4096 bytes, drained chunk-by-chunk) and verifies
with `allow_legacy = false`. `UPDATE_BASE_URL_EXPLICIT` is a baked flag from
`centrald.config`. Admin self-update: `check_admin_update` /
`install_admin_update` Minisign-verify the updater JSON, then call the Tauri
plugin only if versions match.

Until the first signed CDN publish exists, Admin Health and
`centrald-server config` Health may show a release-manifest check error.
That does not block enrollment.

## Client update extraction safety

- Linux updates install with `dpkg -i`; Windows updates extract a ZIP that
  must contain `install-client.ps1`, executed via the trusted Windows system
  directory's PowerShell with `-File` (no shell, fixed arguments).
- ZIP entry names must be simple: non-empty, <= 255 chars, no absolute or
  empty path parts, no `.`/`..`, no trailing dot/space, no Windows device
  names (`CON`, `NUL`, `COM1`, ..., including superscript `COM¹`/`LPT¹`
  aliases), and **no `:` anywhere**. After joining, the target must still be
  contained under the extract directory. Bounds: 512 entries max, 512 MiB
  per entry, 600 s extraction wall clock, hard total expansion cap.
- Every artifact is verified by exact size, SHA-256, and a Minisign
  signature checked with the baked public key before installation.

## Broker and operation hardening

- The broker verifies grants with a root/SYSTEM-owned copy of the grant
  verifying key. Never read the daemon-writable identity PEM for
  authorization. Enrollment and Unix repair publish that copy as root; the
  unprivileged daemon must not.
- Unix broker sockets are `root:centrald` mode `0660`. `/run/centrald` stays
  `0755`. Windows broker pipes use `FRFW` (not `GA`). Unix and Windows both
  cap 64 in-flight connections and a 10 s first-frame timeout; Windows first
  frames must be unframed to the JSON body before dispatch, polled in
  non-blocking mode, then restored to blocking before dispatch. Excess
  connections are dropped, not queued onto extra threads.
- Operation timeouts terminate the whole child process group gracefully
  first: SIGTERM (Unix) or `taskkill /T` (Windows), a 10 s grace, then
  SIGKILL / `taskkill /T /F` — never SIGKILL apt-get/dpkg while it holds its
  package database.
- Fixed executable paths and fixed argument lists only; bounded merged
  output (64 KiB per job event); no shells spawned by the runner.
- Local-control parent directory must refuse `mode & 0o022`.

## Release tooling map

- `scripts/release.js` — orchestrator and the `release:*` npm actions
  (prepare/build/assemble/sign/manifests/verify/publish/publish-channel);
  `verify()` regenerates manifests byte-deterministically from the release
  commit and runs `npm run qa`. Linux `all` calls
  `requireCompleteReleaseHost()`.
- `scripts/build.js` — per-target builds; `--target all` on Windows builds
  Windows on the host and Linux in Docker; `--target all --container` opts
  into both Docker engines (`scripts/lib/docker-engine.js` switches via
  `DockerCli.exe`, ~180 s polling). `--native` is the Linux VM-test path
  (`build:linux:x64:native`).
- `scripts/sync-channel.js` — S3 mirror of the four signed manifest files;
  `scripts/lib/channel-manifest.js` JSON-parses `centrald-release.yml`.
- `scripts/setup-docker.js`, `scripts/setup.js` — release-host and workspace
  setup.
- `scripts/bump-version.js` — lockstep version + offline Cargo.lock regen.
- `scripts/sign-release.js`, `scripts/generate-manifests.js`,
  `scripts/check-config.js`, `scripts/check-onboarding.js`, `scripts/qa.js`,
  `scripts/package-linux.js`, `scripts/ci-linux-package-smoke.js`.
- `scripts/cargo-safe-update.mjs` generates a candidate `Cargo.lock` in a
  copied workspace until Cargo advertises a stable `--lockfile-path`. Do not
  restore `CARGO_RESOLVER_LOCKFILE_PATH`.
- `scripts/lib/build-config.js` and `crates/centrald-common/build.rs` mirror
  each other; `scripts/tests/*.test.js` pin the invariants.
- `npm ci` in CI strips release secrets from the environment of the install
  scripts.

## Release-host environment

The primary release host is a Windows 11 machine with Docker Desktop's
Linux/WSL engine, `gh` authenticated, the `aws` CLI, and `minisign`
installed. Windows artifacts build on the host; the Docker Windows engine is
optional behind `--all-docker`. Minisign keypair:
`~/.config/centrald/minisign.key` (+ `.pub`). Tauri keypair:
`~/.tauri/centrald.key` (+ `.pub`). Public keys are tracked in
`centrald.config`. `npm run release` requires a clean tree; commit before
publishing. The first publish creates the `v<package-version>` tag and the
`centrald-channels` branch.

Known remaining publish gap (not a VM-test blocker):
`requirePublishEnvironment` checks `CENTRALD_S3_ENDPOINT` before tagging,
but bucket/AWS keys/`aws` CLI still fail later in `sync-channel.js` if
unset. Do not weaken the endpoint check; tighten the others if touching
publish.

## Homelab VM testing

Use `npm run build:linux:x64:native` (not `npm run release` on Linux).
Packages land in `dist/linux-x64/`.

Recommended layout: Ubuntu Server 24.04 VM for the server (headless is
fine), Ubuntu Server 24.04 VM for the client, a **graphical** Linux or
Windows workstation for Admin. The AppImage is Tauri/WebKitGTK, not
Electron; do not pass Electron `--no-sandbox`. It needs FUSE 2
(`libfuse2t64` in Ubuntu **universe**). Do **not** install the `fuse`
package to make AppImages work (can break desktop session mounts).

TLS name: enter the server LAN IPv4 unless every machine can resolve the
hostname. Windows enroll must quote paths with spaces
(`"C:\Program Files\CentralD\centrald-client.exe"`). Ignore CDN Health
errors until the first signed publish. Do not enable `centrald-broker`.
Jobs/terminal stay unavailable.

## Docs map

`docs/QUICKSTART.md` (first-run path, guarded by `npm run check:onboarding`),
`docs/OPERATIONS.md`, `docs/RELEASES.md` (channel layout, publish flow, CI
secrets), `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`,
`docs/IMPLEMENTATION_STATUS.md` (authoritative implemented-vs-gated list).
Site content is synced from `docs/*.md` + `SECURITY.md`.

When changing first-run behavior, update QUICKSTART, OPERATIONS, README,
`check-onboarding.js`, and this file together.

## Security requirements

- No plaintext application traffic and no hardcoded secrets.
- Generate client/Admin private keys locally; never send them to the server.
- Validate role, chain, SAN, expiry, revocation, identity binding, protocol
  version, request size, and all enum/string conversions.
- Redact invitations, passwords, private keys, elevation proofs, shell
  bytes, and `SessionWireFrame` Debug output from logs.
- Prefer typed platform APIs and fixed executable/argument lists over
  shells.
- Keep project Rust safe. Isolate and explain unavoidable Windows FFI.
- Bound streams, frames, queues, output, timeouts, and retained data.
- Keep memory-hard enrollment hashing off Tokio worker threads and bound
  concurrent Argon2 work, including local-control invitation create.
- Packaged server listeners use unprivileged ports (1024-65535).
- Revalidate root-owned private and public trust files at point of use with
  no-follow opened-descriptor checks; creation-time permissions and earlier
  path validation are not enough.
- Admin RPC must not park Tokio workers on blocking config locks; use
  non-blocking try-lock from `spawn_blocking` and return a retryable busy
  error.
- Destructive filesystem operations require exact allowlists, ownership
  markers, symlink rejection, and a stopped daemon. Server reset writes a
  durable journal before dropping PostgreSQL, authorizes both the database
  and any managed role, and keeps the data-root marker until every other
  child has been removed.
- Recommended local PostgreSQL objects use the full server instance UUID and
  an instance-bound role comment. The service login never receives
  `CREATEDB`; the pinned local postgres administrator creates its single
  owned database. Cleanup verifies role ownership plus database
  owner/comment state; a generated-looking name alone is never authority.
- Windows machine roots come from Known Folder APIs.

## Repository safety

Generated cleanup is limited to marked directories under `coverage`, `dist`,
`release`, and `target`. Reject repository root, drive roots, UNC/traversal,
empty paths, and symlink/junction escapes. Release scripts must not reset,
checkout, or clean source files.

Preserve unrelated user changes and double-check destructive/privileged
logic. Ignore generated Linux Tauri schema (`linux-schema.json` is
gitignored).

## Website

- `site/` is a static Astro 7 documentation site deployed to Cloudflare
  Pages at `centrald.dev` (Pages project root `site`, build
  `npm ci && npm run build`, output `dist`).
- `docs/*.md` and root `SECURITY.md` are the canonical content source.
  `site/scripts/sync-docs.mjs` copies them into the gitignored
  `site/src/content/docs/` with generated frontmatter (title, description,
  order, group); the build always re-syncs first. Never edit
  `site/src/content/docs/` directly and never duplicate doc content in
  site-authored pages.
- `npm run site:dev`, `site:check` (`astro check`), and `site:build` wrap
  the site commands; `npm run qa` runs `site:check` + `site:build`.
- Site pages and layout live in `site/src/pages` and `site/src/layouts`;
  the docs route map (slug/order/group per document) lives in the sync
  script.

## Quality gates

Run the relevant subset before completion:

```text
npm run format:check
npm run lint
npm run typecheck
npm test
npm run test:rust
npm run qa
```

`npm test` runs Admin vitest plus JS contract tests in `scripts/tests/`
(hardening, channel/URL parity, manifest reproducibility, cleanup safety,
bump helper, onboarding). `npm run lint` is ESLint (`apps/admin/src`,
`scripts`) plus `cargo clippy --workspace --all-targets --locked -- -D warnings`.
Prettier uses `proseWrap: always` on markdown; long `docs/*.md` bullets must
wrap or CI fails.

CI (`.github/workflows/ci.yml`), 5 jobs:

1. Linux QA (`npm run qa`)
2. PostgreSQL migrate smoke (`CENTRALD_TEST_DATABASE_URL` +
   `postgres_migrate_smoke`)
3. Linux package install smoke (`scripts/ci-linux-package-smoke.js`,
   `--debs-only`; asserts Admin key banner, `READY:`, Firewall report, and
   does not enable UFW)
4. Windows compile checks
5. (workflow also covers frontend via Linux QA)

`release.yml` builds/publishes; it has S3 secrets + `awscli` for the CDN
mirror.

Security changes need negative tests for malformed input, wrong role,
expiry, replay, tampering, stale revisions, path escape, partial failure,
and reconnect. If the local environment cannot run a gate, state that
explicitly and leave CI to run it; never claim it passed.

## Agent pitfalls seen in this tree

- Do not use `cargo generate-lockfile` after rewriting `Cargo.toml`; capture
  `--locked` metadata first, then `cargo update --workspace --offline`.
- `verify()` must run before `createAndPushVersionTag()`.
- CDN channel YAML is JSON; parse with `scripts/lib/channel-manifest.js`,
  never line-oriented YAML guesses.
- ESLint `no-regex-spaces` fires on `verify();\n  if` in contract tests;
  write the regex carefully.
- Prettier wrap on `docs/IMPLEMENTATION_STATUS.md` has failed CI; wrap
  prose, then `npx prettier --write` the doc.
- `check-onboarding.js` uses `.includes()` on exact substrings; after
  Prettier wraps a sentence, the required needle must still appear on one
  line.
- Do not add `RuntimeDirectory=centrald` to the client unit.
- Windows enroll help/docs must quote `C:\Program Files\...`.

## Current implementation boundary

The enrollment, owned-database setup/config/reset flow, mTLS onboarding and
renewal/activation, invitation lifecycle, basic inventory, leased typed job
protocol (fail-closed on the wire in this alpha), audited remote settings,
client rescue, Admin Tauri updater (Minisign-verified feed once for
availability; install requires plugin JSON to match the verified body; no
WebView `updater:default` ACL), packaging, immutable manifest/release
pipeline, packaged systemd first-start, and UFW AIO from `initial-setup`
are implemented. Admin Terminal navigation stays hidden while
`TERMINAL_FEATURE_AVAILABLE` is false. Release-manifest check failures are
persisted and surfaced in Admin settings and `centrald-server config`
Health. PTY/ConPTY shell transport, the privileged operation runner,
OS-vault credential saving, and server/client package installation remain
gated on the wire, broker, Tauri commands, Hello capabilities, and packaged
service enablement. See `docs/IMPLEMENTATION_STATUS.md`.
