# CentralD agent context

## Important
Any updates that an agent does to the codebase should be added/updated here if nessecary post-edits for future agents to understand this codebase well.

## Repository state

CentralD is a pre-public clean rewrite at `0.1.0-alpha.1`. Do not restore legacy
architecture, enrollment keys, trust flags, database schemas, or migration
logic. A development install that predates this tree must use the destructive
reset and run `initial-setup` again.

All project code is GPL-3.0-or-later.

## Product and targets

- Server: Ubuntu Server 24.04 x86_64; keep Ubuntu Server 26.04 compatible.
- Database: PostgreSQL through SQLx.
- Client: Linux x86_64 and Windows x86_64/aarch64.
- Admin: Tauri v2 + React + TypeScript; Linux x86_64 AppImage and Windows
  x86_64/aarch64 NSIS.
- Network scope: private LAN/VPN. Clients connect outbound and never listen.
- v1 scope: inventory, typed jobs, secure transient shell, service/machine
  restart, OS update operations, and operator-approved CentralD updates.
- Future scope: Windows policy/GPO and broader Linux distributions.

## Public command contracts

Server first-run and management commands:

```text
centrald-server initial-setup
centrald-server config
centrald-server run
centrald-server channel <stable|alpha|beta>
centrald-server --nuke --yes-i-want-to-do-this
```

Advanced flat commands may remain, but every persisted setting and normal
identity workflow must be reachable through `centrald-server config`.
`centrald-server channel` is the operator-facing release-channel switch: it
sets `updates.channel`, derives `updates.manifest_url` (failing closed when no
per-channel layout exists), sets `allow_prerelease = channel != "stable"`, and
persists through the same locked/journaled save path as the guided console;
the server must be restarted for the change to take effect.

Public client commands are limited to:

```text
centrald-client enroll
centrald-client restart
centrald-client reenroll
centrald-client rescue
```

`centrald-client enroll` without flags is the normal wizard. Automation may read
an invitation only from a protected file or piped standard input; never add a
public argument that places the bearer token in process arguments. Internal
daemon and broker modes stay hidden from help. Do not add nested CLI command
trees.

## Novice and advanced administration contract

- A normal packaged Ubuntu setup must end with a usable server without requiring
  the operator to discover a second daemon-start command. If automatic systemd
  activation is unavailable, print the exact recovery command.
- `centrald-server config` must put common enrollment, health, and recovery tasks
  first and clearly label PKI, database, storage, listener, and destructive
  controls as advanced/local-only. Do not reduce configuration parity to achieve
  this; organize it.
- The Admin GUI must keep an accessible onboarding/common-tasks checklist after
  the first successful connection.
- Do not advertise a client capability or enable a GUI action until the complete
  secure execution path exists. Scaffolded broker/terminal operations stay
  visibly unavailable.
- Keep `docs/QUICKSTART.md` and `npm run check:onboarding` aligned with the
  recommended first-run path.

## Enrollment and Admin authentication contract

Only `centrald-invite1` is supported. Do not add legacy parsing, version
fallbacks, trust-on-first-use, or an unauthenticated CA download endpoint.

A one-time invitation carries public bootstrap metadata plus its bearer secret:
server instance, role, display name, exact TLS name, all service ports, root CA,
and expiry. The server stores an Argon2id hash of the full invitation and
consumes it transactionally. The client/Admin may replace the TCP destination,
but must continue to verify the invitation's TLS name and root CA.

Admin access keys are invitations, not permanent API tokens. Admin generates an
mTLS private key locally, enrolls once, and never stores the invitation. Only
the server-local console may create, rotate, or revoke Admin identities.

## Architecture contracts

- Root `package.json` owns setup, QA, build, package, and release commands.
- Rust Cargo workspace owns runtime/backend behavior.
- Three TLS listeners, on distinct configurable ports:
  - enrollment server-authenticated TLS (default `7443`);
  - client mTLS (default `7444`);
  - Admin mTLS (default `7445`).
- Server-local control uses `/run/centrald/server.sock` with root peer-credential
  checks and bounded typed messages.
- PKI uses a separately stored offline root and online server/client/Admin
  issuers. Persist the online server issuer so a local TLS-name rotation does
  not require the offline root.
- Client network daemon is unprivileged. The future privileged broker has no
  network listener and may accept only typed, short-lived, server-signed grants
  on an ACL-restricted local channel.
- Unix privileged client-state repair and root enrollment persistence must use
  fixed-root descriptor-relative, no-follow operations; never validate a path
  and then mutate that pathname as root. Windows ACL repair is installer-owned.
- Admin profile activation/renewal uses a per-profile cross-process lock.
- Admin settings updates use optimistic revision checks and atomic file
  replacement; local backup retention is bounded. Remote settings must not
  include secret locations, PKI mutation, Admin lifecycle, or destructive
  reset.
- PostgreSQL is authoritative for identities, inventory, jobs, and audit
  metadata. Shell bytes are transient and never durable.
- Recommended local PostgreSQL setup must persist non-secret crash-recovery
  state before the first cluster mutation, bind that state to the creating Linux
  process/boot, and keep it until rollback or commit is durably recoverable.

## Interactive terminal contract

Do not fake an SSH-like terminal by running arbitrary commands as the daemon or
by storing reusable passwords in application files. The final implementation
must use a real PTY/ConPTY stream, bounded frames and backpressure, explicit
session metadata, short idle/absolute timeouts, and a privileged local broker.

User/password prompts may be used to authenticate a requested OS account, but
saved credentials require the operating-system vault (Windows Credential
Manager/DPAPI or Linux Secret Service). Until those pieces exist, keep terminal
execution and credential saving visibly disabled.

## Update and release contracts

- `centrald.config` is tracked and contains public/non-secret build settings
  only. Unknown keys fail closed.
- Mutable manifests and immutable artifacts use separate URL bases.
- Clients never discover updates independently; server/Admin coordinate checks.
- No component installs an update without explicit operator approval.
- Every artifact has a Minisign `.minisig` verified with
  `MINISIGN_PUBLIC_KEY`.
- Admin AppImage/NSIS updater artifacts additionally have Tauri `.sig` files
  verified with `TAURI_UPDATER_PUBKEY`.
- Do not interpret a Tauri `.sig` as a general release signature.
- One release includes server Linux `.deb`, client Linux `.deb`, client Windows
  ZIP/service installer, Admin AppImage, and Admin Windows NSIS for both
  architectures.
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
  tracked `centrald.config` in both the JS tooling and `centrald-common/build.rs`
  (which mirrors the detection from `CARGO_PKG_VERSION`).
- With `CDN_BASE_URL` set in `centrald.config`, all channels (including
  stable) resolve `<CDN_BASE_URL>/<channel>` and the release flow mirrors the
  signed channel manifests to an S3-compatible bucket (DO Spaces or any S3
  endpoint via the `aws` CLI, credentials in `.env`) as the automatic last
  publish step. Artifacts always remain on immutable GitHub tag URLs. Without
  `CDN_BASE_URL`, stable stays on the immutable `/releases/latest/download`
  pointer and non-stable channels on the channel branch.
- Channel updates are monotonic by strict Semantic Versioning. Same-version byte
  replacement is forbidden. Emergency rollback requires the exact explicit
  `CENTRALD_ALLOW_CHANNEL_ROLLBACK=YES` environment variable.
- Release verification uses a reproducible commit-derived manifest timestamp.
  A channel-only retry downloads and verifies the immutable release manifests;
  it must never regenerate mutable pointer bytes from ambient environment.
- Signing private keys come only from process environment or an ephemeral secret
  file. They are never command-line values, tracked files, Docker build args, or
  generated manifests.
- `.env.example` documents every release secret; `.env` is gitignored and loaded
  by release/build scripts via `node --env-file-if-exists=.env`.
- `.npmrc` (root and `site/`) hard-enforces `min-release-age=3`; the Docker
  builder images copy it before `npm ci`. `npm >= 12.0.1` is required by both
  package.json engines and installed inside the builder images. Install
  scripts are allowed in the builder images with the allowlist in
  `package.json` (`allowScripts`). npm upgrades use `npm@latest` everywhere
  (CI, both Dockerfiles, setup-docker); never pin a specific npm version.
- `npm run setup:docker` is the handsfree Docker setup for release hosts:
  installs/starts Docker Desktop, verifies the Linux/WSL engine, and pre-pulls
  Linux builder base images. `--all-docker` additionally enables/checks the
  Windows `Containers` feature, verifies both engine modes, and prepares the
  Windows builder.
- `npm run release` builds every platform the host can produce (Windows hosts
  build Windows artifacts on the host and Linux artifacts in the Docker Linux
  engine; `--all-docker` opts into `build.js --target all --container`), and with
  `CENTRALD_RELEASE_PUBLISH=YES` creates and pushes the `v<package-version>`
  tag before publishing. The Docker-built Linux AppImage and Windows NSIS
  installers are Tauri-signed on the host with `tauri signer sign`, never
  inside Docker. The host and both builder images refresh to the latest stable
  Rust before building (`rustup update stable`); `rust-toolchain.toml` pins
  `stable`. Pass release flags after `--`: `npm run release -- --channel beta`
  or `npm run release -- --all-docker`. `CENTRALD_RELEASE_CHANNEL` also
  overrides the tracked channel for one build.
- The S3 mirror is gated on `CENTRALD_S3_ENDPOINT` being set: without it the
  release flow warns loudly and skips the sync (CI stays green), and
  `sync-channel.js` rejects an empty/undetermined channel instead of uploading
  to a bad prefix.
- `scripts/bump-version.js` keeps `package.json`, workspace `Cargo.toml`,
  `tauri.conf.json`, and `Cargo.lock` in lockstep (stale locks break every
  `--locked` build); it refuses invalid SemVer, existing origin tags, and
  disagreeing version fields.
- `npm run qa` needs the site dependencies (`npm ci --prefix site`); CI
  (`ci.yml`, `release.yml`) and `scripts/setup.js` install them. Linux builds
  require `libpam0g-dev` (the client's `pam` crate) in the linux-builder
  Dockerfile, `ci.yml`, and `release.yml`. In `windows-builder.Dockerfile` the
  node-dir `ENV PATH` must be set before the global `npm install -g npm@latest`.

## Update feed and channel switching

- The feed URL derivation lives in two places that must stay in parity:
  `centrald-common/src/build_info.rs::manifest_url_for_channel` (baked via
  `build.rs`) and `scripts/lib/build-config.js`; the contract tests
  (`hardening-contract.test.js`, `build-config.test.js`) pin the mapping:
  CDN set -> `<CDN_BASE_URL>/<channel>/<manifest>` (CDN wins even when
  `UPDATE_BASE_URL` is also set); GitHub without CDN ->
  stable at `/releases/latest/download`, other channels at
  `raw.githubusercontent.com/<repo>/centrald-channels/channels/<channel>/latest`;
  generic origins -> `<repo>/<channel>/latest`.
- `centrald-server channel` derives `updates.manifest_url` through that
  function and **fails closed** when the build has an explicitly configured
  `UPDATE_BASE_URL` without `CDN_BASE_URL` (such a base has no per-channel
  layout; the command must never repoint the feed at a guessed origin).
- Clients refuse to follow any channel other than their own baked
  `RELEASE_CHANNEL` (`UpdateParameters::validate`). A server channel switch
  therefore only affects installs whose baked channel matches; an alpha
  install never follows beta or stable pointers.
- The server fetches release manifests and Minisign signatures with strict
  bounds (signature body capped at 4096 bytes, drained chunk-by-chunk so a
  chunked response cannot grow memory) and verifies with
  `allow_legacy = false`; `UPDATE_BASE_URL_EXPLICIT` is a baked flag from
  `centrald.config`. HTTPS redirects are capped at 3 hops, HTTPS-only, and
  refuse loopback/RFC1918/link-local/ULA IP literals (cross-host public HTTPS
  stays allowed for GitHub Releases). Admin self-update uses the same fetch
  policy: `check_admin_update` / `install_admin_update` Minisign-verify the
  updater JSON, then call the Tauri plugin only if versions match. Do not
  restore `updater:default` in the Admin capability ACL.

## Client update extraction safety

- Linux updates install with `dpkg -i`; Windows updates extract a ZIP that
  must contain `install-client.ps1`, executed via the trusted Windows system
  directory's PowerShell with `-File` (no shell, fixed arguments).
- ZIP entry names must be simple: non-empty, <= 255 chars, no absolute or
  empty path parts, no `.`/`..`, no trailing dot/space, no Windows device
  names (`CON`, `NUL`, `COM1`, ...), and **no `:` anywhere** (drive
  qualifiers and NTFS alternate data streams). After joining, the target must
  still be contained under the extract directory. Bounds: 512 entries max,
  512 MiB per entry, 600 s extraction wall clock, hard total expansion cap.
- Every artifact is verified by exact size, SHA-256, and a Minisign
  signature checked with the baked public key before installation.

## Broker and operation hardening

- The broker verifies grants with a root/SYSTEM-owned copy of the grant
  verifying key (`/var/lib/centrald-broker/grant-signing-public.pem` on Unix,
  `%ProgramData%\CentralD\Broker\grant-signing-public.pem` on Windows). Never
  read the daemon-writable identity PEM for authorization. Enrollment and
  Unix repair publish that copy as root; the unprivileged daemon must not.
- Unix broker sockets are `root:centrald` mode `0660`. `/run/centrald` stays
  `0755` so the unprivileged client can traverse to `broker.sock`; do not
  chmod the runtime directory to `0700` after create. Windows broker pipes
  use `FRFW` (not `GA`). Unix and Windows both cap 64 in-flight connections
  and a 10 s first-frame timeout; Windows first frames must be unframed to
  the JSON body before dispatch.
- Windows broker pipe connections poll for the first frame in non-blocking
  mode with a 10 s timeout (then restore blocking mode before dispatch), and
  a 64-connection in-flight cap drops excess connections instead of
  exhausting threads.
- Operation timeouts terminate the whole child process group gracefully
  first: SIGTERM (Unix) or `taskkill /T` (Windows), a 10 s grace, then
  SIGKILL / `taskkill /T /F` — never SIGKILL apt-get/dpkg while it holds its
  package database.
- Fixed executable paths and fixed argument lists only; bounded merged output
  (64 KiB per job event); no shells spawned by the runner.

## Release tooling map

- `scripts/release.js` — orchestrator and the `release:*` npm actions
  (prepare/build/assemble/sign/manifests/verify/publish/publish-channel);
  `verify()` regenerates manifests byte-deterministically from the release
  commit and runs `npm run qa`.
- `scripts/build.js` — per-target builds; `--target all` on Windows builds
  Windows on the host and Linux in Docker, while `--target all --container`
  opts into both Docker engines (`scripts/lib/docker-engine.js` switches via
  `DockerCli.exe`, ~180 s polling); host-side Tauri signing of container output;
  `--channel`/`CENTRALD_RELEASE_CHANNEL` become a Docker build arg.
- `scripts/sync-channel.js` — S3 mirror of the four signed manifest files
  (release manifest + `.minisig`, Tauri manifest + `.minisig`), refused on
  symlinks, requires `aws` CLI and S3 env; `release.js` calls it as the last
  publish step only when `CENTRALD_S3_ENDPOINT` is set.
- `scripts/setup-docker.js`, `scripts/setup.js` — handsfree release-host and
  workspace setup; `scripts/bump-version.js` — lockstep version + Cargo.lock
  regen; `scripts/sign-release.js`, `scripts/generate-manifests.js`,
  `scripts/check-config.js`, `scripts/check-onboarding.js`, `scripts/qa.js`.
- `scripts/lib/build-config.js` and `crates/centrald-common/build.rs` mirror
  each other for channel detection/URL derivation; `scripts/tests/*.test.js`
  are the contract tests that pin these invariants.

## Release-host environment

The primary release host is a Windows 11 machine with Docker Desktop's Linux/WSL
engine, `gh` authenticated, the `aws` CLI, and `minisign` installed. Windows
artifacts build on the host; the Docker Windows engine is optional behind
`--all-docker`. The
Minisign keypair lives at `~/.config/centrald/minisign.key` (+ `.pub`), the
Tauri keypair at `~/.tauri/centrald.key` (+ `.pub`); public keys are tracked in
`centrald.config`, private material and publish gates only in `.env`
(`TAURI_SIGNING_PRIVATE_KEY` is the key CONTENT, `MINISIGN_SECRET_KEY_FILE` a
path; `MINISIGN_SECRET_KEY_B64` is CI-only). `centrald.config` currently sets
`CDN_BASE_URL=https://updated.centrald.dev` (DO Spaces bucket, sfo2 endpoint,
AWS region us-east-1). `npm run release` requires a clean tree, so commit
before publishing; the first publish creates the `v<package-version>` tag and
the `centrald-channels` branch.

## Docs map

`docs/QUICKSTART.md` (first-run path, guarded by `npm run check:onboarding`),
`docs/OPERATIONS.md`, `docs/RELEASES.md` (channel layout, publish flow, CI
secrets), `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`,
`docs/IMPLEMENTATION_STATUS.md` (authoritative implemented-vs-gated list).
Site content is synced from `docs/*.md` + `SECURITY.md`.

## Security requirements

- No plaintext application traffic and no hardcoded secrets.
- Generate client/Admin private keys locally; never send them to the server.
- Validate role, chain, SAN, expiry, revocation, identity binding, protocol
  version, request size, and all enum/string conversions.
- Redact invitations, passwords, private keys, elevation proofs, and shell bytes
  from logs.
- Prefer typed platform APIs and fixed executable/argument lists over shells.
- Keep project Rust safe. Isolate and explain unavoidable Windows FFI.
- Bound streams, frames, queues, output, timeouts, and retained data.
- Keep memory-hard enrollment hashing off Tokio worker threads and bound concurrent Argon2 work, including local-control invitation create.
- Packaged server listeners use unprivileged ports (1024-65535); do not add CAP_NET_BIND_SERVICE merely for convenience.
- Revalidate root-owned private and public trust files at point of use with no-follow opened-descriptor checks; creation-time permissions and earlier path validation are not enough.
- Admin RPC must not park Tokio workers on blocking config locks; use non-blocking try-lock from `spawn_blocking` and return a retryable busy error.
- Destructive filesystem operations require exact allowlists, ownership markers,
  symlink rejection, and a stopped daemon. Server reset writes a durable journal
  before dropping PostgreSQL, authorizes both the database and any managed role,
  and keeps the data-root marker until every other child has been removed.
- Recommended local PostgreSQL objects use the full server instance UUID and an
  instance-bound role comment. The service login never receives `CREATEDB`; the
  pinned local postgres administrator creates its single owned database. Cleanup
  verifies role ownership plus database owner/comment state; a generated-looking
  name alone is never authority.
- Windows machine roots come from Known Folder APIs. Failure to resolve them is
  fatal for privileged state/ACL operations; never guess `C:\ProgramData` or
  `C:\Program Files`.

## Repository safety

Generated cleanup is limited to marked directories under `coverage`, `dist`,
`release`, and `target`. Reject repository root, drive roots, UNC/traversal,
empty paths, and symlink/junction escapes. Release scripts must not reset,
checkout, or clean source files.

Preserve unrelated user changes and double-check destructive/privileged logic.

## Website

- `site/` is a static Astro 7 documentation site deployed to Cloudflare Pages
  at `centrald.dev` (Pages project root `site`, build `npm ci && npm run build`,
  output `dist`).
- `docs/*.md` and root `SECURITY.md` are the canonical content source.
  `site/scripts/sync-docs.mjs` copies them into the gitignored
  `site/src/content/docs/` with generated frontmatter (title, description,
  order, group); the build always re-syncs first. Never edit
  `site/src/content/docs/` directly and never duplicate doc content in
  site-authored pages.
- `npm run site:dev`, `site:check` (`astro check`), and `site:build` wrap the
  site commands; `npm run qa` runs `site:check` + `site:build`.
- Site pages and layout live in `site/src/pages` and `site/src/layouts`; the
  docs route map (slug/order/group per document) lives in the sync script.

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

`npm test` runs the JS contract tests in `scripts/tests/` (hardening,
channel/URL parity, manifest reproducibility, cleanup safety, bump helper).
Security changes need negative tests for malformed input, wrong role, expiry,
replay, tampering, stale revisions, path escape, partial failure, and reconnect.
If the local environment cannot run a gate, state that explicitly and leave CI
to run it; never claim it passed.

## Current implementation boundary

The enrollment, owned-database setup/config/reset flow, mTLS onboarding and
renewal/activation, invitation lifecycle, basic inventory, leased typed job
protocol (fail-closed on the wire in this alpha), audited remote settings,
client rescue, Admin Tauri updater with Minisign-then-plugin installation
(no WebView updater ACL), packaging,
and immutable manifest/release pipeline are implemented in this alpha tree.
PTY/ConPTY shell transport, the privileged operation runner, OS-vault credential
saving, and server/client package installation remain gated on the wire, broker,
Tauri commands, Hello capabilities, and packaged service enablement.
See `docs/IMPLEMENTATION_STATUS.md`.
