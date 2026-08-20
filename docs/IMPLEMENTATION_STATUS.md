# Implementation status

This file distinguishes working alpha paths from deliberately gated security
boundaries. Tagging a numeric `0.1.0` (or later) means **enrollment and
inventory are operator-stable on LAN/VPN**, not that every v1 product goal
(jobs, shell, remote package install) is live. Gated surfaces stay fail-closed
until their gates flip with acceptance tests.

## Implemented in this hardening tree

- Guided/non-interactive `centrald-server initial-setup` and the local
  `centrald-server config` console.
- Recommended local PostgreSQL provisioning plus an advanced external-URL path.
  Managed local role/database names use the full server UUID, role and database
  comments bind them to that exact instance, setup writes non-secret recovery
  state before PostgreSQL mutation, the service login never receives `CREATEDB`,
  and inherited libpq environment cannot redirect the pinned local
  administrator.
- Creation of a new dedicated PostgreSQL database only; setup refuses an
  existing database and binds the database comment plus an internal singleton
  row to the server instance.
- Marker-, ownership-, and lock-protected `--nuke --yes-i-want-to-do-this` with
  complete filesystem preflight, durable resume phases, managed-role ownership
  verification, refusal to adopt a non-empty setup data root, and marker-last
  data-root cleanup.
- Offline root recovery material, role-specific online issuers, server identity,
  guided crash-recoverable online-issuer rotation, signing-chain-bounded
  certificate validity, startup plus six-hour server-leaf renewal checks, and
  instance-bound root-only database environment files.
- One `centrald-invite1` format, Argon2id storage, transactional one-time use,
  and listing/revocation of unused invitations within the permitted role scope.
  Server-side invitation hash/verify runs off Tokio worker threads behind a
  shared concurrency limit (including local-control create). Interactive
  enrollment hides the bearer token; automation accepts a protected Unix key
  file or piped standard input rather than a public command-line value.
- Point-of-use secure reads for root private/public server material use
  no-follow opened-descriptor validation (`O_NOFOLLOW` + `fstat`) rather than
  check-then-pathname reads. Packaged listener ports must be 1024-65535.
- Client/Admin local key generation, pinned-TLS enrollment, pending identity and
  certificate activation after durable local publication, automatic renewal
  before expiry, per-profile Admin renewal locking, and fixed crash-recoverable
  active-generation pointers.
- Atomic client identity-generation persistence, Linux ownership handoff,
  explicit Windows state/Admin-key ACLs, fail-closed Windows Known Folder
  resolution, and a real Windows SCM service host.
- Server-directed client heartbeat intervals.
- Hello-first bounded control streams, periodic client and Admin-stream
  revocation/expiry checks, delivery acknowledgements, execution-start leases,
  job lifecycle maintenance, bounded Admin stream concurrency, and transactional
  job-event sequence/state/output limits.
- `centrald-client rescue` diagnostics, redacted bundle creation, Unix
  descriptor-relative fixed-root permission repair while the service is stopped,
  and a separately requested bounded service restart. Windows ACL repair remains
  installer-owned and is refused by the runtime command.
- Offline-root replacement ceremony through `centrald-server config`, authorized
  only by the current offline root recovery key, journaled with the same
  crash-recoverable rollback and post-restart TLS-probe retirement used by
  issuer rotation, and writing the replacement recovery bundle to a new
  root-only file. Every enrolled device must re-enroll after the ceremony.
- External append-only audit export: `centrald-server config` exports the
  verified PostgreSQL audit hash chain into root-owned
  `centrald-audit-<from>-<to>.jsonl` files that are never rewritten; each batch
  re-verifies `previous_hash`/`entry_hash` chaining against the previous export
  file's tail hash and recomputes every record hash from its canonical bytes
  (timestamps are normalized to Postgres microsecond precision at append time —
  including local server-console audits — so read-back verification is
  byte-stable). This is a local JSONL export, not the threat-model external
  audit sink.
- Basic identity/platform/version/health inventory, client/invitation lifecycle,
  revision-checked settings, and operator-approved Tauri self-update wiring
  (Minisign-verified updater JSON once for availability; install requires the
  plugin feed JSON to match that verified body, then Tauri `.sig`). The WebView
  has no `updater:default` capability. Typed job and shell RPCs exist but fail
  closed on the wire until
  `PRIVILEGED_OPERATIONS_ENABLED` / `TERMINAL_SESSIONS_ENABLED` are release
  gates. Client Hello advertises only `heartbeat`. The broker verifies grants
  with a root/SYSTEM-owned copy of the grant verifying key, not the
  daemon-writable identity PEM. Packaged brokers stay installed but are not
  enabled or auto-started.
- Linux systemd/`.deb`, Windows virtual-service-account installer/ZIP, Admin
  AppImage/NSIS build paths, locked dependencies, immutable version publishing,
  manifests, Tauri signatures, and Minisign metadata.
- One-command release orchestration: `npm run release` builds every platform a
  Windows or Linux host can produce (Windows hosts build Windows targets with
  the host toolchain and Linux targets in Docker; `--all-docker` opts into the
  Docker Windows-engine path), signs the Linux AppImage and Windows NSIS
  installers on the host with the Tauri signer, and with
  `CENTRALD_RELEASE_PUBLISH=YES` creates and pushes the `v<version>` tag and
  publishes. The host and both builder images refresh to the latest stable Rust
  (`rustup update stable`). A `release:bump` helper keeps `package.json`, the
  workspace `Cargo.toml`, and `tauri.conf.json` in lockstep; `.env.example`
  documents all release secrets.

## Deliberately gated

- Privileged operation execution, including remote service/machine restart, OS
  updates, and client package installation. Protocol, broker, runner, Tauri, and
  package-enablement paths fail closed; GUI disable flags are not the security
  boundary.
- PTY/ConPTY shell transport and credential saving. The Admin Terminal nav entry
  is hidden while gated; server/broker/Tauri commands reject sessions; no
  password is loaded from or saved to a vault.
- Server/client package installation. Build artifacts exist for manual alpha
  testing, but CentralD does not remotely install itself in this release.

## Validation expectation

A release candidate is not ready until CI compiles/tests the Rust workspace on
Ubuntu and Windows, runs frontend checks, runs the PostgreSQL migrate smoke job,
builds and installs Linux `.deb` packages in CI (file/unit smoke), verifies
release signatures on the release path, and operators still exercise
setup/enrollment/renewal/reset on disposable machines before the tag.

Windows NSIS/ZIP install smoke remains a release-host / disposable-VM checklist
item until an equivalent Windows CI job exists.
