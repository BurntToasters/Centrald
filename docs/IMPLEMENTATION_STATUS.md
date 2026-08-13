# Implementation status

This file distinguishes working alpha paths from deliberately gated security
boundaries. It is not a claim that an uncompiled pre-release checkout is
production-ready.

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
- Privileged broker transport and the concrete operation runner for restart and
  OS-update jobs. The broker runs as root (systemd `centrald-broker.service` /
  Windows `CentralDBroker` SCM service), speaks only over an ACL-restricted
  local channel (`/run/centrald/broker.sock` with peer-credential checks, or a
  DACL-restricted named pipe for `NT SERVICE\CentralDClient`), verifies typed
  server-signed grants, and executes fixed-command operations (service/machine
  restart, check/apply OS updates) with bounded output and a durable
  exactly-once ledger that replays re-dispatched jobs and fails closed on
  interrupted executions. Client service restart, machine restart, and OS update
  check/apply jobs are dispatched end-to-end; terminal jobs and client binary
  installation remain gated.
- PTY/ConPTY terminal streaming is implemented end to end: the Admin opens a
  real terminal (xterm) over a bounded bidi relay; the server validates every
  frame, enforces frame/byte/idle/absolute bounds, and issues OpenLowShell /
  OpenElevatedShell grants; the client daemon relays them to the broker, which
  runs a real PTY/ConPTY session through `portable-pty` with exactly the
  requested OS account. OS-account credentials are validated by the broker (PAM
  / `LogonUserW`), hash-bound to the grant, never stored by the server, and
  optionally saved in the operating-system vault (Windows DPAPI file or the
  freedesktop Secret Service), where Windows vault reads are bounded and
  key/credential buffers are zeroized. Elevated shells require a consumed
  elevation challenge signed by the Admin's locally generated elevation key. Low
  shells run as the managed service account on Linux; low shells on Windows are
  explicitly unsupported in this build. Server housekeeping closes abandoned
  sessions and purges expired elevation challenges; the Admin GUI releases
  session registry entries on every stream exit and never blocks an IPC call on
  a stalled stream.
- Operator-approved client binary installation (`UpdateClient`): the server pins
  the operator-approved version to its latest verified release snapshot and
  applies the configured feed policy; the broker downloads the manifest and
  artifact with strict bounds, verifies channel, pinned version, protocol,
  strict semver monotonicity, SHA-256, and the Minisign signature (build-time
  public key), then installs with dpkg on Linux or the signed installer script
  on Windows. Same-version byte replacement is forbidden.
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
  byte-stable).
- Basic identity/platform/version/health inventory, client/invitation lifecycle,
  typed job submission, revision-checked settings, and operator-approved Tauri
  self-update wiring.
- Linux systemd/`.deb`, Windows virtual-service-account installer/ZIP, Admin
  AppImage/NSIS build paths, locked dependencies, immutable version publishing,
  manifests, Tauri signatures, and Minisign metadata.
- One-command release orchestration: `npm run release` builds every platform a
  Windows or Linux host can produce (Windows hosts build inside both the Docker
  Linux and Docker Windows engines and extract the artifacts), signs the Linux
  AppImage and Windows NSIS installers on the host with the Tauri signer, and
  with `CENTRALD_RELEASE_PUBLISH=YES` creates and pushes the `v<version>` tag
  and publishes. The host and both builder images refresh to the latest stable
  Rust (`rustup update stable`). A `release:bump` helper keeps `package.json`,
  the workspace `Cargo.toml`, and `tauri.conf.json` in lockstep; `.env.example`
  documents all release secrets.

## Deliberately gated

- OS package update check/apply execution on Windows hosts (Debian/Ubuntu is
  implemented); low-privilege shell sessions on Windows (elevated SYSTEM shells
  are implemented).
- Nothing else in the alpha scope remains unimplemented; CI coverage of Windows
  installer and service packaging continues to harden.

## Validation expectation

A release candidate is not ready until CI compiles/tests the Rust workspace on
Ubuntu and Windows, runs frontend checks, exercises PostgreSQL integration
tests, creates native packages, verifies signatures, and tests setup/enrollment/
renewal/reset on disposable machines.
