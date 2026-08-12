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
- Basic identity/platform/version/health inventory, client/invitation lifecycle,
  typed job submission, revision-checked settings, and operator-approved Tauri
  self-update wiring.
- Linux systemd/`.deb`, Windows virtual-service-account installer/ZIP, Admin
  AppImage/NSIS build paths, locked dependencies, immutable version publishing,
  manifests, Tauri signatures, and Minisign metadata.

## Deliberately gated

- Privileged Linux/Windows broker transport and the concrete operation runner.
- PTY/ConPTY terminal streaming, OS-account authentication, and saved
  credentials through Windows Credential Manager/DPAPI or Linux Secret Service.
- OS update execution and server/client binary installation.
- Offline-root recovery ceremony and external append-only audit export.

The Admin terminal must remain disabled until the PTY, broker, authentication,
timeout, and credential-vault boundaries are complete. Never substitute an
arbitrary command runner.

## Validation expectation

A release candidate is not ready until CI compiles/tests the Rust workspace on
Ubuntu and Windows, runs frontend checks, exercises PostgreSQL integration
tests, creates native packages, verifies signatures, and tests setup/enrollment/
renewal/reset on disposable machines.
