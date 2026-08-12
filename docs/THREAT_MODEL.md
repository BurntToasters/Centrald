# Threat model

## Protected assets

- Offline root, online issuer, grant-signing, Tauri, and Minisign private keys.
- PostgreSQL identity/job/audit state and its credentials.
- Client and Admin private identities.
- Admin elevation keys and future saved OS credentials.
- Privileged broker authority.
- Interactive terminal data.
- Release manifests and distributable binaries.

## Assumed environment

- The server is operated by a trusted root user on Ubuntu Server.
- Client/Admin invitations are delivered over a trusted out-of-band channel.
- LAN/VPN peers are not automatically trusted; an attacker may observe, block,
  replay, redirect, or modify network traffic.
- A compromised managed client must not grant authority over other clients or
  the server.
- A compromised Admin identity is full-access in v1 until it is revoked.

## Principal threats and controls

### Stolen or raced invitation

An invitation is short-lived, role-bound, one-time, revocable before use, and
stored as an Argon2id hash. Enrollment locks and consumes it transactionally.
Remote Argon2 work runs off the async executor and is fail-fast
concurrency-bounded so invitation checking cannot monopolize the server's Tokio
workers or memory. Theft before use can still authorize the thief; trusted
delivery and short TTL are required.

### Network redirection during enrollment

The invitation embeds the CA and exact TLS name. A destination override does not
change TLS verification. The CSR and bearer secret are sent only after the TLS
handshake validates that trust.

### Forged client/Admin identity

Every mTLS request validates chain, role-specific issuer, certificate validity,
identity revocation, and the exact presented-certificate fingerprint against the
certificate registry. Enrollment and renewal certificates remain pending until
the endpoint durably publishes the private key and proves possession over mTLS.
Control streams require one bounded Hello first and periodically reauthorize the
certificate. Admin job-stream concurrency is capped, and certificate issuance
never grants validity beyond the shortest-lived parent in the signing chain.
Protocol major versions are checked at enrollment and control boundaries.

### Privileged-operation replay or substitution

The planned broker accepts only signed typed grants bound to a device,
job/session, operation, exact parameter hash, nonce, and short validity window.
Consumed grant IDs are replay-protected. No generic shell command is a durable
job.

### Terminal abuse

PTY/ConPTY traffic must be bounded, sequenced, non-persistent, and protected by
idle/absolute limits. The UI must treat terminal escape sequences as untrusted.
Credentials are never sent to the server for storage and may be saved only in an
OS vault. This subsystem is currently disabled.

### Update-feed or artifact substitution

Channel manifests are mutable but signed artifacts use immutable URLs. The
shared manifest records digest, size, and Minisign signature URL; Admin updater
artifacts additionally carry Tauri signatures. Installation requires explicit
approval. Public verification keys are compiled from tracked configuration.

### Destructive path or database confusion

Repository cleanup is allowlisted and marker-protected. Server reset rejects
symlinks and shallow/root paths, serializes against setup, holds the daemon
lock, and requires the instance-bound data/environment markers, database comment
and installation row, plus any managed-role marker. It journals authorization
before the database drop and keeps the data-root marker until all other children
are removed, allowing an exact retry after partial cleanup. Generated-looking
PostgreSQL names alone are never trusted, and setup never adopts an existing
database.

### Local secret-file tampering

The server revalidates private keys and the database credential file at each
runtime read. They must remain root-owned, single-linked regular files with no
group/other permissions and bounded size. Package-managed paths and ancestor
checks prevent configuration from redirecting these reads.

### Stale or conflicting configuration writes

Admin updates carry an expected revision. The server rejects stale changes,
validates the complete candidate, atomically replaces the file, preserves a
backup, and reports restart requirements. Sensitive trust settings remain local.

### Database-only audit tampering

Database audit metadata is useful but does not protect against a server-root or
PostgreSQL-superuser compromise. An external append-only audit sink is a future
hardening item.

## Required negative tests before stable

Malformed/oversized/revoked invitation, wrong role, expired/consumed key,
concurrent consumption, invalid CSR, unknown/expired/pending certificate,
renewal publication failure, wrong certificate role, revoked identity, protocol
mismatch, invalid heartbeat interval, non-monotonic job events, invalid terminal
state transitions, output-limit overflow, stale configuration revision, manifest
path/URL substitution, digest/signature mismatch, broker replay, symlink/path
escape, existing/wrongly owned database, channel downgrade/same-version
replacement, client pointer/enrollment races, secret debug leakage, and partial
setup/reset failure.
