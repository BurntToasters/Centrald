# Security policy

CentralD controls privileged machines. Treat every protocol, installer, update,
local IPC, and destructive operation as security-sensitive.

Alpha builds are supported only on private LANs or VPNs. Do not expose the
server directly to the public Internet.

Report vulnerabilities privately to the repository owner. Never include live
invitations, private keys, database credentials, elevation material, or shell
transcripts in a report.

## Trust bootstrap

CentralD does not download a CA over an unauthenticated first connection. A
trusted operator delivers one self-contained, one-time invitation. It embeds the
server's public root CA and exact TLS name; only the network destination may be
overridden. Enrollment sends the invitation and CSR only after normal TLS
certificate validation succeeds.

An invitation is a short-lived bearer credential. Anyone who obtains it before
use may race the intended device, so deliver it over a trusted channel. The
server stores an Argon2id hash, enforces role and expiry, and consumes it once
in the enrollment transaction.

Admin invitations are exchanged for locally generated mTLS identities. They are
not durable API keys and are not retained by the Admin app.

## Non-negotiable properties

- No plaintext control traffic or trust-on-first-use.
- No client private key leaves the client; no Admin private key leaves Admin.
- No client-initiated update discovery.
- No arbitrary durable command runner or untyped privileged broker messages.
- No remote shell transcript persistence.
- No plaintext saved terminal credentials; OS-vault integration is required.
- No update installation without explicit operator approval and signature
  verification.
- No destructive cleanup without a repository/data ownership marker, path
  validation, symlink rejection, and durable retry state. The server data-root
  marker remains until every other child has been removed.
- Generated local PostgreSQL names are not ownership proof. Role comments,
  database owner/comment state, and the internal installation row must bind the
  objects to the exact server instance before cleanup. The service login never
  receives `CREATEDB`; the pinned local administrator creates its single owned
  database. Setup refuses to mark a non-empty pre-existing data root as owned.
- No remote Admin creation, Admin revocation, PKI mutation, database-secret
  mutation, or destructive reset.
- Enrollment password hashing is memory-hard and concurrency-bounded so it
  cannot monopolize async runtime workers.
- Private server keys and the database credential file are revalidated as
  root-owned, single-linked, private files before runtime use.
- Packaged server listeners stay on ports 1024-65535 because the hardened unit
  has an empty capability bounding set.
- Privileged repair and root-written secret operations use package-managed
  security roots; configuration-provided paths are never authority for recursive
  ownership or ACL repair. Unix repair and root enrollment use
  descriptor-relative no-follow traversal. Windows ACL replacement is
  installer-only, and Windows system executables are resolved through
  operating-system APIs rather than PATH or process environment variables.

## Release integrity

The shared release manifest contains SHA-256 digests, sizes, immutable artifact
URLs, and separate Minisign signature URLs. Every artifact must have a verified
`.minisig`. Tauri updater `.sig` files are additional signatures used only for
Admin AppImage/NSIS updates.

Private signing material must be supplied through protected CI secrets or an
ephemeral mode-`0600` file and erased after use. Public verification keys belong
in tracked `centrald.config`.

## Known alpha limitations

Privileged jobs, PTY/ConPTY shells, OS-vault credential saving, and remote
package installation stay fail-closed on the wire and in the Admin GUI. Admin
self-update is operator-initiated: Rust commands Minisign-verify the updater
JSON, then install only when the Tauri plugin version matches that signed feed.
The WebView has no updater plugin ACL. Client rescue and certificate renewal are
implemented but still require platform integration testing. Scaffolded UI or
protocol surfaces are not a security boundary. See
`docs/IMPLEMENTATION_STATUS.md`.
