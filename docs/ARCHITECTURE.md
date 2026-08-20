# Architecture

```text
                         server-local root console
                       centrald-server config / nuke
                                  |
                        root-authenticated Unix IPC
                                  |
Admin (Tauri/Rust) -- Admin mTLS --+--> CentralD server <-- client mTLS -- client daemon
                                  |           |
                                  |       PostgreSQL
                                  |           |
                                  +---- typed jobs / transient streams
                                                   |
                                      ACL-restricted local broker
                                      (root/SYSTEM, no network)
```

## Server processes and listeners

The server has three independent TLS listeners with distinct ports and
certificate roles:

1. Enrollment: server-authenticated TLS. It accepts only one-time client/Admin
   invitations and certificate signing requests.
2. Client control: mTLS. Managed clients maintain outbound control streams.
3. Admin API: mTLS. Admin identities access inventory, client lifecycle, typed
   jobs, and the allowed remote settings subset.

The default ports are 7443, 7444, and 7445. Advanced configuration may move them
within the unprivileged 1024-65535 range; the packaged unit intentionally has no
`CAP_NET_BIND_SERVICE`. The server certificate's DNS/IP identity is
`server.public_host`; changing it locally issues a new server leaf from the
persisted online server issuer.

Local management uses `/run/centrald/server.sock`. Kernel peer credentials must
identify root. Packaged security roots are fixed at `/etc/centrald`,
`/var/lib/centrald`, and `/run/centrald`; configuration does not turn
root-written secret paths into arbitrary filesystem capabilities. The config
console can also edit and repair persisted files while the daemon is stopped.

## Setup and persistence

`centrald-server initial-setup` refuses to adopt a non-empty pre-existing data
root. Its recommended PostgreSQL path creates the restricted service login with
no database-creation or role-management privilege, then uses the pinned local
postgres administrator to create the one instance-bound database. It creates:

- a validated server TOML configuration;
- a root-only PostgreSQL environment file;
- a marked server data root;
- an offline root recovery bundle at an operator-selected path;
- online server, client, and Admin issuers;
- server TLS identity and grant-signing keys;
- a previously nonexistent dedicated database, migrations, an instance-bound
  database comment, and an internal installation marker;
- the first one-time Admin invitation.

Ordinary local configuration replacements retain a bounded set of uniquely named
backups. Journaled remote settings transactions reuse their recovery copy
instead of creating a second plaintext backup. Secret files are mode `0600` on
Unix. PKI rotation/offline-root recovery journals and their backups are read
back through root-owned, no-follow, size-bounded secure reads, and every
rollback rename revalidates the destination's ancestors, so an interrupted
ceremony cannot be redirected by a swapped directory. Reset preflights all
targets, holds the same runtime lock as the daemon, and requires the
data/environment markers, database comment and installation row, and any managed
local-role comment to agree on the server instance before dropping PostgreSQL
objects. A durable reset journal separates authorized, database-dropped, and
cleanup retry behavior. The root data marker is removed last, after every other
data child, so interrupted cleanup remains recoverable. The external offline
recovery bundle is preserved.

## Invitation bootstrap

`centrald-invite1` contains JSON claims, a 256-bit random bearer secret, and an
integrity code. Claims include the invitation ID, server instance, role, name,
TLS name, ports, root CA, and expiry. The complete token is Argon2id-hashed in
PostgreSQL.

The client/Admin parses the invitation locally, builds a trust store from the
embedded CA, connects to an operator-supplied IP/FQDN or the embedded TLS name,
and always verifies the embedded TLS name. It then generates its key and CSR
locally. Server enrollment locks the invitation row, verifies the full token,
checks role/expiry/unused state, issues a short-lived pending certificate,
creates the pending identity, and marks the invitation consumed in one
transaction. The endpoint publishes its credential locally and then activates it
by proving possession over mTLS. Pending invitations are listable and revocable
without ever returning their bearer secret again.

## Admin identity and configuration

An Admin access key is used once. The desktop app creates:

- a local mTLS key and CSR;
- a profile containing the resulting certificate, server CA, endpoint, and TLS
  name.

Terminal authorization fields are reserved scaffolding. PTY/ConPTY sessions,
OS-account authentication, and saved credentials remain disabled until the
complete privileged broker and operating-system vault path is release-gated.

Remote configuration reads omit secret locations (data root, PKI paths, database
URL, local socket). Writes include an expected revision derived from the current
serialized configuration. A stale write is rejected. The server validates the
full candidate configuration, uses a shared cross-process lock, journals the
original and intended revision, atomically replaces it, durably audits the
change, and reports that restart is required. Channel, manifest URL, and
`allow_prerelease` stay server-local.

Admin lifecycle, PKI paths/rotation, database secret location, local socket,
data root, and destructive reset are local-only.

## Client privilege split

The Linux package creates an unprivileged `centrald` user and stores client data
under `/var/lib/centrald-client`. Windows installs the network daemon under the
virtual account `NT SERVICE\CentralDClient` and applies explicit program/state
ACLs rather than relying on LocalSystem or inherited permissions. The network
daemon owns only network identity and control-stream state.

Privileged machine changes run through a separate local broker running as
root/SYSTEM (`centrald-broker.service` on Debian/Ubuntu, `CentralDBroker` SCM
service on Windows). The broker has no network listener and accepts only typed,
short-lived, device-bound grants signed by the server, with parameter hashes and
replay protection, over an ACL-restricted local channel
(`/run/centrald/broker.sock` with peer-credential checks, or a DACL-restricted
named pipe). An exactly-once durable ledger replays re-dispatched jobs and fails
closed on interrupted executions. Terminal (PTY/ConPTY) operations and client
binary installation remain disabled in this alpha.

## Jobs and terminal streams

PostgreSQL stores typed jobs, delivery and execution-start leases,
sequence-checked state transitions, bounded output events, basic inventory,
pending/active/retiring identity certificates, and audit metadata. A client that
acknowledges delivery but does not emit its first event loses the short
execution-start lease and the job is requeued. Long-lived Admin job streams are
bounded by a global semaphore and periodically reauthorize the presented
certificate. Client/Admin leaves are capped by the remaining validity of every
signing certificate; an issuer cannot create a child that outlives its chain.
Interactive terminal bytes are never durable.

The final terminal path will multiplex PTY/ConPTY frames between Admin, server,
and client with bounded frame sizes, sequence checks, backpressure, explicit
resize/close frames, and timeouts. Account authentication and optional saved
credentials require operating-system vault integration. Until that path exists,
the desktop terminal remains gated rather than falling back to an unsafe generic
command runner.

## Releases and updates

`centrald.config` is compiled into runtime build information and read by release
tools. Mutable channel manifests are separate from immutable versioned
artifacts. The shared YAML manifest covers server, client, and Admin packages;
the Tauri JSON manifest covers Admin updater artifacts.

All packages have SHA-256 and Minisign verification. Admin updater packages also
have Tauri signatures. The Admin app registers the Tauri updater and exposes an
operator-approved check/download/install action. The server performs
incrementally bounded, HTTPS-only release-manifest checks and records
availability snapshots; the manifest URL itself is server-local-only. GitHub
version artifacts are immutable releases while non-stable channel manifests are
updated together in one non-forced branch commit on the dedicated
`centrald-channels` branch. Strict Semantic Versioning prevents an accidental
channel downgrade; channel-only retries reuse the exact immutable manifest
assets. Server/client package installation remains gated in this alpha.
