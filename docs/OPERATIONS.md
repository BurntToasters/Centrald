# Operations

## Default paths

| Purpose              | Default                                              |
| -------------------- | ---------------------------------------------------- |
| Server config        | `/etc/centrald/server.toml`                          |
| Database environment | `/etc/centrald/server.env`                           |
| Server data          | `/var/lib/centrald`                                  |
| Client data          | `/var/lib/centrald-client`                           |
| Local server socket  | `/run/centrald/server.sock`                          |
| Service units        | `centrald-server.service`, `centrald-client.service` |

Advanced `--config` files must use a clean absolute path outside
`/var/lib/centrald`. That data root is deliberately removed by destructive
reset, so storing the durable server configuration beneath it would make crash
recovery ambiguous.

## Normal lifecycle

```text
sudo centrald-server initial-setup
sudo centrald-server config
```

On a packaged Ubuntu Server installation, `initial-setup` enables and starts
`centrald-server.service` automatically after committing setup. Set
`CENTRALD_SKIP_SERVICE_START=1` only for image-building or another deliberate
advanced workflow; source/container installs print the exact manual start
action.

Recommended local PostgreSQL setup refuses a non-empty `/var/lib/centrald`
directory, then writes a root-only, non-secret recovery journal there before the
first PostgreSQL mutation. The service login is always
`NOCREATEDB NOCREATEROLE NOSUPERUSER NOREPLICATION`; a pinned local postgres
administrator creates its one instance-bound database. The journal binds the
attempt to the Linux boot ID, PID, and process start time. A retry never treats
a live owner as abandoned. After an interrupted attempt, rerun
`sudo centrald-server initial-setup`; CentralD retries deterministic cleanup of
its generated role/database and generated files, preserving the journal until
cleanup succeeds. Advanced external PostgreSQL setup uses the same non-secret
recovery journal. Once the protected environment file exists, recovery will drop
only a database carrying this exact server instance's ownership comment; a
missing/mismatched comment fails closed.

Use the config console to create short-lived invitations and to rotate/revoke
Admin identities. Store the offline recovery bundle separately from the server
data directory and back it up offline.

On a Linux client, install the package before enrollment so the `centrald`
service account exists, then run `sudo centrald-client enroll`. Successful
enrollment publishes the active pointer and enables/starts the client service.
Automation on Unix may use an absolute, root-owned, private `--key-file`; every
platform may use piped `--key-stdin`. These forms use the invitation's server
unless `--server` is explicitly supplied and do not request a second interactive
answer. Invitation secrets are deliberately not accepted as command-line values.
Use `sudo centrald-client restart` for the ordinary service restart path.

## Configuration recovery

`centrald-server config` reads the persisted configuration directly and does not
require a healthy daemon. It can repair invalid listeners, database pool limits,
runtime timing, update policy, paths, and TLS public host. It preserves a backup
when replacing the config.

Database credentials remain in the root-only environment file named by
`database.environment_file`; the config stores only the environment variable
name and file path. The file carries the server instance marker. First setup
requires a database name that does not exist and creates the database itself.
After setup, the protected environment file is authoritative; the running daemon
and TUI do not accept a process-level `CENTRALD_DATABASE_URL` override. Advanced
PostgreSQL URLs require an explicit port. Non-loopback hosts require
`sslmode=verify-full`, and query parameters may not override host/user/password/
database identity. Ambient libpq/SQLx `PG*` connection variables are rejected. A
TUI credential/endpoint replacement is accepted only after the target database
proves both CentralD ownership markers for this same server instance;
managed-local database relocation remains an explicit backup/reset/restore
operation.

## Admin loss

Create and revoke Admin identities only from a root terminal on the server. The
console refuses to revoke the last active Admin unless the explicit local force
path is chosen. An Admin invitation is displayed once; create another if it is
lost rather than attempting to recover it. Pending Admin invitations can be
listed and revoked only from the local server console; pending client
invitations can also be revoked by an enrolled Admin.

## Reset

Stop the service and run:

```text
sudo systemctl stop centrald-server
sudo centrald-server --nuke --yes-i-want-to-do-this
```

The command first serializes setup/reset activity, acquires the daemon lock, and
validates every target. It then requires the database comment and installation
row plus the instance-bound managed-role marker before `DROP DATABASE`; a name
match alone is insufficient. Reset state is journaled before the irreversible
step. If PostgreSQL role removal or filesystem cleanup is interrupted, rerun the
exact command and CentralD resumes. The data-root marker is retired only after
all other children are gone, so a partial recursive cleanup retains recovery
authority. Review the printed database name and removed paths. The command is
intentionally not exposed through Admin or local socket RPC. Run `initial-setup`
to create a new installation.

## Logs and secrets

Set `RUST_LOG` for diagnostic verbosity. Do not enable logging that prints RPC
payloads. Invitations, private keys, database URLs, future elevation proofs,
future terminal credentials, and terminal bytes must remain redacted.

## Client recovery and certificate lifetime

Clients and Admin profiles renew certificates before the 30-day remaining-life
threshold. New enrollment and renewal certificates begin pending, are published
locally through a fixed crash-recoverable `current.pointer`, and become active
only after the endpoint proves possession over mTLS. The previous active
certificate remains valid through its original lifetime until activation; after
activation it is retained only for a bounded one-hour rollback window and is
never extended. Use:

```text
sudo centrald-client rescue
sudo centrald-client rescue --repair
sudo centrald-client rescue --bundle /root/centrald-rescue.json
```

The bundle is redacted and contains paths/status metadata, not private keys or
invitation values. On Windows, the network service must run as
`NT SERVICE\CentralDClient` and the isolated privileged broker runs as
LocalSystem (`CentralDBroker` service); on Debian/Ubuntu the broker runs as root
through `centrald-broker.service`. The installer preserves the prior startup
mode during upgrades. Debian package upgrades call `try-restart` only when the
corresponding CentralD service was already active, so an upgraded binary takes
effect without unexpectedly starting an inactive or unenrolled service. A first
installation becomes delayed-auto after successful enrollment unless the
operator explicitly used `-KeepManualStart`; that choice is persisted in the
administrator-owned installation directory.

## PKI lifetime and rotation planning

CentralD issues the offline root for 15 years, online server/client/Admin
issuers for 3 years, and server/client/Admin leaf certificates for 90 days. The
server automatically renews its own leaf when 30 days or fewer remain, using
only the online server issuer. A long-running daemon checks this condition every
six hours and exits after durable renewal so systemd can restart it with the new
identity. Client and Admin leaf renewal use the same 30-day threshold.

Startup refuses expired root/issuer material and warns 365 days before root
expiration and 180 days before an online issuer expires. Treat those warnings as
a required maintenance window. Run `centrald-server config`, choose **Rotate
online PKI issuers**, and provide the separately stored offline-root recovery
PEM. CentralD verifies that the recovery key belongs to the configured root
certificate, stages all three replacement issuers plus a replacement server
leaf, and commits them as one recoverable rotation. Existing client/Admin
certificates continue chaining to the unchanged root while new certificates use
the new issuers. Keep the offline root private key offline except during this
maintenance ceremony.

A server TLS-name, leaf, or online-issuer rotation retains rollback material
until the restarted daemon completes actual enrollment-TLS, client-mTLS, and
Admin-mTLS probes using the configured public TLS name. Only after those
handshakes succeed is the old private material deleted automatically.

Replacing the offline root is a disaster-recovery ceremony, not a routine
rotation: it requires the current offline root recovery PEM, generates a fresh
root, all three issuers, and a new server leaf, and writes the replacement
recovery material to a new root-only file. Every enrolled client and Admin
chains to the old root and must re-enroll after the ceremony. The commit is
journaled with the same crash-recoverable rollback and post-restart TLS-probe
retirement as issuer rotation.

## Update origin

`updates.manifest_url` is server-local-only. Remote Admins can enable/disable
checks and select policy fields, but cannot turn the root-running server into an
arbitrary HTTPS request client. For GitHub repositories, immutable artifacts and
stable manifests stay in GitHub Releases; mutable non-stable channel manifests
are published to the dedicated `centrald-channels` branch. Generic deployments
may set an explicitly managed `UPDATE_BASE_URL` at build/setup time.

Non-stable channel updates are monotonic by Semantic Versioning and both
manifests move in one branch commit. A channel-only retry downloads the exact
immutable release assets and does not regenerate them. Emergency rollback is an
explicit operator action requiring `CENTRALD_ALLOW_CHANNEL_ROLLBACK=YES`.

## Client state coordination

Enrollment, renewal, reenrollment, daemon pointer recovery, and privileged
repair share one fixed cross-process client-state lock. The daemon releases this
lock before opening its long-lived control stream. On Unix the lock inode is
`/var/lib/centrald-client.lock`, directly below root-owned `/var/lib`, so the
managed service account cannot unlink and replace it.

Unix enrollment persistence, failed-generation cleanup, and privileged repair
start from already-open fixed-root directory descriptors. Every state component
is opened with no-follow semantics, ownership and modes are applied through the
open descriptors, and regular files must have a single link. The advisory lock
coordinates CentralD processes; the descriptor-relative traversal is the
containment boundary against rename and symlink substitution.

Admin profile activation and renewal are serialized by a per-profile
cross-process lock. Multiple GUI processes therefore cannot publish competing
credential generations for the same profile.

Windows state ACLs remain installer-owned. `rescue --repair` refuses to rewrite
Windows ACLs and directs the operator to rerun the signed installer as
Administrator. The manual-start policy marker lives beneath the
administrator-owned installation directory, not the service-writable data
directory.
