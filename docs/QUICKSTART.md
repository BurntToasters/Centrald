# CentralD quick start

This is the recommended path for a first CentralD homelab. Advanced network,
database, PKI, storage, and release settings are available later; you do not
need them for normal enrollment.

## 1. Initialize the Ubuntu server

Install the CentralD server package and PostgreSQL, then run:

```text
sudo centrald-server initial-setup
```

The wizard asks for the public DNS name/IP, PostgreSQL setup mode, offline-root
recovery location, and first Admin name. The recommended mode configures local
PostgreSQL automatically; only the advanced mode asks for a database URL. It
creates the dedicated database, PKI, server identity, and one-time Admin access
key. On a packaged systemd installation it also enables and starts
`centrald-server.service`.

Move the offline-root recovery PEM off the server after setup. Keep the one-time
Admin access key only long enough to enroll the Admin app.

If setup says the service was not started, run:

```text
sudo systemctl enable --now centrald-server
```

If the machine loses power, PostgreSQL stops, or `initial-setup` is otherwise
interrupted while using the recommended local PostgreSQL option, do **not** edit
PostgreSQL by hand. Rerun the same command:

```text
sudo centrald-server initial-setup
```

CentralD records non-secret crash-recovery state before it creates the generated
role or database. A retry refuses to interfere with a still-running setup
process and cleans only CentralD-owned PostgreSQL resources from an abandoned
attempt before restarting the wizard. The advanced external-database path uses
the same non-secret setup journal; if a crash happens in PostgreSQL's narrow
`CREATE DATABASE`-before-ownership-comment window, CentralD fails closed and
asks you to inspect that dedicated database instead of guessing that it owns it.

## 2. Open guided server management

```text
sudo centrald-server config
```

Routine choices are listed first. Use **Add a client (guided)** to create a
short-lived invitation and **Health, status, and next steps** to confirm the
server is healthy. Items marked **advanced** are optional for normal operation.

## 3. Enroll a client

Install the CentralD client package on the Linux or Windows machine. On Linux:

```text
sudo centrald-client enroll
```

Paste the one-time client invitation. The invitation already contains the
trusted CA, TLS name, and service ports; an optional IP/FQDN override changes
only the network destination. Successful Linux enrollment enables and starts the
client service automatically.

On Windows, install from an elevated PowerShell session and follow the
installer's final next-step message, then run `centrald-client enroll` from an
elevated terminal when the machine is not yet enrolled.

For unattended enrollment, keep the invitation out of process arguments and
shell history. Put it in a private file and run:

```text
sudo install -o root -g root -m 600 /path/to/invite /root/centrald-client.invite
sudo centrald-client enroll --key-file /root/centrald-client.invite
rm -f /root/centrald-client.invite
```

The protected-file option is Unix-only and validates the opened inode and its
directory chain. A secret manager on any platform may instead pipe one token to
`--key-stdin`. Both automation forms use the server embedded in the invitation
unless `--server` is supplied and therefore do not stop for another prompt.
Running without key flags remains the recommended interactive wizard.

## 4. Enroll CentralD Admin

Open the Admin application and choose **Add server**. Paste the one-time Admin
access key from `initial-setup` or from `centrald-server config`. The Admin app
generates its own mTLS private key locally.

After connecting, the **Getting started and common tasks** panel remains
available as a checklist. Routine non-secret settings can be managed in the GUI.
Admin lifecycle, PKI, database secrets, update origin/channel, and destructive
reset remain server-local.

## 5. Day-to-day operation

Use the Admin GUI for inventory, enrollment invitations, revocation, and safe
remote settings. Use `centrald-server config` for local-only trust and advanced
server controls.

Privileged client operations, remote CentralD installation, PTY/ConPTY terminal
sessions, and credential saving remain visibly disabled in this alpha. Their
protocol and broker code is security scaffolding, not an operator-ready path.
Use the Admin GUI for the implemented inventory, invitation, revocation, typed
queue, and safe settings flows only.

PKI maintenance: `centrald-server config` offers online-issuer rotation (uses
the offline root recovery PEM) and, for disaster recovery, an offline-root
replacement ceremony that requires the current root recovery key and writes a
new recovery bundle; every enrolled device must re-enroll afterwards. The same
console exports the verified audit chain to root-owned, append-only
`centrald-audit-<from>-<to>.jsonl` files.

## Recovery

Client diagnostics:

```text
sudo centrald-client rescue
sudo centrald-client rescue --repair
sudo centrald-client restart
```

Server configuration remains repairable while the daemon is stopped:

```text
sudo centrald-server config
```

The destructive reset is intentionally local and explicit:

```text
sudo centrald-server --nuke --yes-i-want-to-do-this
```

The reset is journaled. If the command reports incomplete PostgreSQL-role or
filesystem cleanup, correct the reported problem and rerun the same command; do
not delete the recovery journal or edit ownership markers manually.

## PostgreSQL setup

For a normal Ubuntu Server install, choose **Recommended: configure local
PostgreSQL automatically**. CentralD creates a dedicated local role/database and
stores the generated password only in the root-protected server environment
file. The service login has no `CREATEDB`, role-management, superuser, or
replication authority; the pinned local postgres administrator creates its one
owned database. Setup refuses a non-empty `/var/lib/centrald` directory instead
of claiming unrelated files. Choose the advanced URL option only when you
intentionally use an existing or remote PostgreSQL server.
