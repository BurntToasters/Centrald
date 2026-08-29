# CentralD quick start

This is the recommended path for a first CentralD homelab. Advanced network,
database, PKI, storage, and release settings are available later; you do not
need them for normal enrollment.

**This release’s live path** is server setup, one-time invitations, client and
Admin enrollment, inventory, invitation lifecycle, and safe remote settings.
Privileged jobs, remote package install, and PTY/ConPTY terminal sessions stay
fail-closed until their security gates are release-ready—do not treat this build
as a full remote-management suite.

## Homelab VM test

Use disposable Linux packages from a Linux build host:

```text
npm run build:linux:x64:native
```

Do **not** run `npm run release` on Linux; that path fails closed because a
complete GitHub release also needs Windows artifacts.

Recommended layout:

- Ubuntu Server 24.04 VM for `centrald-server` (headless is fine).
- Ubuntu Server 24.04 VM for `centrald-client`.
- A **graphical** Linux or Windows workstation for CentralD Admin. Do not expect
  the AppImage to run on a headless server console.
- Optional Windows VM for the client installer.

**TLS name is the most common first-enroll failure.** The wizard prompt is
`TLS name clients should verify (LAN DNS name or IP)`. It may suggest this
machine's hostname. Other VMs usually cannot resolve that name. For a homelab
without DNS, enter the server's LAN IPv4 address (for example `192.168.1.20`).
That value is baked into the invitation and certificates. A later connection
override only changes where TCP goes; TLS still verifies the invitation name.

Ubuntu 24.04 Server typically ships with **ufw inactive**. If you never enable
it, QUICKSTART `ufw allow` commands are optional. If you _do_ enable ufw, open
7443–7445 **before** `ufw enable`, and keep SSH allowed. Also check the
hypervisor or cloud security group; it is independent of ufw. Do not expose
PostgreSQL (`5432`) to other VMs — CentralD uses `127.0.0.1` on the server.

apt on 24.04 pulls **PostgreSQL 16** for the `postgresql` dependency.

After setup, Admin Health may show a release-manifest check error until the
first signed CDN publish exists. That does not block enrollment.

## 0. Network and clock prerequisites

Before enrollment, confirm every machine has accurate time (NTP) and that the
server can receive CentralD traffic.

```text
timedatectl status
# Enable NTP if needed, then:
sudo timedatectl set-ntp true
```

Enrollment invitations and certificates use wall-clock expiry. Large clock skew
looks like an expired invitation even when the token was just created.

On the **server**, allow inbound TCP for the three TLS listeners (defaults):

| Port | Listener                              |
| ---- | ------------------------------------- |
| 7443 | Enrollment (server-authenticated TLS) |
| 7444 | Client mTLS                           |
| 7445 | Admin mTLS                            |

Example with `ufw` (adjust if you changed listeners in
`centrald-server config`):

```text
sudo ufw allow 7443/tcp
sudo ufw allow 7444/tcp
sudo ufw allow 7445/tcp
sudo ufw reload
```

**Clients and Admin** only make outbound connections; they do not need inbound
CentralD ports. Keep them on the same LAN or VPN as the server.

## 1. Initialize the Ubuntu server

Install the CentralD server package with apt so PostgreSQL is pulled in
automatically, then run setup:

```text
sudo apt install ./centrald-server_*.deb
sudo centrald-server initial-setup
```

The installer prints that setup command until `/etc/centrald/server.toml`
exists. The wizard asks for the TLS name clients verify (LAN DNS name or IP; it
suggests this machine's hostname when that name is usable). For VMs without
shared DNS, type the server's LAN IP instead of accepting the hostname.
PostgreSQL setup mode, offline-root recovery location, and first Admin name
follow. Accept the recommended local PostgreSQL option unless you already run a
dedicated database. It creates the dedicated database, PKI, server identity, and
one-time Admin access key. On a packaged systemd installation it also enables
and starts `centrald-server.service`.

Move the offline-root recovery PEM off the server after setup. Keep the one-time
Admin access key only long enough to enroll the Admin app.

The Admin Linux AppImage is a Tauri/WebKitGTK app, not Electron. It needs a
graphical session and FUSE 2 (`libfuse2t64` lives in Ubuntu **universe**). Do
**not** install the `fuse` package to make AppImages work — that can break
desktop session mounts. If `apt` cannot find `libfuse2t64`, enable universe
first:

```text
sudo add-apt-repository universe
sudo apt update
sudo apt install libfuse2t64
chmod +x centrald-admin_*.AppImage
./centrald-admin_*.AppImage
```

`--appimage-extract-and-run` is a diagnostic fallback when FUSE is unavailable.
Do not pass Electron flags such as `--no-sandbox`; they are not a Tauri AppImage
interface.

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

## 2. Enroll CentralD Admin

Open the Admin application and choose **Add server**. Paste the one-time Admin
access key from `initial-setup`. The Admin app generates its own mTLS private
key locally.

After connecting, the **Getting started and common tasks** panel remains
available as a checklist. Create client invitations from the GUI. Routine
non-secret settings can be managed in the GUI. Admin lifecycle, PKI, database
secrets, update origin/channel, and destructive reset remain server-local.

The local console is optional after the first Admin enroll:

```text
sudo centrald-server config
```

Routine choices are listed first. Use **Add a client (guided)** if you prefer to
mint invitations on the server, and **Health, status, and next steps** to
confirm the server is healthy. Items marked **advanced** are optional for normal
operation.

## 3. Enroll a client

Install the CentralD client package on the Linux or Windows machine. On Linux:

```text
sudo apt install ./centrald-client_*.deb
sudo centrald-client enroll
```

Paste the one-time client invitation. The invitation already contains the
trusted CA, TLS name, and service ports; an optional IP/FQDN override changes
only the network destination. Successful Linux enrollment enables and starts the
client service automatically.

On Windows, install from an elevated PowerShell session and follow the
installer's final next-step message. The installer does not add CentralD to
`PATH`; enroll with the quoted install path when the machine is not yet
enrolled:

```text
& "C:\Program Files\CentralD\centrald-client.exe" enroll
```

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

## 4. Day-to-day operation

Use the Admin GUI for inventory, enrollment invitations, revocation, and safe
remote settings. Use `centrald-server config` for local-only trust and advanced
server controls.

Privileged client operations, remote CentralD installation, PTY/ConPTY terminal
sessions, and credential saving remain gated and hidden from the Admin surface
in this release. Their protocol and broker code is security scaffolding, not an
operator-ready path. Use the Admin GUI for inventory, invitation, revocation,
and safe settings only.

Switch the server's client update channel with
`sudo centrald-server channel beta` (or `alpha` / `stable`). Only installs whose
baked channel matches will follow the new pointer. After an offline-root
replacement, or when a client must replace its identity, run
`sudo centrald-client reenroll`.

PKI maintenance: `centrald-server config` offers online-issuer rotation (uses
the offline root recovery PEM) and, for disaster recovery, an offline-root
replacement ceremony that requires the current root recovery key and writes a
new recovery bundle; every enrolled device must re-enroll afterwards. The same
console exports the verified audit chain to root-owned, append-only
`centrald-audit-<from>-<to>.jsonl` files.

## Recovery

If Admin shows a client offline for a long time after a working enroll, confirm
NTP and network path first, then run client diagnostics. The daemon reconnects
with bounded backoff (up to 60s); rescue reports identity and service state
without printing secrets.

Client diagnostics:

```text
sudo centrald-client rescue
sudo centrald-client rescue --repair
sudo centrald-client restart
sudo centrald-client reenroll
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
