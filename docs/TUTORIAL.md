# CentralD tutorial: from bare machines to managed homelab

This tutorial walks a complete CentralD setup in order: one Ubuntu server, one
Admin workstation, and your first Linux and Windows clients. Every step ends
with a checkpoint so a failure stops you early instead of compounding. For the
short version, see `QUICKSTART.md`; for reference detail, see `OPERATIONS.md`.

This release's live path is setup, one-time invitations, enrollment, inventory,
invitation lifecycle, and safe remote settings. Privileged jobs, remote package
install, and terminal sessions stay fail-closed.

## 0. Gather the machines

You need:

- One Ubuntu Server 24.04 machine for `centrald-server` (headless is fine).
- One Ubuntu Server 24.04 machine for the first `centrald-client`.
- One graphical Linux or Windows workstation for CentralD Admin.
- Optionally, one Windows machine for the Windows client.

Keep every machine on the same LAN or VPN with accurate clocks (NTP). Enrollment
invitations and certificates use wall-clock expiry, so large clock skew looks
like an expired invitation:

```text
timedatectl status
sudo timedatectl set-ntp true
```

Decide the server's TLS name now. The setup wizard suggests this machine's
hostname, but other VMs usually cannot resolve it. Without shared DNS, use the
server's LAN IPv4 address (for example `192.168.1.20`). That value is baked into
invitations and certificates.

Checkpoint: every machine reaches every other machine on the LAN, and clocks
agree within seconds.

## 1. Install the server package

On the server, install with apt so PostgreSQL and UFW arrive automatically:

```text
sudo apt install ./centrald-server_*.deb
```

The installer prints the next command until setup is done:

```text
CentralD server is installed. Next: sudo centrald-server initial-setup
```

Checkpoint: the `.deb` installed without errors and printed the setup command.

## 2. Run initial setup

```text
sudo centrald-server initial-setup
```

Answer the wizard:

1. **TLS name clients verify.** Type the LAN IPv4 unless every machine resolves
   the suggested hostname.
2. **PostgreSQL mode.** Accept the recommended local option unless you run a
   dedicated database. It creates one instance-bound role and database; the
   service login never receives `CREATEDB`.
3. **Offline-root recovery location.** Move the recovery PEM off the server
   afterwards and keep it offline.
4. **First Admin name.** Any readable operator name.

On a packaged systemd install, setup then enables and starts
`centrald-server.service`, allows SSH first, and configures UFW for the actual
listener ports (defaults `7443`, `7444`, `7445`). A healthy finish prints all
three facts:

```text
Initial Admin access key (shown once)
Paste this single key into CentralD Admin.
READY: centrald-server.service is enabled, running, ...
Firewall:
  Allowed inbound TCP 7443, 7444, 7445 and SSH.
```

Copy the one-time Admin access key now. Treat it like a password until it is
consumed; the server never shows it again.

Checkpoint: you hold the Admin key, the output contains `READY:`, and the
firewall report lists the three ports.

## 3. Enroll CentralD Admin

The Admin AppImage is a Tauri/WebKitGTK app, not Electron. It needs a graphical
session and FUSE 2 (`libfuse2t64` in Ubuntu **universe**). Do **not** install
the `fuse` package and do not pass Electron flags such as `--no-sandbox`:

```text
sudo add-apt-repository universe
sudo apt update
sudo apt install libfuse2t64
chmod +x centrald-admin_*.AppImage
./centrald-admin_*.AppImage
```

Choose **Add server** and paste the Admin access key. The app generates its mTLS
private key locally; the invitation is consumed once and never stored. If the
invitation's TLS name does not resolve from this computer, fill **Connection
host or IP** with the server address. That override changes only where TCP goes;
TLS still verifies the invitation name.

After connecting, the **Getting started and common tasks** panel stays open as a
checklist. The local console is optional from here on:

```text
sudo centrald-server config
```

Checkpoint: the Admin top bar shows the server name with an mTLS-verified
indicator, and Overview reports zero managed devices.

## 4. Enroll the Linux client

On the client VM:

```text
sudo apt install ./centrald-client_*.deb
sudo centrald-client enroll
```

Create the invitation first: in Admin choose **Enroll a device** (or run **Add a
client (guided)** in `centrald-server config`). Paste the one-time client
invitation into the wizard. An IP/FQDN override behaves exactly as for Admin:
destination only, trust still pinned.

Successful enrollment prints the configuration path and enables/starts the
client service automatically:

```text
client enrolled; configuration: /var/lib/centrald-client/configurations/...
This device should appear in CentralD Admin shortly.
```

For unattended installs, keep the invitation out of process arguments. Either a
root-owned private file (Unix only) or a single piped token works:

```text
sudo install -o root -g root -m 600 /path/to/invite /root/centrald-client.invite
sudo centrald-client enroll --key-file /root/centrald-client.invite
rm -f /root/centrald-client.invite
```

Checkpoint: Admin Devices lists the client as Online within a minute, and
`sudo centrald-client rescue` reports all checks ok with a pinned-TLS connection
to the server.

## 5. Enroll the Windows client

From an elevated PowerShell session, install the client package and follow the
installer's final message. The installer does not add CentralD to `PATH`, so
enroll with the quoted install path:

```text
& "C:\Program Files\CentralD\centrald-client.exe" enroll
```

Paste the one-time invitation when prompted. Enrollment persists state under
`%ProgramData%\CentralD` using Known Folder locations, and the `CentralDClient`
virtual service account owns the running service. If the device stays offline,
run diagnostics from an elevated terminal:

```text
& "C:\Program Files\CentralD\centrald-client.exe" rescue
```

Checkpoint: Admin Devices lists the Windows client as Online with its OS and
architecture.

## 6. Confirm the inventory in tandem

With server, Admin, Linux client, and Windows client up, confirm every leg:

1. Admin Overview shows the managed-device count and online count.
2. Admin Devices shows each device with platform and last-seen time.
3. On the server, `centrald-server config` → **Health, status, and next steps**
   reports a valid configuration and a healthy daemon.
4. On each client, `rescue` (Linux) reports a pinned-TLS connection.

Checkpoint: every enrolled device is Online and the counts agree between the GUI
and the server console.

## 7. Manage day to day

Routine work lives in Admin Devices and Server settings:

- **New invitations.** Create short-lived client invitations per device; revoke
  the pending ones you no longer need. Each revocation asks for an audit reason
  and confirms in place.
- **Revoke a device.** Revoking removes the identity; the device goes Offline
  and can never reconnect with that credential.
- **Safe settings.** Heartbeat, offline thresholds, job TTL, and listener
  addresses are editable remotely. Trust, secrets, Admin lifecycle, update
  origin, and destructive reset stay on the server console.
- **Release channel.** Switch what the server follows with
  `sudo centrald-server channel beta` (or `alpha` / `stable`), then restart the
  server. Only installs whose baked channel matches follow the pointer.

Checkpoint: create and revoke one test invitation; both actions appear in the
invitation list immediately.

## 8. Recover from trouble

Long-offline client, after confirming NTP and network:

```text
sudo centrald-client rescue
sudo centrald-client rescue --repair
sudo centrald-client restart
sudo centrald-client reenroll
```

`rescue --bundle` writes a redacted JSON diagnostic (paths and statuses, no
private keys or invitation values) for sharing with your administrator.

Server-side repair stays local: `centrald-server config` works even with the
daemon stopped, keeps a backup on every save, and exports the verified audit
chain to append-only JSONL files. The destructive reset is explicit and
local-only:

```text
sudo centrald-server --nuke --yes-i-want-to-do-this
```

Checkpoint: after any repair, the client returns Online and rescue is fully
green again.

## 9. Know what stays gated

This build deliberately leaves privileged operation execution, remote package
installation, and PTY/ConPTY terminal sessions fail-closed on the wire, in the
broker, and in the GUI. Admin shows inventory, invitations, revocation, and safe
settings only. Do not enable `centrald-broker` / `CentralDBroker` until those
paths are release gates with acceptance tests.
