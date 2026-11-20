# Operations

How to configure, secure, back up, upgrade, and troubleshoot a CentralD
installation. For first-time setup, see [Get started](QUICKSTART.md).

## Where things live

| What                       | Where                                                     |
| -------------------------- | --------------------------------------------------------- |
| Server settings (optional) | `/etc/centrald/server.toml`                               |
| Server data                | `/var/lib/centrald` (owned by the `centrald` user)        |
| Database                   | `/var/lib/centrald/centrald.db` (SQLite)                  |
| Certificates and CA key    | `/var/lib/centrald/tls/`                                  |
| Agent builds offered       | `/usr/share/centrald/agents/`                             |
| Server service             | `centrald-server.service`                                 |
| Agent credential (Linux)   | `/etc/centrald/agent.toml` (root only)                    |
| Agent credential (Windows) | `C:\ProgramData\CentralD\agent.toml` (Administrators)     |
| Agent service              | `centrald-agent.service`; Windows service `CentralDAgent` |

The server runs as the unprivileged `centrald` user with a hardened systemd
unit. It needs only its data directory and one TCP port. The agent runs as root
(LocalSystem on Windows) because running commands and installing updates require
it.

## Server settings

Every setting is optional. Edit `/etc/centrald/server.toml`, then
`sudo systemctl restart centrald-server`.

```toml
# Address and port of the web app and agent connections.
listen = "0.0.0.0:7443"

# Extra DNS names or IPs for the server certificate. The machine's hostname
# and LAN addresses are always included.
hostnames = ["nas.home.arpa", "100.64.0.10"]

# Your own certificate for browsers (readable by the centrald user).
tls_cert = "/etc/centrald/tls/fullchain.pem"
tls_key = "/etc/centrald/tls/privkey.pem"

# Rarely changed.
data_dir = "/var/lib/centrald"
agent_dir = "/usr/share/centrald/agents"
```

Unknown keys are an error, so a typo stops the server instead of being ignored.

Each setting also has an environment variable, which wins over the file:
`CENTRALD_LISTEN`, `CENTRALD_HOSTNAMES` (comma-separated), `CENTRALD_TLS_CERT`,
`CENTRALD_TLS_KEY`, `CENTRALD_DATA_DIR`, and `CENTRALD_AGENT_DIR`.
`CENTRALD_LOG` sets the log level (`info` by default; `debug` for more). Set
them with `sudo systemctl edit centrald-server`:

```ini
[Service]
Environment=CENTRALD_LOG=debug
```

Keep the port between 1024 and 65535; the service has no privilege to bind lower
ports. Plain `http://` requests to the port are redirected to `https://`.

## Network and firewall

Browsers and agents both connect to the server's one port (7443 by default).
Agents only make outgoing connections; managed machines need no open ports.

Open the port on the server's firewall:

```sh
sudo ufw allow 7443/tcp                                    # Debian, Ubuntu
sudo firewall-cmd --permanent --add-port=7443/tcp && sudo firewall-cmd --reload  # Fedora
```

Give the server a fixed address (a DHCP reservation, or a DNS name you list in
`hostnames`). Agents remember the addresses from their join code. If the
server's address changes, edit `servers` in each agent's `agent.toml` and
restart the agent, or enroll it again.

Keep CentralD on your LAN or VPN. To reach it from outside, use a VPN such as
WireGuard or Tailscale rather than forwarding the port.

## Trust the certificate

CentralD creates its own certificate authority (CA) on first start and uses it
to issue the server's certificate. Agents trust only that CA's fingerprint,
which comes from their join code. Browsers do not know the CA, so they warn you.

To stop the warning, either:

- **Install the CA** on your computers: **Settings > Download CA certificate**,
  then import it as a trusted root (Windows: double-click it, **Install
  Certificate > Local Machine > Trusted Root Certification Authorities**; macOS:
  Keychain Access, then set it to **Always Trust**; Firefox: **Settings >
  Certificates > Import**). Compare the fingerprint shown in **Settings** with
  `sudo centrald-server status` first.
- **Use your own certificate**, for example from your home lab CA or Let's
  Encrypt via DNS validation. Set `tls_cert` and `tls_key` and restart. Agents
  are unaffected; they keep using CentralD's CA. After renewing the certificate,
  restart the server (for certbot, add
  `--deploy-hook "systemctl restart centrald-server"`).

The server certificate renews itself 30 days before it expires and whenever its
names or addresses change. The CA is valid for 20 years.

## Backups

Everything is in `/var/lib/centrald`. It includes the CA private key and device
credential hashes, so store backups as carefully as the server itself.

```sh
sudo systemctl stop centrald-server
sudo tar -czf centrald-backup.tar.gz -C /var/lib centrald
sudo systemctl start centrald-server
```

To restore on the same or a new machine with the same address, install the
server package, then:

```sh
sudo systemctl stop centrald-server
sudo rm -rf /var/lib/centrald
sudo tar -xzf centrald-backup.tar.gz -C /var/lib
sudo chown -R centrald:centrald /var/lib/centrald
sudo systemctl start centrald-server
```

Agents reconnect on their own because the CA is the same.

CentralD keeps metrics for 8 days, command history for 90 days, the activity log
for a year, and join codes for 30 days after they expire.

## Upgrades

**Server**: install the new package over the old one
(`sudo apt install ./centrald-server_*.deb`,
`sudo dnf upgrade ./centrald-server-*.rpm`, or `makepkg -si` with the new
PKGBUILD). The service restarts by itself; the database is upgraded in place.
The package also brings the new agent builds.

**Agents** installed with the web app's command: run this from **Run command**
on all of them at once (or locally with `sudo`):

```sh
centrald-agent update
```

It downloads the agent build your server offers over the agent's verified
connection, checks its SHA-256, makes sure it runs, swaps the program
atomically, and restarts the service a few seconds later. If anything fails, the
old agent stays in place.

**Agents** installed from a package: upgrade the package with apt, dnf, or
pacman. On Windows, run `centrald-agent update` in an Administrator PowerShell,
then `Restart-Service CentralDAgent`.

## Forgotten password

On the server:

```sh
sudo centrald-server reset-password admin
```

This sets a new password, turns off two-factor sign-in for that account, and
signs it out everywhere. For scripts, pass the password on standard input with
`--password-stdin`.

## Starting over

To erase all accounts, devices, history, and the CA:

```sh
sudo systemctl stop centrald-server
sudo rm -rf /var/lib/centrald
sudo systemctl start centrald-server
sudo centrald-server status      # new setup code
```

Every agent must then be enrolled again (`sudo centrald-agent leave`, then
`enroll` with a new join code).

## Uninstalling

- Server: `sudo apt purge centrald-server` removes the program and all data;
  `apt remove` keeps `/var/lib/centrald`. On Fedora and Arch, remove the
  package, then delete `/var/lib/centrald` yourself if you want the data gone.
- Agents: see [Removing a device](GUIDE.md#removing-a-device).

## Without systemd

The packages work on systems without systemd (for example inside a container),
but nothing starts automatically:

- Server: run `centrald-server run` as the `centrald` user with
  `/var/lib/centrald` owned by that user. Started as root, it switches to the
  data directory's owner by itself.
- Agent: run `centrald-agent run` as root from your init system.

## Troubleshooting

**Logs**

```sh
journalctl -u centrald-server -f
journalctl -u centrald-agent -f
sudo centrald-agent status        # on a managed machine
```

On Windows, the agent service does not keep a log file yet. To watch it, run
these in an Administrator PowerShell:

```powershell
Stop-Service CentralDAgent
& "C:\Program Files\CentralD\centrald-agent.exe" run
# Ctrl+C, then: Start-Service CentralDAgent
```

**A device never joins**

- Run `sudo centrald-agent status` on it. It lists every server address and
  whether it is reachable with the right certificate.
- "cannot reach": the server address is wrong for this machine, or a firewall
  blocks port 7443. Try `curl -k https://SERVER:7443/` from the machine.
- "does not match the pinned fingerprint": something else answered on that
  address, or the server was reset. Create a new join code.
- "This join code was already used" or "expired": create a new one. Codes work
  once and expire after 1 hour to 7 days.

**A device shows offline**

The agent reports every 15 seconds; after 90 seconds of silence it shows
offline. Check `systemctl status centrald-agent` on the machine. After its
credential is rejected (the device was removed, or the server was reset), the
agent waits 10 minutes between attempts and logs how to enroll again.

**The browser says the certificate changed**

The server's address or names changed, so it issued a new certificate from the
same CA. If you installed the CA, nothing to do. Otherwise accept the new
certificate after checking the fingerprint in `sudo centrald-server status`.

**Install command fails on the machine**

- `curl: (90)` means the server's key did not match the pin in the command: you
  are reaching a different server, or the server's certificate changed after you
  copied the command. Create a new join code.
- "the server may not offer a … agent": the server package has no build for that
  architecture. **Settings** lists the builds it offers.
