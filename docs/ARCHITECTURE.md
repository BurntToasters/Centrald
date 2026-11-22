# Architecture

CentralD has three parts: a server, an agent on each managed machine, and a web
app the server hosts. Everything speaks HTTPS on one port.

```text
 Browser ──HTTPS + WebSocket──┐
                              ▼
                     ┌──────────────────┐        SQLite
                     │ centrald-server  │──────► /var/lib/centrald
                     │ (user centrald)  │
                     └──────────────────┘
                              ▲
 centrald-agent ──WSS (pinned CA, device token)──┘   one per machine,
 (root / LocalSystem)                                 outbound only
```

## Repository layout

```text
crates/centrald-proto    wire messages, join codes, TLS pinning, limits
crates/centrald-server   axum HTTPS server, SQLite, sessions, hub, installers
crates/centrald-agent    status collection, command runner, PTY terminal,
                         enrollment, service install, self-update
web/                     React + TypeScript single-page app (embedded)
tests/e2e/               Playwright suite against real binaries
packaging/               systemd units, package hooks, Arch files
scripts/                 packaging, package smoke test, cargo policy tools
site/                    documentation website (synced from docs/)
```

## Server

- One HTTPS listener (default `0.0.0.0:7443`) serves HTTP/1.1 and HTTP/2. The
  first byte of each connection is checked; plain HTTP gets a redirect to
  `https://`. TLS handshakes are bounded in time and number.
- The web app is built by Vite and embedded in the binary, so a server install
  is one file plus its agent builds.
- Storage is one SQLite database in WAL mode with strict tables and forward-only
  migrations. Blocking database work runs off the async workers.
- The **hub** keeps live state in memory: connected agents, running commands and
  their output, open terminals, and a broadcast channel of events for browsers.
  Command results are written to the database when they finish.
- Hourly maintenance renews the certificate when needed and prunes old metrics
  (8 days), runs (90 days), activity (365 days), expired join codes, and expired
  sessions.

### TLS

On first start (an empty data directory) the server creates a private CA (ECDSA
P-256, 20 years) and a server certificate (397 days) for its hostname, LAN
addresses, `localhost`, and the fixed internal name `centrald-server.internal`.
The certificate is reissued 30 days before expiry or when addresses change,
always with the same key.

Agents connect with SNI `centrald-server.internal` and accept only a chain that
ends in the CA whose SHA-256 fingerprint they were given in their join code.
Browsers get either the same certificate or an operator-supplied one
(`tls_cert`/`tls_key`); agents always get the internal chain. At start the
server checks that each key matches its certificate and refuses to run
otherwise.

The listener caps connections (900 total, 128 per address or IPv6 /64), picks
HTTP/2 or HTTP/1.1 by ALPN, and closes idle connections. Requests whose `Host`
or `:authority` is not an IP address or one of the server's names get `421`;
agent paths are exempt. The fallback serves the web app only for `GET`/`HEAD`
outside `/api`.

### Browser API

JSON under `/api`, with a session cookie:

- `__Host-centrald`: `Secure`, `HttpOnly`, `SameSite=Strict`, 30-day maximum and
  7-day idle lifetime. Only a SHA-256 of the token is stored.
- Every state-changing request and WebSocket upgrade must carry an `Origin`
  equal to the server's own origin.
- Passwords use Argon2id (19 MiB, 2 passes), at most two hashes at once and 32
  queued; each hash runs on its own task that outlives a hung-up client. Sign-in
  attempts are counted per address and per username before hashing. Optional
  TOTP with replay protection; turning it on or off needs the password.
- Every API error, including malformed requests, is JSON `{ "error": "…" }`.
- Responses carry a strict Content-Security-Policy, `X-Frame-Options: DENY`,
  `no-referrer`, and `Cache-Control: no-store` for the API.

Live updates use one WebSocket (`/api/events`) carrying device, run, output, and
join-code events. A browser that falls behind gets a `resync` and reloads.
Terminals use a WebSocket per session (`/api/devices/{id}/terminal`).

## Agent

The agent is one static binary with these commands: `enroll`, `status`, `leave`,
`update`, and the hidden `run` used by the service.

### Enrollment

A join code (`cdj1.` + base64url) contains the CA fingerprint, a 20-byte secret,
up to four server addresses, and a checksum. `centrald-agent enroll` reads it
from a prompt, `--key-stdin`, or `--key-file` (never from the command line),
connects to the first reachable address with the pinned CA, and posts the
secret. The server checks that the code is unused, unexpired, and not revoked,
then creates the device and returns a device ID and a random 32-byte token in
the same transaction. The server stores only a SHA-256 of the token.

The agent saves the servers, CA fingerprint, device ID, token, and its mode
(full control or monitor-only) to its config file, readable only by root or
Administrators, then installs and starts its service.

### Connection

The agent opens `wss://…/api/agent/connect` with
`Authorization: Bearer <device>.<token>`, sends `Hello` (versions, OS, hostname,
mode), and expects `Welcome` within 10 seconds. It then sends `Status` every 15
seconds. Both sides ping; 90 seconds of silence ends the connection. The agent
reconnects with jittered backoff from 1 to 60 seconds, trying the last good
address first. A rejected credential backs off for 10 minutes.

Messages are JSON, at most 256 KiB, and tagged by `type`:

| Agent to server            | Server to agent                                        |
| -------------------------- | ------------------------------------------------------ |
| `hello`, `status`          | `welcome`                                              |
| `exec_output`, `exec_exit` | `exec_start`, `exec_cancel`                            |
| `term_output`, `term_exit` | `term_open`, `term_input`, `term_resize`, `term_close` |

### Status

CPU, load, memory, swap, real disks, addresses, uptime, and (on Linux) failed
systemd units and whether a reboot is required. Pending updates come from
`apt-get -s upgrade`, `dnf check-update`, or `pacman -Qu`, checked every six
hours or on request.

### Commands and actions

`exec_start` carries either a shell command or a fixed action:

- **Command**: `/bin/sh -c` on Linux, PowerShell on Windows, in its own process
  group with a clean environment. At most 8 at once.
- **Action**: a fixed list of programs with fixed arguments (apt-get, dnf, or
  pacman to check or install updates; reboot). No shell is involved.

Output streams back in chunks; the agent sends at most 2 MiB and the server
keeps at most 1 MiB per device. On timeout or cancel the whole process group
gets SIGTERM, then SIGKILL 10 seconds later (`taskkill /T`, then `/T /F` on
Windows). The server also stops waiting 30 seconds after the time limit.

A monitor-only agent answers every `exec_start` and `term_open` with a refusal,
whatever the server asks.

### Terminal

`term_open` starts a login shell in a pseudo-terminal (bash on Linux via
openpty, PowerShell via ConPTY on Windows). Keystrokes and output are relayed as
binary WebSocket frames between browser and server and base64 in agent messages.
At most 4 terminals per device. The server closes a terminal after 30 minutes
without input, when the operator's session ends, or when the agent stops reading
for 5 seconds.

### Self-update

`centrald-agent update` downloads `/download/agent/{os}/{arch}` and its
`.sha256` over the pinned connection, compares them, runs the new file with
`--version`, and renames it over the current binary. On Linux a transient
systemd timer restarts the service 5 seconds later so a running command can
report back. Package-managed agents (`/usr/bin`) refuse and defer to the package
manager.

## Data model

| Table         | Holds                                                    |
| ------------- | -------------------------------------------------------- |
| `settings`    | Schema version, first-run setup code (until used)        |
| `users`       | Operators: Argon2id hash, TOTP secret and last used step |
| `sessions`    | Token hashes, expiry, last use                           |
| `join_tokens` | Secret hashes, name, expiry, use, revocation             |
| `devices`     | Identity, token hash, mode, OS, last status, last seen   |
| `metrics`     | Per-minute CPU and memory for charts                     |
| `runs`        | Command or action, who, when, time limit                 |
| `run_targets` | Per-device state, exit code, output (≤ 1 MiB), error     |
| `audit`       | Who did what, to what, from which address                |

Run targets move from `running` to exactly one of `succeeded`, `failed`,
`timed_out`, `canceled`, `refused`, `unreachable`, or `lost`. Targets still
running when the server starts, or when their agent disconnects, become `lost`.

## Installers

`/install.sh` and `/install.ps1` are templates the server fills with its own
address and key pins. The web app's commands download them with the server's
public key pinned (`curl --pinnedpubkey`, or a certificate hash check in
PowerShell), pass the join code in an environment variable, download the agent
from `/download/agent/…`, verify its SHA-256, install it, and run
`enroll --key-stdin`. If a distribution package already installed
`/usr/bin/centrald-agent`, the script uses it instead of downloading.
