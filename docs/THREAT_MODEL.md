# Threat model

CentralD gives operators root on every full-control machine. This page says what
it protects, against whom, and where its limits are.

## What matters

1. **Root on managed machines.** Anyone who can drive a full-control agent owns
   that machine.
2. **Operator accounts and sessions**, which grant (1).
3. **Device tokens**, which let something pose as a machine.
4. **The server's CA key**, which agents trust.
5. **Command output and history**, which can contain secrets.

## Trust boundaries

- **Browser ↔ server**: HTTPS with the server's own CA or your certificate.
  Sessions are cookies the page's scripts cannot read.
- **Agent ↔ server**: the agent trusts only the CA fingerprint from its join
  code. The server trusts only a device ID plus a token whose hash it stored.
- **Server process ↔ host**: the server runs as the unprivileged `centrald` user
  under a hardened systemd unit with no capabilities. It never runs commands
  itself.
- **Agent ↔ host**: the agent is root by design. Its monitor-only setting is
  enforced on the machine itself.

## Attackers and defenses

### Someone on your network without an account

- Every page and API call needs a session; there is no unauthenticated data
  besides the sign-in page, the installer scripts, and agent downloads (which
  are public builds).
- Sign-in and first-run setup back off after five failures per address and per
  username, up to 15 minutes. Each attempt is counted before its password is
  checked, so parallel guesses gain nothing, and a client that hangs up still
  leaves its audit record. Unknown usernames take as long as known ones. IPv6
  addresses are grouped by /64, and the failure table has a fixed size.
- Unauthenticated load is bounded: at most two password hashes run at once (32
  may queue), connections are capped per address and in total, idle connections
  are closed, and agent downloads stream from disk.
- The server answers only to its own names and IP addresses (`421` otherwise),
  so a DNS rebinding page cannot read it or fetch an installer with its own name
  inside.
- First-run setup needs a setup code printed only on the server, so the first
  account cannot be claimed by whoever finds the page first.
- Join codes are single-use, expire within 7 days, can be revoked, and are
  stored as hashes. Agent enrollment is rate-limited per address.
- Failed agent connections are throttled per address and device, and a valid
  device credential is always let through, so someone sharing a device's address
  (a NAT gateway, another user on that machine) cannot lock it out.
- An attacker who answers on the server's address cannot fool an agent or an
  install command: both pin the server's key or CA.

### A malicious web page in an operator's browser

- `SameSite=Strict` cookies, an `Origin` check on every write and WebSocket
  upgrade, and a CSP without inline scripts block cross-site requests and
  injected scripts. Framing is denied.

### A stolen operator password

- Two-factor sign-in (TOTP) stops password-only attacks. Codes cannot be
  replayed, even by two sign-ins racing with the same code. Turning two-factor
  sign-in on or off needs the current password, so a borrowed session cannot
  lock the owner out.
- A right password with a missing or wrong code is recorded in **Activity**.
- Signing out, changing a password (other sessions), a console `reset-password`,
  removing an operator, and session expiry all close that session's open
  terminals and live updates within about a second.
- Two operators cannot remove each other at the same time, and the last account
  cannot be removed.
- **Activity** records sign-ins, failures, commands, terminals, and device
  changes with the source address.

### A compromised server

The server can tell every full-control agent to run anything as root. This is
the core trade-off of a remote management tool. Mitigations:

- Machines that must never be controlled remotely should be enrolled as
  **monitor-only**: their agent refuses commands, actions, terminals, and the
  server cannot change that.
- The server runs unprivileged and hardened, holds no agent credentials in
  usable form (token hashes only), and does not keep terminal transcripts.
- Keep the server on a trusted, patched machine, and back up its data directory
  securely (it contains the CA key).
- A missing or mismatched CA, key, or database stops the server with a clear
  message; it never silently mints a new CA or starts as a fresh install. A lock
  on the data directory keeps a second server from touching its state.

### A compromised managed machine

- Its token is only good for that one device. It can send false status or output
  for itself, and cannot see or affect other devices: the server accepts output
  and terminal data only for sessions it started on that device.
- Text it reports (names, status, error messages) is stripped of control,
  escape, bidi, and zero-width characters and capped in length and count. Status
  faster than every 5 seconds is ignored.
- A device that stops reading is disconnected after 10 seconds instead of
  holding server memory or an operator's terminal.
- Removing the device on the server revokes the token immediately: its
  connection closes, its open terminals end, its running commands are marked
  interrupted, and the agent is asked to stop them.

### Network attackers between agent and server

- All traffic is TLS 1.2+ with the pinned CA. There is no plaintext protocol and
  no trust-on-first-use.

## Limits and non-goals

- **Not for the public Internet.** CentralD is built for a LAN or VPN. Put a VPN
  in front of it rather than forwarding its port.
- **All operators are equal.** There are no roles or per-device permissions yet.
- **Lockouts are in memory.** Restarting the server (root on the server) clears
  sign-in lockouts.
- **No HSTS.** Browsers would refuse to let you past the warning for the
  built-in CA. Install the CA or use your own certificate instead.
- **Command output is stored** (up to 1 MiB per device per run, 90 days). Do not
  print secrets in commands, or delete the run history if you do.
- **Join codes are bearer secrets** until used. Anyone who sees one first can
  enroll a machine. Use short expiry times and revoke unused codes.
- **Agent builds are as trustworthy as the server package** that ships them;
  release packages are signed (see [Releases](RELEASES.md)).
