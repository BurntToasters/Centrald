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
  username, up to 15 minutes. Unknown usernames take as long as known ones.
- First-run setup needs a setup code printed only on the server, so the first
  account cannot be claimed by whoever finds the page first.
- Join codes are single-use, expire within 7 days, can be revoked, and are
  stored as hashes. Agent enrollment is rate-limited per address.
- An attacker who answers on the server's address cannot fool an agent or an
  install command: both pin the server's key or CA.

### A malicious web page in an operator's browser

- `SameSite=Strict` cookies, an `Origin` check on every write and WebSocket
  upgrade, and a CSP without inline scripts block cross-site requests and
  injected scripts. Framing is denied.

### A stolen operator password

- Two-factor sign-in (TOTP) stops password-only attacks. Codes cannot be
  replayed.
- Changing a password ends that operator's other sessions; removing an operator
  ends all of theirs, including open terminals within 30 seconds.
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

### A compromised managed machine

- Its token is only good for that one device. It can send false status or output
  for itself, and cannot see or affect other devices: the server accepts output
  and terminal data only for sessions it started on that device.
- Removing the device on the server revokes the token immediately.

### Network attackers between agent and server

- All traffic is TLS 1.2+ with the pinned CA. There is no plaintext protocol and
  no trust-on-first-use.

## Limits and non-goals

- **Not for the public Internet.** CentralD is built for a LAN or VPN. Put a VPN
  in front of it rather than forwarding its port.
- **All operators are equal.** There are no roles or per-device permissions yet.
- **No HSTS.** Browsers would refuse to let you past the warning for the
  built-in CA. Install the CA or use your own certificate instead.
- **Command output is stored** (up to 1 MiB per device per run, 90 days). Do not
  print secrets in commands, or delete the run history if you do.
- **Join codes are bearer secrets** until used. Anyone who sees one first can
  enroll a machine. Use short expiry times and revoke unused codes.
- **Agent builds are as trustworthy as the server package** that ships them;
  release packages are signed (see [Releases](RELEASES.md)).
