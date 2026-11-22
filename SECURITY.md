# Security policy

CentralD runs commands as root on the machines it manages, so we treat security
reports as the highest priority.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/BurntToasters/centrald/security/advisories/new).
Please do not open a public issue.

Include the version, what you did, and what happened. Never include live join
codes, session cookies, device tokens, CA keys, or command output containing
secrets.

## Supported versions

CentralD is pre-1.0. Only the latest release receives fixes.

## Design commitments

- No plaintext application traffic and no trust-on-first-use. Agents and install
  commands pin the server's key or CA.
- No secrets on command lines. Join codes reach the agent through standard
  input, a file, a prompt, or an environment variable.
- Passwords, session tokens, join codes, and device tokens are stored only as
  hashes.
- The server runs unprivileged and never executes commands itself.
- Monitor-only machines enforce their mode locally, regardless of the server.
- Terminal sessions are relayed, never recorded.
- Release packages and binaries are listed in a Minisign-signed `SHA256SUMS`.
- Agents update only to a build signed with the release key for their platform
  and a newer version, checked before the file is written or run. A compromised
  server cannot push code through an update.
- Commands start from a clean environment and are stopped as a whole process
  group on timeout, cancel, and when the agent stops. Commands the server no
  longer tracks after a restart are canceled when the agent reconnects.
- The agent never logs its device credential, at any log level.
- Every external program the agent runs for actions uses a fixed path and fixed
  arguments.

See the [threat model](docs/THREAT_MODEL.md) for what CentralD defends against
and its limits.
