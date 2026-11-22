# Project status

CentralD is pre-1.0. This page lists what works today, how it is tested, and
what is planned.

## Works today

| Feature                                                 | Linux | Windows |
| ------------------------------------------------------- | :---: | :-----: |
| Install server from package; first-run setup code       |  ✓\*  |    —    |
| One-command agent install with pinned download          |   ✓   |   ✓†    |
| Enroll with `centrald-agent enroll` (prompt/stdin/file) |   ✓   |    ✓    |
| Live status: CPU, memory, disks, uptime, addresses      |   ✓   |    ✓    |
| Pending updates, reboot required, failed services       |   ✓   |    —    |
| Run commands on many devices with live output           |   ✓   |    ✓    |
| Cancel and time limits that stop the whole process tree |   ✓   |    ✓    |
| Interactive terminal in the browser                     |   ✓   |   ✓†    |
| Check/install updates (apt, dnf, pacman), reboot        |   ✓   | reboot  |
| Monitor-only devices enforced on the machine            |   ✓   |    ✓    |
| Signed agent self-update from the server                |   ✓   |   ✓†    |
| Operators, two-factor sign-in, activity log             |   ✓   |    —    |
| Your own browser certificate                            |   ✓   |    —    |

\* Server packages: Debian/Ubuntu `.deb`, Fedora `.rpm`, Arch `PKGBUILD`, and a
tarball for other distributions.

† Built and linted in CI on Windows, but not yet exercised end to end on a
Windows machine by the automated tests.

## How it is tested

- **End-to-end suite** (`npm run e2e`): starts the real server and real agents,
  drives the web app in Chromium, and checks security properties with real
  requests. It covers first-run setup, adding devices with the copied install
  command, live status, commands with output and exit codes, cancelation and
  time limits that leave no processes behind, a clean command environment,
  stopping commands the server forgot after a restart, the terminal,
  monitor-only refusal, two-factor sign-in, device removal, signed agent
  self-update (unsigned, tampered, wrong-key, wrong-platform, and downgrade
  builds refused before anything runs), cookies, cross-site requests, join-code
  reuse, forgery and revocation, agent credentials, key pinning, security
  headers, and sign-in throttling. It writes a report with binary hashes,
  screenshots, and a `SHA256SUMS` to `e2e-report/`.
- **Package smoke test** (`scripts/package-smoke.sh`, CI): installs the `.deb`
  packages on a systemd host and walks the whole first-run path.

## Not yet

- Docker image for the server.
- Windows updates from the web app (use Windows Update for now).
- Roles or per-device permissions for operators.
- Scheduled or saved commands.
- Alerts (email, push) when a device goes offline or a disk fills up.
- macOS agent.
- Desktop app (the web app works on any desktop browser).
