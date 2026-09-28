# CentralD E2E report — 1.0.0 readiness (VM runs 2026-09-27/28)

Host: Ubuntu 26.04.1 x86_64, systemd PID 1, Postgres 18, Rust 1.98.1, LAN IP
10.100.0.117. Official sources only (Ubuntu archive, rustup, npm). No bearers
below; invitation files shredded after use. Repo tree holds all fixes (revoke
modal, daemon self-heal, ledger clippy allow, Astro prettier, config test
skip-guard). dist rebuilt 00:08 with all fixes (build exit 0).

## Linux server (packaged .deb, systemd)

- `centrald-server status`: instance 01a0e5fc-..., TLS 10.100.0.117, listeners
  0.0.0.0:7443/7444/7445. Service active, READY after setup, UFW 7443-45 + SSH.
  Survived host restart; restart clean post settings-save.
- PROVEN config TUI via pty harness: Diagnostics (config valid, daemon health,
  manifest 404) then Exit; List clients shows e2e-client active plus revoked
  wine identities with timestamps; audit export 30 records to root-owned 0600
  JSONL. Artifacts tui-diagnostics.log, tui-list-clients.log,
  tui-list-admins.log (gui-admin active), audit-export.jsonl.
- PROVEN channel round-trip: beta (manifest beta URL, prerelease true, backup
  file created) -> stable (manifest stable URL, prerelease false) -> restart
  clean, services active.
- Overnight triage: zero server errors in 6h; client warnings only the healed
  finalize loop; heartbeat live; reconnect cycle healthy.
- PROVEN backup retention bound: 8 more switches capped at exactly 10
  server.toml backups (oldest pruned); back to stable, restart clean.
- PROVEN TUI guided enrollment (client): name prompt -> lifetime default ->
  confirm -> "Access key (shown once)", DB row tui-created, clean exit. Bearer
  pty log shredded (never artifacted).
- PROVEN TUI guided Admin enrollment: same flow, DB row tui-admin2, clean exit,
  bearer log shredded.
- PROVEN TUI device revoke: throwaway enrolled via Wine, menu highlight verified
  before Enter (blind arrows misfire), reason + explicit confirm, "tui-victim
  revoked", DB revoked. Artifact tui-revoke.log.
- PROVEN TUI Admin revoke: gui2-admin selected by verified highlight, reason +
  confirm, "gui2-admin revoked"; gui-admin stays active (last-Admin guard
  untriggered with 2 active). Artifact tui-revoke-admin.log.
- PROVEN advanced Configure navigation (read-only): Server settings -> View
  complete non-secret TOML (job_ttl visible) -> Back -> Exit -> Goodbye, zero
  mutations. Artifact tui-configure.log.
- PROVEN TUI firewall refresh: rules ensured for 7443-45 + SSH, enable skipped
  via env, clean exit, UFW still inactive. Artifact tui-fw.log.
- Last-Admin guard PROVEN live: scratch socket client (LocalControlClient,
  throwaway crate, deleted target after) listed admins then attempted revoke of
  sole active gui-admin -> refused "refusing to revoke the last active Admin;
  create a replacement first". gui-admin still active. Disk hygiene: cleaned
  scratch targets (tmpfs had hit 94%).
- PROVEN TUI invitation management list: client rows with state (expired
  timestamps shown after TTLs lapsed); revoke confirm declined (default false),
  no revocation performed. Artifact tui-invites.log.
- PROVEN audit export via TUI: 30 records sequences 1-30 to root-owned 0600
  JSONL (never rewritten), tail hash printed, clean exit. Refused a main-owned
  dir first (fail-closed ownership check), accepted /root/centrald-audit-export.
  Artifact audit-export.jsonl (copy).
- PROVEN audit append-only chaining: second export wrote 31-68 only, first file
  byte-unchanged, batch2 previousHash equals batch1 tail hash.
- PROVEN hash chain independently: Python recomputed all 68 entry hashes
  (BTreeMap-sorted canonical JSON, compact separators) and every previousHash
  link — 0 problems.

## Linux client (packaged .deb, systemd)

- Enrolled via protected key file; `rescue` all [ok], pinned mTLS ok.
- Heartbeat live in DB: linux/x86_64 0.1.0 ["heartbeat"], current last_seen.
- `restart` exit 0, service back active.
- PROVEN Linux reenroll: new identity activated, previous revoked server-side,
  rescue 10 [ok], heartbeat live on new identity.
- PROVEN interactive wizard refusal: garbage key -> "invalid CentralD access key
  ... invalid format", no state touched. Artifact enroll-wizard.log.
- PROVEN server-restart resilience: restart -> client "control stream failed;
  reconnecting" -> heartbeat live within ~2 min, no intervention. 4-minute
  outage soak: reconnected, heartbeat live, no wedge.
- PROVEN database outage recovery: 2-min PostgreSQL stop -> zero server error
  logs -> restart -> all services active, heartbeat live.
- PROVEN daemon self-heal (new fix): an out-of-band revoke of the previous
  identity during a staged reenroll used to wedge the device (activation retry
  loop + blocked enroll/reenroll). Daemon now adopts the live new identity when
  replacement auth is rejected as unknown (typed Unauthenticated; transient
  failures still retry with rollback intact). Deployed fixed binary, observed
  "adopting the new identity", pointer committed, heartbeat resumed. dist debs +
  AppImage repacked with fixes.
- PROVEN repair loop: stop -> `rescue --repair` (perms reapplied, reports
  stopped) -> `rescue --restart-service` -> active, heartbeat live in DB.
- PROVEN fixed-deb reinstall: same-version reinstall, services active, heartbeat
  live, rescue 10 [ok]. Shippable artifacts verified.
- PROVEN rescue bundle: `--bundle` writes root-only JSON diagnostics (10 checks
  all ok, paths+statuses only); secret scan clean (sole match is the check label
  "identity private key", no key material). Artifact rescue-diagnostics.json.

## Admin GUI AppImage (Tauri/WebKitGTK, 83-87MB)

- Window mapped 1280x800, WebKit processes alive.
- PROVEN enroll (OCR loop, fresh HOME): empty state -> Add server -> paste Admin
  key -> Enroll securely -> "Connected ... with local mTLS identity". Note:
  clipboard paste bypasses React onChange under Xvfb; typing the key via key
  events works. Same for all text entry below.
- PROVEN Devices inventory: e2e-client Online (linux), wine-client-re Offline
  (windows, daemon stopped), pending invitations section.
- PROVEN update-check error path: "Check app update" click -> banner "Admin
  update check failed ... updater endpoint and public key ... HTTP 404", the
  designed pre-publish behavior. Artifact admin-gui-update-check.png.
- PROVEN invitation creation in GUI: Devices -> "New invitation" button (found
  via pixel-art scan at right edge) -> typed device name via key events -> Enter
  -> "One-time client invitation" key view; DB row gui-created pending. Artifact
  admin-gui-create-invitation.png.
- PROVEN audited settings save: Job TTL 1800->1801 via Enter-in-field,
  /etc/centrald/server.toml confirmed, reverted, service restarted clean.
- PROVEN invitation revoke with NEW inline audit-reason modal: Revoke click ->
  "INVITATION REVOCATION / Revoke gui-revoke2 / Audit reason" -> Enter -> "Done
  Invitation for gui-revoke2 was revoked", list empty. DB confirms revoked.
  Submit buttons don't activate under Xvfb (clicks land, verified via
  Cancel/nav); Enter-in-input submits reliably.
- PROVEN device revoke with same modal: wine-client-re row Revoke -> "DEVICE
  REVOCATION / Revoke wine-client-re" with default reason -> Enter -> "Done
  wine-client-re was revoked"; DB identity revoked. Artifact
  admin-gui-device-revoked.png.
- Artifacts: admin-gui2-enrolled.png, admin-gui-devices.png,
  admin-gui-settings-saved.png, admin-gui-revoked.png, admin-xvfb.png.
- Desktop session runs the fixed dist build (relaunched after host restart;
  Xauthority rotates per session). Enrolled Xvfb profile migrated into the
  desktop HOME (same host, keys never leave it); window mapped, no errors.

## Bug found + fixed (in tree)

- `window.prompt` has no script-dialog host in Tauri WebView: device +
  invitation revocation silently no-op. Replaced with inline modal (default
  reasons kept, same RPCs/notices). typecheck/eslint/prettier/ vitest green.
  Proven by revoke E2E above.
- ledger.rs sync_directory: allow clippy::unnecessary_wraps (Windows stub).
  windows-gnu clippy 0 warnings client+admin; host clippy clean.

## Windows client (mingw exe under Wine 10)

- --help exact public contract, --version 0.1.0.
- enroll --key-stdin ok (Known Folder paths), rescue ok + pinned mTLS ok.
- daemon heartbeat in DB: windows/x86_64 0.1.0 ["heartbeat"].
- reenroll ok: new identity active, old revoked server-side.
- PROVEN clean-room enroll: fresh prefix + installer-created data dir, exit 0,
  heartbeat live (cleanroom-win).
- Only [failed]: service check 1060 (no SCM under Wine; installer-owned).
- Workspace-wide windows-gnu clippy: 0 errors; 15 dead_code warnings all in
  centrald-server (Unix-only items unused on Windows; server is Ubuntu-only by
  design, CI uses check not clippy there). No change made.

## Gates

- Full `npm run qa` EXIT 0 on the live-install host (18 ok suites, zero
  failures), re-certified on the committed `e2e-hardening` branch: the
  skip-guard fix for valid_config_is_accepted closed the last gap (skips with
  note for unprivileged runners beside a live install; full validation still
  runs as root and on clean CI hosts). typecheck, eslint+clippy
  (host+windows-gnu), prettier, Admin vitest, contracts 116 all green.

## Not verifiable on this Linux VM (needs Windows host)

- NSIS/ZIP packaging + Admin GUI on Windows (WebView2). CI `windows` job owns
  msvc x64/ARM64 checks + tests; release-host owns install smoke.

## 1.0.0 release ceremony (operator-owned, not done here)

- No signing keys on this VM (no minisign/tauri keypairs, no release env
  secrets) — correct: keys live with the release host/CI secrets.
- gh authenticated as BurntToasters; version still 0.1.0 (bump to 1.0.0 is a
  release decision with tag+publish attached — not executed solo).
- Tree gates green: format, lint (host+windows-gnu), typecheck, vitest,
  contracts 116, full `npm run qa` EXIT 0 on live-install host.

## Repeat (GUI loop)

Xvfb :99 -> AppImage with fresh HOME -> xwd+xwdtopnm+tesseract OCR -> xdotool
click/type (type text, never trust clipboard paste) -> Enter submits.
