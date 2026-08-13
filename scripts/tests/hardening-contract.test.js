import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path) =>
  readFile(new URL(`../../${path}`, import.meta.url), "utf8");

test("database setup and reset are instance-owned", async () => {
  const [db, nuke, migration] = await Promise.all([
    read("crates/centrald-server/src/db.rs"),
    read("crates/centrald-server/src/nuke.rs"),
    read("crates/centrald-server/migrations/0001_initial.sql"),
  ]);
  assert.match(db, /DatabaseAdminError::AlreadyExists/);
  assert.match(db, /COMMENT ON DATABASE/);
  assert.match(db, /centrald_installation/);
  assert.match(nuke, /acquire_server_lock/);
  assert.match(nuke, /drop_owned_database/);
  assert.match(migration, /CREATE TABLE centrald_installation/);
});

test("renewal uses a presented-certificate registry and two-phase activation", async () => {
  const [server, migration, client, admin] = await Promise.all([
    read("crates/centrald-server/src/services.rs"),
    read("crates/centrald-server/migrations/0001_initial.sql"),
    read("crates/centrald-client/src/daemon.rs"),
    read("apps/admin/src-tauri/src/profiles.rs"),
  ]);
  assert.match(migration, /CREATE TABLE identity_certificates/);
  assert.match(server, /peer_certificate_fingerprint/);
  assert.match(server, /activate_identity_certificate/);
  assert.match(server, /state = 'pending'/);
  assert.match(client, /renew_certificate_if_needed/);
  assert.match(admin, /renew_admin_profile/);
});

test("invitations are listable and revocable without legacy keys", async () => {
  const [proto, server, common] = await Promise.all([
    read("proto/centrald/v1/centrald.proto"),
    read("crates/centrald-server/src/services.rs"),
    read("crates/centrald-common/src/enrollment.rs"),
  ]);
  assert.match(proto, /rpc ListEnrollmentKeys/);
  assert.match(proto, /rpc RevokeEnrollmentKey/);
  assert.match(server, /revoked_at IS NULL/);
  assert.match(common, /centrald-invite1/);
  assert.doesNotMatch(common, /legacy/i);
});

test("client runtime honors server timing and bounds job events", async () => {
  const [daemon, server] = await Promise.all([
    read("crates/centrald-client/src/daemon.rs"),
    read("crates/centrald-server/src/services.rs"),
  ]);
  assert.match(daemon, /next_interval_seconds/);
  assert.match(server, /MAX_JOB_EVENT_OUTPUT_BYTES/);
  assert.match(server, /MAX_JOB_RETAINED_OUTPUT_BYTES/);
  assert.match(server, /validate_job_transition/);
});

test("Windows client daemon is a real SCM service isolated from LocalSystem", async () => {
  const [installer, service] = await Promise.all([
    read("deploy/windows/install-client.ps1"),
    read("crates/centrald-client/src/windows_service.rs"),
  ]);
  assert.match(installer, /NT SERVICE\\\$serviceName/);
  assert.match(installer, /obj= \$serviceIdentity/);
  assert.match(installer, /SetAccessRuleProtection/);
  assert.match(installer, /Set-Acl/);
  assert.match(installer, /ReparsePoint/);
  assert.doesNotMatch(installer, /obj= LocalSystem/i);
  assert.match(service, /define_windows_service!/);
  assert.match(service, /service_dispatcher::start/);
  assert.match(service, /service_control_handler::register/);
  assert.match(service, /ServiceState::StopPending/);
});

test("credential publication and settings writes are crash recoverable", async () => {
  const [pointer, server, configLock] = await Promise.all([
    read("crates/centrald-common/src/active_pointer.rs"),
    read("crates/centrald-server/src/services.rs"),
    read("crates/centrald-server/src/config_lock.rs"),
  ]);
  assert.match(pointer, /current\.pointer/);
  assert.match(pointer, /PointerPublication/);
  assert.match(server, /server_settings\.update\.prepare/);
  assert.match(configLock, /SettingsUpdateTransaction/);
  assert.match(configLock, /recover_interrupted_settings_update_locked/);
  assert.match(server, /recover_server_transactions_locked/);
  assert.match(server, /recover_interrupted_database_update_locked/);
  assert.match(server, /recover_interrupted_online_issuer_rotation_locked/);
  assert.match(server, /recover_interrupted_tls_rotation_locked/);
});

test("certificate serials are generated per issuance", async () => {
  const pki = await read("crates/centrald-pki/src/lib.rs");
  assert.match(pki, /fresh_certificate_serial/);
  assert.match(pki, /fill_bytes/);
  assert.doesNotMatch(
    pki,
    /SerialNumber::from_slice\(identity_id\.as_bytes\(\)\)/,
  );
});

test("Admin updater is registered and remains operator initiated", async () => {
  const [cargo, runtime, capability, app, pkg] = await Promise.all([
    read("apps/admin/src-tauri/Cargo.toml"),
    read("apps/admin/src-tauri/src/lib.rs"),
    read("apps/admin/src-tauri/capabilities/default.json"),
    read("apps/admin/src/App.tsx"),
    read("package.json").then(JSON.parse),
  ]);
  assert.match(cargo, /tauri-plugin-updater/);
  assert.match(runtime, /tauri_plugin_updater::Builder/);
  assert.match(capability, /updater:default/);
  assert.match(app, /downloadAndInstall/);
  assert.equal(pkg.dependencies["@tauri-apps/plugin-updater"], "2.10.1");
});

test("terminal transport never falls back to an arbitrary command runner", async () => {
  const services = await read("crates/centrald-server/src/services.rs");
  const shellRelay = await read("crates/centrald-server/src/shell.rs");
  const client = await read("crates/centrald-client/src/daemon.rs");
  const broker = await read("crates/centrald-client/src/broker_session.rs");
  // The relay is bounded end-to-end: frame sizes, byte totals, and timeouts
  // are enforced on the server relay and the broker session.
  assert.match(shellRelay, /shell session timeout reached/);
  assert.match(shellRelay, /shell data frame exceeds the limit/);
  assert.match(client, /MAX_SHELL_SESSIONS/);
  assert.match(broker, /MAX_CONCURRENT_SESSIONS/);
  assert.match(broker, /session output bound reached/);
  assert.match(broker, /session idle timeout reached/);
  assert.doesNotMatch(services, /Command::new\([^)]*sh/);
});

test("client key material is zeroized and vault reads are bounded", async () => {
  const [daemon, vault] = await Promise.all([
    read("crates/centrald-client/src/daemon.rs"),
    read("crates/centrald-client/src/vault.rs"),
  ]);
  // tonic copies PEM bytes into its TLS identity; the intermediate client
  // buffers must be wiped rather than left as plaintext key material.
  assert.match(daemon, /Zeroizing::new\(/);
  assert.match(daemon, /zeroize::Zeroizing/);
  // The Windows credential vault file is read through a bounded, zeroized path
  // so an oversized replacement cannot exhaust memory.
  assert.match(vault, /MAX_VAULT_FILE_BYTES/);
  assert.match(vault, /read_vault_file/);
  assert.match(vault, /bail!\("credential vault exceeds/);
});

test("Admin shell sessions release registry entries and never block on sends", async () => {
  const shell = await read("apps/admin/src-tauri/src/shell.rs");
  // Every exit path (close, stream end, or error) must release the registry
  // entry so sessions cannot leak across the GUI session.
  assert.match(shell, /remove_session\(\)/);
  assert.match(shell, /sessions\.remove\(&session_handle\)/);
  // Input/resize/close must fail fast instead of parking the async runtime on
  // a stalled stream.
  assert.match(shell, /\.try_send\(AdminShellFrame/);
  assert.match(shell, /shell stream is backed up/);
  assert.match(shell, /shell input stream is backed up/);
  assert.doesNotMatch(shell, /\.blocking_send\(AdminShellFrame/);
  assert.match(shell, /MAX_INPUT_BASE64_CHARS/);
});

test("abandoned shell sessions are closed by server housekeeping", async () => {
  const services = await read("crates/centrald-server/src/services.rs");
  const migration = await read(
    "crates/centrald-server/migrations/0001_initial.sql",
  );
  assert.match(services, /shell_housekeeping/);
  assert.match(services, /outcome = 'abandoned'/);
  assert.match(services, /active_shell_session_ids/);
  assert.match(migration, /CREATE TABLE shell_sessions/);
  assert.match(migration, /CREATE TABLE elevation_challenges/);
});

test("client updater verifies release integrity before installation", async () => {
  const updater = await read("crates/centrald-client/src/updates.rs");
  const runners = await read("crates/centrald-client/src/runners.rs");
  assert.match(updater, /minisign::verify/);
  assert.match(updater, /same-version byte replacement is forbidden/);
  assert.match(updater, /SHA-256 mismatch/);
  assert.match(updater, /create_new\(true\)/);
  assert.match(updater, /is_simple_entry_name/);
  assert.doesNotMatch(updater, /Command::new\([^)]*sh\b/);
  assert.match(runners, /update_client_operation/);
});

test("root replacement is authorized by the current root and journaled", async () => {
  const pki = await read("crates/centrald-pki/src/lib.rs");
  const manage = await read("crates/centrald-server/src/manage.rs");
  assert.match(pki, /pub fn replace_root/);
  assert.match(
    pki,
    /current offline root private key does not match the configured root certificate/,
  );
  assert.match(manage, /Replace the offline root CA/);
  assert.match(manage, /recover_interrupted_root_replacement_locked/);
  assert.match(manage, /targets\.len\(\) != 9/);
});

test("audit export verifies the hash chain before writing", async () => {
  const exporter = await read("crates/centrald-server/src/audit_export.rs");
  assert.match(exporter, /audit chain broken at sequence/);
  assert.match(exporter, /entry_hash does not match its canonical record/);
  assert.match(exporter, /never rewritten/);
  assert.match(exporter, /write_new_file/);
});

test("audit export continuation windows are seeded by the previous tail hash", async () => {
  const exporter = await read("crates/centrald-server/src/audit_export.rs");
  const manage = await read("crates/centrald-server/src/manage.rs");
  const services = await read("crates/centrald-server/src/services.rs");
  // The continuation seed must chain against the previous export's tail so a
  // gap between windows is a verification failure, not a silent skip.
  assert.match(exporter, /previous export tail hash is not valid hex/);
  assert.match(exporter, /expected_previous\.as_deref\(\)/);
  assert.match(
    exporter,
    /chain_verification_accepts_a_valid_continuation_window/,
  );
  // Local server-console audits must produce entries the exporter can verify:
  // timestamps are normalized to the same microsecond precision as RPC audits.
  assert.match(services, /pub\(crate\) fn normalized_audit_timestamp/);
  assert.match(
    manage,
    /crate::services::normalized_audit_timestamp\(Utc::now\(\)\)/,
  );
});

test("rotation recovery revalidates root ownership and ancestors at point of use", async () => {
  const manage = await read("crates/centrald-server/src/manage.rs");
  // Recovery must read journals and backups through the no-follow, root-owned
  // secure-read path, not a bare fs::read.
  assert.match(manage, /read_root_private_text\(\s*&journal_path/);
  assert.match(manage, /recover_interrupted_online_issuer_rotation_locked/);
  assert.match(manage, /recover_interrupted_tls_rotation_locked/);
  // The final rename revalidates the destination's ancestors so a directory
  // swapped for a symlink cannot redirect the rollback outside the PKI tree.
  assert.match(manage, /validate_no_symlink_ancestors\(destination\)/);
  assert.doesNotMatch(
    manage,
    /serde_json::from_slice\(&fs::read\(&journal_path\)\?\)/,
  );
});

test("release channels stay mutable outside immutable GitHub Releases", async () => {
  const [release, buildConfig] = await Promise.all([
    read("scripts/release.js"),
    read("scripts/lib/build-config.js"),
  ]);
  assert.match(release, /publishMutableChannelManifests/);
  assert.match(release, /centrald-channels/);
  assert.match(release, /immutableReleaseChannelEntries/);
  assert.match(release, /CENTRALD_ALLOW_CHANNEL_ROLLBACK/);
  assert.match(release, /compareSemver/);
  assert.match(release, /verifyReleaseAssetIntegrity/);
  assert.match(
    release,
    /verifyReleaseAssetIntegrity\(release, files, `Draft release/,
  );
  assert.match(release, /names, sizes, and SHA-256 digests/);
  assert.doesNotMatch(release, /release[", ]+upload[\s\S]{0,200}--clobber/);
  assert.match(buildConfig, /raw\.githubusercontent\.com/);
});

test("PKI lifetimes and server leaf renewal are explicit", async () => {
  const [pki, server] = await Promise.all([
    read("crates/centrald-pki/src/lib.rs"),
    read("crates/centrald-server/src/manage.rs"),
  ]);
  assert.match(pki, /ROOT_VALIDITY_DAYS: i64 = 15 \* 365/);
  assert.match(pki, /ISSUER_VALIDITY_DAYS: i64 = 3 \* 365/);
  assert.match(pki, /SERVER_VALIDITY_DAYS: i64 = 90/);
  assert.match(pki, /apply_ca_validity/);
  assert.match(server, /renew_server_identity_if_needed/);
  assert.match(server, /retire_completed_tls_rotation/);
});

test("audit chain is monotonic and local root changes are journaled", async () => {
  const [migration, localAudit, manage] = await Promise.all([
    read("crates/centrald-server/migrations/0001_initial.sql"),
    read("crates/centrald-server/src/local_audit.rs"),
    read("crates/centrald-server/src/manage.rs"),
  ]);
  assert.match(migration, /sequence BIGSERIAL UNIQUE NOT NULL/);
  assert.match(localAudit, /ORDER BY sequence DESC LIMIT 1/);
  assert.match(manage, /server_settings\.local_update/);
  assert.match(manage, /server_tls\.rotate/);
});

test("release feed is bounded and its URL is server-local-only", async () => {
  const server = await read("crates/centrald-server/src/services.rs");
  assert.match(server, /while let Some\(chunk\) = response\.chunk\(\)\.await/);
  assert.match(server, /MAX_RELEASE_MANIFEST_BYTES/);
  assert.match(server, /"updateManifestUrl"\.into\(\)/);
  assert.match(
    server,
    /requested\.update_manifest_url == config\.updates\.manifest_url/,
  );
  assert.doesNotMatch(
    server,
    /config\.updates\.manifest_url = requested\.update_manifest_url/,
  );
});

test("Windows startup preference and Admin profile corruption are recoverable", async () => {
  const [installer, enrollment, service, profiles] = await Promise.all([
    read("deploy/windows/install-client.ps1"),
    read("crates/centrald-client/src/enrollment.rs"),
    read("crates/centrald-client/src/windows_service.rs"),
    read("apps/admin/src-tauri/src/profiles.rs"),
  ]);
  assert.match(
    installer,
    /Join-Path \$InstallDirectory "manual-start\.optout"/,
  );
  assert.match(enrollment, /client_manual_start_marker/);
  assert.match(service, /ServiceState::StartPending/);
  assert.match(service, /ServiceState::Stopped/);
  assert.match(profiles, /ProfileWarning/);
  assert.match(profiles, /warnings\.push/);
});

test("privileged client repair is pinned to the platform state root", async () => {
  const [config, rescue, enrollment] = await Promise.all([
    read("crates/centrald-common/src/config.rs"),
    read("crates/centrald-client/src/rescue.rs"),
    read("crates/centrald-client/src/enrollment.rs"),
  ]);
  assert.match(config, /pub fn client_data_dir\(\)/);
  assert.match(
    config,
    /client data_dir must be the platform-managed state root/,
  );
  assert.match(config, /validate_storage_path/);
  assert.match(enrollment, /validate_repair_layout/);
  assert.match(enrollment, /ClientStateLock::acquire/);
  assert.match(enrollment, /state_lock_path/);
  assert.match(rescue, /--restart-service|restart_service/);
  assert.match(rescue, /stop_client_service/);
});

test("Windows installer preflights fixed non-reparse CentralD paths before mutation", async () => {
  const installer = await read("deploy/windows/install-client.ps1");
  assert.doesNotMatch(installer, /\[string\]\$InstallDirectory/);
  assert.doesNotMatch(installer, /\[string\]\$DataDirectory/);
  assert.match(installer, /Assert-CentralDLeafPath/);
  assert.match(installer, /Assert-NoReparseAncestors/);
  assert.match(installer, /Get-CentralDAclSnapshot/);
  assert.match(installer, /Restore-CentralDAclSnapshot/);
  const preflight = installer.indexOf("Assert-CentralDLeafPath");
  const serviceMutation = installer.indexOf(
    "Invoke-NativeChecked $ScExe config",
  );
  assert.ok(preflight >= 0 && serviceMutation > preflight);
});

test("server secret paths are fixed and every Unix ancestor is validated", async () => {
  const [config, setup, wizard] = await Promise.all([
    read("crates/centrald-common/src/config.rs"),
    read("crates/centrald-server/src/setup.rs"),
    read("crates/centrald-server/src/wizard.rs"),
  ]);
  assert.match(config, /SERVER_DATA_DIR: &str = "\/var\/lib\/centrald"/);
  assert.match(
    config,
    /SERVER_DATABASE_ENV_FILE: &str = "\/etc\/centrald\/server\.env"/,
  );
  assert.match(config, /validate_server_fixed_paths/);
  assert.match(config, /while let Some\(ancestor\) = current/);
  assert.match(setup, /while let Some\(ancestor\) = current/);
  assert.match(wizard, /Package-managed data directory/);
});

test("database settings use one crash-recoverable generation without plaintext backups", async () => {
  const [configLock, manage] = await Promise.all([
    read("crates/centrald-server/src/config_lock.rs"),
    read("crates/centrald-server/src/manage.rs"),
  ]);
  assert.match(configLock, /DatabaseUpdateTransaction/);
  assert.match(configLock, /\.centrald-database-update\.json/);
  assert.match(configLock, /recover_interrupted_database_update_locked/);
  assert.match(manage, /DatabaseUpdateTransaction::begin_locked/);
  const databaseBlock = configLock.slice(
    configLock.indexOf("pub struct DatabaseUpdateTransaction"),
    configLock.indexOf("pub struct SettingsUpdateTransaction"),
  );
  assert.doesNotMatch(databaseBlock, /replace_file_with_backup/);
});

test("committed local configuration changes do not become false failures on audit append", async () => {
  const manage = await read("crates/centrald-server/src/manage.rs");
  assert.match(
    manage,
    /server configuration was committed; final local audit append is pending reconciliation/,
  );
  assert.match(
    manage,
    /server TLS rotation committed; final local audit append is pending reconciliation/,
  );
});

test("channel publication commits both mutable manifests atomically and is separately retryable", async () => {
  const [release, pkg] = await Promise.all([
    read("scripts/release.js"),
    read("package.json").then(JSON.parse),
  ]);
  assert.equal(
    pkg.scripts["release:publish-channel"],
    "node --env-file-if-exists=.env scripts/release.js publish-channel",
  );
  assert.match(release, /publishChannelOnly/);
  assert.match(release, /git\/blobs/);
  assert.match(release, /git\/trees/);
  assert.match(release, /git\/commits/);
  assert.match(release, /git\/refs\/heads/);
  assert.match(release, /force: false/);
  assert.doesNotMatch(release, /repos\/\$\{repository\}\/contents\//);
});

test("one-command release builds every host platform, tags, and publishes only when gated", async () => {
  const [release, build, pkg] = await Promise.all([
    read("scripts/release.js"),
    read("scripts/build.js"),
    read("package.json").then(JSON.parse),
  ]);
  // A Windows host must produce Windows and Linux artifacts in one build step,
  // with every updater artifact Tauri-signed on the host (never inside Docker).
  assert.match(release, /buildAllPlatforms/);
  assert.match(
    release,
    /--target"[\s\S]*"all"[\s\S]*--container"[\s\S]*--target"[\s\S]*"linux-x64"/,
  );
  assert.equal(
    pkg.scripts["release"],
    "node --env-file-if-exists=.env scripts/release.js all",
  );
  assert.equal(
    pkg.scripts["build:all:container"],
    "node --env-file-if-exists=.env scripts/build.js --target all --container",
  );
  // The version tag is created and pushed only when publishing is explicitly
  // requested; a plain run stops after verification.
  assert.match(release, /createAndPushVersionTag/);
  assert.match(release, /CENTRALD_RELEASE_PUBLISH === "YES"/);
  assert.match(release, /git", \["tag", expectedTag\]/);
  assert.match(release, /git", \["push", "origin", expectedTag\]/);
  assert.match(release, /refusing to move it/);
  // Manifests are signed after generation so their .minisig files exist for
  // the release upload, not only the artifacts.
  assert.match(
    release,
    /signReleaseArtifacts\(\);\n[ ]{2}generateManifests\(\);\n[ ]{2}signReleaseArtifacts\(\)/,
  );
  // The Docker-built Linux AppImage and Windows NSIS installers are signed on
  // the host with tauri signer, which reads the key from the environment,
  // never a Docker build argument.
  assert.match(build, /signHostUpdaterArtifact/);
  assert.match(build, /tauri", "signer", "sign/);
  assert.match(build, /TAURI_SIGNING_PRIVATE_KEY/);
  assert.doesNotMatch(build, /--build-arg[^\n]*(?:SIGNING|PRIVATE)/);
});

test("containerized builds isolate the host and refresh Rust stable everywhere", async () => {
  const [build, release, linuxDockerfile, windowsDockerfile, dockerEngine] =
    await Promise.all([
      read("scripts/build.js"),
      read("scripts/release.js"),
      read("docker/linux-builder.Dockerfile"),
      read("docker/windows-builder.Dockerfile"),
      read("scripts/lib/docker-engine.js"),
    ]);
  // Windows artifacts are built in a Windows container and extracted with
  // docker create + docker cp; the engine is switched between the Linux and
  // Windows builder images.
  assert.match(build, /buildWindowsContainer/);
  assert.match(build, /ensureDockerEngine/);
  assert.match(dockerEngine, /-SwitchWindowsContainers/);
  assert.match(dockerEngine, /-SwitchLinuxContainers/);
  assert.match(build, /"create",\n\s+"--name"/);
  assert.match(build, /\$\{containerName\}:C:/);
  assert.match(build, /"rm", "-f", containerName/);
  // The release preflight refreshes the host Rust stable toolchain.
  assert.match(release, /refreshHostRustStable/);
  assert.match(release, /rustup", \["update", "stable"\]/);
  // Both builder images use the latest stable Rust, not a pinned toolchain.
  assert.match(linuxDockerfile, /rust:bookworm/);
  assert.match(linuxDockerfile, /rustup update stable/);
  assert.match(windowsDockerfile, /servercore:ltsc2022/);
  assert.match(windowsDockerfile, /rustup update stable/);
  assert.match(windowsDockerfile, /rustup-init\.exe/);
  // The Windows container image must never receive signing keys.
  assert.doesNotMatch(windowsDockerfile, /SIGNING|PRIVATE_KEY/);
  assert.match(
    windowsDockerfile,
    /node scripts\/build\.js --target windows-x64/,
  );
  assert.match(
    windowsDockerfile,
    /node scripts\/build\.js --target windows-arm64/,
  );
});

test("npm supply-chain policy requires npm 12 and a three-day release age", async () => {
  const [rootNpmrc, siteNpmrc, rootPackage, sitePackage, setupDocker, pkg] =
    await Promise.all([
      read(".npmrc"),
      read("site/.npmrc"),
      read("package.json").then(JSON.parse),
      read("site/package.json").then(JSON.parse),
      read("scripts/setup-docker.js"),
      read("package.json").then((value) => JSON.parse(value)),
    ]);
  // Every project-level npm operation (local and inside the Docker builders,
  // which copy the repo) hard-enforces a minimum package release age.
  assert.match(rootNpmrc, /min-release-age=3/);
  assert.match(siteNpmrc, /min-release-age=3/);
  assert.equal(rootPackage.engines.npm, ">=12.0.1");
  assert.equal(sitePackage.engines.npm, ">=12.0.1");
  const linuxDockerfile = await read("docker/linux-builder.Dockerfile");
  const windowsDockerfile = await read("docker/windows-builder.Dockerfile");
  // The builder images upgrade npm and copy the policy file before npm ci.
  assert.match(linuxDockerfile, /npm install -g npm@12\.0\.2/);
  assert.match(windowsDockerfile, /npm install -g npm@12\.0\.2/);
  assert.match(
    linuxDockerfile,
    /COPY package\.json package-lock\.json \.npmrc \.\//,
  );
  assert.match(
    windowsDockerfile,
    /COPY package\.json package-lock\.json \.npmrc \.\//,
  );
  // Install scripts are explicitly allowed inside the builder images while
  // the allowlist stays in package.json (allowScripts).
  assert.match(linuxDockerfile, /--ignore-scripts=false/);
  assert.match(windowsDockerfile, /--ignore-scripts=false/);
  assert.equal(pkg.scripts["setup:docker"], "node scripts/setup-docker.js");
  // The handsfree setup installs/starts Docker Desktop, enables the Windows
  // Containers feature, verifies both engine modes, and pre-pulls base images.
  assert.match(setupDocker, /Docker\.DockerDesktop/);
  assert.match(setupDocker, /Enable-WindowsOptionalFeature.*Containers/);
  assert.match(setupDocker, /verifyEngineSwitching/);
  assert.match(
    setupDocker,
    /mcr\.microsoft\.com\/windows\/servercore:ltsc2022/,
  );
  assert.match(setupDocker, /rust:bookworm/);
  // The npm age gate belongs to the .npmrc files, not the setup script.
  assert.doesNotMatch(setupDocker, /min-release-age/);
});

test("channels are baked per build and CDN manifests are mirrored to S3 after publish", async () => {
  const [buildConfig, release, sync, build, envExample, buildRust] =
    await Promise.all([
      read("scripts/lib/build-config.js"),
      read("scripts/release.js"),
      read("scripts/sync-channel.js"),
      read("scripts/build.js"),
      read(".env.example"),
      read("crates/centrald-common/build.rs"),
    ]);
  // A single tree builds any channel: --channel on build/release and the
  // CENTRALD_RELEASE_CHANNEL env override beat the tracked config in both the
  // JS tooling and the Rust build script that bakes values into binaries.
  assert.match(buildConfig, /overrides\.releaseChannel/);
  assert.match(buildConfig, /CENTRALD_RELEASE_CHANNEL/);
  assert.match(build, /--channel/);
  assert.match(build, /CENTRALD_RELEASE_CHANNEL/);
  assert.match(release, /parseChannelArgument/);
  assert.match(release, /--channel/);
  assert.match(buildRust, /CENTRALD_RELEASE_CHANNEL/);
  assert.match(buildRust, /rerun-if-env-changed=CENTRALD_RELEASE_CHANNEL/);
  // CDN_BASE_URL unifies every channel (including stable) under
  // <cdn>/<channel>, and stable falls back to the GitHub latest pointer
  // without it.
  assert.match(buildConfig, /CDN_BASE_URL/);
  assert.match(
    buildConfig,
    /cdnBaseUrl\s*\?\s*`\$\{cdnBaseUrl\}\/\$\{releaseChannel\}`/,
  );
  assert.match(
    release,
    /config\.releaseChannel !== "stable" \|\| config\.cdnBaseUrl/,
  );
  assert.match(
    release,
    /config\.releaseChannel === "stable" && !config\.cdnBaseUrl/,
  );
  // The S3 sync mirrors the signed manifests (not artifacts) and is the
  // automatic last publish step when the CDN is configured.
  assert.match(release, /syncChannelToCdn/);
  assert.match(release, /if \(config\.cdnBaseUrl\) syncChannelToCdn\(\);/);
  assert.match(sync, /CENTRALD_S3_ENDPOINT/);
  assert.match(sync, /CENTRALD_S3_BUCKET/);
  assert.match(sync, /s3",\n\s+"cp"/);
  assert.match(sync, /minisig/);
  assert.match(sync, /Amazon\.AWSCli/);
  assert.match(sync, /Refusing symbolic-link release manifest/);
  assert.match(envExample, /CENTRALD_S3_ENDPOINT/);
  assert.match(envExample, /updated\.centrald\.dev/);
  // Manifests are mirrored, but artifacts stay on immutable GitHub tag URLs.
  assert.doesNotMatch(sync, /release\/artifacts/);
});

test("Linux enrollment publishes only the active pointer and enables the service", async () => {
  const [enrollment, unit] = await Promise.all([
    read("crates/centrald-client/src/enrollment.rs"),
    read("deploy/systemd/centrald-client.service"),
  ]);
  assert.match(
    enrollment,
    /systemctl[\s\S]{0,200}enable[\s\S]{0,100}--now[\s\S]{0,100}centrald-client\.service/,
  );
  assert.match(
    unit,
    /ConditionPathExists=\/var\/lib\/centrald-client\/configurations\/current\.pointer/,
  );
  assert.doesNotMatch(unit, /ConditionPathExistsGlob/);
});

test("online issuer rotation is guided, root-key bound, and crash recoverable", async () => {
  const [pki, manage] = await Promise.all([
    read("crates/centrald-pki/src/lib.rs"),
    read("crates/centrald-server/src/manage.rs"),
  ]);
  assert.match(pki, /rotate_online_issuers/);
  assert.match(pki, /public_key_raw/);
  assert.match(manage, /Rotate online PKI issuers/);
  assert.match(manage, /recover_interrupted_online_issuer_rotation/);
  assert.match(manage, /offline root recovery/);
});

test("local audit tolerates only a torn final record and checksums complete records", async () => {
  const audit = await read("crates/centrald-server/src/local_audit.rs");
  assert.match(audit, /LocalAuditEnvelope/);
  assert.match(audit, /checksum_sha256/);
  assert.match(audit, /recover_torn_final_record/);
  assert.match(audit, /centrald-local-audit-torn/);
});

test("TLS rollback retirement requires live TLS probes on all listeners", async () => {
  const [main, manage] = await Promise.all([
    read("crates/centrald-server/src/main.rs"),
    read("crates/centrald-server/src/manage.rs"),
  ]);
  assert.match(main, /verify_tls_listeners_before_retirement/);
  assert.match(main, /probe_tls_listener/);
  assert.match(main, /client_issuer/);
  assert.match(main, /admin_issuer/);
  assert.match(manage, /tls_retirement_pending/);
});

test("client state mutation and signed-grant retention are bounded", async () => {
  const [daemon, enrollment, stateLock, config, unit] = await Promise.all([
    read("crates/centrald-client/src/daemon.rs"),
    read("crates/centrald-client/src/enrollment.rs"),
    read("crates/centrald-client/src/state_lock.rs"),
    read("crates/centrald-common/src/config.rs"),
    read("deploy/systemd/centrald-client.service"),
  ]);
  assert.match(daemon, /ClientStateLock::try_acquire/);
  assert.match(enrollment, /ClientStateLock::acquire/);
  assert.match(stateLock, /\.centrald-state\.lock/);
  assert.match(stateLock, /\/var\/lib\/centrald-client\.lock/u);
  assert.match(unit, /ReadWritePaths=.*\/var\/lib\/centrald-client\.lock/u);
  assert.match(daemon, /MAX_PENDING_GRANTS/);
  assert.match(daemon, /grants\.retain/);
  assert.match(config, /client configuration path must be/);
  assert.match(config, /client identity generation is not a UUID/);
});

test("secret-bearing server and PKI debug state is redacted", async () => {
  const [server, pki, manage] = await Promise.all([
    read("crates/centrald-server/src/services.rs"),
    read("crates/centrald-pki/src/lib.rs"),
    read("crates/centrald-server/src/manage.rs"),
  ]);
  assert.match(server, /Arc<SecretString>/);
  assert.match(server, /expose_secret/);
  assert.match(pki, /private_key_pem", &"\[REDACTED\]"/);
  assert.match(manage, /offline root recovery bundle/);
  assert.match(manage, /read_root_private_text/);
  assert.match(manage, /SecretString::from/);
});

test("privileged Unix repair uses descriptor-relative no-follow ownership changes", async () => {
  const [unixState, clientCargo, workspaceCargo, packaging] = await Promise.all(
    [
      read("crates/centrald-client/src/unix_state.rs"),
      read("crates/centrald-client/Cargo.toml"),
      read("Cargo.toml"),
      read("scripts/package-linux.js"),
    ],
  );
  assert.match(unixState, /openat/);
  assert.match(unixState, /mkdirat/);
  assert.match(unixState, /unlinkat/);
  assert.match(unixState, /persist_enrollment_generation/);
  assert.match(unixState, /cleanup_enrollment_generation/);
  assert.match(unixState, /load_active_configuration/);
  assert.match(unixState, /read_bounded_utf8/);
  assert.match(unixState, /OFlags::NOFOLLOW/);
  assert.match(unixState, /OFlags::CREATE \| OFlags::EXCL/);
  assert.match(unixState, /fsync/);
  assert.match(unixState, /fchown/);
  assert.match(unixState, /fchmod/);
  assert.match(unixState, /FileType::from_raw_mode/);
  assert.doesNotMatch(unixState, /std::fs::set_permissions/);
  assert.doesNotMatch(unixState, /std::os::unix::fs::\{[^}]*chown/);
  assert.match(
    unixState,
    /const DATA_ROOT: &str = "\/var\/lib\/centrald-client"/,
  );
  assert.match(unixState, /Uid::ROOT/);
  assert.match(clientCargo, /rustix\.workspace = true/);
  assert.match(
    workspaceCargo,
    /rustix = \{ version = "1\.1\.4", features = \["fs"\] \}/,
  );
  assert.match(
    packaging,
    /install -d -m 0750 -o root -g centrald \/var\/lib\/centrald-client/,
  );
  assert.match(
    packaging,
    /install -d -m 0750 -o root -g centrald \/var\/lib\/centrald-client\/identities/,
  );
  assert.match(packaging, /if \[ -e \/var\/lib\/centrald-client\.lock \]/);
  assert.match(
    packaging,
    /chown centrald:centrald \/var\/lib\/centrald-client\.lock/,
  );
  assert.match(
    packaging,
    /install -m 0600 -o centrald -g centrald \/dev\/null \/var\/lib\/centrald-client\.lock/,
  );
});

test("Admin renewal is serialized across app processes and cleans failed publications", async () => {
  const [profiles, cargo] = await Promise.all([
    read("apps/admin/src-tauri/src/profiles.rs"),
    read("apps/admin/src-tauri/Cargo.toml"),
  ]);
  assert.match(profiles, /struct AdminProfileLock/);
  assert.match(profiles, /\.centrald-profile-state\.lock/);
  assert.match(profiles, /FileExt::try_lock_exclusive/);
  const acquire = profiles.indexOf("AdminProfileLock::acquire");
  const renew = profiles.indexOf("renew_admin_profile", acquire);
  assert.ok(acquire >= 0 && renew > acquire);
  assert.match(
    profiles,
    /Err\(error\) => \{\s*cleanup_profile_generation\(profile_dir, generation_id, &replacement\);\s*return Err\(error\.context\("publish renewed Admin credential generation"\)\);/,
  );
  assert.match(cargo, /fs2\.workspace = true/);
});

test("server settings replacement has bounded backups and recoverable committed cleanup", async () => {
  const [secureFs, services, configLock, manage] = await Promise.all([
    read("crates/centrald-common/src/secure_fs.rs"),
    read("crates/centrald-server/src/services.rs"),
    read("crates/centrald-server/src/config_lock.rs"),
    read("crates/centrald-server/src/manage.rs"),
  ]);
  assert.match(secureFs, /pub fn replace_file_atomically/);
  assert.match(secureFs, /pub fn prune_file_backups/);
  assert.match(services, /replace_file_atomically/);
  assert.doesNotMatch(services, /replace_file_with_backup/);
  assert.match(services, /recovery transaction cleanup was incomplete/);
  assert.match(configLock, /Removing the journal is the durable transition/);
  assert.match(configLock, /committed settings cleanup marker/);
  assert.match(
    configLock,
    /committed_cleanup_without_journal_keeps_replacement/,
  );
  assert.match(manage, /CONFIG_BACKUP_RETENTION: usize = 10/);
  assert.match(manage, /prune_file_backups/);
});

test("Windows privileged paths use OS APIs and ACL recursion is bounded", async () => {
  const [config, windowsPaths, enrollment, profiles, installer] =
    await Promise.all([
      read("crates/centrald-common/src/config.rs"),
      read("crates/centrald-common/src/windows_paths.rs"),
      read("crates/centrald-client/src/enrollment.rs"),
      read("apps/admin/src-tauri/src/profiles.rs"),
      read("deploy/windows/install-client.ps1"),
    ]);
  assert.match(windowsPaths, /SHGetKnownFolderPath/);
  assert.match(windowsPaths, /GetSystemDirectoryW/);
  assert.doesNotMatch(
    config,
    /env::var\("(?:PROGRAMDATA|ProgramData|PROGRAMFILES|ProgramFiles|SystemRoot|SYSTEMROOT)"/,
  );
  assert.match(enrollment, /windows_system_executable\("sc\.exe"\)/);
  assert.match(profiles, /windows_powershell_executable\(\)/);
  assert.match(profiles, /\$maximumItems = 4096/);
  assert.match(installer, /\$maximumItems = 4096/);
  assert.match(
    installer,
    /\[Environment\]::GetFolderPath\(\[Environment\+SpecialFolder\]::CommonApplicationData\)/,
  );
  assert.match(installer, /\[Environment\]::SystemDirectory/);
});

test("certificate issuance is bounded by signing-chain expiration", async () => {
  const [pki, services] = await Promise.all([
    read("crates/centrald-pki/src/lib.rs"),
    read("crates/centrald-server/src/services.rs"),
  ]);
  assert.match(pki, /InsufficientSigningValidity/);
  assert.match(pki, /fn bounded_not_after/);
  assert.match(pki, /SIGNING_CHAIN_SAFETY_MARGIN_DAYS/);
  assert.match(pki, /MINIMUM_LEAF_VALIDITY_DAYS/);
  assert.match(pki, /MINIMUM_ISSUER_VALIDITY_DAYS/);
  assert.match(pki, /certificate_not_after\(issuer_certificate_pem\)/);
  assert.match(pki, /certificate_not_after\(root_certificate_pem\)/);
  assert.match(services, /INTERVAL '1 hour'/);
  assert.doesNotMatch(services, /INTERVAL '24 hours'/);
});

test("job delivery and long-lived Admin streams have bounded recovery", async () => {
  const [migration, services, daemon, main] = await Promise.all([
    read("crates/centrald-server/migrations/0001_initial.sql"),
    read("crates/centrald-server/src/services.rs"),
    read("crates/centrald-client/src/daemon.rs"),
    read("crates/centrald-server/src/main.rs"),
  ]);
  assert.match(migration, /execution_start_expires_at/);
  assert.match(services, /JOB_EXECUTION_START_LEASE_SECONDS/);
  assert.match(services, /MAX_CONCURRENT_JOB_STREAMS/);
  assert.match(services, /ADMIN_STREAM_REAUTH_SECONDS/);
  assert.match(services, /authorize_existing_identity/);
  assert.match(daemon, /healthy_stream/);
  assert.match(daemon, /send_job_event\([\s\S]*?1,/);
  assert.match(main, /monitor_server_tls_renewal/);
});

test("managed setup preflights every filesystem output before PostgreSQL mutation", async () => {
  const [main, setup] = await Promise.all([
    read("crates/centrald-server/src/main.rs"),
    read("crates/centrald-server/src/setup.rs"),
  ]);
  assert.match(setup, /pub fn preflight\(options: &SetupOptions\)/);
  const collect = main.indexOf("let options = collect_setup");
  const preflight = main.indexOf("preflight(&options)", collect);
  const journal = main.indexOf("setup_recovery::begin_setup", collect);
  const role = main.indexOf("local_postgres::provision_role", collect);
  assert.ok(
    collect >= 0 &&
      preflight > collect &&
      journal > preflight &&
      role > journal,
  );
});

test("recommended local PostgreSQL administration is destination-pinned and environment-clean", async () => {
  const postgres = await read("crates/centrald-server/src/local_postgres.rs");
  assert.match(postgres, /Command::new\(RUNUSER\)[\s\S]*?\.env_clear\(\)/);
  assert.match(postgres, /ENV,[\s\S]*?"-i"/);
  assert.match(postgres, /"--host",\s*LOCAL_POSTGRES_SOCKET/);
  assert.match(postgres, /"--port",\s*LOCAL_POSTGRES_PORT/);
  assert.match(postgres, /"--username",\s*"postgres"/);
  assert.match(
    postgres,
    /LOCAL_POSTGRES_SOCKET: &str = "\/var\/run\/postgresql"/,
  );
  assert.match(postgres, /stderr\(Stdio::piped\(\)\)/);
  assert.doesNotMatch(postgres, /fn try_start_postgresql/);
});

test("client invitations never use public process arguments", async () => {
  const [cli, enrollment, quickstart] = await Promise.all([
    read("crates/centrald-client/src/cli.rs"),
    read("crates/centrald-client/src/enrollment.rs"),
    read("docs/QUICKSTART.md"),
  ]);
  assert.match(cli, /pub key_file: Option<PathBuf>/);
  assert.match(cli, /pub key_stdin: bool/);
  assert.doesNotMatch(cli, /pub key: Option<String>/);
  assert.match(enrollment, /MAX_INVITATION_BYTES/);
  assert.match(enrollment, /access-key file must be .*private/);
  assert.match(enrollment, /stdin\(\)\.is_terminal\(\)/);
  assert.match(quickstart, /--key-file/);
  assert.match(quickstart, /--key-stdin/);
});

test("managed PostgreSQL objects require instance-bound ownership markers", async () => {
  const [postgres, wizard, nuke] = await Promise.all([
    read("crates/centrald-server/src/local_postgres.rs"),
    read("crates/centrald-server/src/wizard.rs"),
    read("crates/centrald-server/src/nuke.rs"),
  ]);
  assert.match(wizard, /centrald_\{\}.*instance_id\.simple\(\)/s);
  assert.doesNotMatch(wizard, /simple\(\).*\[\.\.16\]/s);
  assert.match(postgres, /COMMENT ON ROLE/);
  assert.match(postgres, /centrald-instance:/);
  assert.match(postgres, /DROP DATABASE/);
  assert.match(postgres, /drop_owned_role/);
  assert.match(nuke, /NukeRecoveryJournal/);
  assert.match(nuke, /drop_owned_role/);
});

test("client enrollment secrets use protected channels and stable file descriptors", async () => {
  const enrollment = await read("crates/centrald-client/src/enrollment.rs");
  assert.match(enrollment, /Result<SecretString>/);
  assert.match(enrollment, /opened\.dev\(\) != inspected\.dev\(\)/);
  assert.match(enrollment, /validate_access_key_ancestors/);
  assert.match(enrollment, /inspected\.uid\(\) != 0/);
  assert.match(enrollment, /--key-file is disabled on Windows/);
  assert.doesNotMatch(enrollment, /SecretString::from\(key\.clone\(\)\)/);
});

test("Windows known folders initialize COM and have no hardcoded fallback", async () => {
  const [paths, config] = await Promise.all([
    read("crates/centrald-common/src/windows_paths.rs"),
    read("crates/centrald-common/src/config.rs"),
  ]);
  assert.match(paths, /CoInitializeEx/);
  assert.match(paths, /CoUninitialize/);
  assert.match(paths, /SHGetKnownFolderPath/);
  assert.doesNotMatch(config, /C:\\\\ProgramData/);
  assert.doesNotMatch(config, /C:\\\\Program Files/);
});

test("guided trust export resolves its default to an absolute path", async () => {
  const manage = await read("crates/centrald-server/src/manage.rs");
  assert.match(manage, /current_dir\(\)/);
  assert.match(manage, /default_destination\.display\(\)\.to_string\(\)/);
  assert.match(manage, /destination\.is_absolute\(\)/);
});

test("documented client restart remains visible in the public CLI", async () => {
  const cli = await read("crates/centrald-client/src/cli.rs");
  const restart = cli.slice(
    cli.indexOf("Restart") - 120,
    cli.indexOf("Restart") + 120,
  );
  assert.doesNotMatch(restart, /command\(hide = true\)/);
  assert.match(restart, /Restart/);
});

test("setup recovery and destructive reset share one fixed mutation lock", async () => {
  const [main, recovery] = await Promise.all([
    read("crates/centrald-server/src/main.rs"),
    read("crates/centrald-server/src/setup_recovery.rs"),
  ]);
  assert.match(
    recovery,
    /SETUP_MUTATION_LOCK: &str = "\/var\/lib\/centrald-initial-setup\.lock"/,
  );
  assert.match(recovery, /FileExt::try_lock_exclusive/);
  assert.match(recovery, /reset_interrupted_setup_for_nuke/);
  assert.match(recovery, /process_owner_is_live/);
  const setup = main.indexOf("async fn initial_setup");
  const setupLock = main.indexOf("acquire_setup_mutation_lock", setup);
  const recover = main.indexOf("recover_before_initial_setup", setup);
  assert.ok(setup >= 0 && setupLock > setup && recover > setupLock);
  const nuke = main.indexOf("if cli.nuke");
  const nukeLock = main.indexOf("acquire_setup_mutation_lock", nuke);
  const resetInterrupted = main.indexOf(
    "reset_interrupted_setup_for_nuke",
    nuke,
  );
  assert.ok(nuke >= 0 && nukeLock > nuke && resetInterrupted > nukeLock);
});

test("setup and reset keep the durable configuration outside the disposable data root", async () => {
  const [setup, nuke] = await Promise.all([
    read("crates/centrald-server/src/setup.rs"),
    read("crates/centrald-server/src/nuke.rs"),
  ]);
  assert.match(setup, /validate_clean_absolute_path/);
  assert.match(setup, /config_path\.starts_with\(&options\.data_dir\)/);
  assert.match(nuke, /canonical_config\.starts_with\(&canonical_data\)/);
});

test("destructive reset is journaled, bounded, and instance-owned", async () => {
  const [nuke, database, postgres] = await Promise.all([
    read("crates/centrald-server/src/nuke.rs"),
    read("crates/centrald-server/src/db.rs"),
    read("crates/centrald-server/src/local_postgres.rs"),
  ]);
  assert.match(nuke, /enum NukePhase[\s\S]*Authorized[\s\S]*DatabaseDropped/);
  assert.match(nuke, /MAX_NUKE_JOURNAL_BYTES/);
  assert.match(nuke, /validate_nuke_journal_parent/);
  assert.match(nuke, /replace_file_atomically/);
  assert.match(nuke, /rerun the exact --nuke command/);
  assert.match(nuke, /require_owned_role\(role, journal\.instance_id\)/);
  assert.match(
    nuke,
    /Keep the instance-bound marker until every other child has been/,
  );
  assert.match(nuke, /validate_empty_data_root_after_marker_retirement/);
  assert.doesNotMatch(nuke, /remove_dir_all\(data_dir\)/);
  assert.match(database, /verify_owned_database/);
  assert.match(database, /MissingDatabase/);
  assert.match(
    postgres,
    /drop_owned_role\(role, journal\.instance_id\)|drop_owned_role/,
  );
});

test("managed PostgreSQL objects are bound to the full server instance", async () => {
  const [wizard, setup, recovery, postgres] = await Promise.all([
    read("crates/centrald-server/src/wizard.rs"),
    read("crates/centrald-server/src/setup.rs"),
    read("crates/centrald-server/src/setup_recovery.rs"),
    read("crates/centrald-server/src/local_postgres.rs"),
  ]);
  assert.match(wizard, /format!\("centrald_\{\}", instance_id\.simple\(\)\)/);
  assert.match(setup, /instance_id: options\.instance_id/);
  assert.match(recovery, /instance_id: uuid::Uuid/);
  assert.match(postgres, /COMMENT ON ROLE/);
  assert.match(postgres, /ROLE_COMMENT_PREFIX/);
  assert.match(postgres, /role_ownership\(role, instance_id\)/);
});

test("invitation automation uses bounded no-follow input instead of argv", async () => {
  const enrollment = await read("crates/centrald-client/src/enrollment.rs");
  assert.match(enrollment, /OFlags::NOFOLLOW/);
  assert.match(enrollment, /inspected\.nlink\(\) != 1/);
  assert.match(enrollment, /MAX_INVITATION_BYTES \+ 1/);
  assert.match(enrollment, /--key-stdin requires piped input/);
  assert.match(enrollment, /automated_input && args\.server\.is_none\(\)/);
  assert.doesNotMatch(enrollment, /args\.key\b/);
});

test("Windows machine roots fail closed when known-folder lookup fails", async () => {
  const [config, windowsPaths] = await Promise.all([
    read("crates/centrald-common/src/config.rs"),
    read("crates/centrald-common/src/windows_paths.rs"),
  ]);
  assert.match(config, /ConfigError::PlatformPath/);
  assert.match(config, /refusing to guess a machine state path/);
  assert.match(config, /refusing to guess an installation path/);
  assert.doesNotMatch(config, /PathBuf::from\(r"C:\\\\ProgramData"\)/);
  assert.doesNotMatch(config, /PathBuf::from\(r"C:\\\\Program Files"\)/);
  assert.match(windowsPaths, /CoInitializeEx/);
  assert.match(windowsPaths, /CoUninitialize/);
});

test("server no-color flag changes console output", async () => {
  const [cli, main] = await Promise.all([
    read("crates/centrald-server/src/cli.rs"),
    read("crates/centrald-server/src/main.rs"),
  ]);
  assert.match(cli, /pub no_color: bool/);
  assert.match(main, /console::set_colors_enabled\(false\)/);
  assert.match(main, /console::set_colors_enabled_stderr\(false\)/);
});

test("destructive reset ignores process database overrides and keeps its journal outside data", async () => {
  const [db, nuke, setup] = await Promise.all([
    read("crates/centrald-server/src/db.rs"),
    read("crates/centrald-server/src/nuke.rs"),
    read("crates/centrald-server/src/setup.rs"),
  ]);
  assert.match(db, /pub fn resolve_database_url_from_file/);
  assert.match(nuke, /resolve_database_url_from_file/);
  assert.doesNotMatch(nuke, /resolve_database_url\(&config\)/);
  assert.match(nuke, /path\.starts_with\(&canonical_data\)/);
  assert.match(setup, /config_path\.starts_with\(&options\.data_dir\)/);
});

test("managed PostgreSQL service login never receives database-creation authority", async () => {
  const [main, database, postgres] = await Promise.all([
    read("crates/centrald-server/src/main.rs"),
    read("crates/centrald-server/src/db.rs"),
    read("crates/centrald-server/src/local_postgres.rs"),
  ]);
  assert.match(
    postgres,
    /CREATE ROLE \{\} LOGIN NOCREATEDB NOSUPERUSER NOCREATEROLE NOREPLICATION/,
  );
  assert.match(postgres, /pub fn provision_database/);
  assert.match(postgres, /CREATE DATABASE \{\} OWNER \{\}/);
  assert.match(main, /migrate_precreated_database/);
  assert.match(database, /pub async fn migrate_precreated_database/);
  assert.doesNotMatch(postgres, /CREATE ROLE \{\} LOGIN CREATEDB/);
});

test("initial setup refuses to claim unrelated data-root contents", async () => {
  const setup = await read("crates/centrald-server/src/setup.rs");
  assert.match(setup, /preflight_data_root/);
  assert.match(setup, /refusing to adopt non-empty CentralD data root/);
  assert.match(setup, /remove_empty_setup_directories/);
  assert.doesNotMatch(setup, /remove_dir_all\(data_dir\)/);
});

test("operations documentation names the actual server database environment file", async () => {
  const operations = await read("docs/OPERATIONS.md");
  assert.match(operations, /\/etc\/centrald\/server\.env/);
  assert.doesNotMatch(operations, /\/etc\/centrald\/database\.env/);
});

test("setup output paths cannot overlap through parent-child aliases", async () => {
  const setup = await read("crates/centrald-server/src/setup.rs");
  assert.match(setup, /setup output paths must not overlap/);
  assert.match(
    setup,
    /target\.starts_with\(other\) \|\| other\.starts_with\(target\)/,
  );
});

test("managed local PostgreSQL administration has fixed execution deadlines", async () => {
  const postgres = await read("crates/centrald-server/src/local_postgres.rs");
  assert.match(postgres, /const TIMEOUT: &str = "\/usr\/bin\/timeout"/);
  assert.match(postgres, /--kill-after=5s/);
  assert.match(postgres, /"30s",\s*PSQL/);
  assert.match(postgres, /"45s",\s*SYSTEMCTL/);
});

test("advanced PostgreSQL URLs cannot override connection identity or downgrade remote TLS", async () => {
  const [db, wizard, manage] = await Promise.all([
    read("crates/centrald-server/src/db.rs"),
    read("crates/centrald-server/src/wizard.rs"),
    read("crates/centrald-server/src/manage.rs"),
  ]);
  assert.match(db, /pub fn validate_database_url_policy/);
  assert.match(
    db,
    /"user" \| "password" \| "passfile" \| "host" \| "hostaddr" \| "port"/,
  );
  assert.match(db, /"dbname" \| "options"/);
  assert.match(db, /sslmode\.as_deref\(\) != Some\("verify-full"\)/);
  assert.match(db, /parsed\.port\(\)\.is_none\(\)/);
  assert.match(db, /reject_ambient_postgres_environment/);
  assert.match(wizard, /validate_database_url_policy/);
  assert.match(manage, /validate_database_url_policy/);
});

test("runtime database credentials come only from the protected instance file", async () => {
  const db = await read("crates/centrald-server/src/db.rs");
  const resolver =
    /pub fn resolve_database_url\([\s\S]*?\n\}/.exec(db)?.[0] ?? "";
  assert.match(resolver, /resolve_database_url_from_file\(config\)/);
  assert.doesNotMatch(resolver, /std::env::var/);
});

test("advanced setup has a non-secret crash journal and safe external rollback", async () => {
  const [main, recovery] = await Promise.all([
    read("crates/centrald-server/src/main.rs"),
    read("crates/centrald-server/src/setup_recovery.rs"),
  ]);
  assert.match(main, /setup_recovery::begin_setup\(&options\)/);
  assert.match(recovery, /SetupDatabaseMode::External/);
  assert.match(recovery, /database_url_env: String/);
  assert.match(recovery, /cleanup_external_database/);
  assert.match(recovery, /rollback_setup_database/);
  assert.match(recovery, /DatabaseAdminError::MissingDatabase/);
  const journalFields =
    /struct SetupRecoveryJournal \{([\s\S]*?)\n\}/.exec(recovery)?.[1] ?? "";
  assert.doesNotMatch(journalFields, /password|SecretString|database_url:\s/);
});

test("database relocation is ownership-verified and managed-local relocation is refused", async () => {
  const manage = await read("crates/centrald-server/src/manage.rs");
  assert.match(manage, /async fn configure_database/);
  assert.match(manage, /verify_owned_database/);
  assert.match(manage, /managed-local PostgreSQL location is lifecycle-bound/);
  assert.match(manage, /Duration::from_secs\(15\)/);
});

test("package upgrades restart only already-active CentralD services", async () => {
  const packaging = await read("scripts/package-linux.js");
  assert.match(
    packaging,
    /systemctl is-active --quiet centrald-server\.service/,
  );
  assert.match(packaging, /systemctl try-restart centrald-server\.service/);
  assert.match(
    packaging,
    /systemctl is-active --quiet centrald-client\.service/,
  );
  assert.match(packaging, /systemctl try-restart centrald-client\.service/);
  assert.match(packaging, /"coreutils"/);
});

test("packaged first-start systemd command has an execution deadline", async () => {
  const main = await read("crates/centrald-server/src/main.rs");
  assert.match(main, /Command::new\(timeout\)/);
  assert.match(main, /"--kill-after=5s"/);
  assert.match(main, /"45s"/);
  assert.match(main, /"--no-ask-password"/);
});

test("packaged services use exec startup semantics and setup waits for server readiness", async () => {
  const [main, serverUnit, clientUnit] = await Promise.all([
    read("crates/centrald-server/src/main.rs"),
    read("deploy/systemd/centrald-server.service"),
    read("deploy/systemd/centrald-client.service"),
  ]);
  assert.match(serverUnit, /Type=exec/);
  assert.match(clientUnit, /Type=exec/);
  assert.match(main, /async fn try_start_packaged_service/);
  assert.match(
    main,
    /UnixStream::connect\(centrald_server::DEFAULT_LOCAL_SOCKET\)/,
  );
  assert.match(main, /Duration::from_secs\(15\)/);
});

test("systemd services drop ambient Linux capabilities and restrict address families", async () => {
  const [serverUnit, clientUnit] = await Promise.all([
    read("deploy/systemd/centrald-server.service"),
    read("deploy/systemd/centrald-client.service"),
  ]);
  for (const unit of [serverUnit, clientUnit]) {
    assert.match(unit, /CapabilityBoundingSet=\r?\n/);
    assert.match(unit, /AmbientCapabilities=\r?\n/);
    assert.match(unit, /RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6/);
    assert.match(unit, /RestrictNamespaces=true/);
    assert.match(unit, /ProtectHostname=true/);
  }
});

test("enrollment crypto is offloaded and concurrency bounded", async () => {
  const server = await readFile(
    "crates/centrald-server/src/services.rs",
    "utf8",
  );
  const manage = await readFile("crates/centrald-server/src/manage.rs", "utf8");
  const local = await readFile(
    "crates/centrald-server/src/local_control.rs",
    "utf8",
  );
  assert.match(server, /MAX_CONCURRENT_ENROLLMENT_CRYPTO:\s*usize\s*=\s*2/);
  assert.match(server, /enrollment_crypto_limit:\s*Arc<Semaphore>/);
  assert.match(server, /tokio::task::spawn_blocking/);
  assert.match(server, /try_acquire_owned/);
  assert.match(
    server,
    /Status::resource_exhausted\("enrollment cryptography is busy/,
  );
  assert.match(server, /verify_enrollment_key_bounded/);
  assert.match(server, /hash_enrollment_key_bounded/);
  assert.match(manage, /create_enrollment_key_bounded/);
  assert.match(manage, /tokio::task::spawn_blocking/);
  assert.match(local, /create_enrollment_key_bounded/);
  assert.match(local, /enrollment_crypto_limit/);
  assert.match(local, /\[REDACTED\]/);
});

test("server private material is revalidated before runtime use", async () => {
  const security = await readFile(
    "crates/centrald-server/src/file_security.rs",
    "utf8",
  );
  const server = await readFile(
    "crates/centrald-server/src/services.rs",
    "utf8",
  );
  const main = await readFile("crates/centrald-server/src/main.rs", "utf8");
  const db = await readFile("crates/centrald-server/src/db.rs", "utf8");
  const lock = await readFile(
    "crates/centrald-server/src/config_lock.rs",
    "utf8",
  );
  assert.match(security, /O_NOFOLLOW/);
  assert.match(security, /custom_flags\(O_NOFOLLOW \| O_CLOEXEC\)/);
  assert.match(security, /SecureReadClass::PrivateRoot/);
  assert.match(security, /SecureReadClass::PublicRootTrust/);
  assert.match(security, /metadata\.uid\(\) != 0/);
  assert.match(security, /metadata\.nlink\(\) != 1/);
  assert.match(security, /mode & 0o077 != 0/);
  assert.match(server, /client issuer private key/);
  assert.match(server, /Admin issuer private key/);
  assert.match(server, /acquire_config_lock_nonblocking/);
  assert.match(
    server,
    /Status::unavailable\("configuration is busy; retry shortly"\)/,
  );
  assert.match(main, /server TLS private key/);
  assert.match(main, /read_root_public_text/);
  assert.match(db, /database environment file/);
  assert.match(lock, /fn try_acquire/);
});

test("capability-free packaged server rejects privileged listener ports", async () => {
  const config = await readFile("crates/centrald-common/src/config.rs", "utf8");
  const unit = await readFile("deploy/systemd/centrald-server.service", "utf8");
  assert.match(unit, /^CapabilityBoundingSet=\s*$/m);
  assert.match(config, /port\| \*port < 1024/);
});
