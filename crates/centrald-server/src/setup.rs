use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use centrald_common::build_info;
use centrald_common::config::{
    DatabaseSection, RuntimeSection, SERVER_CONFIG_SCHEMA_VERSION, SERVER_DATA_DIR,
    SERVER_DATABASE_ENV_FILE, SERVER_DATABASE_URL_ENV, ServerConfig, ServerPkiSection,
    ServerSection, UpdateSection,
};
use centrald_common::secure_fs::{validate_no_symlink_ancestors, write_new_file};
use centrald_pki::PkiHierarchy;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use pkcs8::LineEnding;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use crate::db::database_environment_contents;

pub const DATA_ROOT_MARKER: &str = ".centrald-data-root";
pub const DATA_ROOT_MARKER_PREFIX: &str = "centrald-data-root-v1:";
const SETUP_RECOVERY_JOURNAL: &str = ".centrald-initial-setup-recovery.json";

#[must_use]
pub fn data_root_marker_contents(instance_id: Uuid) -> String {
    format!("{DATA_ROOT_MARKER_PREFIX}{instance_id}\n")
}

#[derive(Debug)]
pub struct SetupOptions {
    pub instance_id: Uuid,
    pub config_path: PathBuf,
    pub public_host: String,
    pub database_url_env: String,
    pub database_url: SecretString,
    pub managed_local_role: Option<String>,
    pub environment_file: PathBuf,
    pub data_dir: PathBuf,
    pub recovery_key_output: PathBuf,
    pub admin_name: String,
}

#[derive(Debug)]
pub struct SetupSummary {
    pub config_path: PathBuf,
    pub trust_certificate_path: PathBuf,
    pub root_fingerprint_sha256: String,
    pub recovery_key_output: PathBuf,
}

#[derive(Debug)]
struct SetupPaths {
    data_root_marker: PathBuf,
    root_cert: PathBuf,
    server_chain: PathBuf,
    server_key: PathBuf,
    server_issuer_cert: PathBuf,
    server_issuer_key: PathBuf,
    client_issuer_cert: PathBuf,
    client_issuer_key: PathBuf,
    admin_issuer_cert: PathBuf,
    admin_issuer_key: PathBuf,
    grant_signing_key: PathBuf,
    grant_signing_public_key: PathBuf,
}

impl SetupPaths {
    fn new(data_dir: &Path) -> Self {
        let pki_dir = data_dir.join("pki");
        Self {
            data_root_marker: data_dir.join(DATA_ROOT_MARKER),
            root_cert: pki_dir.join("root-ca.pem"),
            server_chain: pki_dir.join("server-chain.pem"),
            server_key: pki_dir.join("server-key.pem"),
            server_issuer_cert: pki_dir.join("server-issuer.pem"),
            server_issuer_key: pki_dir.join("server-issuer-key.pem"),
            client_issuer_cert: pki_dir.join("client-issuer.pem"),
            client_issuer_key: pki_dir.join("client-issuer-key.pem"),
            admin_issuer_cert: pki_dir.join("admin-issuer.pem"),
            admin_issuer_key: pki_dir.join("admin-issuer-key.pem"),
            grant_signing_key: pki_dir.join("grant-signing-key.pem"),
            grant_signing_public_key: pki_dir.join("grant-signing-public.pem"),
        }
    }
}

/// Validates every setup option and output path without creating files or
/// changing `PostgreSQL`. This must run before a managed local role/database is
/// provisioned so interrupted-setup rollback can remove only paths that were
/// proven absent before the first external mutation.
///
/// # Errors
///
/// Returns an error when an option is invalid, an output already exists, two
/// outputs overlap, or any path has an unsafe ancestor.
pub fn preflight(options: &SetupOptions) -> Result<()> {
    validate_options(options)?;
    preflight_data_root(&options.data_dir)?;
    let paths = SetupPaths::new(&options.data_dir);
    preflight_targets(options, &paths)
}

/// Creates the fixed server data and PKI directories with an explicit private
/// mode instead of inheriting the invoking shell's umask. Existing directories
/// are accepted only when they already satisfy the setup ownership boundary.
///
/// This function performs no `PostgreSQL` mutation and creates no credential
/// file. A crash after this step therefore leaves only empty directories that a
/// subsequent `initial-setup` can safely reuse.
///
/// # Errors
///
/// Returns an error when a setup directory cannot be created or an existing
/// directory does not satisfy the setup ownership boundary.
pub fn prepare_directories(options: &SetupOptions) -> Result<()> {
    let paths = SetupPaths::new(&options.data_dir);
    let mut parents = setup_targets(options, &paths)
        .into_iter()
        .filter_map(Path::parent)
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    parents.sort_by_key(|path| path.components().count());
    parents.dedup();
    for parent in parents {
        ensure_setup_directory(&parent, "setup output directory")?;
    }
    Ok(())
}

fn ensure_setup_directory(path: &Path, label: &str) -> Result<()> {
    match path.symlink_metadata() {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!("{label} must be a real directory: {}", path.display());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                    bail!(
                        "{label} must be root-owned and not group/world-writable: {}",
                        path.display()
                    );
                }
            }
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {label} {}", path.display()));
        }
    }

    let parent = path.parent().context("setup directory has no parent")?;
    validate_no_symlink_ancestors(path)
        .with_context(|| format!("validate {label} ancestors for {}", path.display()))?;
    validate_setup_ancestor_ownership(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        match builder.create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return ensure_setup_directory(path, label);
            }
            Err(error) => {
                return Err(error).with_context(|| format!("create {label} {}", path.display()));
            }
        }
    }
    #[cfg(not(unix))]
    {
        match std::fs::create_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return ensure_setup_directory(path, label);
            }
            Err(error) => {
                return Err(error).with_context(|| format!("create {label} {}", path.display()));
            }
        }
    }
    std::fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync {label} {}", path.display()))?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync {label} parent {}", parent.display()))?;
    ensure_setup_directory(path, label)
}

/// Creates a new server configuration, PKI hierarchy, and broker-grant key.
///
/// Every output uses create-new semantics; setup never overwrites a prior
/// installation or recovery key.
///
/// # Errors
///
/// Returns an error for invalid options, certificate/key generation failures,
/// serialization failures, or any safe filesystem creation failure.
pub fn initialize(options: &SetupOptions) -> Result<SetupSummary> {
    preflight(options)?;
    prepare_directories(options)?;
    let paths = SetupPaths::new(&options.data_dir);
    let result: Result<SetupSummary> = (|| {
        let hierarchy = PkiHierarchy::generate().context("generate CentralD PKI hierarchy")?;
        let server_identity = hierarchy
            .issue_server(&options.public_host)
            .context("issue server TLS identity")?;

        let mut grant_seed = [0_u8; 32];
        rand::rng().fill_bytes(&mut grant_seed);
        let grant_key = SigningKey::from_bytes(&grant_seed);
        let grant_private_pem = grant_key
            .to_pkcs8_pem(LineEnding::LF)
            .context("encode broker-grant private key")?;
        let grant_public_pem = grant_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .context("encode broker-grant public key")?;

        let config = build_config(options, &paths);
        config.validate()?;
        let config_toml = toml::to_string_pretty(&config).context("serialize server config")?;
        persist_runtime_material(
            &paths,
            &hierarchy,
            &server_identity,
            grant_private_pem.as_bytes(),
            grant_public_pem.as_bytes(),
        )?;

        let recovery_bundle = format!(
            "# CentralD offline root recovery material\n{}{}",
            hierarchy.root.certificate_pem(),
            hierarchy.root.private_key_pem()
        );
        write_new_file(
            &options.recovery_key_output,
            recovery_bundle.as_bytes(),
            true,
        )?;
        let environment = database_environment_contents(
            config.server.instance_id,
            &options.database_url_env,
            options.database_url.expose_secret(),
        );
        write_new_file(&options.environment_file, environment.as_bytes(), true)?;
        let marker = data_root_marker_contents(config.server.instance_id);
        write_new_file(&paths.data_root_marker, marker.as_bytes(), true)?;
        write_new_file(&options.config_path, config_toml.as_bytes(), true)?;

        Ok(SetupSummary {
            config_path: options.config_path.clone(),
            trust_certificate_path: paths.root_cert.clone(),
            root_fingerprint_sha256: hierarchy.root.certificate_sha256(),
            recovery_key_output: options.recovery_key_output.clone(),
        })
    })();

    match result {
        Ok(summary) => Ok(summary),
        Err(error) => match rollback_failed_setup(options) {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(error.context(format!(
                "automatic setup rollback was incomplete: {rollback_error:#}"
            ))),
        },
    }
}

/// Removes only the exact files reserved by a failed setup attempt.
///
/// Preflight guarantees these targets did not exist before setup. Symlinks and
/// non-regular replacements are never followed or removed.
///
/// # Errors
///
/// Returns an error when a created output cannot be safely removed. All other
/// outputs are still attempted so a retry is as likely as possible to succeed.
pub fn rollback_failed_setup(options: &SetupOptions) -> Result<()> {
    rollback_interrupted_setup_files(
        &options.config_path,
        &options.recovery_key_output,
        &options.environment_file,
        &options.data_dir,
    )?;
    remove_empty_setup_directories(&options.data_dir)
}

/// Removes the exact filesystem outputs that may have been published by an
/// interrupted setup. This recovery path intentionally needs no database URL or
/// other secret; all paths are either package-fixed or were recorded before the
/// first managed `PostgreSQL` mutation.
///
/// # Errors
///
/// Returns an error when an output cannot be removed or a replacement symlink
/// or non-file output is encountered.
pub fn rollback_interrupted_setup_files(
    config_path: &Path,
    recovery_key_output: &Path,
    environment_file: &Path,
    data_dir: &Path,
) -> Result<()> {
    let paths = SetupPaths::new(data_dir);
    let mut failures = Vec::new();
    for target in setup_target_paths(config_path, recovery_key_output, environment_file, &paths)
        .into_iter()
        .rev()
    {
        match target.symlink_metadata() {
            Ok(metadata) if metadata.file_type().is_symlink() => failures.push(format!(
                "refusing to remove replacement symlink {}",
                target.display()
            )),
            Ok(metadata) if metadata.is_file() => {
                if let Err(error) = std::fs::remove_file(target) {
                    failures.push(format!("remove {}: {error}", target.display()));
                }
            }
            Ok(_) => failures.push(format!(
                "refusing to remove non-file setup output {}",
                target.display()
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => failures.push(format!("inspect {}: {error}", target.display())),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!(failures.join("; "))
    }
}

fn preflight_data_root(data_dir: &Path) -> Result<()> {
    let metadata = match data_dir.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect setup data root {}", data_dir.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "setup data root must be a real directory: {}",
            data_dir.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!(
                "setup data root must be root-owned and not group/world-writable: {}",
                data_dir.display()
            );
        }
    }

    for entry in std::fs::read_dir(data_dir)
        .with_context(|| format!("list setup data root {}", data_dir.display()))?
    {
        let entry = entry
            .with_context(|| format!("read setup data-root entry under {}", data_dir.display()))?;
        let name = entry.file_name();
        let path = entry.path();
        if name == SETUP_RECOVERY_JOURNAL {
            let metadata = path
                .symlink_metadata()
                .with_context(|| format!("inspect setup recovery state {}", path.display()))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!(
                    "setup recovery state is not a regular file: {}",
                    path.display()
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
                    bail!(
                        "setup recovery state must be root-owned, private, and single-linked: {}",
                        path.display()
                    );
                }
            }
            continue;
        }
        if name == "pki" {
            let metadata = path
                .symlink_metadata()
                .with_context(|| format!("inspect setup PKI directory {}", path.display()))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!(
                    "setup PKI path must be a real directory: {}",
                    path.display()
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                    bail!(
                        "setup PKI directory must be root-owned and not group/world-writable: {}",
                        path.display()
                    );
                }
            }
            if std::fs::read_dir(&path)
                .with_context(|| format!("list setup PKI directory {}", path.display()))?
                .next()
                .transpose()?
                .is_none()
            {
                continue;
            }
        }
        bail!(
            "refusing to adopt non-empty CentralD data root {}; move or remove the unexpected entry {} before initial-setup",
            data_dir.display(),
            path.display()
        );
    }
    Ok(())
}

/// Removes only empty package-created setup directories after all generated
/// files and any recovery journal have been retired. No recursive deletion is
/// performed.
///
/// # Errors
///
/// Returns an error when an empty setup directory cannot be removed.
pub fn remove_empty_setup_directories(data_dir: &Path) -> Result<()> {
    let pki_dir = data_dir.join("pki");
    remove_empty_setup_directory(&pki_dir, "setup PKI directory")?;
    remove_empty_setup_directory(data_dir, "setup data directory")
}

fn remove_empty_setup_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {label} {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "refusing to remove non-directory {label}: {}",
            path.display()
        );
    }
    if std::fs::read_dir(path)
        .with_context(|| format!("list {label} {}", path.display()))?
        .next()
        .transpose()?
        .is_some()
    {
        return Ok(());
    }
    std::fs::remove_dir(path).with_context(|| format!("remove empty {label} {}", path.display()))
}

fn preflight_targets(options: &SetupOptions, paths: &SetupPaths) -> Result<()> {
    let targets = setup_targets(options, paths);
    for (index, target) in targets.iter().enumerate() {
        for other in targets.iter().skip(index + 1) {
            if target.starts_with(other) || other.starts_with(target) {
                bail!(
                    "setup output paths must not overlap: {} and {}",
                    target.display(),
                    other.display()
                );
            }
        }
    }
    let mut unique = HashSet::with_capacity(targets.len());
    for target in targets {
        if !unique.insert(target.to_path_buf()) {
            bail!("setup output paths must be unique: {}", target.display());
        }
        validate_clean_absolute_path(target)?;
        validate_no_symlink_ancestors(target)
            .with_context(|| format!("validate setup path ancestors for {}", target.display()))?;
        validate_setup_ancestor_ownership(target)?;
        if target.symlink_metadata().is_ok() {
            bail!(
                "refusing to overwrite existing setup output: {}",
                target.display()
            );
        }
    }
    Ok(())
}

fn validate_clean_absolute_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("setup output paths must be absolute: {}", path.display());
    }
    let display = path.to_string_lossy();
    let has_dot_component = display
        .split(['/', '\\'])
        .any(|component| matches!(component, "." | ".."));
    if has_dot_component
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        bail!(
            "setup output paths must not contain relative or platform-prefix components: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn validate_setup_ancestor_ownership(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mut current = path.parent();
    let mut found_existing = false;
    while let Some(ancestor) = current {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        match ancestor.symlink_metadata() {
            Ok(metadata) => {
                found_existing = true;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    bail!(
                        "setup ancestor must be a real directory: {}",
                        ancestor.display()
                    );
                }
                if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                    bail!(
                        "every existing setup path ancestor must be root-owned and not group/world-writable: {}",
                        ancestor.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("inspect {}", ancestor.display()));
            }
        }
        current = ancestor.parent();
    }
    if found_existing {
        Ok(())
    } else {
        bail!("setup output has no existing ancestor: {}", path.display())
    }
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn validate_setup_ancestor_ownership(_path: &Path) -> Result<()> {
    Ok(())
}

fn setup_targets<'a>(options: &'a SetupOptions, paths: &'a SetupPaths) -> [&'a Path; 15] {
    setup_target_paths(
        &options.config_path,
        &options.recovery_key_output,
        &options.environment_file,
        paths,
    )
}

fn setup_target_paths<'a>(
    config_path: &'a Path,
    recovery_key_output: &'a Path,
    environment_file: &'a Path,
    paths: &'a SetupPaths,
) -> [&'a Path; 15] {
    [
        config_path,
        recovery_key_output,
        environment_file,
        &paths.data_root_marker,
        &paths.root_cert,
        &paths.server_chain,
        &paths.server_key,
        &paths.server_issuer_cert,
        &paths.server_issuer_key,
        &paths.client_issuer_cert,
        &paths.client_issuer_key,
        &paths.admin_issuer_cert,
        &paths.admin_issuer_key,
        &paths.grant_signing_key,
        &paths.grant_signing_public_key,
    ]
}

fn build_config(options: &SetupOptions, paths: &SetupPaths) -> ServerConfig {
    ServerConfig {
        schema_version: SERVER_CONFIG_SCHEMA_VERSION,
        server: ServerSection {
            instance_id: options.instance_id,
            public_host: options.public_host.clone(),
            enrollment_listen: unspecified(7443),
            client_listen: unspecified(7444),
            admin_listen: unspecified(7445),
            data_dir: options.data_dir.clone(),
            local_socket: PathBuf::from("/run/centrald/server.sock"),
        },
        database: DatabaseSection {
            url_env: options.database_url_env.clone(),
            environment_file: options.environment_file.clone(),
            max_connections: 10,
            managed_local_role: options.managed_local_role.clone(),
        },
        pki: ServerPkiSection {
            root_cert: paths.root_cert.clone(),
            server_chain: paths.server_chain.clone(),
            server_key: paths.server_key.clone(),
            server_issuer_cert: paths.server_issuer_cert.clone(),
            server_issuer_key: paths.server_issuer_key.clone(),
            client_issuer_cert: paths.client_issuer_cert.clone(),
            client_issuer_key: paths.client_issuer_key.clone(),
            admin_issuer_cert: paths.admin_issuer_cert.clone(),
            admin_issuer_key: paths.admin_issuer_key.clone(),
            grant_signing_key: paths.grant_signing_key.clone(),
            grant_signing_public_key: paths.grant_signing_public_key.clone(),
        },
        runtime: RuntimeSection {
            heartbeat_interval_seconds: 30,
            offline_after_seconds: 90,
            // Job TTL must comfortably exceed the longest broker round trip
            // (up to 15 minutes for package operations) so a terminal event
            // is never rejected as "job expired" after the operation ran.
            job_ttl_seconds: 60 * 60,
            shell_idle_timeout_seconds: 15 * 60,
            max_shell_frame_bytes: 64 * 1024,
        },
        updates: UpdateSection {
            enabled: true,
            channel: build_info::RELEASE_CHANNEL.to_owned(),
            manifest_url: build_info::release_manifest_url(),
            check_interval_seconds: 6 * 60 * 60,
            allow_prerelease: build_info::RELEASE_CHANNEL != "stable",
        },
    }
}

fn persist_runtime_material(
    paths: &SetupPaths,
    hierarchy: &PkiHierarchy,
    server_identity: &centrald_pki::PemIdentity,
    grant_private_pem: &[u8],
    grant_public_pem: &[u8],
) -> Result<()> {
    write_new_file(
        &paths.root_cert,
        hierarchy.root.certificate_pem().as_bytes(),
        false,
    )?;
    write_new_file(
        &paths.server_chain,
        server_identity.certificate_chain_pem.as_bytes(),
        false,
    )?;
    write_new_file(
        &paths.server_key,
        server_identity.private_key_pem.as_bytes(),
        true,
    )?;
    write_new_file(
        &paths.server_issuer_cert,
        hierarchy.server_issuer.certificate_pem().as_bytes(),
        false,
    )?;
    write_new_file(
        &paths.server_issuer_key,
        hierarchy.server_issuer.private_key_pem().as_bytes(),
        true,
    )?;
    write_new_file(
        &paths.client_issuer_cert,
        hierarchy.client_issuer.certificate_pem().as_bytes(),
        false,
    )?;
    write_new_file(
        &paths.client_issuer_key,
        hierarchy.client_issuer.private_key_pem().as_bytes(),
        true,
    )?;
    write_new_file(
        &paths.admin_issuer_cert,
        hierarchy.admin_issuer.certificate_pem().as_bytes(),
        false,
    )?;
    write_new_file(
        &paths.admin_issuer_key,
        hierarchy.admin_issuer.private_key_pem().as_bytes(),
        true,
    )?;
    write_new_file(&paths.grant_signing_key, grant_private_pem, true)?;
    write_new_file(&paths.grant_signing_public_key, grant_public_pem, false)?;
    Ok(())
}

fn validate_options(options: &SetupOptions) -> Result<()> {
    if options.instance_id.is_nil() {
        bail!("server instance ID must not be nil");
    }
    if options.public_host.trim().is_empty() {
        bail!("public host must not be empty");
    }
    if options.database_url_env.trim().is_empty() {
        bail!("database URL environment-variable name must not be empty");
    }
    if options.admin_name.trim().is_empty()
        || options.admin_name.len() > 128
        || options.admin_name.chars().any(char::is_control)
    {
        bail!("initial Admin name must be 1-128 printable characters");
    }
    let database_url = options.database_url.expose_secret();
    if database_url.contains(char::is_whitespace)
        || !(database_url.starts_with("postgres://") || database_url.starts_with("postgresql://"))
    {
        bail!("database URL must be a single PostgreSQL URL without whitespace");
    }
    for path in [
        &options.config_path,
        &options.data_dir,
        &options.recovery_key_output,
        &options.environment_file,
    ] {
        if path.as_os_str().is_empty() {
            bail!("setup paths must not be empty");
        }
    }
    if options.data_dir != Path::new(SERVER_DATA_DIR) {
        bail!("packaged CentralD setup requires data directory {SERVER_DATA_DIR}");
    }
    validate_clean_absolute_path(&options.config_path)?;
    if options.config_path.starts_with(&options.data_dir) {
        bail!(
            "server configuration must be stored outside the disposable CentralD data root {}",
            options.data_dir.display()
        );
    }
    if options.environment_file != Path::new(SERVER_DATABASE_ENV_FILE) {
        bail!("packaged CentralD setup requires database secret file {SERVER_DATABASE_ENV_FILE}");
    }
    if options.database_url_env != SERVER_DATABASE_URL_ENV {
        bail!(
            "packaged CentralD setup requires database environment variable {SERVER_DATABASE_URL_ENV}"
        );
    }
    if options.recovery_key_output.starts_with(&options.data_dir) {
        bail!("offline root recovery key must be stored outside the server data directory");
    }
    Ok(())
}

const fn unspecified(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn setup_paths_reject_relative_components() {
        assert!(validate_clean_absolute_path(Path::new("/etc/centrald/server.toml")).is_ok());
        assert!(validate_clean_absolute_path(Path::new("etc/centrald/server.toml")).is_err());
        assert!(
            validate_clean_absolute_path(Path::new("/etc/../var/lib/centrald/server.toml"))
                .is_err()
        );
        assert!(validate_clean_absolute_path(Path::new("/etc/./centrald/server.toml")).is_err());
    }
}
