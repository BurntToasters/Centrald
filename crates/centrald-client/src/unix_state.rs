//! Descriptor-relative ownership and mode enforcement for the fixed Unix client
//! state tree.
//!
//! Filesystem traversal and mutation uses open descriptors, `O_NOFOLLOW`,
//! `fstat`, `fchown`, and `fchmod`; privileged code never validates one pathname
//! and then mutates a separately resolved pathname.

#![cfg(unix)]

use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use centrald_common::config::ClientConfig;
use rustix::fd::OwnedFd;
use rustix::fs::{
    AtFlags, FileType, Gid, Mode, OFlags, Uid, fchmod, fchown, fstat, fsync, mkdirat,
    open, openat, unlinkat,
};
use rustix::io::Errno;
use uuid::Uuid;

const DATA_ROOT: &str = "/var/lib/centrald-client";
const LOCK_PATH: &str = "/var/lib/centrald-client.lock";
const DATA_ROOT_NAME: &str = "centrald-client";
const LOCK_NAME: &str = "centrald-client.lock";
const ROOT_DIRECTORY_MODE: u32 = 0o750;
const SERVICE_DIRECTORY_MODE: u32 = 0o700;
const SERVICE_FILE_MODE: u32 = 0o600;
const MAX_POINTER_BYTES: usize = 512;
const MAX_CLIENT_CONFIG_BYTES: usize = 64 * 1024;

#[derive(Debug)]
struct StateHandles {
    var_lib: OwnedFd,
    identities: OwnedFd,
    configurations: OwnedFd,
    service_uid: Uid,
    service_gid: Gid,
}


/// Reads the authoritative active configuration through fixed-root, no-follow
/// descriptors. This is used by privileged repair so an untrusted pathname is
/// never opened as root after a separate validation step.
pub(crate) fn load_active_configuration(
    data_dir: &Path,
    service_ids: (u32, u32),
) -> Result<(std::path::PathBuf, ClientConfig)> {
    let state = open_state(data_dir, service_ids)?;
    let pointer = open_regular(&state.configurations, "current.pointer")?;
    let pointer = read_bounded_utf8(pointer, MAX_POINTER_BYTES, "current.pointer")?;
    let filename = pointer.trim();
    if pointer.lines().count() != 1
        || !filename.starts_with("client-")
        || !filename.ends_with(".toml")
    {
        bail!("active client configuration pointer is invalid");
    }
    validate_configuration_filename(filename)?;
    let configuration = open_regular(&state.configurations, filename)?;
    let raw = read_bounded_utf8(configuration, MAX_CLIENT_CONFIG_BYTES, filename)?;
    let path = data_dir.join("configurations").join(filename);
    let config = ClientConfig::parse_at(&raw, &path)
        .context("parse descriptor-opened active client configuration")?;
    Ok((path, config))
}

/// Creates and publishes one enrollment generation entirely relative to open,
/// no-follow directory descriptors. The configuration file is created last,
/// after every credential file and containing directory has been synchronized.
pub(crate) fn persist_enrollment_generation(
    data_dir: &Path,
    identity_id: Uuid,
    generation_id: Uuid,
    configuration_name: &str,
    certificate: &[u8],
    private_key: &[u8],
    root_ca: &[u8],
    grant_key: &[u8],
    configuration: &[u8],
    service_ids: (u32, u32),
) -> Result<()> {
    validate_configuration_filename(configuration_name)?;
    let state = open_state(data_dir, service_ids)?;
    let identity_name = identity_id.to_string();
    let identity = open_or_create_service_directory(
        &state.identities,
        &identity_name,
        state.service_uid,
        state.service_gid,
    )?;
    let generations = open_or_create_service_directory(
        &identity,
        "generations",
        state.service_uid,
        state.service_gid,
    )?;
    let generation_name = generation_id.to_string();
    create_service_directory(
        &generations,
        &generation_name,
        state.service_uid,
        state.service_gid,
    )?;
    let generation = open_directory(&generations, &generation_name)?;

    let result = (|| {
        create_owned_file(
            &generation,
            "identity-chain.pem",
            certificate,
            state.service_uid,
            state.service_gid,
        )?;
        create_owned_file(
            &generation,
            "identity-key.pem",
            private_key,
            state.service_uid,
            state.service_gid,
        )?;
        create_owned_file(
            &generation,
            "root-ca.pem",
            root_ca,
            state.service_uid,
            state.service_gid,
        )?;
        create_owned_file(
            &generation,
            "grant-signing-public.pem",
            grant_key,
            state.service_uid,
            state.service_gid,
        )?;
        fsync(&generation).context("synchronize enrolled credential directory")?;
        create_owned_file(
            &state.configurations,
            configuration_name,
            configuration,
            state.service_uid,
            state.service_gid,
        )?;
        fsync(&state.configurations).context("synchronize enrolled configuration directory")?;
        fsync(&generations).context("synchronize client generation directory")?;
        Ok::<(), anyhow::Error>(())
    })();

    if let Err(error) = result {
        if let Err(cleanup_error) = cleanup_open_generation(
            &state.configurations,
            configuration_name,
            &generations,
            &generation_name,
        ) {
            return Err(error.context(format!(
                "failed generation cleanup also failed: {cleanup_error:#}"
            )));
        }
        return Err(error);
    }
    Ok(())
}

/// Removes one known generation without following pathnames outside the fixed
/// client state tree. Missing components are treated as already cleaned.
pub(crate) fn cleanup_enrollment_generation(
    data_dir: &Path,
    identity_id: Uuid,
    generation_id: Uuid,
    configuration_name: &str,
    service_ids: (u32, u32),
) -> Result<()> {
    validate_configuration_filename(configuration_name)?;
    let state = open_state(data_dir, service_ids)?;
    let identity_name = identity_id.to_string();
    let identity = open_directory_optional(&state.identities, &identity_name)?;
    let generations = match identity.as_ref() {
        Some(identity) => open_directory_optional(identity, "generations")?,
        None => None,
    };
    if let Some(generations) = generations.as_ref() {
        cleanup_open_generation(
            &state.configurations,
            configuration_name,
            generations,
            &generation_id.to_string(),
        )?;
    } else if remove_at_if_present(
        &state.configurations,
        configuration_name,
        AtFlags::empty(),
    )? {
        fsync(&state.configurations).context("synchronize configuration cleanup")?;
    }
    Ok(())
}

pub(crate) fn secure_base_state(
    data_dir: &Path,
    lock_path: &Path,
    service_ids: (u32, u32),
) -> Result<()> {
    let state = open_state(data_dir, service_ids)?;
    if lock_path != Path::new(LOCK_PATH) {
        bail!("Unix client state lock is not the fixed packaged path");
    }
    let lock = open_regular(&state.var_lib, LOCK_NAME)?;
    assign(
        &lock,
        FileType::RegularFile,
        SERVICE_FILE_MODE,
        state.service_uid,
        state.service_gid,
        LOCK_NAME,
    )
}

pub(crate) fn secure_generation(
    data_dir: &Path,
    identity_id: Uuid,
    generation_id: Uuid,
    service_ids: (u32, u32),
) -> Result<()> {
    let state = open_state(data_dir, service_ids)?;
    let identity_name = identity_id.to_string();
    let identity = open_directory(&state.identities, &identity_name)?;
    assign(
        &identity,
        FileType::Directory,
        SERVICE_DIRECTORY_MODE,
        state.service_uid,
        state.service_gid,
        &identity_name,
    )?;
    let generations = open_directory(&identity, "generations")?;
    assign(
        &generations,
        FileType::Directory,
        SERVICE_DIRECTORY_MODE,
        state.service_uid,
        state.service_gid,
        "generations",
    )?;
    let generation_name = generation_id.to_string();
    let generation = open_directory(&generations, &generation_name)?;
    assign(
        &generation,
        FileType::Directory,
        SERVICE_DIRECTORY_MODE,
        state.service_uid,
        state.service_gid,
        &generation_name,
    )?;
    for filename in [
        "identity-chain.pem",
        "identity-key.pem",
        "root-ca.pem",
        "grant-signing-public.pem",
    ] {
        let file = open_regular(&generation, filename)?;
        assign(
            &file,
            FileType::RegularFile,
            SERVICE_FILE_MODE,
            state.service_uid,
            state.service_gid,
            filename,
        )?;
    }
    Ok(())
}

pub(crate) fn secure_configuration(
    data_dir: &Path,
    filename: &str,
    service_ids: (u32, u32),
) -> Result<()> {
    validate_configuration_filename(filename)?;
    let state = open_state(data_dir, service_ids)?;
    let file = open_regular(&state.configurations, filename)?;
    assign(
        &file,
        FileType::RegularFile,
        SERVICE_FILE_MODE,
        state.service_uid,
        state.service_gid,
        filename,
    )
}

pub(crate) fn secure_lock(lock_path: &Path, service_ids: (u32, u32)) -> Result<()> {
    if lock_path != Path::new(LOCK_PATH) {
        bail!("Unix client state lock is not the fixed packaged path");
    }
    let state = open_state(Path::new(DATA_ROOT), service_ids)?;
    let file = open_regular(&state.var_lib, LOCK_NAME)?;
    assign(
        &file,
        FileType::RegularFile,
        SERVICE_FILE_MODE,
        state.service_uid,
        state.service_gid,
        LOCK_NAME,
    )
}

fn open_state(data_dir: &Path, service_ids: (u32, u32)) -> Result<StateHandles> {
    if data_dir != Path::new(DATA_ROOT) {
        bail!("Unix client state must use the fixed packaged data root");
    }
    let (service_uid, service_gid) = typed_service_ids(service_ids)?;
    let flags = directory_flags();
    let filesystem_root = open("/", flags, Mode::empty())
        .context("open filesystem root for descriptor-relative client state access")?;
    require_root_ancestor(&filesystem_root, "/")?;
    let var = open_directory(&filesystem_root, "var")?;
    require_root_ancestor(&var, "/var")?;
    let var_lib = open_directory(&var, "lib")?;
    require_root_ancestor(&var_lib, "/var/lib")?;

    let data_root = open_directory(&var_lib, DATA_ROOT_NAME)?;
    assign(
        &data_root,
        FileType::Directory,
        ROOT_DIRECTORY_MODE,
        Uid::ROOT,
        service_gid,
        DATA_ROOT_NAME,
    )?;
    let identities = open_directory(&data_root, "identities")?;
    assign(
        &identities,
        FileType::Directory,
        ROOT_DIRECTORY_MODE,
        Uid::ROOT,
        service_gid,
        "identities",
    )?;
    let configurations = open_directory(&data_root, "configurations")?;
    assign(
        &configurations,
        FileType::Directory,
        SERVICE_DIRECTORY_MODE,
        service_uid,
        service_gid,
        "configurations",
    )?;

    Ok(StateHandles {
        var_lib,
        identities,
        configurations,
        service_uid,
        service_gid,
    })
}

fn typed_service_ids((uid, gid): (u32, u32)) -> Result<(Uid, Gid)> {
    if uid == u32::MAX || gid == u32::MAX || uid == 0 || gid == 0 {
        bail!("centrald service account has an unsafe UID or GID");
    }
    // `from_raw` is safe after rejecting the reserved all-ones value. Root is
    // also rejected because this is the unprivileged network-service identity.
    Ok((Uid::from_raw(uid), Gid::from_raw(gid)))
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn regular_flags() -> OFlags {
    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn open_directory(parent: &OwnedFd, name: &str) -> Result<OwnedFd> {
    open_directory_optional(parent, name)?.with_context(|| {
        format!("protected client directory component {name} does not exist")
    })
}

fn open_directory_optional(parent: &OwnedFd, name: &str) -> Result<Option<OwnedFd>> {
    match openat(parent, name, directory_flags(), Mode::empty()) {
        Ok(descriptor) => {
            require_type(&descriptor, FileType::Directory, name)?;
            Ok(Some(descriptor))
        }
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("open protected client directory component {name}")),
    }
}

fn open_regular(parent: &OwnedFd, name: &str) -> Result<OwnedFd> {
    let descriptor = openat(parent, name, regular_flags(), Mode::empty())
        .with_context(|| format!("open protected client file component {name}"))?;
    require_type(&descriptor, FileType::RegularFile, name)?;
    Ok(descriptor)
}

fn require_type(descriptor: &OwnedFd, expected: FileType, label: &str) -> Result<()> {
    let metadata = fstat(descriptor).with_context(|| format!("inspect open component {label}"))?;
    let actual = FileType::from_raw_mode(metadata.st_mode);
    if actual != expected {
        bail!("protected component {label} has unsafe type {actual:?}");
    }
    Ok(())
}

fn require_root_ancestor(descriptor: &OwnedFd, label: &str) -> Result<()> {
    let metadata = fstat(descriptor).with_context(|| format!("inspect trusted ancestor {label}"))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != 0
        || metadata.st_gid != 0
        || metadata.st_mode & 0o022 != 0
    {
        bail!("trusted client-state ancestor {label} is not root-owned and non-writable");
    }
    Ok(())
}

fn assign(
    descriptor: &OwnedFd,
    expected: FileType,
    mode: u32,
    owner: Uid,
    group: Gid,
    label: &str,
) -> Result<()> {
    require_type(descriptor, expected, label)?;
    let metadata = fstat(descriptor).with_context(|| format!("inspect open component {label}"))?;
    if expected == FileType::RegularFile && metadata.st_nlink != 1 {
        bail!("protected client file {label} has more than one hard link");
    }
    if metadata.st_uid != owner.as_raw() || metadata.st_gid != group.as_raw() {
        fchown(descriptor, Some(owner), Some(group))
            .with_context(|| format!("assign protected client component {label}"))?;
    }
    if metadata.st_mode & 0o7777 != mode {
        fchmod(descriptor, Mode::from_raw_mode(mode))
            .with_context(|| format!("secure protected client component {label}"))?;
    }
    Ok(())
}


fn read_bounded_utf8(descriptor: OwnedFd, maximum: usize, label: &str) -> Result<String> {
    require_type(&descriptor, FileType::RegularFile, label)?;
    let metadata = fstat(&descriptor)
        .with_context(|| format!("inspect protected client file {label}"))?;
    if metadata.st_nlink != 1 {
        bail!("protected client file {label} has more than one hard link");
    }
    let limit = u64::try_from(maximum)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(maximum.min(4096));
    std::fs::File::from(descriptor)
        .take(limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read protected client file {label}"))?;
    if bytes.len() > maximum {
        bail!("protected client file {label} exceeds its size limit");
    }
    String::from_utf8(bytes)
        .with_context(|| format!("protected client file {label} is not UTF-8"))
}

fn open_or_create_service_directory(
    parent: &OwnedFd,
    name: &str,
    owner: Uid,
    group: Gid,
) -> Result<OwnedFd> {
    match mkdirat(parent, name, Mode::from_raw_mode(SERVICE_DIRECTORY_MODE)) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(error) => {
            return Err(error).with_context(|| format!("create protected client directory {name}"));
        }
    }
    let descriptor = open_directory(parent, name)?;
    assign(
        &descriptor,
        FileType::Directory,
        SERVICE_DIRECTORY_MODE,
        owner,
        group,
        name,
    )?;
    Ok(descriptor)
}

fn create_service_directory(
    parent: &OwnedFd,
    name: &str,
    owner: Uid,
    group: Gid,
) -> Result<()> {
    mkdirat(parent, name, Mode::from_raw_mode(SERVICE_DIRECTORY_MODE))
        .with_context(|| format!("create new client generation directory {name}"))?;
    let descriptor = open_directory(parent, name)?;
    assign(
        &descriptor,
        FileType::Directory,
        SERVICE_DIRECTORY_MODE,
        owner,
        group,
        name,
    )?;
    fsync(parent).with_context(|| format!("synchronize parent of client generation {name}"))
}

fn create_owned_file(
    parent: &OwnedFd,
    name: &str,
    contents: &[u8],
    owner: Uid,
    group: Gid,
) -> Result<()> {
    let descriptor = openat(
        parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(SERVICE_FILE_MODE),
    )
    .with_context(|| format!("create protected client file {name}"))?;
    assign(
        &descriptor,
        FileType::RegularFile,
        SERVICE_FILE_MODE,
        owner,
        group,
        name,
    )?;
    let mut file = std::fs::File::from(descriptor);
    file.write_all(contents)
        .with_context(|| format!("write protected client file {name}"))?;
    file.sync_all()
        .with_context(|| format!("synchronize protected client file {name}"))
}

fn cleanup_open_generation(
    configurations: &OwnedFd,
    configuration_name: &str,
    generations: &OwnedFd,
    generation_name: &str,
) -> Result<()> {
    if remove_at_if_present(configurations, configuration_name, AtFlags::empty())? {
        fsync(configurations).context("synchronize configuration cleanup")?;
    }
    if let Some(generation) = open_directory_optional(generations, generation_name)? {
        for filename in [
            "identity-chain.pem",
            "identity-key.pem",
            "root-ca.pem",
            "grant-signing-public.pem",
        ] {
            remove_at_if_present(&generation, filename, AtFlags::empty())?;
        }
        fsync(&generation).context("synchronize credential cleanup")?;
    }
    if remove_at_if_present(generations, generation_name, AtFlags::REMOVEDIR)? {
        fsync(generations).context("synchronize generation cleanup")?;
    }
    Ok(())
}

fn remove_at_if_present(parent: &OwnedFd, name: &str, flags: AtFlags) -> Result<bool> {
    match unlinkat(parent, name, flags) {
        Ok(()) => Ok(true),
        Err(Errno::NOENT) => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("remove protected client component {name}")),
    }
}

fn validate_configuration_filename(filename: &str) -> Result<()> {
    let pointer = matches!(
        filename,
        "current.pointer"
            | ".current.pointer.next"
            | ".current.pointer.previous"
            | ".current.pointer.lock"
    );
    let configuration = filename.starts_with("client-") && filename.ends_with(".toml");
    if filename.is_empty()
        || filename.contains('/')
        || filename.contains('\\')
        || filename.contains('\0')
        || !(pointer || configuration)
    {
        bail!("protected client configuration filename is invalid");
    }
    Ok(())
}
