use std::path::Path;

use anyhow::{Context, Result, bail};
use centrald_common::secure_fs::validate_no_symlink_ancestors;

/// Classification for root-integrity revalidation at the point of use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureReadClass {
    /// Private keys, database environment files, and other secrets.
    ///
    /// Must be root-owned, mode `0600` (no group/other bits), and `nlink == 1`.
    PrivateRoot,
    /// Public trust material such as CA/issuer certificates.
    ///
    /// Must be root-owned regular files with no group/other write bits.
    PublicRootTrust,
}

/// Reads a root-owned private server file after validating the opened inode.
///
/// Server secrets must remain regular, single-linked files owned by root and
/// inaccessible to group/other users. Validation happens on the opened
/// descriptor (`O_NOFOLLOW`) rather than a separate metadata snapshot followed
/// by a pathname read.
pub fn read_root_private_text(path: &Path, maximum_bytes: u64, label: &str) -> Result<String> {
    read_secure_text(path, SecureReadClass::PrivateRoot, maximum_bytes, label)
}

/// Reads root-owned public trust material (certificates / public keys).
pub fn read_root_public_text(path: &Path, maximum_bytes: u64, label: &str) -> Result<String> {
    read_secure_text(path, SecureReadClass::PublicRootTrust, maximum_bytes, label)
}

/// Validates a root-owned private server file without returning its contents.
pub fn validate_root_private_file(path: &Path, maximum_bytes: u64, label: &str) -> Result<()> {
    let _ = read_secure_bytes(path, SecureReadClass::PrivateRoot, maximum_bytes, label)?;
    Ok(())
}

fn read_secure_text(
    path: &Path,
    class: SecureReadClass,
    maximum_bytes: u64,
    label: &str,
) -> Result<String> {
    let bytes = read_secure_bytes(path, class, maximum_bytes, label)?;
    String::from_utf8(bytes).with_context(|| format!("{label} is not UTF-8: {}", path.display()))
}

fn read_secure_bytes(
    path: &Path,
    class: SecureReadClass,
    maximum_bytes: u64,
    label: &str,
) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        bail!("{label} path must be absolute: {}", path.display());
    }
    validate_no_symlink_ancestors(path)
        .with_context(|| format!("validate {label} ancestors for {}", path.display()))?;

    #[cfg(all(unix, target_os = "linux"))]
    {
        use std::fs::OpenOptions;
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

        // linux/fcntl.h values used by the Ubuntu Server packaging target.
        const O_NOFOLLOW: i32 = 0o400000;
        const O_CLOEXEC: i32 = 0o2000000;

        let file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW | O_CLOEXEC)
            .open(path)
            .with_context(|| format!("open {label} {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("inspect {label} {}", path.display()))?;
        if !metadata.is_file() {
            bail!("{label} must be a regular non-symbolic-link file: {}", path.display());
        }
        if metadata.uid() != 0 {
            bail!("{label} must be owned by root: {}", path.display());
        }
        if metadata.len() == 0 || metadata.len() > maximum_bytes {
            bail!(
                "{label} size is outside the supported 1..={maximum_bytes} byte range: {}",
                path.display()
            );
        }

        let mode = metadata.permissions().mode() & 0o7777;
        match class {
            SecureReadClass::PrivateRoot => {
                if metadata.nlink() != 1 {
                    bail!("{label} must have exactly one hard link: {}", path.display());
                }
                if mode & 0o077 != 0 {
                    bail!(
                        "{label} must not be accessible by group or other users: {}",
                        path.display()
                    );
                }
            }
            SecureReadClass::PublicRootTrust => {
                if mode & 0o022 != 0 {
                    bail!(
                        "{label} must not be writable by group or other users: {}",
                        path.display()
                    );
                }
            }
        }

        let limit = maximum_bytes.saturating_add(1);
        let mut bytes = Vec::new();
        file.take(limit)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read {label} {}", path.display()))?;        if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum_bytes {
            bail!(
                "{label} size is outside the supported 1..={maximum_bytes} byte range: {}",
                path.display()
            );
        }
        Ok(bytes)
    }

    #[cfg(not(all(unix, target_os = "linux")))]
    {
        let _ = (class, maximum_bytes);
        bail!("CentralD server secure-file validation is supported only on Ubuntu Server hosts");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn rejects_relative_paths() {
        let error = read_root_private_text(Path::new("relative.key"), 1024, "test key")
            .expect_err("relative paths must fail closed");
        assert!(error.to_string().contains("absolute"));
    }

    #[test]
    fn rejects_missing_private_files() {
        let path = PathBuf::from("/tmp/centrald-missing-audit12-private.key");
        let error = read_root_private_text(&path, 1024, "test key")
            .expect_err("missing files must fail closed");
        let message = format!("{error:#}");
        assert!(
            message.contains("open")
                || message.contains("Ubuntu Server")
                || message.contains("ancestor"),
            "{message}"
        );
    }
}
