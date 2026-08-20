//! Windows-specific FFI for the privileged broker.
//!
//! `CentralD` keeps its Rust safe elsewhere; this module is the audited
//! exception for unavoidable Windows APIs, exactly like
//! [`windows_service.rs`](crate::windows_service). It contains no hand-written
//! logic beyond thin, bounded wrappers:
//!
//! - a DACL-restricted named pipe for the broker transport,
//! - the machine reboot API used by the machine-restart operation,
//! - OS-account validation (`LogonUserW`) and DPAPI vault encryption,
//! - the vault file writer, and
//! - `GetTickCount64` for Hello uptime.
//!
//! The pipe DACL grants access only to Local System (the broker itself) and
//! the fixed `NT SERVICE\CentralDClient` virtual service account, which is
//! resolved at runtime rather than assumed.

#![cfg(windows)]
#![allow(unsafe_code)]
// FFI signatures force raw-pointer and length casts; the buffer sizes here are
// bounded constants so the truncation casts cannot lose data.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::ptr_as_ptr,
    clippy::unnecessary_cast
)]

use std::ffi::c_void;
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use anyhow::{Context, Result, bail};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_MORE_DATA, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
    GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows_sys::Win32::Security::{
    LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, LogonUserW, LookupAccountNameW,
    SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_NOWAIT, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, SetNamedPipeHandleState, WaitNamedPipeW,
};
use windows_sys::Win32::System::Shutdown::InitiateSystemShutdownExW;
use windows_sys::Win32::System::SystemInformation::GetTickCount64;

use centrald_platform::broker::{MAX_WIRE_REQUEST_BYTES, MAX_WIRE_RESPONSE_BYTES};

/// The fixed broker pipe name. Only the broker and the client daemon may open
/// it; the DACL is set at pipe creation time.
const PIPE_NAME: &str = r"\\.\pipe\CentralDBroker";
const SERVICE_ACCOUNT: &str = r"NT SERVICE\CentralDClient";
/// Sized to fit the largest encoded session frame (1 MiB of data expands to
/// ~1.4 MiB of base64 JSON plus envelope overhead).
const PIPE_BUFFER_BYTES: u32 = 1_600_000;

/// Requests an immediate reboot of the machine.
///
/// # Errors
///
/// Returns an error when the Windows shutdown API rejects the request.
pub fn request_system_reboot() -> Result<()> {
    let result = unsafe {
        InitiateSystemShutdownExW(
            ptr::null_mut(),
            ptr::null(),
            0,
            1, // force applications to close
            1, // reboot after shutdown
            0,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error())
            .context("InitiateSystemShutdownExW rejected the machine restart");
    }
    Ok(())
}

/// Returns the approximate system uptime in seconds.
#[must_use]
pub fn uptime_seconds() -> u64 {
    // SAFETY: GetTickCount64 has no parameters and returns a process-independent
    // monotonic millisecond counter maintained by the operating system.
    unsafe { GetTickCount64() / 1_000 }
}

/// Creates one named-pipe instance with a DACL restricted to Local System and
/// the `CentralD` client service account.
fn create_pipe_instance() -> Result<OwnedHandle> {
    let service_sid = resolve_service_sid(SERVICE_ACCOUNT)?;
    let service_sid_string = sid_to_string(&service_sid)?;
    let sddl = format!("D:P(A;;FRFW;;;SY)(A;;FRFW;;;{service_sid_string})");
    let mut descriptor_pointer: *mut c_void = ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            encode_wide(&sddl).as_ptr(),
            1, // SDDL_REVISION_1
            &raw mut descriptor_pointer,
            ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(std::io::Error::last_os_error())
            .context("build the broker pipe security descriptor");
    }
    if descriptor_pointer.is_null() {
        bail!("broker pipe security descriptor is null");
    }
    let security_attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor_pointer,
        bInheritHandle: 0,
    };
    let handle = unsafe {
        CreateNamedPipeW(
            encode_wide(PIPE_NAME).as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            &raw const security_attributes,
        )
    };
    // The kernel has copied the security descriptor into the pipe object; the
    // converted buffer can be released now.
    unsafe {
        LocalFree(descriptor_pointer);
    }
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .context("create the broker named-pipe instance");
    }
    // SAFETY: CreateNamedPipeW returned a valid pipe handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as *mut c_void) })
}

/// Blocks until one client connects to a freshly created pipe instance.
///
/// # Errors
///
/// Returns an error when pipe creation or the connect wait fails.
pub fn accept_pipe_connection() -> Result<OwnedHandle> {
    let instance = create_pipe_instance()?;
    let handle = instance.as_raw_handle() as HANDLE;
    let connected = unsafe { ConnectNamedPipe(handle, ptr::null_mut()) };
    if connected == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
            return Err(error).context("wait for a broker pipe client");
        }
    }
    Ok(instance)
}

/// Reads one complete bounded message from the pipe.
///
/// A message-mode named-pipe stream: each `Read`/`Write` call transfers one
/// complete pipe message, which holds exactly one length-prefixed broker
/// frame.
#[derive(Debug)]
pub struct PipeStream {
    handle: OwnedHandle,
}

impl PipeStream {
    #[must_use]
    pub fn new(handle: OwnedHandle) -> Self {
        Self { handle }
    }

    /// Splits the stream into owned read/write halves for concurrent use.
    ///
    /// # Errors
    ///
    /// Returns an error when the handle cannot be duplicated.
    pub fn split(self) -> Result<(PipeStream, PipeStream)> {
        let read_half = self
            .handle
            .try_clone()
            .context("duplicate broker pipe handle")?;
        Ok((PipeStream::new(read_half), self))
    }
}

impl crate::broker_session::DuplexStream for PipeStream {
    fn try_duplicate(&self) -> io::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self::new(self.handle.try_clone()?))
    }
}

/// Switches a connected pipe instance between blocking (`PIPE_WAIT`) and
/// polling (`PIPE_NOWAIT`) message mode. The broker polls in non-blocking
/// mode to bound the first-frame wait, then restores blocking mode before
/// dispatch so the session exchange keeps message semantics.
///
/// # Errors
///
/// Returns an error when the handle mode cannot be changed.
pub fn set_pipe_polling(stream: &PipeStream, polling: bool) -> Result<()> {
    let mode: u32 = PIPE_READMODE_MESSAGE | if polling { PIPE_NOWAIT } else { PIPE_WAIT };
    let result = unsafe {
        SetNamedPipeHandleState(
            stream.handle.as_raw_handle() as HANDLE,
            &raw const mode,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error()).context("set broker pipe handle mode");
    }
    Ok(())
}

impl PipeStream {
    /// Reads one complete pipe message without blocking.
    ///
    /// Returns `Ok(None)` when no message is available yet (polling mode
    /// only), `Ok(Some(bytes))` for a partial or complete message piece.
    ///
    /// # Errors
    ///
    /// Returns an error when the pipe read fails for a reason other than
    /// "no data available".
    pub fn try_read_message(&self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        let mut read_bytes = 0_u32;
        let result = unsafe {
            ReadFile(
                self.handle.as_raw_handle() as HANDLE,
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).unwrap_or(u32::MAX),
                &raw mut read_bytes,
                ptr::null_mut(),
            )
        };
        if result == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_DATA as i32) {
                return Ok(None);
            }
            // A message larger than the buffer is read in pieces.
            if error.raw_os_error() == Some(ERROR_MORE_DATA as i32) && read_bytes > 0 {
                return Ok(Some(read_bytes as usize));
            }
            return Err(error);
        }
        if read_bytes == 0 {
            return Ok(None);
        }
        Ok(Some(read_bytes as usize))
    }
}

impl Read for PipeStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut read_bytes = 0_u32;
        let result = unsafe {
            ReadFile(
                self.handle.as_raw_handle() as HANDLE,
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).unwrap_or(u32::MAX),
                &raw mut read_bytes,
                ptr::null_mut(),
            )
        };
        if result == 0 {
            let error = io::Error::last_os_error();
            // A message larger than the buffer is read in pieces; callers
            // continue with the next read once the frame length is known.
            if error.raw_os_error() == Some(ERROR_MORE_DATA as i32) && read_bytes > 0 {
                return Ok(read_bytes as usize);
            }
            return Err(error);
        }
        Ok(read_bytes as usize)
    }
}

impl Write for PipeStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut written_bytes = 0_u32;
        let result = unsafe {
            WriteFile(
                self.handle.as_raw_handle() as HANDLE,
                buffer.as_ptr(),
                u32::try_from(buffer.len()).unwrap_or(u32::MAX),
                &raw mut written_bytes,
                ptr::null_mut(),
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        let flushed = unsafe { FlushFileBuffers(self.handle.as_raw_handle() as HANDLE) };
        if flushed == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(written_bytes as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        let flushed = unsafe { FlushFileBuffers(self.handle.as_raw_handle() as HANDLE) };
        if flushed == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Connects to the broker pipe as the client daemon, sending one bounded
/// request and returning the bounded response.
///
/// # Errors
///
/// Returns an error when the broker is unavailable, the request is too large,
/// or the response is malformed/oversized.
pub fn pipe_request(request: &[u8]) -> Result<Vec<u8>> {
    if request.len() > MAX_WIRE_REQUEST_BYTES {
        bail!("broker pipe request exceeds the wire bound");
    }
    let handle = connect_pipe_client()?;
    let stream = PipeStream::new(handle);
    let (mut reader, mut writer) = stream.split()?;
    crate::broker_session::write_frame(&mut writer, request)?;
    let response = crate::broker_session::read_frame(&mut reader, MAX_WIRE_RESPONSE_BYTES)?;
    Ok(response)
}

/// Connects to the broker pipe as a client.
///
/// # Errors
///
/// Returns an error when the broker is unavailable.
pub fn connect_pipe_client() -> Result<OwnedHandle> {
    let mut attempts = 0_u32;
    loop {
        let handle = unsafe {
            CreateFileW(
                encode_wide(PIPE_NAME).as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null_mut(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            // SAFETY: CreateFileW returned a valid pipe handle.
            return Ok(unsafe { OwnedHandle::from_raw_handle(handle as *mut c_void) });
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_PIPE_BUSY as i32) {
            return Err(error).context("open the broker pipe");
        }
        let waited = unsafe { WaitNamedPipeW(encode_wide(PIPE_NAME).as_ptr(), 5_000) };
        if waited == 0 {
            return Err(std::io::Error::last_os_error()).context("wait for the broker pipe");
        }
        attempts += 1;
        if attempts >= 3 {
            bail!("broker pipe remained busy after repeated attempts");
        }
    }
}

fn resolve_service_sid(account: &str) -> Result<Vec<u8>> {
    let mut sid: [u8; 68] = [0; 68]; // SID_MAX_SIZE
    let mut sid_size = sid.len() as u32;
    let mut domain = [0_u16; 256];
    let mut domain_size = domain.len() as u32;
    let mut sid_use: i32 = 0;
    let found = unsafe {
        LookupAccountNameW(
            ptr::null_mut(),
            encode_wide(account).as_ptr(),
            sid.as_mut_ptr() as *mut c_void,
            &raw mut sid_size,
            domain.as_mut_ptr(),
            &raw mut domain_size,
            &raw mut sid_use,
        )
    };
    if found == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("resolve the {account} service account SID"));
    }
    Ok(sid[..sid_size as usize].to_vec())
}

fn sid_to_string(sid: &[u8]) -> Result<String> {
    let mut string_pointer: *mut u16 = ptr::null_mut();
    let converted =
        unsafe { ConvertSidToStringSidW(sid.as_ptr() as *mut c_void, &raw mut string_pointer) };
    if converted == 0 || string_pointer.is_null() {
        return Err(std::io::Error::last_os_error()).context("convert the service SID to text");
    }
    let mut length = 0;
    unsafe {
        while *string_pointer.add(length) != 0 {
            length += 1;
        }
    }
    let wide = unsafe { std::slice::from_raw_parts(string_pointer, length) };
    let text = String::from_utf16_lossy(wide);
    unsafe {
        LocalFree(string_pointer as *mut c_void);
    }
    Ok(text)
}

fn encode_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Validates an OS account password with `LogonUserW`. The returned token is
/// closed immediately; only the validation result is used.
///
/// # Errors
///
/// Returns an error when the account or password is rejected.
pub fn validate_account_credentials(user: &str, password: &str) -> Result<(), String> {
    let mut token: HANDLE = ptr::null_mut();
    let result = unsafe {
        LogonUserW(
            encode_wide(user).as_ptr(),
            encode_wide(".").as_ptr(),
            encode_wide(password).as_ptr(),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &raw mut token,
        )
    };
    if result == 0 {
        return Err(format!(
            "the OS account password was rejected: {}",
            std::io::Error::last_os_error()
        ));
    }
    unsafe {
        CloseHandle(token);
    }
    Ok(())
}

/// Encrypts bytes with DPAPI (`CryptProtectData`) under the machine scope.
///
/// # Errors
///
/// Returns an error when DPAPI rejects the input.
pub fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(plaintext.len()).context("plaintext is too large")?,
        pbData: plaintext.as_ptr().cast_mut(),
    };
    let mut output: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };
    let protected = unsafe {
        CryptProtectData(
            &raw const input,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    };
    if protected == 0 {
        return Err(std::io::Error::last_os_error()).context("DPAPI encryption failed");
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData as *mut c_void);
    }
    Ok(result)
}

/// Decrypts DPAPI-encrypted bytes.
///
/// # Errors
///
/// Returns an error when DPAPI rejects the blob.
pub fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(ciphertext.len()).context("ciphertext is too large")?,
        pbData: ciphertext.as_ptr().cast_mut(),
    };
    let mut output: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };
    let unprotected = unsafe {
        CryptUnprotectData(
            &raw const input,
            ptr::null_mut::<*mut u16>(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    };
    if unprotected == 0 {
        return Err(std::io::Error::last_os_error()).context("DPAPI decryption failed");
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData as *mut c_void);
    }
    Ok(result)
}

/// Durably writes the vault file with owner-only access.
///
/// A first store creates the file with `write_new_file`; every later store or
/// delete atomically replaces it via a private sibling temporary and
/// `MoveFileExW` with write-through, so a crash or partial write can never
/// corrupt the DPAPI blobs and a pre-existing vault is never clobbered
/// non-atomically.
///
/// # Errors
///
/// Returns an error when the file cannot be written safely.
pub fn write_vault_file(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    if !path.exists() {
        return centrald_common::secure_fs::write_new_file(path, contents, true)
            .with_context(|| format!("write credential vault {}", path.display()));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .with_context(|| format!("credential vault has no parent: {}", path.display()))?;
    let temporary = parent.join(format!(
        ".vault.json.centrald-replacement-{}",
        uuid::Uuid::now_v7()
    ));
    centrald_common::secure_fs::write_new_file(&temporary, contents, true)
        .with_context(|| format!("write credential vault replacement {}", temporary.display()))?;
    let replaced = unsafe {
        MoveFileExW(
            encode_wide(&temporary.to_string_lossy()).as_ptr(),
            encode_wide(&path.to_string_lossy()).as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        let _ = std::fs::remove_file(&temporary);
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("replace credential vault {}", path.display()));
    }
    Ok(())
}
