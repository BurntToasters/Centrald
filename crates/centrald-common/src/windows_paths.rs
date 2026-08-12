#![cfg(windows)]
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr;

use windows_sys::Win32::Foundation::RPC_E_CHANGED_MODE;
use windows_sys::Win32::System::Com::{
    COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_ProgramData, FOLDERID_ProgramFiles, SHGetKnownFolderPath,
};
use windows_sys::core::GUID;

const MAX_WINDOWS_PATH_U16: usize = 32_768;

/// Returns the machine-wide application-data directory through the Windows
/// known-folder API. Process environment variables are deliberately ignored.
pub(crate) fn program_data_dir() -> Option<PathBuf> {
    known_folder(&FOLDERID_ProgramData)
}

/// Returns the native Program Files directory through the Windows known-folder
/// API. Process environment variables are deliberately ignored.
pub(crate) fn program_files_dir() -> Option<PathBuf> {
    known_folder(&FOLDERID_ProgramFiles)
}

/// Returns the native Windows system directory through `GetSystemDirectoryW`.
pub(crate) fn system_directory() -> Option<PathBuf> {
    let mut buffer = vec![0_u16; MAX_WINDOWS_PATH_U16];
    // SAFETY: `buffer` is writable for exactly `buffer.len()` UTF-16 code units,
    // and the API does not retain the pointer after returning.
    let length = unsafe {
        GetSystemDirectoryW(
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).unwrap_or(u32::MAX),
        )
    };
    let length = usize::try_from(length).ok()?;
    if length == 0 || length >= buffer.len() {
        return None;
    }
    buffer.truncate(length);
    Some(PathBuf::from(OsString::from_wide(&buffer)))
}

fn known_folder(folder_id: &GUID) -> Option<PathBuf> {
    // Microsoft requires COM initialization on the calling thread for the
    // Known Folder APIs. `RPC_E_CHANGED_MODE` means the thread was already
    // initialized with another apartment model; the existing initialization is
    // still usable and must not be uninitialized by this call.
    // SAFETY: the reserved pointer is null as required and the flag is a valid
    // COM apartment mode.
    let com_status = unsafe { CoInitializeEx(ptr::null(), COINIT_MULTITHREADED as u32) };
    if com_status < 0 && com_status != RPC_E_CHANGED_MODE {
        return None;
    }
    let uninitialize = com_status >= 0;

    let result = (|| {
        let mut raw = ptr::null_mut::<u16>();
        // SAFETY: `folder_id` is a valid static KNOWNFOLDERID, the token is null
        // for the current machine context, and `raw` is a valid output pointer.
        let status = unsafe { SHGetKnownFolderPath(folder_id, 0, ptr::null_mut(), &mut raw) };
        if status < 0 || raw.is_null() {
            // Microsoft requires freeing the returned pointer even on failure.
            // SAFETY: `CoTaskMemFree` accepts null and any pointer returned
            // through `SHGetKnownFolderPath`.
            unsafe { CoTaskMemFree(raw.cast()) };
            return None;
        }

        let mut length = 0_usize;
        // SAFETY: a successful `SHGetKnownFolderPath` returns a null-terminated
        // UTF-16 allocation. We stop at either its terminator or a defensive
        // path ceiling before constructing the slice.
        unsafe {
            while length < MAX_WINDOWS_PATH_U16 && *raw.add(length) != 0 {
                length += 1;
            }
        }
        if length == MAX_WINDOWS_PATH_U16 {
            // SAFETY: `raw` is the allocation returned by the Shell API.
            unsafe { CoTaskMemFree(raw.cast()) };
            return None;
        }
        // SAFETY: the preceding loop established that the first `length` code
        // units belong to the returned allocation and precede its terminator.
        let path = unsafe { std::slice::from_raw_parts(raw, length) };
        let result = PathBuf::from(OsString::from_wide(path));
        // SAFETY: `raw` is the allocation returned by the Shell API and is no
        // longer referenced after this call.
        unsafe { CoTaskMemFree(raw.cast()) };
        if result.as_os_str().is_empty() {
            None
        } else {
            Some(result)
        }
    })();

    if uninitialize {
        // SAFETY: this call balances the successful `CoInitializeEx` performed
        // above on the same thread.
        unsafe { CoUninitialize() };
    }
    result
}
