mod bundle;
pub mod clipboard;
pub mod divert;
mod geoip;
pub mod http;
pub mod monitor;
pub mod network;
pub mod passive;
pub mod picker;
pub mod presentation;
pub mod process;
mod process_icons;
pub mod startup;
pub mod tray;
pub mod update;

pub use geoip::proxy_location;
pub use process_icons::process_icon;

use anyhow::{Context, Result, ensure};
use std::{path::Path, ptr};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, LocalFree, SYSTEMTIME},
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    },
    Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW},
    System::{
        SystemInformation::GetLocalTime,
        Threading::{CreateMutexW, OpenProcess, WaitForSingleObject},
    },
    UI::{
        Shell::{IsUserAnAdmin, ShellExecuteW},
        WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW, SW_SHOWNORMAL},
    },
};

fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

pub struct SingleInstance(HANDLE);
impl SingleInstance {
    pub fn acquire() -> Result<Option<Self>> {
        // SAFETY: NUL-terminated name, null optional security descriptor, owned handle.
        let handle =
            unsafe { CreateMutexW(ptr::null(), 0, wide("Local\\TrueProxy.Desktop.v1").as_ptr()) };
        ensure!(
            !handle.is_null(),
            "Could not acquire the application instance lock"
        );
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe { CloseHandle(handle) };
            if tray::activate_existing() {
                return Ok(None);
            }
            anyhow::bail!("True Proxy is already running. Open it from the tray icon.");
        }
        Ok(Some(Self(handle)))
    }
}
impl Drop for SingleInstance {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

pub fn show_error(message: &str) {
    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            wide(message).as_ptr(),
            wide("True Proxy").as_ptr(),
            MB_OK | MB_ICONERROR,
        )
    };
}
pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

/// Current local wall clock as hour, minute and second.
pub fn local_clock() -> Option<(u16, u16, u16)> {
    let mut time = SYSTEMTIME::default();
    // SAFETY: time is writable SYSTEMTIME storage for this synchronous call.
    unsafe { GetLocalTime(&mut time) };
    Some((time.wHour, time.wMinute, time.wSecond))
}

pub fn relaunch_elevated() -> Result<()> {
    let exe = std::env::current_exe()?;
    // Normal launches elevate before creating UI or reading the profile. Safe
    // diagnostic/preview modes bypass this path. Never force-enable a saved pause.
    let mut arguments = format!("--wait-parent {}", std::process::id());
    for flag in ["--paused", "--enable", "--tray"] {
        if std::env::args().any(|argument| argument == flag) {
            arguments.push(' ');
            arguments.push_str(flag);
        }
    }
    let result = unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            wide("runas").as_ptr(),
            wide(exe.as_os_str()).as_ptr(),
            wide(arguments).as_ptr(),
            ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    ensure!(
        result as isize > 32,
        "Administrator launch was canceled or unavailable"
    );
    Ok(())
}

pub fn wait_for_parent(pid: u32) -> Result<()> {
    let handle = unsafe { OpenProcess(0x00100000, 0, pid) };
    if !handle.is_null() {
        let result = unsafe { WaitForSingleObject(handle, 15000) };
        unsafe { CloseHandle(handle) };
        ensure!(result == 0, "The previous instance is still shutting down");
    }
    Ok(())
}

pub fn replace_file(source: &Path, target: &Path) -> Result<()> {
    ensure!(
        unsafe {
            MoveFileExW(
                wide(source).as_ptr(),
                wide(target).as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } != 0,
        "{}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

pub fn protect(secret: &str) -> Result<String> {
    ensure!(secret.len() <= 255, "The SOCKS5 password exceeds 255 bytes");
    let input = CRYPT_INTEGER_BLOB {
        cbData: secret.len() as u32,
        pbData: secret.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    // SAFETY: input remains live throughout the call, DPAPI owns the output allocation.
    ensure!(
        unsafe {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } != 0,
        "Could not protect the password: {}",
        std::io::Error::last_os_error()
    );
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    let mut result = String::from("dpapi:");
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut result, "{byte:02x}")?;
    }
    unsafe { LocalFree(output.pbData as _) };
    Ok(result)
}
pub fn unprotect(secret: &str) -> Result<String> {
    let hex = secret
        .strip_prefix("dpapi:")
        .context("Unknown protected password format")?;
    ensure!(
        hex.len() % 2 == 0 && hex.len() <= 65536 && hex.is_ascii(),
        "Invalid protected password"
    );
    let mut bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    ensure!(
        unsafe {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } != 0,
        "The password is unavailable to this Windows account"
    );
    let plain = unsafe { std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize) };
    let result = String::from_utf8(plain.to_vec()).context("Invalid password encoding");
    plain.fill(0);
    unsafe { LocalFree(output.pbData as _) };
    result
}
