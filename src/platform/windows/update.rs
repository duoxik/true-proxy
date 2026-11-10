//! Native hashing and update-helper process ownership. The helper never opens
//! WinDivert, reads the routing profile, or invokes a shell.
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, FILETIME, HANDLE},
    Security::Cryptography::*,
    System::Threading::{
        CreateEventW, EVENT_MODIFY_STATE, GetCurrentProcess, GetProcessTimes, OpenEventW,
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW, SetEvent,
        WaitForSingleObject,
    },
};

struct Algorithm(BCRYPT_ALG_HANDLE);
impl Drop for Algorithm {
    fn drop(&mut self) {
        unsafe {
            BCryptCloseAlgorithmProvider(self.0, 0);
        }
    }
}
struct Hash {
    handle: BCRYPT_HASH_HANDLE,
    _algorithm: Algorithm,
    _object: Vec<u8>,
}
impl Drop for Hash {
    fn drop(&mut self) {
        unsafe {
            BCryptDestroyHash(self.handle);
        }
    }
}
fn crypto(status: i32) -> Result<()> {
    ensure!(status >= 0, "Windows SHA-256 error ({status})");
    Ok(())
}

pub fn sha256(path: &Path) -> Result<String> {
    let mut algorithm = ptr::null_mut();
    // SAFETY: provider/hash handles are exclusively owned. Hash backing storage
    // stays allocated until BCryptDestroyHash, before closing the provider.
    crypto(unsafe {
        BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_SHA256_ALGORITHM, ptr::null(), 0)
    })?;
    let algorithm = Algorithm(algorithm);
    let mut length = 0u32;
    let mut returned = 0;
    crypto(unsafe {
        BCryptGetProperty(
            algorithm.0,
            BCRYPT_OBJECT_LENGTH,
            (&mut length as *mut u32).cast(),
            4,
            &mut returned,
            0,
        )
    })?;
    ensure!(
        returned == 4 && (1..=65536).contains(&length),
        "Invalid Windows SHA-256 size"
    );
    let mut object = vec![0; length as usize];
    let mut handle = ptr::null_mut();
    crypto(unsafe {
        BCryptCreateHash(
            algorithm.0,
            &mut handle,
            object.as_mut_ptr(),
            length,
            ptr::null(),
            0,
            0,
        )
    })?;
    let hash = Hash {
        handle,
        _algorithm: algorithm,
        _object: object,
    };
    let mut file = fs::File::open(path)?;
    ensure!(
        file.metadata()?.len() <= crate::updates::MAX_EXE_SIZE,
        "The executable is too large"
    );
    let mut buffer = [0u8; 32768];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        crypto(unsafe { BCryptHashData(hash.handle, buffer.as_ptr(), count as u32, 0) })?;
    }
    let mut digest = [0u8; 32];
    crypto(unsafe { BCryptFinishHash(hash.handle, digest.as_mut_ptr(), 32, 0) })?;
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn created(handle: HANDLE) -> Result<u64> {
    let (mut creation, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    ensure!(
        unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } != 0,
        "Could not verify the process creation time"
    );
    Ok((creation.dwHighDateTime as u64) << 32 | creation.dwLowDateTime as u64)
}
pub fn current_created() -> Result<u64> {
    created(unsafe { GetCurrentProcess() })
}

pub struct Parent {
    handle: HANDLE,
    pub image: PathBuf,
}
impl Drop for Parent {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
impl Parent {
    pub fn open(pid: u32, creation: u64) -> Result<Self> {
        ensure!(
            pid != 0 && pid != std::process::id(),
            "Invalid update target process"
        );
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | 0x00100000, 0, pid) };
        ensure!(
            !handle.is_null(),
            "Could not open the update target process"
        );
        let mut parent = Self {
            handle,
            image: PathBuf::new(),
        };
        ensure!(
            created(handle)? == creation,
            "Update canceled because the PID now belongs to a different process"
        );
        let mut path = vec![0u16; 32768];
        let mut size = path.len() as u32;
        ensure!(
            unsafe { QueryFullProcessImageNameW(handle, 0, path.as_mut_ptr(), &mut size) } != 0,
            "Could not identify the executable to update"
        );
        use std::os::windows::ffi::OsStringExt;
        parent.image = PathBuf::from(std::ffi::OsString::from_wide(&path[..size as usize]));
        Ok(parent)
    }
    pub fn wait(&self) -> Result<()> {
        ensure!(
            unsafe { WaitForSingleObject(self.handle, 60000) } == 0,
            "Update canceled because the previous version did not exit"
        );
        Ok(())
    }
    pub fn is_running(&self) -> bool {
        unsafe { WaitForSingleObject(self.handle, 0) != 0 }
    }
}

pub fn spawn_hidden(
    executable: &Path,
    arguments: &[std::ffi::OsString],
) -> Result<std::process::Child> {
    use std::os::windows::process::CommandExt;
    std::process::Command::new(executable)
        .args(arguments)
        .creation_flags(0x08000000)
        .spawn()
        .context("Could not start the update helper")
}

const HEALTH_PREFIX: &str = "Local\\TrueProxy.Update.";

/// One random, non-inherited event per owned restart. No destination file path
/// is accepted from the new application's command line.
pub struct HealthEvent {
    handle: HANDLE,
    name: String,
}
impl Drop for HealthEvent {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
impl HealthEvent {
    pub fn create() -> Result<Self> {
        let mut random = [0u8; 16];
        // SAFETY: a valid 16-byte output buffer, using the system RNG provider.
        crypto(unsafe {
            BCryptGenRandom(
                ptr::null_mut(),
                random.as_mut_ptr(),
                random.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        })?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let name = format!("{HEALTH_PREFIX}{suffix}");
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: NUL-terminated name; the owned handle is closed by Drop.
        let handle = unsafe { CreateEventW(ptr::null(), 1, 0, wide.as_ptr()) };
        ensure!(
            !handle.is_null(),
            "Could not create the update startup event"
        );
        Ok(Self { handle, name })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn wait(&self, child: &mut std::process::Child) -> Result<()> {
        let started = std::time::Instant::now();
        loop {
            ensure!(
                child.try_wait()?.is_none(),
                "The new version exited before confirming startup"
            );
            // SAFETY: this event remains owned throughout the wait.
            if unsafe { WaitForSingleObject(self.handle, 50) } == 0 {
                return Ok(());
            }
            ensure!(
                started.elapsed() < std::time::Duration::from_secs(30),
                "The new version did not confirm startup"
            );
        }
    }
}

pub fn confirm_health(name: &str) -> Result<()> {
    ensure!(
        name.strip_prefix(HEALTH_PREFIX).is_some_and(
            |suffix| suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        ),
        "Invalid update startup event"
    );
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: opens only an existing event with the narrow right to signal it.
    let handle = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, wide.as_ptr()) };
    ensure!(!handle.is_null(), "Could not open the update startup event");
    let event = HealthEvent {
        handle,
        name: name.into(),
    };
    ensure!(
        unsafe { SetEvent(event.handle) } != 0,
        "Could not confirm app startup"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_event_is_validated_and_requires_a_real_signal() {
        let event = HealthEvent::create().unwrap();
        assert_ne!(unsafe { WaitForSingleObject(event.handle, 0) }, 0);
        assert!(confirm_health("C:\\arbitrary-file").is_err());
        assert!(confirm_health("Local\\TrueProxy.Update.not-a-token").is_err());
        confirm_health(event.name()).unwrap();
        assert_eq!(unsafe { WaitForSingleObject(event.handle, 0) }, 0);
        let other = HealthEvent::create().unwrap();
        assert_ne!(unsafe { WaitForSingleObject(other.handle, 0) }, 0);
    }
    #[test]
    fn sha256_detects_modified_payload_with_known_digest() {
        let path = std::env::temp_dir().join(format!("true-proxy-hash-{}.tmp", std::process::id()));
        fs::write(&path, b"abc").unwrap();
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        crate::updates::verify_file(&path, expected).unwrap();
        fs::write(&path, b"abd").unwrap();
        assert!(crate::updates::verify_file(&path, expected).is_err());
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn process_identity_rejects_pid_reuse() {
        let creation = current_created().unwrap();
        assert!(Parent::open(std::process::id(), creation).is_err());
        assert!(Parent::open(0, creation).is_err());
    }
}
