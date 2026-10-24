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
        GetCurrentProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW, WaitForSingleObject,
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
    ensure!(status >= 0, "Ошибка SHA-256 Windows ({status})");
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
        "Некорректный размер SHA-256 Windows"
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
        "Слишком большой EXE"
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
        "Не удалось проверить время создания процесса"
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
            "Некорректный процесс обновления"
        );
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | 0x00100000, 0, pid) };
        ensure!(!handle.is_null(), "Не удалось открыть обновляемый процесс");
        let mut parent = Self {
            handle,
            image: PathBuf::new(),
        };
        ensure!(
            created(handle)? == creation,
            "PID уже принадлежит другому процессу; обновление отменено"
        );
        let mut path = vec![0u16; 32768];
        let mut size = path.len() as u32;
        ensure!(
            unsafe { QueryFullProcessImageNameW(handle, 0, path.as_mut_ptr(), &mut size) } != 0,
            "Не удалось определить обновляемый EXE"
        );
        use std::os::windows::ffi::OsStringExt;
        parent.image = PathBuf::from(std::ffi::OsString::from_wide(&path[..size as usize]));
        Ok(parent)
    }
    pub fn wait(&self) -> Result<()> {
        ensure!(
            unsafe { WaitForSingleObject(self.handle, 60000) } == 0,
            "Предыдущая версия не завершилась; обновление отменено"
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
        .context("Не удалось запустить компонент обновления")
}

#[cfg(test)]
mod tests {
    use super::*;
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
