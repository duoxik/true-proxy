//! The EXE carries the original, unmodified x64 WinDivert runtime. Extraction
//! does not install or start the kernel driver and requires no elevation.
use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

const DLL: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/vendor/WinDivert/WinDivert-2.2.2-A/x64/WinDivert.dll"
));
const SYS: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/vendor/WinDivert/WinDivert-2.2.2-A/x64/WinDivert64.sys"
));
const LICENSE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/vendor/WinDivert/WinDivert-2.2.2-A/LICENSE"
));
const VERSION: &str = "WinDivert-2.2.2-A-x64";
const DLL_NAME: &str = "WinDivert.dll";
const SYS_NAME: &str = "WinDivert64.sys";
static TEMP_ID: AtomicU64 = AtomicU64::new(0);

pub(super) struct PreparedDriver {
    pub dll: PathBuf,
    // Keep the verified files read-only until after the DLL is unloaded.
    _files: [File; 2],
}

pub(super) fn prepare() -> Result<PreparedDriver> {
    let executable = std::env::current_exe()?;
    let local_data = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    prepare_at(&executable, local_data.as_deref())
        .context("Не удалось подготовить сетевой компонент WinDivert")
}

fn prepare_at(executable: &Path, local_data: Option<&Path>) -> Result<PreparedDriver> {
    let adjacent = executable.parent().context("Не найдена папка приложения")?;
    ensure!(
        adjacent.is_absolute(),
        "Папка приложения должна иметь полный путь"
    );
    // A complete adjacent pair is an intentional, replaceable DLL installation
    // (also supports upstream LGPL replacement). Never search the working directory.
    if adjacent.join(DLL_NAME).is_file() && adjacent.join(SYS_NAME).is_file() {
        return lock_pair(adjacent, false);
    }
    let local_data = local_data.context("Не найдена локальная папка пользователя Windows")?;
    ensure!(
        local_data.is_absolute(),
        "Локальная папка пользователя должна иметь полный путь"
    );
    let directory = local_data.join("TrueProxy").join("runtime").join(VERSION);
    fs::create_dir_all(&directory)
        .with_context(|| format!("Нет доступа к папке {}", directory.display()))?;
    for (name, bytes) in [
        (DLL_NAME, DLL),
        (SYS_NAME, SYS),
        ("LICENSE-WinDivert.txt", LICENSE),
    ] {
        write_if_changed(&directory.join(name), bytes)?;
    }
    lock_pair(&directory, true)
}

fn matches(file: &mut File, expected: &[u8]) -> Result<bool> {
    if file.metadata()?.len() != expected.len() as u64 {
        return Ok(false);
    }
    // Bound reads even if the cache is damaged; compare the actual embedded bytes.
    let mut contents = vec![0; expected.len()];
    file.read_exact(&mut contents)?;
    Ok(contents == expected)
}

fn write_if_changed(path: &Path, expected: &[u8]) -> Result<()> {
    if File::open(path).is_ok_and(|mut file| matches(&mut file, expected).unwrap_or(false)) {
        return Ok(());
    }
    let mut temporary = None;
    for _ in 0..32 {
        let candidate = path.with_extension(format!(
            "{}.{}.tmp",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Не удалось записать {}", path.display()));
            }
        }
    }
    let (temporary, mut file) =
        temporary.context("Не удалось создать временный файл сетевого компонента")?;
    let result = (|| {
        file.write_all(expected)?;
        file.sync_all()?;
        drop(file);
        super::replace_file(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.with_context(|| format!("Не удалось подготовить {}", path.display()))
}

fn lock_pair(directory: &Path, verify: bool) -> Result<PreparedDriver> {
    let mut files = Vec::with_capacity(2);
    for (name, expected) in [(DLL_NAME, DLL), (SYS_NAME, SYS)] {
        let path = directory.join(name);
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
            .with_context(|| format!("Не удалось открыть {}", path.display()))?;
        if verify {
            ensure!(
                matches(&mut file, expected)?,
                "Поврежден сетевой компонент {}",
                path.display()
            );
        }
        files.push(file);
    }
    Ok(PreparedDriver {
        dll: directory.join(DLL_NAME),
        _files: files.try_into().expect("exactly two runtime files"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "true-proxy-bundle-{}-{}",
                std::process::id(),
                TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(path.join("app")).unwrap();
            Self(path)
        }
        fn prepare(&self) -> Result<PreparedDriver> {
            prepare_at(
                &self.0.join("app/TrueProxy.exe"),
                Some(&self.0.join("profile")),
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn single_exe_extracts_pair_and_repairs_missing_or_corrupt_cache() -> Result<()> {
        let fixture = Fixture::new();
        let prepared = fixture.prepare()?;
        let dll = prepared.dll.clone();
        let directory = dll.parent().unwrap().to_owned();
        assert_eq!(fs::read(&dll)?, DLL);
        assert_eq!(fs::read(directory.join(SYS_NAME))?, SYS);
        // Verified runtime files cannot be changed while a Driver uses them.
        assert!(File::create(&dll).is_err());
        drop(prepared);
        fs::write(&dll, vec![0; DLL.len()])?;
        fs::remove_file(directory.join(SYS_NAME))?;
        let repaired = fixture.prepare()?;
        assert_eq!(repaired.dll, dll);
        assert_eq!(fs::read(&dll)?, DLL);
        assert_eq!(fs::read(directory.join(SYS_NAME))?, SYS);
        Ok(())
    }

    #[test]
    fn incomplete_sidecars_use_embedded_pair_but_complete_pair_is_replaceable() -> Result<()> {
        let fixture = Fixture::new();
        let adjacent = fixture.0.join("app");
        fs::write(adjacent.join(DLL_NAME), b"user supplied DLL")?;
        assert_ne!(fixture.prepare()?.dll, adjacent.join(DLL_NAME));
        fs::write(adjacent.join(SYS_NAME), b"user supplied driver")?;
        let replacement = prepare_at(&adjacent.join("TrueProxy.exe"), None)?;
        assert_eq!(replacement.dll, adjacent.join(DLL_NAME));
        assert_eq!(fs::read(&replacement.dll)?, b"user supplied DLL");
        Ok(())
    }

    #[test]
    fn unavailable_or_relative_cache_fails_without_using_working_directory() {
        let fixture = Fixture::new();
        let executable = fixture.0.join("app/TrueProxy.exe");
        assert!(prepare_at(&executable, None).is_err());
        assert!(prepare_at(&executable, Some(Path::new("relative"))).is_err());
        let blocked = fixture.0.join("blocked");
        fs::write(&blocked, b"not a directory").unwrap();
        assert!(prepare_at(&executable, Some(&blocked)).is_err());
    }
}
