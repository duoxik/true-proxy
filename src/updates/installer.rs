use super::{MAX_EXE_SIZE, Staged, validate_pe, verify_file};
use crate::platform::{
    replace_file,
    windows::update::{self, Parent},
};
use anyhow::{Context, Result, ensure};
use std::{
    ffi::OsString,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn copy_new(source: &Path, destination: &Path) -> Result<()> {
    ensure!(
        !super::is_reparse(source),
        "Обновление не должно ссылаться на другой файл"
    );
    let mut input = fs::File::open(source)?.take(MAX_EXE_SIZE + 1);
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let written = std::io::copy(&mut input, &mut output)?;
    ensure!(written <= MAX_EXE_SIZE, "Слишком большой файл обновления");
    output.sync_all()?;
    Ok(())
}

/// Called only while routing is paused. The helper confirms preparation before
/// the UI exits; a failed download/copy therefore leaves the old app running.
pub fn prepare(staged: &Staged) -> Result<()> {
    verify_file(&staged.payload(), &staged.release.sha256)?;
    validate_pe(&staged.payload())?;
    let current = std::env::current_exe()?;
    let helper = staged.directory.join("updater.exe");
    if helper.exists() {
        ensure!(
            update::sha256(&helper)? == update::sha256(&current)?,
            "Повреждён компонент обновления"
        );
    } else {
        copy_new(&current, &helper)?;
    }
    let creation = update::current_created()?;
    for name in ["ready", "error.txt"] {
        let path = staged.directory.join(name);
        if path.exists() {
            fs::remove_file(path)?;
        }
    }
    let arguments = [
        OsString::from("--apply-update"),
        std::process::id().to_string().into(),
        creation.to_string().into(),
        staged.release.sha256.clone().into(),
    ];
    let mut child = update::spawn_hidden(&helper, &arguments)?;
    let started = Instant::now();
    let result = (|| {
        loop {
            if staged.directory.join("ready").is_file() {
                return Ok(());
            }
            if let Some(status) = child.try_wait()? {
                let error = read_error(&staged.directory)
                    .unwrap_or_else(|| format!("Компонент обновления завершился: {status}"));
                anyhow::bail!(error);
            }
            ensure!(
                started.elapsed() < Duration::from_secs(20),
                "Компонент обновления не подтвердил готовность"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    })();
    if result.is_err() {
        // Until readiness/parent exit this child can only be copying a temporary
        // sibling. Stop our own helper before a retry can reuse its marker.
        if child.try_wait()?.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ =
            fs::remove_file(current.with_extension(format!("true-proxy-new-{}.exe", child.id())));
        let _ = fs::remove_file(staged.directory.join("ready"));
    }
    result
}

fn read_error(directory: &Path) -> Option<String> {
    let mut file = fs::File::open(directory.join("error.txt")).ok()?.take(4096);
    let mut text = String::new();
    file.read_to_string(&mut text).ok()?;
    Some(text)
}

fn replace_and_launch(
    target: &Path,
    replacement: &Path,
    backup: &Path,
    expected_old: &str,
    launch: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    verify_file(target, expected_old)?;
    copy_new(target, backup)?;
    verify_file(backup, expected_old)?;
    replace_file(replacement, target)?;
    if let Err(error) = launch(target) {
        // The verified backup may be on another volume. Restore through a new
        // sibling of the target, then use the same atomic replacement operation.
        copy_new(backup, replacement)?;
        verify_file(replacement, expected_old)?;
        replace_file(replacement, target).context("Не удалось восстановить предыдущий EXE")?;
        return Err(error)
            .context("Не удалось запустить новую версию; предыдущий EXE восстановлен");
    }
    Ok(())
}

pub fn apply(pid: u32, creation: u64, digest: &str) -> Result<()> {
    let helper = std::env::current_exe()?;
    ensure!(
        helper.file_name() == Some(std::ffi::OsStr::new("updater.exe")),
        "Некорректный компонент обновления"
    );
    let directory = helper.parent().context("Не найдена папка обновления")?;
    let result = apply_inner(&helper, directory, pid, creation, digest);
    if let Err(error) = &result {
        let _ = fs::write(directory.join("error.txt"), format!("{error:#}"));
    }
    result
}

fn apply_inner(
    helper: &Path,
    directory: &Path,
    pid: u32,
    creation: u64,
    digest: &str,
) -> Result<()> {
    super::validate_digest(digest)?;
    ensure!(
        !super::is_reparse(directory),
        "Некорректная папка обновления"
    );
    let parent = Parent::open(pid, creation)?;
    // The destination is obtained from an OS process handle, never from a job
    // file or a target-path command argument. It must be this exact old binary.
    let old_hash = update::sha256(helper)?;
    ensure!(
        !super::is_reparse(&parent.image),
        "Нельзя обновить EXE-ссылку"
    );
    verify_file(&parent.image, &old_hash)?;
    let payload = directory.join("payload.exe");
    verify_file(&payload, digest)?;
    validate_pe(&payload)?;
    let replacement = replacement_path(&parent.image);
    let backup = directory.join("previous.exe");
    ensure!(
        !backup.exists(),
        "Предыдущая попытка обновления уже создала резервную копию"
    );
    copy_new(&payload, &replacement)?;
    let result = (|| {
        verify_file(&replacement, digest)?;
        let mut ready = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("ready"))?;
        ready.write_all(b"ready")?;
        ready.sync_all()?;
        parent.wait()?;
        verify_file(&replacement, digest)?;
        replace_and_launch(&parent.image, &replacement, &backup, &old_hash, |target| {
            update::spawn_hidden(target, &[])?;
            Ok(())
        })
    })();
    let _ = fs::remove_file(&replacement);
    if result.is_err() && backup.exists() {
        // On a copy/launch error after shutdown, reopen the preserved old app.
        // No routing state is changed by the helper.
        if update::sha256(&parent.image).is_ok_and(|hash| hash == old_hash) {
            let _ = update::spawn_hidden(&parent.image, &[]);
        }
    }
    result
}

fn replacement_path(target: &Path) -> PathBuf {
    target.with_extension(format!("true-proxy-new-{}.exe", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_restart_restores_old_executable_and_keeps_backup() {
        let root = std::env::temp_dir().join(format!("true-proxy-install-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let (target, replacement, backup) = (
            root.join("app.exe"),
            root.join("new.exe"),
            root.join("previous.exe"),
        );
        fs::write(&target, b"old").unwrap();
        fs::write(&replacement, b"new").unwrap();
        let old = update::sha256(&target).unwrap();
        let result = replace_and_launch(&target, &replacement, &backup, &old, |path| {
            assert_eq!(fs::read(path).unwrap(), b"new");
            anyhow::bail!("simulated launch failure")
        });
        assert!(result.is_err());
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert_eq!(fs::read(&backup).unwrap(), b"old");
        fs::remove_file(&backup).unwrap();
        fs::write(&replacement, b"new").unwrap();
        replace_and_launch(&target, &replacement, &backup, &old, |_| Ok(())).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert_eq!(fs::read(&backup).unwrap(), b"old");
        fs::remove_file(target).unwrap();
        fs::remove_file(backup).unwrap();
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn changed_target_or_existing_backup_cannot_be_overwritten() {
        let root =
            std::env::temp_dir().join(format!("true-proxy-install-guard-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let (target, replacement, backup) = (
            root.join("app.exe"),
            root.join("new.exe"),
            root.join("previous.exe"),
        );
        fs::write(&target, b"old").unwrap();
        fs::write(&replacement, b"new").unwrap();
        let old = update::sha256(&target).unwrap();
        fs::write(&target, b"changed").unwrap();
        assert!(
            replace_and_launch(&target, &replacement, &backup, &old, |_| panic!(
                "must not launch"
            ))
            .is_err()
        );
        assert_eq!(fs::read(&target).unwrap(), b"changed");
        fs::write(&target, b"old").unwrap();
        fs::write(&backup, b"existing").unwrap();
        assert!(
            replace_and_launch(&target, &replacement, &backup, &old, |_| panic!(
                "must not launch"
            ))
            .is_err()
        );
        assert_eq!(fs::read(&backup).unwrap(), b"existing");
        assert_eq!(fs::read(&target).unwrap(), b"old");
        for path in [target, replacement, backup] {
            fs::remove_file(path).unwrap();
        }
        fs::remove_dir(root).unwrap();
    }
}
