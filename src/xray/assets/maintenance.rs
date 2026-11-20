use super::*;

pub(super) fn decoder_file(name: &str) -> bool {
    name == HPWNR_FILE
        || name
            .strip_prefix("hpwnr-")
            .and_then(|s| s.strip_suffix(".exe"))
            .is_some_and(|digest| crate::updates::validate_digest(digest).is_ok())
}

pub fn installed_size(installed: &Installed, hpwnr: bool) -> Result<u64> {
    let directory = installed
        .executable
        .parent()
        .context("Invalid module path")?;
    plain_directory(directory)?;
    if hpwnr {
        plain_file(&installed.executable)?;
        return Ok(fs::metadata(&installed.executable)?.len());
    }
    CORE_FILES.iter().try_fold(0, |total, name| {
        let path = directory.join(name);
        plain_file(&path)?;
        Ok(total + fs::metadata(path)?.len())
    })
}

/// Retire only the selected module's known assets. Profiles, separate geodata
/// and unrecognized files in the same directory belong to the user.
pub fn remove_module(root: &Path, hpwnr: bool) -> Result<()> {
    ensure!(root.is_absolute(), "The module directory must be absolute");
    plain_directory(root)?;
    let mut files = Vec::new();
    let mut directories = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if hpwnr && decoder_file(name) {
            files.push(entry.path());
        } else if !hpwnr
            && name
                .strip_prefix("core-")
                .is_some_and(|digest| crate::updates::validate_digest(digest).is_ok())
        {
            let directory = entry.path();
            plain_directory(&directory)?;
            for name in CORE_FILES {
                let file = directory.join(name);
                if file.try_exists()? {
                    files.push(file);
                }
            }
            directories.push(directory);
        }
    }
    let manifest = root.join(if hpwnr { HPWNR_MANIFEST } else { CORE_MANIFEST });
    if manifest.try_exists()? {
        files.push(manifest);
    }
    for path in &files {
        plain_file(path)?;
    }
    if files.is_empty() {
        return Ok(());
    }

    // All moves stay on one volume. A locked executable must leave the user's
    // original selection and all the files already moved in this attempt intact.
    let stage = Stage::new(root, "uninstall")?;
    for (i, path) in files.iter().enumerate() {
        if let Err(error) = fs::rename(path, stage.path.join(i.to_string())) {
            for (j, original) in files[..i].iter().enumerate().rev() {
                fs::rename(stage.path.join(j.to_string()), original)
                    .context("Could not restore module files after an interrupted removal")?;
            }
            return Err(error).with_context(|| format!("Could not remove {}", path.display()));
        }
    }
    for i in 0..files.len() {
        fs::remove_file(stage.path.join(i.to_string()))?;
    }
    for directory in directories {
        if fs::read_dir(&directory)?.next().is_none() {
            fs::remove_dir(directory)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn locked_manifest_restores_files_already_moved() -> Result<()> {
        use std::os::windows::fs::OpenOptionsExt;
        let temp = Stage::new(&std::env::temp_dir(), "module-locked-test")?;
        let legacy = temp.path.join(HPWNR_FILE);
        let manifest = temp.path.join(HPWNR_MANIFEST);
        fs::write(&legacy, b"decoder")?;
        fs::write(&manifest, b"manifest")?;
        let lock = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&manifest)?;
        assert!(remove_module(&temp.path, true).is_err());
        assert_eq!(fs::read(&legacy)?, b"decoder");
        drop(lock);
        assert_eq!(fs::read(&manifest)?, b"manifest");
        remove_module(&temp.path, true)
    }

    #[test]
    fn independent_removal_preserves_other_modules_profiles_and_user_files() -> Result<()> {
        let temp = Stage::new(&std::env::temp_dir(), "module-maintenance-test")?;
        let root = &temp.path;
        let core = root.join(core_directory_name(&"a".repeat(64)));
        fs::create_dir(&core)?;
        for file in CORE_FILES {
            fs::write(core.join(file), b"core")?;
        }
        let installed = Installed {
            executable: core.join("xray.exe"),
            version: "1.0.0".into(),
            sha256: String::new(),
        };
        assert_eq!(installed_size(&installed, false)?, 16);
        fs::write(core.join("mine.txt"), b"keep")?;
        for file in [
            CORE_MANIFEST,
            HPWNR_FILE,
            HPWNR_MANIFEST,
            "profiles.json",
            GEO_MANIFEST,
            "hpwnr-custom.exe",
        ] {
            fs::write(root.join(file), b"fixture")?;
        }
        remove_module(root, false)?;
        assert!(core.join("mine.txt").exists() && root.join(HPWNR_FILE).exists());
        assert!(!installed.executable.exists() && !root.join(CORE_MANIFEST).exists());
        remove_module(root, true)?;
        assert!(!root.join(HPWNR_FILE).exists() && !root.join(HPWNR_MANIFEST).exists());
        for name in ["profiles.json", GEO_MANIFEST, "hpwnr-custom.exe"] {
            assert_eq!(fs::read(root.join(name))?, b"fixture");
            fs::remove_file(root.join(name))?;
        }
        fs::remove_file(core.join("mine.txt"))?;
        fs::remove_dir(core)?;
        Ok(())
    }
}
