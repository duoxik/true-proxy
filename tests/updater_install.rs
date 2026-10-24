//! Replace only owned fixture executables in Temp, including a real helper handoff.
#![cfg(all(windows, debug_assertions))]
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};
use true_proxy::platform::windows::update::sha256;

#[test]
fn helper_waits_for_parent_replaces_only_its_exe_and_restarts_owned_payload() -> Result<()> {
    let root =
        std::env::temp_dir().join(format!("true-proxy-update-fixture-{}", std::process::id()));
    ensure!(!root.exists(), "Fixture directory already exists");
    let app = root.join("приложение с пробелами");
    let stage = root.join("обновление с пробелами");
    fs::create_dir_all(&app)?;
    fs::create_dir(&stage)?;
    let parent = app.join("TrueProxy.exe");
    let parent_build = root.join("fixture-parent.exe");
    fs::copy(env!("CARGO_BIN_EXE_true-proxy"), &parent_build)?;
    // GNU dev builds carry hundreds of MiB of DWARF. Strip only this fixture copy;
    // MSVC keeps debug symbols in PDBs and does not need this step.
    if fs::metadata(&parent_build)?.len() > true_proxy::updates::MAX_EXE_SIZE {
        let strip = std::env::var_os("CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER")
            .and_then(|linker| {
                PathBuf::from(linker)
                    .parent()
                    .map(|path| path.join("strip.exe"))
            })
            .unwrap_or_else(|| PathBuf::from("strip"));
        ensure!(
            Command::new(strip)
                .arg("--strip-all")
                .arg("fixture-parent.exe")
                .current_dir(&root)
                .status()?
                .success(),
            "Cannot strip fixture debug symbols"
        );
    }
    fs::rename(parent_build, &parent)?;
    let payload = stage.join("payload.exe");
    let payload_build = root.join("fixture-payload.exe");
    let compile = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .arg("--edition=2024")
        .arg("-Cstrip=symbols")
        .arg("tests/helpers/update-payload.rs")
        .arg("-o")
        .arg(&payload_build)
        .output()?;
    ensure!(
        compile.status.success(),
        "Cannot compile fixture payload: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    fs::rename(payload_build, &payload)?;
    let old_hash = sha256(&parent)?;
    let new_hash = sha256(&payload)?;
    let mut process = Command::new(&parent)
        .arg("--exercise-update")
        .arg(&stage)
        .spawn()?;
    let started = Instant::now();
    loop {
        if let Some(status) = process.try_wait()? {
            ensure!(
                status.success(),
                "Parent failed: {}",
                fs::read_to_string(stage.join("parent-error.txt")).unwrap_or_default()
            );
            break;
        }
        ensure!(
            started.elapsed() < Duration::from_secs(25),
            "Fixture parent did not finish"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let marker = parent.with_extension("updated");
    while !marker.exists() {
        if stage.join("error.txt").exists() {
            anyhow::bail!(
                "Helper error: {}",
                fs::read_to_string(stage.join("error.txt"))?
            );
        }
        ensure!(
            started.elapsed() < Duration::from_secs(30),
            "Owned payload did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    ensure!(
        fs::read(&marker)? == b"new payload started",
        "Wrong restart marker"
    );
    ensure!(sha256(&parent)? == new_hash, "Target was not replaced");
    ensure!(
        sha256(&stage.join("previous.exe"))? == old_hash,
        "Old EXE was not preserved"
    );
    // All paths were created under this unique fixture root, never a user install.
    ensure!(
        root.is_absolute() && root.parent() == Some(std::env::temp_dir().as_path()),
        "Invalid cleanup root"
    );
    for _ in 0..40 {
        if fs::remove_dir_all(&root).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(anyhow::anyhow!("Cannot clean fixture")).context(root.display().to_string())
}
