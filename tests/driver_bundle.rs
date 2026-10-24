//! Run a copy of the EXE with no sidecars; only load DLL helpers, never a device.
#![cfg(windows)]
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn check(exe: &Path, root: &Path) -> Result<PathBuf> {
    let report = root.join("report.json");
    let _ = fs::remove_file(&report);
    let status = Command::new(exe)
        .arg("--check-driver")
        .arg(&report)
        .current_dir(root.join("working directory"))
        .env("LOCALAPPDATA", root.join("profile"))
        .env(
            "PATH",
            std::env::var_os("SystemRoot")
                .context("SystemRoot")?
                .to_string_lossy()
                .to_string()
                + "\\System32",
        )
        .status()?;
    let result: serde_json::Value = serde_json::from_slice(&fs::read(report)?)?;
    ensure!(
        status.success() && result["ok"] == true,
        "Standalone diagnostic failed: {result}"
    );
    ensure!(
        result["interception"] == false,
        "Diagnostic must not enable interception"
    );
    Ok(PathBuf::from(result["dll"].as_str().context("DLL path")?))
}

#[test]
fn copied_exe_loads_embedded_runtime_and_repairs_cache_without_sidecars() -> Result<()> {
    let fixture = Fixture(std::env::temp_dir().join(format!(
        "true-proxy-standalone-{}-тест с пробелами",
        std::process::id()
    )));
    fs::create_dir_all(fixture.0.join("app"))?;
    fs::create_dir_all(fixture.0.join("working directory"))?;
    // A fake DLL in CWD must never be picked up by the loader.
    fs::write(
        fixture.0.join("working directory/WinDivert.dll"),
        b"wrong DLL",
    )?;
    let exe = fixture.0.join("app/TrueProxy.exe");
    fs::copy(env!("CARGO_BIN_EXE_true-proxy"), &exe)?;
    let dll = check(&exe, &fixture.0)?;
    ensure!(
        dll.starts_with(fixture.0.join("profile")),
        "Must extract into the isolated profile"
    );
    let sys = dll.with_file_name("WinDivert64.sys");
    let original_dll = fs::read(&dll)?;
    let original_sys = fs::read(&sys)?;
    fs::write(&dll, vec![0; original_dll.len()])?;
    fs::remove_file(&sys)?;
    ensure!(check(&exe, &fixture.0)? == dll, "Cache location changed");
    ensure!(
        fs::read(&dll)? == original_dll && fs::read(&sys)? == original_sys,
        "Cache was not repaired"
    );
    ensure!(
        fs::read_dir(fixture.0.join("app"))?.count() == 1,
        "Must not write next to the EXE"
    );
    Ok(())
}
