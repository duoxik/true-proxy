#[cfg(not(windows))]
use anyhow::Result;
#[cfg(not(windows))]
use std::path::Path;

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use windows::{
    SingleInstance, is_admin, protect, relaunch_elevated, replace_file, show_error, unprotect,
};

#[derive(Clone)]
pub struct RunningProcess {
    pub name: String,
    pub path: String,
    pub pids: Vec<u32>,
}
#[cfg(windows)]
pub use windows::picker::choose_executable;
#[cfg(windows)]
pub use windows::process::running_processes;
#[cfg(windows)]
pub use windows::startup::{autostart_enabled, set_autostart};
#[cfg(not(windows))]
pub fn choose_executable() -> anyhow::Result<Option<String>> {
    anyhow::bail!("Executable selection is currently available only on Windows")
}
#[cfg(not(windows))]
pub fn autostart_enabled() -> Result<bool> {
    Ok(false)
}
#[cfg(not(windows))]
pub fn set_autostart(_: bool) -> Result<bool> {
    anyhow::bail!("Automatic startup is currently available only on Windows")
}
#[cfg(not(windows))]
pub fn running_processes() -> anyhow::Result<Vec<RunningProcess>> {
    anyhow::bail!("Running process selection is currently available only on Windows")
}

#[cfg(not(windows))]
pub fn protect(_: &str) -> Result<String> {
    anyhow::bail!("Password storage is currently available only on Windows")
}
#[cfg(not(windows))]
pub fn unprotect(_: &str) -> Result<String> {
    anyhow::bail!("Password storage is currently available only on Windows")
}
#[cfg(not(windows))]
pub fn replace_file(source: &Path, target: &Path) -> Result<()> {
    Ok(std::fs::rename(source, target)?)
}
#[cfg(not(windows))]
pub fn show_error(message: &str) {
    eprintln!("True Proxy: {message}");
}
#[cfg(not(windows))]
pub fn is_admin() -> bool {
    false
}
#[cfg(not(windows))]
pub fn relaunch_elevated() -> Result<()> {
    anyhow::bail!("Traffic interception is not yet available on macOS")
}
#[cfg(not(windows))]
pub struct SingleInstance;
#[cfg(not(windows))]
impl SingleInstance {
    pub fn acquire() -> Result<Option<Self>> {
        Ok(Some(Self))
    }
}
