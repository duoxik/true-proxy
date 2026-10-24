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
pub use windows::process::running_processes;
#[cfg(not(windows))]
pub fn running_processes() -> anyhow::Result<Vec<RunningProcess>> {
    anyhow::bail!("Выбор запущенных процессов пока поддерживается только в Windows")
}

#[cfg(not(windows))]
pub fn protect(_: &str) -> Result<String> {
    anyhow::bail!("Хранилище паролей пока реализовано только для Windows")
}
#[cfg(not(windows))]
pub fn unprotect(_: &str) -> Result<String> {
    anyhow::bail!("Хранилище паролей пока реализовано только для Windows")
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
    anyhow::bail!("Перехват macOS пока не реализован")
}
#[cfg(not(windows))]
pub struct SingleInstance;
#[cfg(not(windows))]
impl SingleInstance {
    pub fn acquire() -> Result<Self> {
        Ok(Self)
    }
}
