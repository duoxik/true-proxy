use super::{Command, Controller, Installed, MainWindow, XrayModule, assets, newer, profile};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use slint::ComponentHandle;
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    rc::Rc,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Default, Serialize, Deserialize)]
pub(super) struct Check {
    at: u64,
    installed_version: String,
    #[serde(skip)]
    result: Option<Result<(), String>>,
}

pub(super) type SharedChecks = Arc<Mutex<[Check; 2]>>;
const CHECKS_FILE: &str = "module-checks.json";

pub(super) fn load_checks(directory: &Path) -> SharedChecks {
    let cached = (|| {
        let mut bytes = Vec::new();
        fs::File::open(directory.join(CHECKS_FILE))
            .ok()?
            .take(2049)
            .read_to_end(&mut bytes)
            .ok()?;
        (bytes.len() <= 2048)
            .then(|| serde_json::from_slice(&bytes).ok())
            .flatten()
    })()
    .unwrap_or_default();
    Arc::new(Mutex::new(cached))
}

fn save_checks(directory: &Path, checks: &[Check; 2]) -> Result<()> {
    let temp = directory.join(format!("module-checks-{}.tmp", super::super::id()));
    let mut file = fs::File::create_new(&temp)?;
    let result = (|| {
        file.write_all(&serde_json::to_vec(checks)?)?;
        file.sync_all()?;
        drop(file);
        true_proxy::platform::replace_file(&temp, &directory.join(CHECKS_FILE))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn age(seconds: u64) -> String {
    let (value, unit) = match seconds {
        0..60 => return "just now".into(),
        60..3600 => (seconds / 60, "minute"),
        3600..86400 => (seconds / 3600, "hour"),
        _ => (seconds / 86400, "day"),
    };
    format!("{value} {unit}{} ago", if value == 1 { "" } else { "s" })
}

impl Check {
    pub(super) fn error(&self) -> String {
        self.result
            .as_ref()
            .and_then(|r| r.as_ref().err())
            .cloned()
            .unwrap_or_default()
    }
    fn label(&self, version: &str, latest: &str, now: u64) -> (String, bool) {
        if version.is_empty() {
            return (String::new(), false);
        }
        if matches!(self.result, Some(Err(_))) {
            return ("Check failed".into(), false);
        }
        if !latest.is_empty() && newer(latest, version) {
            return (format!("v{latest} available"), true);
        }
        if self.at == 0 || self.installed_version != version {
            return ("Not checked yet".into(), false);
        }
        let seconds = now.saturating_sub(self.at);
        if matches!(self.result, Some(Ok(()))) && seconds < 60 {
            return ("Up to date · Just now".into(), true);
        }
        (format!("Checked {}", age(seconds)), false)
    }
}

pub(super) fn wire_check_times(ui: &MainWindow, checks: SharedChecks) {
    let timer = Rc::new(slint::Timer::default());
    let weak = ui.as_weak();
    ui.global::<XrayModule>()
        .on_refresh_module_check_times(move || {
            let Some(ui) = weak.upgrade() else { return };
            timer.stop();
            if ui.get_page() != 4
                || ui.get_settings_section() != 2
                || !ui.window().is_visible()
                || ui.window().is_minimized()
            {
                return;
            }
            let xray = ui.global::<XrayModule>();
            let checks = checks.lock().unwrap();
            let now = profile::now();
            let (status, highlight) =
                checks[0].label(&xray.get_version(), &xray.get_latest_version(), now);
            xray.set_module_check_status(status.into());
            xray.set_module_check_highlight(highlight);
            let (status, highlight) = checks[1].label(
                &xray.get_hpwnr_version(),
                &xray.get_hpwnr_latest_version(),
                now,
            );
            xray.set_hpwnr_check_status(status.into());
            xray.set_hpwnr_check_highlight(highlight);
            if checks.iter().any(|check| check.at != 0) {
                let weak = weak.clone();
                timer.start(
                    slint::TimerMode::SingleShot,
                    Duration::from_secs(60),
                    move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.global::<XrayModule>()
                                .invoke_refresh_module_check_times();
                        }
                    },
                );
            }
        });
}

pub(super) fn size(installed: Option<&Installed>, hpwnr: bool) -> String {
    installed
        .and_then(|module| assets::installed_size(module, hpwnr).ok())
        .map(super::super::bytes)
        .unwrap_or_default()
}

pub(super) fn operation(command: &Command) -> (&'static str, i32) {
    match command {
        Command::CheckAllModules | Command::CheckUpdates | Command::CheckHpwnrUpdates => {
            ("Checking…", -1)
        }
        Command::ReinstallModule(_) => ("Reinstalling…", 0),
        Command::InstallUpdate | Command::UpdateHpwnr => ("Updating…", 0),
        Command::Install | Command::InstallHpwnr(_) => ("Downloading…", 0),
        Command::RemoveModule(_) => ("Removing…", -1),
        _ => ("", -1),
    }
}

pub(super) fn show_operation(xray: &XrayModule<'_>, hpwnr: bool, text: &str, progress: i32) {
    if hpwnr {
        xray.set_hpwnr_operation(text.into());
        xray.set_hpwnr_progress(progress);
    } else {
        xray.set_module_operation(text.into());
        xray.set_module_progress(progress);
    }
}

pub(super) fn progress_reporter(weak: slint::Weak<MainWindow>) -> Box<dyn Fn(bool, u8) + Send> {
    Box::new(move |hpwnr, progress| {
        let _ = weak.upgrade_in_event_loop(move |ui| {
            let xray = ui.global::<XrayModule>();
            if hpwnr {
                xray.set_hpwnr_progress(i32::from(progress));
            } else {
                xray.set_module_progress(i32::from(progress));
            }
        });
    })
}

impl Controller {
    pub(super) fn module(&self, hpwnr: bool) -> Option<&Installed> {
        if hpwnr {
            self.hpwnr_installed.as_ref()
        } else {
            self.installed.as_ref()
        }
    }

    fn record_check(&self, hpwnr: bool) {
        let check = Check {
            at: profile::now(),
            installed_version: self
                .module(hpwnr)
                .map_or_else(String::new, |module| module.version.clone()),
            result: Some(Ok(())),
        };
        self.cache_check(hpwnr, |saved| *saved = check);
    }

    fn cache_check(&self, hpwnr: bool, update: impl FnOnce(&mut Check)) {
        let checks = {
            let mut checks = self.checks.lock().unwrap();
            update(&mut checks[usize::from(hpwnr)]);
            checks.clone()
        };
        // The verified result remains usable when a read-only directory cannot cache its time.
        let _ = save_checks(&self.directory, &checks);
    }

    pub(super) fn check_module(&mut self, hpwnr: bool) -> Result<()> {
        let release = if hpwnr {
            assets::latest_hpwnr()
        } else {
            assets::latest()
        };
        let release = release.inspect_err(|error| {
            self.checks.lock().unwrap()[usize::from(hpwnr)].result = Some(Err(error.to_string()));
        })?;
        let available = self
            .module(hpwnr)
            .is_none_or(|installed| newer(&release.version, &installed.version));
        if hpwnr {
            self.hpwnr_update_status = if available {
                "An hpwnr update is available."
            } else {
                "You're using the latest hpwnr version."
            }
            .into();
            self.hpwnr_latest = available.then_some(release);
        } else {
            self.latest = available.then_some(release);
        }
        self.record_check(hpwnr);
        Ok(())
    }

    pub(super) fn install_module(
        &mut self,
        hpwnr: bool,
        reinstall: bool,
        update: bool,
    ) -> Result<()> {
        ensure!(
            hpwnr || self.runtime.is_none(),
            "Stop Xray before installing an update"
        );
        let offered = if hpwnr {
            &self.hpwnr_latest
        } else {
            &self.latest
        };
        let fresh_check = !reinstall && offered.is_none();
        let release = if reinstall {
            let installed = self.module(hpwnr).context("The module is not installed")?;
            assets::release_for_version(&installed.version, hpwnr)?
        } else if let Some(release) = offered {
            release.clone()
        } else {
            ensure!(!hpwnr || !update, "Check for hpwnr updates first");
            if hpwnr {
                assets::latest_hpwnr()?
            } else {
                assets::latest()?
            }
        };
        let report = |percent| {
            if let Some(progress) = &self.progress {
                progress(hpwnr, percent);
            }
        };
        if hpwnr {
            self.hpwnr_installed = Some(assets::install_hpwnr_with_progress(
                &self.directory,
                &release,
                reinstall,
                report,
            )?);
            self.hpwnr_update_status = "Installed".into();
            if !reinstall {
                self.hpwnr_latest = None;
            }
        } else {
            self.installed = Some(assets::install_with_progress(
                &self.directory,
                &release,
                reinstall,
                report,
            )?);
            if !reinstall {
                self.latest = None;
            }
            self.reload_geo_tags(true);
            self.status = "Installed · Stopped".into();
            self.last_geo_attempt = profile::now();
        }
        self.module_sizes[usize::from(hpwnr)] = size(self.module(hpwnr), hpwnr);
        if fresh_check {
            self.record_check(hpwnr);
        } else if update {
            self.cache_check(hpwnr, |check| check.installed_version = release.version);
        }
        if !hpwnr
            && self.settings.geoip_url == assets::DEFAULT_GEOIP_URL
            && self.settings.geosite_url == assets::DEFAULT_GEOSITE_URL
            && self.settings.geo_refreshed_at == 0
        {
            self.change(false, |settings| {
                settings.geo_refreshed_at = profile::now();
                Ok(())
            })?;
        }
        Ok(())
    }

    pub(super) fn open_module_folder(&self, hpwnr: bool) -> Result<()> {
        let module = self.module(hpwnr).context("The module is not installed")?;
        let directory = module
            .executable
            .parent()
            .context("Missing module directory")?;
        true_proxy::platform::windows::open_folder(directory)
    }

    pub(super) fn remove_module(&mut self, hpwnr: bool) -> Result<()> {
        ensure!(self.module(hpwnr).is_some(), "The module is not installed");
        ensure!(
            hpwnr || self.runtime.is_none(),
            "Stop Xray before removing the module"
        );
        if !hpwnr {
            self.remember_enabled(false)?;
        }
        let result = assets::remove_module(&self.directory, hpwnr);
        // An error cleaning old snapshots can follow a successful deactivation.
        if hpwnr {
            self.hpwnr_installed = assets::hpwnr_installation(&self.directory)?;
            if self.hpwnr_installed.is_none() {
                self.hpwnr_latest = None;
                self.hpwnr_update_status.clear();
            }
        } else {
            self.installed = assets::installed(&self.directory)?;
            if self.installed.is_none() {
                self.latest = None;
                self.pending = false;
                self.failed_ports.clear();
                self.status = "Not installed".into();
            }
        }
        self.module_sizes[usize::from(hpwnr)] = size(self.module(hpwnr), hpwnr);
        if self.module(hpwnr).is_none() {
            self.cache_check(hpwnr, |check| *check = Check::default());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_age_and_available_version_follow_only_verified_results() {
        let check = Check {
            at: 5,
            installed_version: "1.0.3".into(),
            result: Some(Ok(())),
        };
        assert_eq!(
            check.label("1.0.3", "", 40),
            ("Up to date · Just now".into(), true)
        );
        assert_eq!(
            check.label("1.0.3", "", 7205),
            ("Checked 2 hours ago".into(), false)
        );
        assert_eq!(
            check.label("1.0.3", "1.0.4", 7205),
            ("v1.0.4 available".into(), true)
        );
        assert_eq!(
            check.label("1.1.0", "", 40),
            ("Not checked yet".into(), false)
        );
        let failed = Check {
            result: Some(Err("offline".into())),
            ..check
        };
        assert_eq!(
            failed.label("1.0.3", "1.0.4", 50),
            ("Check failed".into(), false)
        );
        assert_eq!(failed.error(), "offline");
    }

    #[test]
    fn restart_remembers_check_time_but_requires_new_release_metadata_for_updates() -> Result<()> {
        let directory = std::env::temp_dir().join(format!("module-time-{}", crate::app::id()));
        fs::create_dir(&directory)?;
        let core = Check {
            at: 10,
            installed_version: "2.0.1".into(),
            result: Some(Ok(())),
        };
        save_checks(&directory, &[core, Check::default()])?;
        let checks = load_checks(&directory);
        let checks = checks.lock().unwrap();
        assert_eq!(
            checks[0].label("2.0.1", "", 15),
            ("Checked just now".into(), false)
        );
        assert_eq!(
            checks[1].label("1.0.3", "", 15),
            ("Not checked yet".into(), false)
        );
        fs::remove_dir_all(&directory)?;
        Ok(())
    }
}
