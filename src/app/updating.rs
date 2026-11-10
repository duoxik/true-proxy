use crate::MainWindow;
use anyhow::{Context, Result};
use slint::ComponentHandle;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
    },
    thread,
    time::{Duration, Instant},
};
use true_proxy::updates::{self, Preferences, Release, Staged};

enum Command {
    Check,
    Install,
    Automatic,
    Quit,
}
pub struct Controller(SyncSender<Command>);

impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.0.try_send(Command::Quit);
    }
}

pub fn wire(
    ui: &MainWindow,
    preferences_path: PathBuf,
    preview: bool,
) -> Result<Option<Controller>> {
    let preview = preview || ui.get_local_build();
    ui.set_app_version(if ui.get_local_build() {
        format!("{}-dev", updates::VERSION).into()
    } else {
        updates::VERSION.into()
    });
    let preferences = if preview {
        Ok(Preferences::default())
    } else {
        Preferences::load(&preferences_path)
    };
    let automatic = !preview
        && preferences
            .as_ref()
            .map(|preferences| preferences.automatic)
            .unwrap_or(false);
    ui.set_updates_automatic(automatic);
    let automatic = Arc::new(AtomicBool::new(automatic));
    ui.set_update_status(match preferences {
        Ok(_) => "Updates haven't been checked yet.".into(),
        Err(error) => format!("{error:#}").into(),
    });
    let (sender, receiver) = mpsc::sync_channel(4);
    let weak = ui.as_weak();
    let tx = sender.clone();
    ui.on_check_updates(move || {
        if let Some(ui) = weak.upgrade() {
            if preview {
                ui.set_update_status("Update checks are disabled in local/preview builds.".into());
                return;
            }
            if !ui.get_update_busy() {
                if tx.try_send(Command::Check).is_ok() {
                    ui.set_update_busy(true);
                    ui.set_update_status("Checking for updates…".into());
                } else {
                    ui.set_update_status(
                        "An update check is already running. Try again later.".into(),
                    );
                }
            }
        }
    });
    let weak = ui.as_weak();
    let tx = sender.clone();
    let setting = automatic.clone();
    ui.on_set_updates_automatic(move |enabled| {
        if let Some(ui) = weak.upgrade() {
            if preview {
                ui.set_updates_automatic(false);
                ui.set_update_status(
                    "Automatic updates are disabled in local/preview builds.".into(),
                );
                return;
            }
            let result = Preferences { automatic: enabled }.save(&preferences_path);
            match result {
                Ok(()) => {
                    ui.set_updates_automatic(enabled);
                    setting.store(enabled, Ordering::Relaxed);
                    let _ = tx.try_send(Command::Automatic);
                }
                Err(error) => {
                    ui.set_updates_automatic(setting.load(Ordering::Relaxed));
                    ui.set_update_status(format!("Could not save the setting: {error:#}").into());
                }
            }
        }
    });
    let weak = ui.as_weak();
    let tx = sender.clone();
    ui.on_update_now(move || {
        if let Some(ui) = weak.upgrade() {
            if preview {
                ui.set_update_text(
                    "Update installation is disabled in local/preview builds.".into(),
                );
                return;
            }
            if ui.get_update_busy() {
                return;
            }
            if ui.get_busy() {
                return;
            }
            if tx.try_send(Command::Install).is_ok() {
                ui.set_update_busy(true);
                ui.set_busy(true);
                ui.set_update_text("Preparing to download, install and restart…".into());
            }
        }
    });
    if preview {
        return Ok(None);
    }
    let root = preferences_path_for_cache()?.join("updates");
    let weak = ui.as_weak();
    thread::Builder::new().name("updates".into()).spawn(move || {
        let mut deadline = Instant::now() + Duration::from_secs(8);
        let mut release: Option<Release> = None;
        let mut staged: Option<Staged> = None;
        loop {
            let command = if automatic.load(Ordering::Relaxed) {
                match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                    Ok(command) => command,
                    Err(mpsc::RecvTimeoutError::Timeout) => { if !automatic.load(Ordering::Relaxed) { continue; } Command::Check },
                    Err(_) => break,
                }
            } else { match receiver.recv() { Ok(command) => command, Err(_) => break } };
            match command {
                Command::Quit => break,
                Command::Automatic => { deadline = Instant::now() + Duration::from_secs(1); }
                Command::Check => {
                    post(&weak, |ui| { ui.set_update_busy(true); ui.set_update_status("Checking for updates…".into()); });
                    let result = (|| -> Result<Option<Release>> {
                        Ok(updates::latest()?.filter(|candidate| updates::is_newer(candidate, updates::VERSION).unwrap_or(false)))
                    })();
                    deadline = Instant::now() + updates::CHECK_INTERVAL;
                    match result {
                        Ok(Some(candidate)) => {
                            let already_ready = staged.as_ref().is_some_and(|staged| staged.release.version == candidate.version && staged.release.sha256 == candidate.sha256);
                            if !already_ready { staged = None; }
                            release = Some(candidate.clone());
                            post(&weak, move |ui| {
                                ui.set_update_version(candidate.version.into()); ui.set_update_available(true); ui.set_update_ready(already_ready); ui.set_update_busy(false);
                                ui.set_update_text(if already_ready { "Ready to install. Routing will stop and resume automatically if it is enabled." } else { "Install and restart automatically. Active proxy connections will close briefly." }.into());
                                ui.set_update_status("An update is available.".into());
                            });
                        }
                        Ok(None) => { release = None; staged = None; post(&weak, |ui| { ui.set_update_available(false); ui.set_update_ready(false); ui.set_update_busy(false); ui.set_update_status("You're on the latest published version.".into()); }); }
                        Err(error) => post(&weak, move |ui| { ui.set_update_busy(false); ui.set_update_status(format!("Could not check for updates: {error:#}").into()); }),
                    }
                }

                Command::Install => {
                    let result = (|| -> Result<()> {
                        #[cfg(windows)] {
                            if staged.is_none() {
                                let candidate = release.as_ref().context("Check for updates first")?;
                                staged = Some(updates::download(candidate, &root, |downloaded, total| {
                                    let percent = downloaded * 100 / total;
                                    post(&weak, move |ui| ui.set_update_text(format!("Downloading update… {percent}%").into()));
                                })?);
                            }
                            post(&weak, |ui| { ui.set_update_ready(true); ui.set_update_text("Restarting the app. Routing will resume with its saved state…".into()); });
                            updates::installer::prepare(staged.as_ref().context("Update is not ready")?)
                        }
                        #[cfg(not(windows))] { let _ = (&staged, &root); anyhow::bail!("Installation is currently available only on Windows") }
                    })();
                    match result {
                        Ok(()) => { let _ = slint::invoke_from_event_loop(|| { let _ = slint::quit_event_loop(); }); break; }
                        Err(error) => post(&weak, move |ui| { ui.set_busy(false); ui.set_update_busy(false); ui.set_update_text(format!("Could not prepare the update: {error:#}").into()); }),
                    }
                }
            }
        }
    })?;
    Ok(Some(Controller(sender)))
}

fn preferences_path_for_cache() -> Result<PathBuf> {
    Ok(true_proxy::config::Config::path()?
        .parent()
        .context("Could not find the True Proxy folder")?
        .to_owned())
}
fn post(ui: &slint::Weak<MainWindow>, callback: impl FnOnce(MainWindow) + Send + 'static) {
    let weak = ui.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            callback(ui);
        }
    });
}

#[cfg(test)]
mod local_tests {
    use super::*;

    #[test]
    fn local_build_disables_updates_without_writing_preferences() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.set_local_build(true);
        let path = std::env::temp_dir().join(format!(
            "true-proxy-local-updates-{}.json",
            crate::app::id()
        ));
        assert!(!path.exists());
        assert!(wire(&ui, path.clone(), false).unwrap().is_none());
        assert!(ui.get_app_version().ends_with("-dev"));
        assert!(!ui.get_updates_automatic());
        ui.invoke_set_updates_automatic(true);
        ui.invoke_check_updates();
        ui.invoke_update_now();
        assert!(!ui.get_updates_automatic() && !ui.get_update_busy());
        assert!(!path.exists());
    }
}
