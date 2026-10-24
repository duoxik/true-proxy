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
    Download,
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
    ui.set_app_version(updates::VERSION.into());
    let preferences = if preview {
        Ok(Preferences::default())
    } else {
        Preferences::load(&preferences_path)
    };
    let automatic = preferences
        .as_ref()
        .map(|preferences| preferences.automatic)
        .unwrap_or(false);
    ui.set_updates_automatic(automatic);
    let automatic = Arc::new(AtomicBool::new(automatic));
    ui.set_update_status(match preferences {
        Ok(_) => "Ещё не проверяли обновления.".into(),
        Err(error) => format!("{error:#}").into(),
    });
    let (sender, receiver) = mpsc::sync_channel(4);
    let weak = ui.as_weak();
    let tx = sender.clone();
    ui.on_check_updates(move || {
        if let Some(ui) = weak.upgrade() {
            if preview {
                ui.set_update_status("В режиме проверки UI запросы к GitHub отключены.".into());
                return;
            }
            if !ui.get_update_busy() {
                if tx.try_send(Command::Check).is_ok() {
                    ui.set_update_busy(true);
                    ui.set_update_status("Проверяем обновления…".into());
                } else {
                    ui.set_update_status("Проверка уже выполняется. Повторите позже.".into());
                }
            }
        }
    });
    let weak = ui.as_weak();
    let tx = sender.clone();
    let setting = automatic.clone();
    ui.on_set_updates_automatic(move |enabled| {
        if let Some(ui) = weak.upgrade() {
            let result = Preferences { automatic: enabled }.save(&preferences_path);
            match result {
                Ok(()) => {
                    ui.set_updates_automatic(enabled);
                    setting.store(enabled, Ordering::Relaxed);
                    let _ = tx.try_send(Command::Automatic);
                }
                Err(error) => {
                    ui.set_updates_automatic(setting.load(Ordering::Relaxed));
                    ui.set_update_status(
                        format!("Не удалось сохранить настройку: {error:#}").into(),
                    );
                }
            }
        }
    });
    let weak = ui.as_weak();
    let tx = sender.clone();
    ui.on_update_now(move || {
        if let Some(ui) = weak.upgrade() {
            if preview {
                ui.set_update_text("Режим проверки UI: установка отключена.".into());
                return;
            }
            if ui.get_update_busy() {
                return;
            }
            let install = ui.get_update_ready();
            if install && (ui.get_active() || ui.get_busy()) {
                ui.set_update_text(
                    "Приостановите маршрутизацию перед установкой обновления.".into(),
                );
                return;
            }
            if tx
                .try_send(if install {
                    Command::Install
                } else {
                    Command::Download
                })
                .is_ok()
            {
                ui.set_update_busy(true);
                if install {
                    ui.set_busy(true);
                }
                ui.set_update_text(
                    if install {
                        "Подготавливаем установку…"
                    } else {
                        "Загружаем обновление…"
                    }
                    .into(),
                );
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
                    post(&weak, |ui| { ui.set_update_busy(true); ui.set_update_status("Проверяем обновления…".into()); });
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
                                ui.set_update_text(if already_ready { "Обновление загружено. Приостановите прокси и перезапустите приложение." } else { "Новая версия готова к загрузке." }.into());
                                ui.set_update_status("Доступно обновление.".into());
                            });
                        }
                        Ok(None) => { release = None; staged = None; post(&weak, |ui| { ui.set_update_available(false); ui.set_update_ready(false); ui.set_update_busy(false); ui.set_update_status("Новых опубликованных версий нет.".into()); }); }
                        Err(error) => post(&weak, move |ui| { ui.set_update_busy(false); ui.set_update_status(format!("Не удалось проверить обновления: {error:#}").into()); }),
                    }
                }
                Command::Download => {
                    let result = (|| -> Result<Staged> {
                        let release = release.as_ref().context("Сначала проверьте наличие обновлений")?;
                        #[cfg(windows)] { updates::download(release, &root, |downloaded, total| {
                            let percent = downloaded * 100 / total;
                            post(&weak, move |ui| ui.set_update_text(format!("Загружаем обновление… {percent}%").into()));
                        }) }
                        #[cfg(not(windows))] { let _ = (&root, release); anyhow::bail!("Обновление пока поддерживается только в Windows") }
                    })();
                    match result {
                        Ok(ready) => { staged = Some(ready); post(&weak, |ui| { ui.set_update_busy(false); ui.set_update_ready(true); ui.set_update_text("Обновление загружено. Для установки приостановите маршрутизацию.".into()); }); }
                        Err(error) => post(&weak, move |ui| { ui.set_update_busy(false); ui.set_update_text(format!("Загрузка не завершена: {error:#}").into()); }),
                    }
                }
                Command::Install => {
                    let result = (|| -> Result<()> {
                        let staged = staged.as_ref().context("Сначала загрузите обновление")?;
                        #[cfg(windows)] { updates::installer::prepare(staged) }
                        #[cfg(not(windows))] { let _ = staged; anyhow::bail!("Установка пока поддерживается только в Windows") }
                    })();
                    match result {
                        Ok(()) => { let _ = slint::invoke_from_event_loop(|| { let _ = slint::quit_event_loop(); }); break; }
                        Err(error) => post(&weak, move |ui| { ui.set_busy(false); ui.set_update_busy(false); ui.set_update_text(format!("Не удалось подготовить установку: {error:#}").into()); }),
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
        .context("Не найдена папка True Proxy")?
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
