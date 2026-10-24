mod activity;
mod proxies;
mod routing;
mod updating;
use crate::{MainWindow, RuleRow, Tray};
use anyhow::{Context, Result, ensure};
use slint::{ComponentHandle, Model, ModelRc, VecModel};
use std::{
    cell::RefCell,
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
    },
    thread,
    time::Duration,
};
use true_proxy::{
    config::{Action, Config, DnsPolicy, PortRange, Protocol, Proxy, Rule},
    engine::{Engine, Statistics},
    platform,
};

enum Command {
    Start(Config),
    Stop,
    Probe(Proxy, Option<String>),
    CheckProxies(Vec<Proxy>),
    Failed(String),
    Processes,
    Autostart(Option<bool>),
    Quit,
}
type State = Rc<RefCell<Config>>;

fn model<T: Clone + 'static>(rows: Vec<T>) -> ModelRc<T> {
    Rc::new(VecModel::from(rows)).into()
}
fn id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!(
        "{:x}-{:x}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        std::process::id()
    )
}
fn route_name(config: &Config, action: &Action) -> String {
    match action {
        Action::Direct => "Напрямую".into(),
        Action::Block => "Блокировать".into(),
        Action::Proxy(id) => config
            .proxy(id)
            .map(|p| p.name.clone())
            .unwrap_or_else(|_| "Прокси отсутствует".into()),
    }
}
fn selected_proxy(config: &Config, index: i32) -> Result<String> {
    config
        .proxies
        .get(index.max(0) as usize)
        .map(|p| p.id.clone())
        .context("Сначала добавьте SOCKS5-подключение")
}
fn index_of(config: &Config, id: Option<&str>) -> i32 {
    config
        .proxies
        .iter()
        .position(|p| Some(p.id.as_str()) == id)
        .unwrap_or(0) as i32
}

fn refresh(ui: &MainWindow, config: &Config, statuses: &proxies::Statuses) {
    ui.set_proxy_names(model(
        config
            .proxies
            .iter()
            .map(|p| p.name.clone().into())
            .collect(),
    ));
    ui.set_proxies(model(
        config
            .proxies
            .iter()
            .map(|p| proxies::row(p, statuses))
            .collect(),
    ));
    ui.set_rules(model(
        config
            .rules
            .iter()
            .map(|r| {
                let processes = if r.process_names.is_empty() && r.process_paths.is_empty() {
                    "Все процессы".into()
                } else {
                    r.process_names
                        .iter()
                        .chain(&r.process_paths)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let protocol = match r.protocol {
                    Protocol::Both => "TCP + UDP",
                    Protocol::Tcp => "TCP",
                    Protocol::Udp => "UDP",
                };
                let mut conditions = vec![protocol.to_string()];
                if !r.domains.is_empty() || !r.domain_suffixes.is_empty() {
                    conditions.push("домены".into());
                }
                if !r.networks.is_empty() {
                    conditions.push("IP/CIDR".into());
                }
                if !r.ports.is_empty() {
                    conditions.push("порты".into());
                }
                RuleRow {
                    id: r.id.clone().into(),
                    name: r.name.clone().into(),
                    process: processes.into(),
                    conditions: conditions.join(" · ").into(),
                    route: route_name(config, &r.action).into(),
                    enabled: r.enabled,
                }
            })
            .collect(),
    ));
    ui.set_fallback_action(match config.default_action {
        Action::Direct => 0,
        Action::Block => 1,
        Action::Proxy(_) => 2,
    });
    ui.set_fallback_proxy(index_of(
        config,
        if let Action::Proxy(id) = &config.default_action {
            Some(id)
        } else {
            None
        },
    ));
}

fn persist(
    ui: &MainWindow,
    state: &State,
    path: &std::path::Path,
    _command: &SyncSender<Command>,
    statuses: &proxies::Statuses,
    mutate: impl FnOnce(&mut Config) -> Result<()>,
) -> Result<()> {
    ensure!(
        !ui.get_active() && !ui.get_busy(),
        "Приостановите маршрутизацию перед изменением настроек. После сохранения включите ее снова."
    );
    let mut next = state.borrow().clone();
    mutate(&mut next)?;
    next.save(path)?;
    *state.borrow_mut() = next.clone();
    refresh(ui, &next, statuses);
    ui.set_notice("".into());
    Ok(())
}

fn report(ui: &MainWindow, result: Result<()>) {
    if let Err(error) = result {
        ui.set_notice(format!("{error:#}").into());
    }
}

fn remember_routing(state: &State, path: &std::path::Path, enabled: bool) -> Result<()> {
    let mut next = state.borrow().clone();
    if next.routing_enabled != enabled {
        next.routing_enabled = enabled;
        next.save(path)
            .context("Не удалось запомнить состояние тумблера")?;
        *state.borrow_mut() = next;
    }
    Ok(())
}

fn should_start(config: &Config, paused: bool, enable: bool) -> bool {
    !paused && !config.proxies.is_empty() && (config.routing_enabled || enable)
}

fn icon(active: bool, _error: bool) -> slint::Image {
    let pixels = true_proxy::branding::rgba(64, Some(active));
    let buffer = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(&pixels, 64, 64);
    slint::Image::from_rgba8(buffer)
}
fn update_status(
    ui: slint::Weak<MainWindow>,
    tray: slint::Weak<Tray>,
    active: bool,
    busy: bool,
    message: String,
    error: bool,
) {
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = ui.upgrade() {
            ui.set_active(active);
            ui.set_busy(busy);
            ui.set_status(message.clone().into());
            if error {
                ui.set_notice(message.clone().into());
            }
            if !busy {
                ui.invoke_remember_routing(active);
            }
        }
        if let Some(tray) = tray.upgrade() {
            tray.set_active(active);
            tray.set_status(message.into());
            tray.set_tray_image(icon(active, error));
        }
    });
}

fn worker(
    rx: mpsc::Receiver<Command>,
    sender: SyncSender<Command>,
    ui: slint::Weak<MainWindow>,
    tray: slint::Weak<Tray>,
    stats: Arc<Statistics>,
    statuses: Arc<std::sync::Mutex<proxies::Statuses>>,
    preview: bool,
) {
    let mut engine: Option<Engine> = None;
    let sweeping = Arc::new(AtomicBool::new(false));
    while let Ok(command) = rx.recv() {
        match command {
            Command::Start(config) => {
                update_status(
                    ui.clone(),
                    tray.clone(),
                    false,
                    true,
                    "Запускаем сетевой слой…".into(),
                    false,
                );
                drop(engine.take());
                stats.routing_active(false);
                let sender = sender.clone();
                let failure = Arc::new(move |error| {
                    let _ = sender.try_send(Command::Failed(error));
                });
                let result = if preview {
                    Err(anyhow::anyhow!("В режиме проверки UI перехват отключен"))
                } else {
                    Engine::start(config, stats.clone(), failure)
                };
                match result {
                    Ok(running) => {
                        engine = Some(running);
                        stats.routing_active(true);
                        update_status(
                            ui.clone(),
                            tray.clone(),
                            true,
                            false,
                            "Маршрутизация работает. Приложение можно свернуть в трей.".into(),
                            false,
                        );
                    }
                    Err(error) => update_status(
                        ui.clone(),
                        tray.clone(),
                        false,
                        false,
                        format!("{error:#}"),
                        true,
                    ),
                }
            }
            Command::Stop => {
                drop(engine.take());
                stats.routing_active(false);
                update_status(
                    ui.clone(),
                    tray.clone(),
                    false,
                    false,
                    "Приостановлено".into(),
                    false,
                );
            }
            Command::Failed(error) => {
                drop(engine.take());
                stats.routing_active(false);
                update_status(ui.clone(), tray.clone(), false, false, error, true);
            }
            Command::Probe(proxy, token) => {
                let weak = ui.clone();
                let statuses = statuses.clone();
                let result = thread::Builder::new()
                    .name("proxy-probe".into())
                    .spawn(move || {
                        if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                        {
                            let health = rt.block_on(proxies::check(&proxy));
                            let list = token.is_none();
                            proxies::publish(weak.clone(), &statuses, proxy, health, token);
                            if list {
                                let _ = slint::invoke_from_event_loop(move || {
                                    if let Some(ui) = weak.upgrade() {
                                        ui.set_probe_busy(false);
                                    }
                                });
                            }
                        } else {
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Some(ui) = weak.upgrade() {
                                    ui.set_probe_busy(false);
                                    ui.set_notice("Не удалось запустить проверку прокси".into());
                                }
                            });
                        }
                    });
                if let Err(error) = result {
                    let weak = ui.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_probe_busy(false);
                            ui.set_notice(format!("Не удалось запустить проверку: {error}").into());
                        }
                    });
                }
            }
            Command::CheckProxies(profiles) => {
                if sweeping.swap(true, Ordering::AcqRel) {
                    continue;
                }
                statuses
                    .lock()
                    .unwrap()
                    .retain(|id, _| profiles.iter().any(|p| &p.id == id));
                let sweep = sweeping.clone();
                let weak = ui.clone();
                let statuses = statuses.clone();
                let result = thread::Builder::new()
                    .name("proxy-health".into())
                    .spawn(move || {
                        struct Reset(Arc<AtomicBool>);
                        impl Drop for Reset {
                            fn drop(&mut self) {
                                self.0.store(false, Ordering::Release);
                            }
                        }
                        let _reset = Reset(sweep);
                        if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                        {
                            rt.block_on(async move {
                                let mut tasks = tokio::task::JoinSet::new();
                                let mut remaining = profiles.into_iter();
                                loop {
                                    while tasks.len() < 4 {
                                        let Some(proxy) = remaining.next() else {
                                            break;
                                        };
                                        tasks.spawn(async move {
                                            let health = proxies::check(&proxy).await;
                                            (proxy, health)
                                        });
                                    }
                                    match tasks.join_next().await {
                                        Some(Ok((proxy, health))) => proxies::publish(
                                            weak.clone(),
                                            &statuses,
                                            proxy,
                                            health,
                                            None,
                                        ),
                                        Some(Err(_)) => {}
                                        None => break,
                                    }
                                }
                            });
                        }
                    });
                if result.is_err() {
                    sweeping.store(false, Ordering::Release);
                }
            }
            Command::Processes => {
                let result = platform::running_processes();
                let weak = ui.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_processes_busy(false);
                        match result {
                            Ok(processes) => routing::set_processes(&ui, processes),
                            Err(error) => ui.set_notice(format!("{error:#}").into()),
                        }
                    }
                });
            }
            Command::Autostart(requested) => {
                let weak = ui.clone();
                let result = thread::Builder::new()
                    .name("proxy-startup".into())
                    .spawn(move || {
                        let previous = platform::autostart_enabled();
                        let result = match previous.as_ref() {
                            Ok(_) => requested
                                .map_or_else(platform::autostart_enabled, platform::set_autostart),
                            Err(error) => Err(anyhow::anyhow!("{error:#}")),
                        };
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak.upgrade() {
                                ui.set_autostart_busy(false);
                                match result {
                                    Ok(enabled) => ui.set_autostart_enabled(enabled),
                                    Err(error) => {
                                        ui.set_autostart_enabled(previous.unwrap_or(false));
                                        ui.set_notice(
                                            format!("Не удалось настроить автозапуск: {error:#}")
                                                .into(),
                                        );
                                    }
                                }
                            }
                        });
                    });
                if let Err(error) = result {
                    let weak = ui.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_autostart_busy(false);
                            ui.set_notice(
                                format!("Не удалось запустить настройку автозапуска: {error}")
                                    .into(),
                            );
                        }
                    });
                }
            }
            Command::Quit => break,
        }
    }
    drop(engine);
    stats.routing_active(false);
}

pub fn run() -> Result<()> {
    let arguments = std::env::args().collect::<Vec<_>>();
    let preview = arguments
        .iter()
        .position(|a| a == "--smoke-ui" || a == "--benchmark-ui")
        .and_then(|i| arguments.get(i + 1))
        .map(PathBuf::from);
    #[cfg(windows)]
    if preview.is_none() && !platform::is_admin() {
        platform::relaunch_elevated()?;
        return Ok(());
    }
    #[cfg(windows)]
    if let Some(i) = arguments.iter().position(|a| a == "--wait-parent")
        && let Some(pid) = arguments.get(i + 1).and_then(|s| s.parse().ok())
    {
        platform::windows::wait_for_parent(pid)?;
    }
    let _instance = if preview.is_none() {
        Some(platform::SingleInstance::acquire()?)
    } else {
        None
    };
    let path = if let Some(dir) = &preview {
        std::fs::create_dir_all(dir)?;
        dir.join("config.json")
    } else {
        Config::path()?
    };
    let config = if preview.is_some() {
        Config::default()
    } else {
        Config::load(&path)?
    };
    let auto_start = preview.is_none()
        && should_start(
            &config,
            arguments.iter().any(|a| a == "--paused"),
            arguments.iter().any(|a| a == "--enable"),
        );
    let state = Rc::new(RefCell::new(config));
    if preview.is_none() && arguments.iter().any(|a| a == "--paused") {
        remember_routing(&state, &path, false)?;
    }
    let ui = MainWindow::new()?;
    let _updates = match updating::wire(&ui, path.with_file_name("updates.json"), preview.is_some())
    {
        Ok(controller) => controller,
        Err(error) => {
            ui.set_update_status(format!("Проверка обновлений недоступна: {error:#}").into());
            None
        }
    };
    let tray = Tray::new()?;
    tray.set_tray_image(icon(false, false));
    let initial_status = if state.borrow().proxies.is_empty() {
        "Настройте подключение"
    } else {
        "Приостановлено"
    };
    ui.set_status(initial_status.into());
    tray.set_status(initial_status.into());
    let statuses = Arc::new(std::sync::Mutex::new(proxies::Statuses::new()));
    refresh(&ui, &state.borrow(), &statuses.lock().unwrap());
    let stats = Arc::new(Statistics::default());
    let (sender, receiver) = mpsc::sync_channel(16);
    {
        let weak = ui.as_weak();
        let sender = sender.clone();
        let is_preview = preview.is_some();
        ui.on_set_autostart(move |enabled| {
            if let Some(ui) = weak.upgrade() {
                if is_preview {
                    ui.set_autostart_enabled(false);
                    ui.set_notice("В режиме проверки UI автозапуск Windows не изменяется.".into());
                    return;
                }
                if sender.try_send(Command::Autostart(Some(enabled))).is_ok() {
                    ui.set_autostart_busy(true);
                } else {
                    ui.set_autostart_enabled(!enabled);
                    ui.set_notice("Приложение занято. Повторите настройку автозапуска.".into());
                }
            }
        });
    }
    routing::wire(&ui, sender.clone());
    proxies::wire_form_probe(&ui, state.clone(), sender.clone(), preview.is_some());
    activity::wire(&ui, stats.clone());
    activity::render(&ui, &stats);
    {
        let weak = ui.as_weak();
        let state = state.clone();
        let path = path.clone();
        ui.on_remember_routing(move |enabled| {
            if let Some(ui) = weak.upgrade() {
                report(&ui, remember_routing(&state, &path, enabled));
            }
        });
    }
    let worker_ui = ui.as_weak();
    let worker_tray = tray.as_weak();
    let worker_stats = stats.clone();
    let worker_sender = sender.clone();
    let worker_statuses = statuses.clone();
    let is_preview = preview.is_some();
    let worker = thread::Builder::new()
        .name("proxy-control".into())
        .spawn(move || {
            worker(
                receiver,
                worker_sender,
                worker_ui,
                worker_tray,
                worker_stats,
                worker_statuses,
                is_preview,
            )
        })?;
    if preview.is_none() {
        ui.set_autostart_busy(true);
        sender.send(Command::Autostart(None))?;
    }

    let health_timer = slint::Timer::default();
    if preview.is_none() {
        let health_sender = sender.clone();
        let health_state = state.clone();
        let check = move || {
            let profiles = health_state.borrow().proxies.clone();
            if !profiles.is_empty() {
                let _ = health_sender.try_send(Command::CheckProxies(profiles));
            }
        };
        check();
        health_timer.start(slint::TimerMode::Repeated, Duration::from_secs(30), check);
    }

    // Only the visible window refreshes aggregated statistics; there is no UI polling in the tray.
    let stats_timer = Rc::new(slint::Timer::default());
    let restart_stats = {
        let weak = ui.as_weak();
        let stats = stats.clone();
        let timer = stats_timer.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_uptime(uptime(stats.uptime()).into());
            }
            let weak = weak.clone();
            let stats = stats.clone();
            timer.start(
                slint::TimerMode::Repeated,
                Duration::from_secs(1),
                move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_uptime(uptime(stats.uptime()).into());
                        ui.set_uploaded(bytes(stats.uploaded.load(Ordering::Relaxed)).into());
                        ui.set_downloaded(bytes(stats.downloaded.load(Ordering::Relaxed)).into());
                        ui.set_connection_count(
                            stats.connections.load(Ordering::Relaxed).to_string().into(),
                        );
                        ui.set_blocked_count(
                            stats.blocked.load(Ordering::Relaxed).to_string().into(),
                        );
                        if ui.get_page() == 3 {
                            activity::render(&ui, &stats);
                        }
                    }
                },
            );
        }
    };
    let restart_stats = Rc::new(restart_stats);
    restart_stats();
    {
        let timer = stats_timer.clone();
        ui.window().on_close_requested(move || {
            timer.stop();
            slint::CloseRequestResponse::HideWindow
        });
    }
    {
        let weak = ui.as_weak();
        let timer = stats_timer.clone();
        ui.on_hide_window(move || {
            timer.stop();
            if let Some(ui) = weak.upgrade() {
                let _ = ui.hide();
            }
        });
    }
    {
        let weak = ui.as_weak();
        let restart = restart_stats.clone();
        tray.on_open(move || {
            if let Some(ui) = weak.upgrade() {
                let _ = ui.show();
                restart();
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        let path = path.clone();
        let sender = sender.clone();
        let toggle = Rc::new(move || {
            if let Some(ui) = weak.upgrade() {
                if ui.get_busy() {
                    return;
                }
                if let Err(error) = remember_routing(&state, &path, !ui.get_active()) {
                    report(&ui, Err(error));
                    // Failure to write preferences must never prevent a manual pause.
                    if !ui.get_active() {
                        return;
                    }
                }
                let command = if ui.get_active() {
                    Command::Stop
                } else {
                    Command::Start(state.borrow().clone())
                };
                match sender.try_send(command) {
                    Ok(()) => ui.set_busy(true),
                    Err(_) => {
                        let _ = remember_routing(&state, &path, ui.get_active());
                        ui.set_notice("Сетевой слой занят. Повторите действие.".into());
                    }
                }
            }
        });
        let t = toggle.clone();
        ui.on_toggle(move || t());
        tray.on_toggle(move || toggle());
    }
    tray.on_exit(|| {
        let _ = slint::quit_event_loop();
    });
    {
        let weak = ui.as_weak();
        ui.on_close_dialog(move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_dialog(0);
                ui.set_form_probe_token("".into());
                ui.set_form_probe_status("".into());
                ui.set_form_probe_health(0);
                ui.set_form_password("".into());
                ui.set_notice("".into());
            }
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_add_proxy(move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_form_id("".into());
                ui.set_form_name("".into());
                ui.set_form_host("127.0.0.1".into());
                ui.set_form_port("1080".into());
                ui.set_form_auth(false);
                ui.set_form_username("".into());
                ui.set_form_probe_token("".into());
                ui.set_form_probe_status("".into());
                ui.set_form_probe_health(0);
                ui.set_form_password("".into());
                ui.set_notice("".into());
                ui.set_dialog(1);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_edit_proxy(move |id| {
            if let Some(ui) = weak.upgrade()
                && let Ok(p) = state.borrow().proxy(&id)
            {
                ui.set_form_id(p.id.clone().into());
                ui.set_form_name(p.name.clone().into());
                ui.set_form_host(p.host.clone().into());
                ui.set_form_port(p.port.to_string().into());
                ui.set_form_username(p.username.clone().into());
                ui.set_form_probe_token("".into());
                ui.set_form_probe_status("".into());
                ui.set_form_probe_health(0);
                ui.set_form_password("".into());
                ui.set_form_auth(!p.username.is_empty() || p.protected_password.is_some());
                ui.set_notice("".into());
                ui.set_dialog(1);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        let path = path.clone();
        let sender = sender.clone();
        let statuses = statuses.clone();
        ui.on_save_proxy(move || {
            if let Some(ui) = weak.upgrade() {
                let result = (|| {
                    let proxy = proxies::from_form(&ui, &state.borrow())?;
                    persist(
                        &ui,
                        &state,
                        &path,
                        &sender,
                        &statuses.lock().unwrap(),
                        |c| {
                            if let Some(old) = c.proxies.iter_mut().find(|p| p.id == proxy.id) {
                                *old = proxy;
                            } else {
                                c.proxies.push(proxy);
                            }
                            Ok(())
                        },
                    )?;
                    statuses
                        .lock()
                        .unwrap()
                        .remove(&ui.get_form_id().to_string());
                    ui.set_form_probe_token("".into());
                    ui.set_form_probe_status("".into());
                    ui.set_form_probe_health(0);
                    ui.set_form_password("".into());
                    ui.set_dialog(0);
                    ui.set_page(2);
                    Ok(())
                })();
                report(&ui, result);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        let path = path.clone();
        let sender = sender.clone();
        let statuses = statuses.clone();
        ui.on_delete_proxy(move |id| {
            if let Some(ui) = weak.upgrade() {
                report(
                    &ui,
                    persist(
                        &ui,
                        &state,
                        &path,
                        &sender,
                        &statuses.lock().unwrap(),
                        |c| c.remove_proxy(&id),
                    ),
                );
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        let sender = sender.clone();
        ui.on_probe_proxy(move |id| {
            if let Some(ui) = weak.upgrade() {
                let result = (|| {
                    ensure!(
                        !is_preview,
                        "В режиме проверки UI сетевые проверки отключены"
                    );
                    ensure!(!ui.get_probe_busy(), "Проверка уже выполняется");
                    let proxy = state.borrow().proxy(&id)?.clone();
                    sender
                        .try_send(Command::Probe(proxy, None))
                        .context("Проверка уже выполняется")?;
                    ui.set_probe_busy(true);
                    Ok(())
                })();
                report(&ui, result);
            }
        });
    }

    {
        let weak = ui.as_weak();
        ui.on_add_rule(move || {
            if let Some(ui) = weak.upgrade() {
                reset_rule(&ui);
                ui.set_dialog(2);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_edit_rule(move |id| {
            if let Some(ui) = weak.upgrade()
                && let Some(r) = state.borrow().rules.iter().find(|r| id == r.id)
            {
                reset_rule(&ui);
                ui.set_form_id(r.id.clone().into());
                ui.set_form_name(r.name.clone().into());
                ui.set_form_processes(routing::strings(r.process_names.clone()));
                ui.set_form_paths(routing::strings(r.process_paths.clone()));
                ui.set_form_show_paths(!r.process_paths.is_empty());
                let mut domains = r.domains.clone();
                domains.extend(r.domain_suffixes.iter().map(|d| format!("*.{d}")));
                let has_domains = !domains.is_empty();
                ui.set_form_domains(routing::strings(domains));
                ui.set_form_advanced(has_domains || !r.networks.is_empty() || !r.ports.is_empty());
                ui.set_form_networks(routing::strings(
                    r.networks.iter().map(ToString::to_string).collect(),
                ));
                ui.set_form_ports(routing::strings(
                    r.ports
                        .iter()
                        .map(|p| {
                            if p.start == p.end {
                                p.start.to_string()
                            } else {
                                format!("{}-{}", p.start, p.end)
                            }
                        })
                        .collect(),
                ));
                ui.set_form_protocol(match r.protocol {
                    Protocol::Both => 0,
                    Protocol::Tcp => 1,
                    Protocol::Udp => 2,
                });
                ui.set_form_action(match r.action {
                    Action::Proxy(_) => 0,
                    Action::Direct => 1,
                    Action::Block => 2,
                });
                ui.set_form_proxy(index_of(
                    &state.borrow(),
                    if let Action::Proxy(id) = &r.action {
                        Some(id)
                    } else {
                        None
                    },
                ));
                ui.set_form_enabled(r.enabled);
                ui.set_dialog(2);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        let path = path.clone();
        let sender = sender.clone();
        let statuses = statuses.clone();
        ui.on_save_rule(move || {
            if let Some(ui) = weak.upgrade() {
                let result = (|| {
                    routing::flush_drafts(&ui)?;
                    let config = state.borrow();
                    let action = match ui.get_form_action() {
                        0 => Action::Proxy(selected_proxy(&config, ui.get_form_proxy())?),
                        1 => Action::Direct,
                        _ => Action::Block,
                    };
                    drop(config);
                    let mut domains = Vec::new();
                    let mut suffixes = Vec::new();
                    for d in routing::values(ui.get_form_domains()) {
                        if let Some(s) = d.strip_prefix("*.") {
                            suffixes.push(s.to_ascii_lowercase());
                        } else {
                            domains.push(d.to_ascii_lowercase());
                        }
                    }
                    let rule = Rule {
                        id: if ui.get_form_id().is_empty() {
                            id()
                        } else {
                            ui.get_form_id().to_string()
                        },
                        name: ui.get_form_name().trim().into(),
                        enabled: ui.get_form_enabled(),
                        process_names: routing::values(ui.get_form_processes()),
                        process_paths: routing::values(ui.get_form_paths()),
                        domains,
                        domain_suffixes: suffixes,
                        networks: routing::values(ui.get_form_networks())
                            .iter()
                            .map(|n| {
                                n.parse()
                                    .with_context(|| format!("Некорректный IP/CIDR: {n}"))
                            })
                            .collect::<Result<_>>()?,
                        ports: routing::values(ui.get_form_ports())
                            .iter()
                            .map(|p| PortRange::parse(p))
                            .collect::<Result<_>>()?,
                        protocol: match ui.get_form_protocol() {
                            1 => Protocol::Tcp,
                            2 => Protocol::Udp,
                            _ => Protocol::Both,
                        },
                        action,
                        dns: DnsPolicy::Inherit,
                    };
                    persist(
                        &ui,
                        &state,
                        &path,
                        &sender,
                        &statuses.lock().unwrap(),
                        |c| {
                            if let Some(old) = c.rules.iter_mut().find(|r| r.id == rule.id) {
                                *old = rule;
                            } else {
                                c.rules.push(rule);
                            }
                            Ok(())
                        },
                    )?;
                    ui.set_dialog(0);
                    ui.set_page(1);
                    Ok(())
                })();
                report(&ui, result);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        let path = path.clone();
        let sender = sender.clone();
        let statuses = statuses.clone();
        ui.on_delete_rule(move |id| {
            if let Some(ui) = weak.upgrade() {
                report(
                    &ui,
                    persist(
                        &ui,
                        &state,
                        &path,
                        &sender,
                        &statuses.lock().unwrap(),
                        |c| {
                            c.rules.retain(|r| id != r.id);
                            Ok(())
                        },
                    ),
                );
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        let path = path.clone();
        let sender = sender.clone();
        let statuses = statuses.clone();
        ui.on_toggle_rule(move |id| {
            if let Some(ui) = weak.upgrade() {
                report(
                    &ui,
                    persist(
                        &ui,
                        &state,
                        &path,
                        &sender,
                        &statuses.lock().unwrap(),
                        |c| {
                            if let Some(r) = c.rules.iter_mut().find(|r| id == r.id) {
                                r.enabled = !r.enabled;
                            }
                            Ok(())
                        },
                    ),
                );
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        let path = path.clone();
        let sender = sender.clone();
        let statuses = statuses.clone();
        ui.on_move_rule(move |id, direction| {
            if let Some(ui) = weak.upgrade() {
                report(
                    &ui,
                    persist(
                        &ui,
                        &state,
                        &path,
                        &sender,
                        &statuses.lock().unwrap(),
                        |c| {
                            if let Some(index) = c.rules.iter().position(|r| id == r.id) {
                                let other = index as i32 + direction;
                                if other >= 0 && (other as usize) < c.rules.len() {
                                    c.rules.swap(index, other as usize);
                                }
                            }
                            Ok(())
                        },
                    ),
                );
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        let path = path.clone();
        let sender = sender.clone();
        let statuses = statuses.clone();
        ui.on_save_fallback(move || {
            if let Some(ui) = weak.upgrade() {
                report(
                    &ui,
                    persist(
                        &ui,
                        &state,
                        &path,
                        &sender,
                        &statuses.lock().unwrap(),
                        |c| {
                            c.default_action = match ui.get_fallback_action() {
                                1 => Action::Block,
                                2 => Action::Proxy(selected_proxy(c, ui.get_fallback_proxy())?),
                                _ => Action::Direct,
                            };
                            Ok(())
                        },
                    ),
                );
            }
        });
    }
    {
        let weak = ui.as_weak();
        let stats = stats.clone();
        ui.on_clear_logs(move || {
            stats.clear();
            if let Some(ui) = weak.upgrade() {
                activity::render(&ui, &stats);
            }
        });
    }

    if auto_start {
        ui.set_busy(true);
        sender.send(Command::Start(state.borrow().clone()))?;
    }
    if arguments.iter().any(|argument| argument == "--tray") && preview.is_none() {
        stats_timer.stop();
        ui.hide()?;
    } else {
        ui.show()?;
    }
    let preview_timer = slint::Timer::default();
    if let Some(dir) = preview {
        if arguments.iter().any(|a| a == "--benchmark-ui") {
            benchmark_ui(&ui, &preview_timer, dir);
        } else {
            smoke_ui(&ui, &tray, &preview_timer, dir, stats.clone());
        }
    }
    let result = slint::run_event_loop();
    stats_timer.stop();
    preview_timer.stop();
    health_timer.stop();
    let _ = sender.send(Command::Quit);
    let _ = worker.join();
    result.context("Ошибка цикла интерфейса")
}

fn reset_rule(ui: &MainWindow) {
    ui.set_form_manual(false);
    ui.set_form_new_process("".into());
    ui.set_form_new_path("".into());
    ui.set_form_new_domain("".into());
    ui.set_form_new_network("".into());
    ui.set_form_new_port("".into());
    ui.set_form_id("".into());
    ui.set_form_name("".into());
    ui.set_form_processes(routing::strings(vec![]));
    ui.set_form_paths(routing::strings(vec![]));
    ui.set_form_domains(routing::strings(vec![]));
    ui.set_form_networks(routing::strings(vec![]));
    ui.set_form_ports(routing::strings(vec![]));
    ui.set_form_advanced(false);
    ui.set_form_show_paths(false);
    ui.set_form_protocol(0);
    ui.set_form_action(0);
    ui.set_form_proxy(0);
    ui.set_form_enabled(true);
    ui.set_notice("".into());
}
fn uptime(duration: Duration) -> String {
    let seconds = duration.as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}
fn bytes(value: u64) -> String {
    let value = value as f64;
    if value < 1024.0 {
        format!("{value:.0} Б")
    } else if value < 1048576.0 {
        format!("{:.1} КБ", value / 1024.0)
    } else if value < 1073741824.0 {
        format!("{:.1} МБ", value / 1048576.0)
    } else {
        format!("{:.2} ГБ", value / 1073741824.0)
    }
}

fn smoke_ui(
    ui: &MainWindow,
    tray: &Tray,
    timer: &slint::Timer,
    dir: PathBuf,
    stats: Arc<Statistics>,
) {
    let weak = ui.as_weak();
    let weak_tray = tray.as_weak();
    let mut step = 0;
    let mut startup_waits = 0;
    timer.start(slint::TimerMode::Repeated, Duration::from_millis(400), move || {
        let Some(ui) = weak.upgrade() else { return; };
        // A slow disk/scheduler may delay the worker response beyond one frame.
        if step == 7 && ui.get_busy() && startup_waits < 25 { startup_waits += 1; return; }
        let result = (|| -> Result<()> {
            match step {
                0 => {
                    snapshot(&ui, &dir.join("01-overview.png"))?;
                    for (name, active) in [("logo.png", None), ("tray-on.png", Some(true)), ("tray-off.png", Some(false))] {
                        let file = std::fs::File::create(dir.join(name))?;
                        let mut encoder = png::Encoder::new(file, 128, 128);
                        encoder.set_color(png::ColorType::Rgba); encoder.set_depth(png::BitDepth::Eight);
                        encoder.write_header()?.write_image_data(&true_proxy::branding::rgba(128, active))?;
                    }
                    ui.invoke_add_proxy();
                }
                1 => {
                    snapshot(&ui, &dir.join("02-proxy-editor.png"))?;
                    ui.set_form_name("Локальный VPN".into()); ui.set_form_port("1080".into()); ui.invoke_save_proxy();
                    ensure!(ui.get_dialog() == 0, "Не сохраняется прокси: {}", ui.get_notice());
                }
                2 => {
                    snapshot(&ui, &dir.join("03-proxies.png"))?; ui.invoke_add_rule();
                    ui.set_form_name("Браузер через VPN".into()); ui.invoke_add_condition(0, "firefox.exe, chrome.exe".into()); ui.invoke_add_condition(4, "80, 443, 8000-9000".into());
                    ui.invoke_add_condition(2, "*.steamserver.net; *.deadorbit.net; *.gravityshavings.net; exact.example.com".into());
                }
                3 => {
                    snapshot(&ui, &dir.join("04-rule-editor.png"))?;
                    let logical_size = ui.window().size().to_logical(ui.window().scale_factor());
                    ui.window().dispatch_event(slint::platform::WindowEvent::PointerScrolled {
                        position: slint::LogicalPosition::new(logical_size.width / 2., logical_size.height / 2.), delta_x: 0., delta_y: -10000.,
                    });
                    snapshot(&ui, &dir.join("04b-rule-bottom.png"))?;
                    routing::set_processes(&ui, vec![platform::RunningProcess { name: "destiny2.exe".into(), path: "C:\\Games\\Destiny 2\\destiny2.exe".into(), pids: vec![100] }, platform::RunningProcess { name: "steam.exe".into(), path: "C:\\Apps\\Steam\\steam.exe".into(), pids: vec![101, 102] }]);
                    ui.set_process_picker(true); snapshot(&ui, &dir.join("04a-process-picker.png"))?; ui.set_process_picker(false);
                    ui.set_form_manual(false);
                    ui.set_form_new_process("steam.exe".into()); ui.set_form_advanced(false); ui.invoke_save_rule(); ensure!(ui.get_dialog() == 0, "Не сохраняется правило: {}", ui.get_notice());
                }
                4 => { snapshot(&ui, &dir.join("05-rules.png"))?; ui.set_page(4); }
                5 => { snapshot(&ui, &dir.join("06-settings.png"))?; ui.invoke_save_fallback(); ui.set_page(3); }
                6 => {
                    stats.log("firefox.exe", "203.0.113.1:443", "Локальный VPN", "TCP · Браузер через VPN · example.com");
                    stats.log("firefox.exe", "203.0.113.2:443", "Локальный VPN", "UDP · Браузер через VPN · имя DNS неизвестно");
                    stats.log("steam.exe", "203.0.113.3:443", "Напрямую", "TCP · по умолчанию");
                    activity::render(&ui, &stats);
                    ui.set_connection_process(ui.get_connection_processes().iter().position(|name| name == "firefox.exe").unwrap() as i32); ui.invoke_filter_connections(); ensure!(ui.get_filtered_event_count() == 2, "Не работает фильтр процесса");
                    ui.set_connection_query("203.0.113.2".into()); ui.invoke_filter_connections(); ensure!(ui.get_filtered_event_count() == 1, "Не работает поиск соединений");
                    ui.set_connection_query("".into()); ui.set_connection_process(0); ui.invoke_filter_connections();
                    ui.invoke_expand_process("firefox.exe".into());
                    ui.set_notice("Проверка UI: тестовые события, перехват отключён".into());
                    snapshot(&ui, &dir.join("07-connections.png"))?;
                    let config = Config::load(&dir.join("config.json"))?;
                    ensure!(config.proxies.len() == 1 && config.rules.len() == 1, "Не пройдена проверка сохранения UI");
                    ensure!(config.rules[0].process_names.iter().any(|name| name == "steam.exe"), "Не сохранён незавершённый ввод списка");
                    ensure!(config.rules[0].domains == ["exact.example.com"] && config.rules[0].domain_suffixes.len() == 3, "Неверная семантика явных доменных масок");
                    ui.invoke_toggle();
                }
                7 => {
                    ensure!(!ui.get_active() && !ui.get_busy(), "UI не отобразил отказ запуска: active={}, busy={}, notice={}",ui.get_active(),ui.get_busy(),ui.get_notice());
                    ensure!(ui.get_notice().contains("перехват отключен"), "Нет сообщения об отказе запуска");
                    ensure!(!Config::load(&dir.join("config.json"))?.routing_enabled, "Отказ запуска должен сохранить выключенное состояние");
                    snapshot(&ui, &dir.join("08-engine-error.png"))?; ui.invoke_hide_window();
                }
                8 => { weak_tray.upgrade().context("Значок трея исчез")?.invoke_open(); ui.set_notice("".into()); ui.set_page(0); }
                9 => {
                    snapshot(&ui, &dir.join("09-restored-from-tray.png"))?;
                    ui.set_notice("Проверка UI: пример уведомления об обновлении; запросы к GitHub и установка отключены.".into());
                    ui.set_update_available(true); ui.set_update_version("0.3.0".into()); ui.set_update_text("Новая версия готова к загрузке.".into());
                    snapshot(&ui, &dir.join("10-update-available.png"))?;
                    ui.set_update_ready(true); ui.set_update_text("Обновление загружено. Для установки приостановите маршрутизацию.".into());
                    ui.set_page(4); snapshot(&ui, &dir.join("11-update-ready.png"))?;
                    std::fs::write(dir.join("result.txt"), "PASS: proxy/rule editors, settings, persistence, startup failure and tray hide/restore; interception was disabled.")?;
                    slint::quit_event_loop()?;
                }
                _ => {}
            }
            Ok(())
        })();
        if let Err(error) = result { let _ = std::fs::write(dir.join("result.txt"), format!("FAIL: {error:#}")); let _ = slint::quit_event_loop(); }
        step += 1;
    });
}

fn snapshot(ui: &MainWindow, path: &std::path::Path) -> Result<()> {
    let pixels = ui.window().take_snapshot()?;
    let file = std::fs::File::create(path)?;
    let mut encoder = png::Encoder::new(file, pixels.width(), pixels.height());
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()?
        .write_image_data(pixels.as_bytes())?;
    Ok(())
}

/// An isolated UI/tray benchmark. It never loads the user's config or opens the driver.
fn benchmark_ui(ui: &MainWindow, timer: &slint::Timer, dir: PathBuf) {
    let weak = ui.as_weak();
    let mut second = 0;
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_secs(1),
        move || {
            if let Some(ui) = weak.upgrade() {
                match second {
                    0 => {
                        let _ = std::fs::write(dir.join("phase.txt"), "visible");
                    }
                    4 => {
                        ui.invoke_hide_window();
                        let _ = std::fs::write(dir.join("phase.txt"), "tray");
                    }
                    12 => {
                        let _ = std::fs::write(dir.join("phase.txt"), "finished");
                        let _ = slint::quit_event_loop();
                    }
                    _ => {}
                }
            }
            second += 1;
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pause_and_enable_survive_restart_without_opening_the_network() {
        let dir = std::env::temp_dir().join(format!("true-proxy-switch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let mut config = Config::default();
        config.proxies.push(Proxy {
            id: "vpn".into(),
            name: "VPN".into(),
            host: "127.0.0.1".into(),
            port: 1080,
            username: String::new(),
            protected_password: None,
        });
        let state = Rc::new(RefCell::new(config));
        remember_routing(&state, &path, false).unwrap();
        let paused = Config::load(&path).unwrap();
        assert!(!should_start(&paused, false, false));
        // Saving unrelated settings must not flip the remembered pause.
        paused.save(&path).unwrap();
        assert!(!should_start(&Config::load(&path).unwrap(), false, false));
        remember_routing(&state, &path, true).unwrap();
        let enabled = Config::load(&path).unwrap();
        assert!(should_start(&enabled, false, false));
        assert!(!should_start(&enabled, true, false));
        assert!(
            !should_start(&enabled, true, true),
            "--paused wins over --enable"
        );
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
