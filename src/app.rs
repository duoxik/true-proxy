mod activity;
mod appearance;
mod fallback;
mod json_highlight;
mod pending;
mod proxies;
mod routing;
mod transfer;
mod updating;
#[cfg(not(windows))]
use crate::Tray;
use crate::{ConnectionsWindow, MainWindow, RuleRow};
use anyhow::{Context, Result, ensure};
use slint::{ComponentHandle, Model, ModelRc, VecModel, winit_030::WinitWindowAccessor};
use std::{
    cell::RefCell,
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc,
        atomic::Ordering,
        mpsc::{self, SyncSender},
    },
    thread,
    time::Duration,
};
#[cfg(windows)]
use true_proxy::platform::windows::tray::Tray;
use true_proxy::{
    config::{Action, Config, DnsPolicy, PortRange, Protocol, Proxy, Rule},
    engine::{Engine, Statistics},
    platform,
};

enum Command {
    Start(Config),
    Stop,
    Probe(Proxy, Option<String>),
    Failed { generation: u64, error: String },
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
    ui.set_local_networks(true_proxy::local_network::NETWORKS.join(", ").into());
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
            .map(|r| RuleRow {
                id: r.id.clone().into(),
                name: r.name.clone().into(),
                route: route_name(config, &r.action).into(),
                enabled: r.enabled,
            })
            .collect(),
    ));
    ui.set_fallback_label(fallback::label(config).into());
}

fn report(ui: &MainWindow, result: Result<()>) {
    if let Err(error) = result {
        ui.set_notice(format!("{error:#}").into());
    }
}

fn clear_toast(ui: &MainWindow) {
    ui.set_toast_token(id().into());
    ui.set_toast("".into());
}

fn show_toast(ui: &MainWindow, message: String, error: bool) {
    let token = id();
    ui.set_toast_token(token.clone().into());
    ui.set_toast_error(error);
    ui.set_toast(message.into());
    let weak = ui.as_weak();
    slint::Timer::single_shot(Duration::from_secs(5), move || {
        if let Some(ui) = weak.upgrade()
            && ui.get_toast_token() == token
        {
            ui.set_toast("".into());
        }
    });
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

#[cfg(not(windows))]
fn icon(active: bool, _error: bool) -> slint::Image {
    let pixels = true_proxy::branding::rgba(64, Some(active));
    let buffer = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(&pixels, 64, 64);
    slint::Image::from_rgba8(buffer)
}
fn sync_tray(tray: &Tray, active: bool, status: &str) {
    #[cfg(windows)]
    tray.update(active, status);
    #[cfg(not(windows))]
    {
        tray.set_active(active);
        tray.set_status(status.into());
        tray.set_tray_image(icon(active, false));
    }
}

fn focus_window(ui: &impl ComponentHandle) {
    ui.window()
        .with_winit_window(|window| window.focus_window());
}

fn show_panel(ui: &MainWindow, tray: &Tray) -> Result<()> {
    #[cfg(windows)]
    if let Some(bounds) = tray.popup_geometry(420, 720) {
        ui.window()
            .set_position(slint::PhysicalPosition::new(bounds.x, bounds.y));
        ui.window()
            .set_size(slint::PhysicalSize::new(bounds.width, bounds.height));
    }
    #[cfg(not(windows))]
    let _ = tray;
    ui.window().set_minimized(false);
    ui.show()?;
    #[cfg(windows)]
    ui.window().with_winit_window(|window| {
        use slint::winit_030::winit::platform::windows::{CornerPreference, WindowExtWindows};
        window.set_corner_preference(CornerPreference::Round);
        window.set_skip_taskbar(true);
    });
    focus_window(ui);
    appearance::refresh(ui);
    Ok(())
}

/// The connection journal belongs to its own window, independent of the panel.
fn wire_connection_window(
    main: &MainWindow,
    view: &ConnectionsWindow,
    statistics: Arc<Statistics>,
) -> Rc<slint::Timer> {
    activity::wire(view, statistics.clone());
    appearance::wire_connections(view);
    let timer = Rc::new(slint::Timer::default());
    let resume = {
        let main = main.as_weak();
        let weak = view.as_weak();
        let statistics = statistics.clone();
        let timer = timer.clone();
        Rc::new(move || {
            let Some(view) = weak.upgrade() else {
                return;
            };
            if !view.window().is_visible() || view.window().is_minimized() {
                activity::suspend_tracking(&view, &statistics);
                return;
            }
            if let Some(main) = main.upgrade() {
                activity::refresh_proxy_sources(&view, &main);
            }
            activity::render(&view, &statistics);
            let main = main.clone();
            let weak = weak.clone();
            let statistics = statistics.clone();
            let weak_timer = Rc::downgrade(&timer);
            timer.start(
                slint::TimerMode::Repeated,
                Duration::from_secs(1),
                move || {
                    let Some(view) = weak.upgrade() else {
                        return;
                    };
                    if !view.window().is_visible() || view.window().is_minimized() {
                        activity::suspend_tracking(&view, &statistics);
                        if let Some(timer) = weak_timer.upgrade() {
                            timer.stop();
                        }
                        return;
                    }
                    if let Some(main) = main.upgrade() {
                        activity::refresh_proxy_sources(&view, &main);
                    }
                    activity::render(&view, &statistics);
                },
            );
        })
    };
    {
        let resume = resume.clone();
        view.on_resume_observation(move || resume());
    }
    {
        let weak = view.as_weak();
        let timer = timer.clone();
        let statistics = statistics.clone();
        view.window().on_close_requested(move || {
            timer.stop();
            if let Some(view) = weak.upgrade() {
                activity::suspend_tracking(&view, &statistics);
            }
            slint::CloseRequestResponse::HideWindow
        });
    }
    {
        let weak = view.as_weak();
        let timer = timer.clone();
        let statistics = statistics.clone();
        view.on_hide_window(move || {
            timer.stop();
            if let Some(view) = weak.upgrade() {
                let _ = view.hide();
                activity::suspend_tracking(&view, &statistics);
            }
        });
    }
    {
        let weak = view.as_weak();
        let main_weak = main.as_weak();
        main.on_open_connections(move || {
            if let Some(view) = weak.upgrade() {
                view.window().set_minimized(false);
                if view.show().is_ok() {
                    view.window().with_winit_window(|window| {
                        window.set_theme(Some(slint::winit_030::winit::window::Theme::Dark));
                    });
                    focus_window(&view);
                    view.invoke_resume_observation();
                    if let Some(main) = main_weak.upgrade() {
                        main.invoke_hide_window();
                    }
                }
            }
        });
    }
    timer
}
fn update_status(
    ui: slint::Weak<MainWindow>,
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
            pending::on_status(&ui, busy);
            ui.invoke_sync_tray(active, message.clone().into());
            if error {
                ui.set_notice(message.clone().into());
            }
            if !busy {
                ui.invoke_remember_routing(active);
            }
        }
    });
}

fn worker(
    rx: mpsc::Receiver<Command>,
    sender: SyncSender<Command>,
    ui: slint::Weak<MainWindow>,
    stats: Arc<Statistics>,
    statuses: Arc<std::sync::Mutex<proxies::Statuses>>,
    preview: bool,
) {
    let mut engine: Option<Engine> = None;
    let mut generation = 0_u64;
    while let Ok(command) = rx.recv() {
        match command {
            Command::Start(config) => {
                generation = generation.wrapping_add(1);
                update_status(
                    ui.clone(),
                    false,
                    true,
                    "Запускаем сетевой слой…".into(),
                    false,
                );
                drop(engine.take());
                stats.routing_active(false);
                let sender = sender.clone();
                let started_generation = generation;
                let failure = Arc::new(move |error| {
                    let _ = sender.try_send(Command::Failed {
                        generation: started_generation,
                        error,
                    });
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
                            true,
                            false,
                            "Маршрутизация работает. Приложение можно свернуть в трей.".into(),
                            false,
                        );
                    }
                    Err(error) => {
                        update_status(ui.clone(), false, false, format!("{error:#}"), true)
                    }
                }
            }
            Command::Stop => {
                generation = generation.wrapping_add(1);
                drop(engine.take());
                stats.routing_active(false);
                update_status(ui.clone(), false, false, "Приостановлено".into(), false);
            }
            Command::Failed {
                generation: failed_generation,
                error,
            } => {
                if failed_generation != generation {
                    continue;
                }
                drop(engine.take());
                stats.routing_active(false);
                update_status(ui.clone(), false, false, error, true);
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
    if preview.is_none() && platform::windows::tray::activate_existing() {
        return Ok(());
    }
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
        let Some(instance) = platform::SingleInstance::acquire()? else {
            return Ok(());
        };
        Some(instance)
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
    let connections = ConnectionsWindow::new()?;
    appearance::wire(&ui, &connections, preview.is_some());
    let _updates = match updating::wire(&ui, path.with_file_name("updates.json"), preview.is_some())
    {
        Ok(controller) => controller,
        Err(error) => {
            ui.set_update_status(format!("Проверка обновлений недоступна: {error:#}").into());
            None
        }
    };
    #[cfg(windows)]
    let tray = Rc::new(Tray::new(preview.is_some())?);
    #[cfg(not(windows))]
    let tray = Rc::new(Tray::new()?);
    let initial_status = if state.borrow().proxies.is_empty() {
        "Настройте подключение"
    } else {
        "Приостановлено"
    };
    ui.set_status(initial_status.into());
    sync_tray(&tray, false, initial_status);
    {
        let tray = tray.clone();
        ui.on_sync_tray(move |active, status| sync_tray(&tray, active, &status));
    }
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
    pending::wire(&ui, state.clone(), sender.clone());
    transfer::wire(
        &ui,
        state.clone(),
        path.clone(),
        statuses.clone(),
        preview.is_some(),
    );
    proxies::wire_form_probe(&ui, state.clone(), sender.clone(), preview.is_some());
    let connections_timer = wire_connection_window(&ui, &connections, stats.clone());
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
                worker_stats,
                worker_statuses,
                is_preview,
            )
        })?;
    if preview.is_none() {
        ui.set_autostart_busy(true);
        sender.send(Command::Autostart(None))?;
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
                        if !ui.window().is_visible() || ui.window().is_minimized() {
                            return;
                        }
                        ui.set_uptime(uptime(stats.uptime()).into());
                        ui.set_uploaded(bytes(stats.uploaded.load(Ordering::Relaxed)).into());
                        ui.set_downloaded(bytes(stats.downloaded.load(Ordering::Relaxed)).into());
                        ui.set_connection_count(
                            stats.connections.load(Ordering::Relaxed).to_string().into(),
                        );
                        ui.set_blocked_count(
                            stats.blocked.load(Ordering::Relaxed).to_string().into(),
                        );
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
        let placement_tray = tray.clone();
        tray.on_open(move || {
            if let Some(ui) = weak.upgrade() {
                let _ = show_panel(&ui, &placement_tray);
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
        let statuses = statuses.clone();
        ui.on_save_proxy(move || {
            if let Some(ui) = weak.upgrade() {
                let result = (|| {
                    let proxy = proxies::from_form(&ui, &state.borrow())?;
                    pending::persist(&ui, &state, &path, &statuses.lock().unwrap(), |c| {
                        if let Some(old) = c.proxies.iter_mut().find(|p| p.id == proxy.id) {
                            *old = proxy;
                        } else {
                            c.proxies.push(proxy);
                        }
                        Ok(())
                    })?;
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
        let statuses = statuses.clone();
        ui.on_delete_proxy(move |id| {
            if let Some(ui) = weak.upgrade() {
                report(
                    &ui,
                    pending::persist(&ui, &state, &path, &statuses.lock().unwrap(), |c| {
                        c.remove_proxy(&id)
                    }),
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
                    pending::persist(&ui, &state, &path, &statuses.lock().unwrap(), |c| {
                        if let Some(old) = c.rules.iter_mut().find(|r| r.id == rule.id) {
                            *old = rule;
                        } else {
                            c.rules.push(rule);
                        }
                        Ok(())
                    })?;
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
        let statuses = statuses.clone();
        ui.on_delete_rule(move |id| {
            if let Some(ui) = weak.upgrade() {
                report(
                    &ui,
                    pending::persist(&ui, &state, &path, &statuses.lock().unwrap(), |c| {
                        c.rules.retain(|r| id != r.id);
                        Ok(())
                    }),
                );
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        let path = path.clone();
        let statuses = statuses.clone();
        ui.on_toggle_rule(move |id| {
            if let Some(ui) = weak.upgrade() {
                report(
                    &ui,
                    pending::persist(&ui, &state, &path, &statuses.lock().unwrap(), |c| {
                        if let Some(r) = c.rules.iter_mut().find(|r| id == r.id) {
                            r.enabled = !r.enabled;
                        }
                        Ok(())
                    }),
                );
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        let path = path.clone();
        let statuses = statuses.clone();
        ui.on_move_rule(move |id, direction| {
            if let Some(ui) = weak.upgrade() {
                report(
                    &ui,
                    pending::persist(&ui, &state, &path, &statuses.lock().unwrap(), |c| {
                        if let Some(index) = c.rules.iter().position(|r| id == r.id) {
                            let other = index as i32 + direction;
                            if other >= 0 && (other as usize) < c.rules.len() {
                                c.rules.swap(index, other as usize);
                            }
                        }
                        Ok(())
                    }),
                );
            }
        });
    }
    fallback::wire(&ui, state.clone(), path.clone(), statuses.clone());

    if auto_start {
        ui.set_busy(true);
        sender.send(Command::Start(state.borrow().clone()))?;
    }
    if arguments.iter().any(|argument| argument == "--tray") {
        stats_timer.stop();
        ui.hide()?;
    } else {
        show_panel(&ui, &tray)?;
    }
    let preview_timer = slint::Timer::default();
    if let Some(dir) = preview {
        if arguments.iter().any(|a| a == "--benchmark-ui") {
            benchmark_ui(&ui, &preview_timer, dir);
        } else {
            smoke_ui(&ui, &connections, &tray, &preview_timer, dir, stats.clone());
        }
    }
    let result = slint::run_event_loop_until_quit();
    stats.activity.set_tracking(false);
    stats_timer.stop();
    connections_timer.stop();
    preview_timer.stop();
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
    connections: &ConnectionsWindow,
    tray: &Rc<Tray>,
    timer: &slint::Timer,
    dir: PathBuf,
    stats: Arc<Statistics>,
) {
    let weak = ui.as_weak();
    let weak_connections = connections.as_weak();
    let weak_tray = Rc::downgrade(tray);
    let mut step = 0;
    let mut fixture_records = Vec::new();
    let mut startup_waits = 0;
    let mut tray_waits = 0;
    #[cfg(windows)]
    let mut surface_probe = None;
    timer.start(slint::TimerMode::Repeated, Duration::from_millis(400), move || {
        let Some(ui) = weak.upgrade() else { return; };
        #[cfg(windows)]
        let tray_available = weak_tray.upgrade().is_some_and(|tray| tray.registered());
        #[cfg(not(windows))]
        let tray_available = true;
        if step == 0 && (!ui.window().is_visible() || !tray_available) && tray_waits < 25 {
            tray_waits += 1;
            if !ui.window().is_visible() && let Some(tray) = weak_tray.upgrade() { tray.invoke_open(); }
            return;
        }
        // A slow disk/scheduler may delay the worker response beyond one frame.
        if step == 7 && ui.get_busy() && startup_waits < 25 { startup_waits += 1; return; }
        let result = (|| -> Result<()> {
            match step {
                0 => {
                    ensure!(ui.window().is_visible(), "Трей не открыл скрытое окно");
                    #[cfg(windows)]
                    ensure!(weak_tray.upgrade().is_some_and(|tray| tray.registered()), "Значок не зарегистрирован в Windows");
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
                    snapshot(&ui, &dir.join("03b-empty-rule-editor.png"))?;
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
                4 => {
                    snapshot(&ui, &dir.join("05-rules.png"))?;
                    // Explicit preview fixture: no backend is running in this mode.
                    ui.set_notice("Проверка UI: перехват отключён".into());
                    ui.set_active(true);
                    ui.invoke_edit_rule(ui.get_rules().row_data(0).unwrap().id);
                    ui.set_form_name("Браузер через VPN · изменено".into());
                    ui.invoke_save_rule();
                    ensure!(ui.get_dialog() == 0 && ui.get_restart_prompt() && ui.get_routing_pending(), "Нет предложения применить сохранённые правила");
                    ui.set_notice("Проверка UI: перехват отключён".into());
                    snapshot(&ui, &dir.join("05a-restart-prompt.png"))?;
                    ui.set_restart_prompt(false);
                    snapshot(&ui, &dir.join("05b-pending-rules.png"))?;
                    ui.set_active(false);
                    pending::on_status(&ui, false);
                    ui.set_notice("".into());
                    ui.set_page(4);
                }
                5 => {
                    snapshot(&ui, &dir.join("06-settings.png"))?;
                    ui.invoke_open_import();
                    let config=Config::load(&dir.join("config.json"))?;
                    ui.set_import_json(true_proxy::profile::Profile::export(&config)?.into());
                    ui.invoke_format_import();
                    ensure!(ui.get_import_valid(), "Импорт отклонил экспортированную конфигурацию: {}", ui.get_import_error());
                    snapshot(&ui,&dir.join("06a-json-import.png"))?;
                    ui.set_import_json("{\n  \"proxies\": [\n}".into());ui.invoke_format_import();
                    ensure!(!ui.get_import_valid() && !ui.get_import_error().is_empty(), "Нет ошибки некорректного JSON");
                    snapshot(&ui,&dir.join("06b-json-error.png"))?;
                    ui.invoke_cancel_import();
                    ui.invoke_select_fallback(0, "".into()); ui.invoke_open_connections();
                }
                6 => {
                    let view = weak_connections.upgrade().context("Окно соединений исчезло")?;
                    activity::sync_tracking(&view, &stats);
                        let fixture_proxy = ui.get_proxies().row_data(0).context("Нет тестового прокси")?.id.to_string();
                    for (index,(process,destination,protocol)) in [("firefox.exe","203.0.113.1:443",Protocol::Tcp),("firefox.exe","203.0.113.2:443",Protocol::Udp),("steam.exe","203.0.113.3:443",Protocol::Tcp)].into_iter().enumerate() {
                        if let Some(record)=stats.activity.start(true_proxy::connections::Info {pid:100,process:process.into(),source:format!("192.0.2.1:{}",5000+index).parse()?,destination:destination.parse()?,protocol,route:"Локальный VPN".into(),detail:"Тестовое соединение".into(),action:Action::Proxy(fixture_proxy.clone()),stamp:0},true_proxy::connections::Status::Active) {fixture_records.push(record);}
                    }
                    activity::render(&view, &stats);
                    view.set_connection_query("FIREFOX".into()); view.invoke_filter_connections(); ensure!(view.get_filtered_event_count() == 2, "Не работает поиск процесса");
                    view.set_connection_query("steam".into()); view.invoke_filter_connections(); ensure!(view.get_filtered_event_count() == 1, "Не работает поиск процесса по подстроке");
                    view.set_connection_query("".into()); view.invoke_filter_connections();
                    view.invoke_expand_process("firefox.exe".into());
                    ui.set_notice("Проверка UI: тестовые события, перехват отключён".into());
                    snapshot(&view, &dir.join("07-connections.png"))?;
                    view.set_only_active(false);view.invoke_set_only_active(false);
                    fixture_records[0].finish(true_proxy::connections::Status::Closed,"Тестовое завершение");
                    fixture_records[1].finish(true_proxy::connections::Status::Failed,"Тестовый отказ SOCKS");
                    activity::render(&view,&stats);snapshot(&view,&dir.join("07b-history.png"))?;
                    view.set_only_active(true);view.invoke_set_only_active(true);ensure!(view.get_filtered_event_count()==1,"Завершённые соединения не очищены");
                    view.set_only_active(false);view.invoke_set_only_active(false);ensure!(view.get_filtered_event_count()==1,"Старая история вернулась");
                    view.set_only_active(true);view.invoke_set_only_active(true);
                    let config = Config::load(&dir.join("config.json"))?;
                    ensure!(config.proxies.len() == 1 && config.rules.len() == 1, "Не пройдена проверка сохранения UI");
                    ensure!(config.rules[0].process_names.iter().any(|name| name == "steam.exe"), "Не сохранён незавершённый ввод списка");
                    ensure!(config.rules[0].domains == ["exact.example.com"] && config.rules[0].domain_suffixes.len() == 3, "Неверная семантика явных доменных масок");
                    view.invoke_hide_window();
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
                    #[cfg(windows)] { surface_probe = Some(appearance::mark_surface(&ui)?); }
                    ui.window().set_minimized(true);
                }
                10 => {ui.window().set_minimized(false);}
                11 => {
                    #[cfg(windows)] appearance::verify_surface(&ui, surface_probe.as_ref().context("Нет меток перерисовки")?)?;
                    ui.set_notice("Проверка UI: пример уведомления об обновлении; запросы к GitHub и установка отключены.".into());
                    ui.set_update_available(true); ui.set_update_version(true_proxy::updates::VERSION.into()); ui.set_update_text("Новая версия готова к загрузке.".into());
                    snapshot(&ui, &dir.join("10-update-available.png"))?;
                    ui.set_update_ready(true); ui.set_update_text("Обновление загружено. Для установки приостановите маршрутизацию.".into());
                    ui.set_page(4); snapshot(&ui, &dir.join("11-update-ready.png"))?;
                    std::fs::write(dir.join("result.txt"), "PASS: editors, persistence, connection history, startup failure, tray restore and native minimize repaint; interception was disabled.")?;
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

fn snapshot(ui: &impl ComponentHandle, path: &std::path::Path) -> Result<()> {
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
    fn opening_connections_hides_only_the_panel_and_close_stops_its_journal() {
        i_slint_backend_testing::init_no_event_loop();
        let main = MainWindow::new().unwrap();
        let view = ConnectionsWindow::new().unwrap();
        let statistics = Arc::new(Statistics::default());
        let timer = wire_connection_window(&main, &view, statistics.clone());
        let weak = main.as_weak();
        main.on_hide_window(move || {
            weak.unwrap().hide().unwrap();
        });
        main.show().unwrap();
        assert!(!statistics.activity.tracking());
        main.invoke_open_connections();
        assert!(!main.window().is_visible());
        assert!(view.window().is_visible() && statistics.activity.tracking());
        assert!(timer.running());
        let record = statistics
            .activity
            .start(
                true_proxy::connections::Info {
                    pid: 10,
                    process: "game.exe".into(),
                    source: "192.0.2.1:5000".parse().unwrap(),
                    destination: "203.0.113.1:443".parse().unwrap(),
                    protocol: Protocol::Tcp,
                    route: "Direct".into(),
                    detail: String::new(),
                    action: Action::Direct,
                    stamp: 0,
                },
                true_proxy::connections::Status::Active,
            )
            .unwrap();
        assert_eq!(statistics.activity.snapshots().len(), 1);
        view.invoke_hide_window();
        assert!(!view.window().is_visible() && !statistics.activity.tracking());
        assert!(!timer.running() && statistics.activity.snapshots().is_empty());
        assert_eq!(record.status(), true_proxy::connections::Status::Stopped);
        main.show().unwrap();
        main.invoke_open_connections();
        assert!(statistics.activity.tracking() && statistics.activity.snapshots().is_empty());
        view.window()
            .dispatch_event(slint::platform::WindowEvent::CloseRequested);
        assert!(!statistics.activity.tracking() && !timer.running());
    }

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
