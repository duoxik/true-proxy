use super::{model, uptime};
use crate::{MainWindow, XrayConnectionRow, XrayHostRow, XrayModule, XrayProfileRow};
use anyhow::{Context, Result, ensure};
use slint::ComponentHandle;
use std::{
    cell::{OnceCell, RefCell},
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};
use true_proxy::xray::{
    assets::{self, Installed, Release},
    profile::{self, Settings},
    runtime::{self, Activity, Bypass, Runtime},
};

enum Command {
    Install,
    CheckUpdates,
    InstallUpdate,
    Toggle,
    Import(String),
    RefreshSubscription(String),
    Activate(String),
    Remove(String),
    Port(String),
    Dns(String),
    PinHost,
    RemoveHost(String),
    Geo {
        ips: String,
        domains: String,
        geoip: String,
        geosite: String,
        hours: String,
    },
    RefreshGeo,
    Record(bool),
}

struct Controller {
    directory: PathBuf,
    settings_path: PathBuf,
    settings: Settings,
    installed: Option<Installed>,
    latest: Option<Release>,
    runtime: Option<Runtime>,
    runtime_geo: Option<PathBuf>,
    bypass: Arc<Bypass>,
    activity: Arc<Activity>,
    pending: bool,
    status: String,
    geo_status: String,
    last_geo_attempt: u64,
}

impl Controller {
    fn load(directory: PathBuf, bypass: Arc<Bypass>, activity: Arc<Activity>) -> Result<Self> {
        let settings_path = directory.join("settings.json");
        let settings = Settings::load(&settings_path)?;
        activity.set_recording(settings.log_recording);
        let installed = assets::installed(&directory)?;
        let status = if installed.is_some() {
            "Stopped"
        } else {
            "Not installed"
        }
        .into();
        Ok(Self {
            directory,
            settings_path,
            settings,
            installed,
            latest: None,
            runtime: None,
            runtime_geo: None,
            bypass,
            activity,
            pending: false,
            status,
            geo_status: String::new(),
            last_geo_attempt: 0,
        })
    }

    fn change(
        &mut self,
        runtime_change: bool,
        update: impl FnOnce(&mut Settings) -> Result<()>,
    ) -> Result<()> {
        let mut next = self.settings.clone();
        update(&mut next)?;
        next.save(&self.settings_path)?;
        self.settings = next;
        self.pending |= runtime_change && self.runtime.is_some();
        Ok(())
    }

    fn perform(&mut self, command: Command) -> Result<()> {
        match command {
            Command::Install | Command::InstallUpdate => {
                ensure!(
                    self.runtime.is_none(),
                    "Stop Xray before installing an update"
                );
                let release = match self.latest.take() {
                    Some(release) => release,
                    None => assets::latest()?,
                };
                self.installed = Some(assets::install(&self.directory, &release)?);
                self.status = "Installed · Stopped".into();
                self.last_geo_attempt = profile::now();
                if self.settings.geoip_url == assets::DEFAULT_GEOIP_URL
                    && self.settings.geosite_url == assets::DEFAULT_GEOSITE_URL
                    && self.settings.geo_refreshed_at == 0
                {
                    self.change(false, |settings| {
                        settings.geo_refreshed_at = profile::now();
                        Ok(())
                    })?;
                }
            }
            Command::CheckUpdates => {
                let release = assets::latest()?;
                let available = self
                    .installed
                    .as_ref()
                    .is_none_or(|installed| newer(&release.version, &installed.version));
                self.status = if available {
                    "Update available"
                } else {
                    "Xray is up to date"
                }
                .into();
                self.latest = available.then_some(release);
            }
            Command::Toggle => {
                if let Some(mut runtime) = self.runtime.take() {
                    runtime.stop();
                    self.runtime_geo = None;
                    let _ = assets::prune_geo(&self.directory, None);
                    self.pending = false;
                    self.status = "Stopped".into();
                } else {
                    self.start()?;
                }
            }
            Command::Import(input) => {
                self.change(false, |settings| settings.import(&input))?;
            }
            Command::RefreshSubscription(id) => {
                self.change(false, |settings| settings.refresh_subscription(&id))?;
            }
            Command::Activate(id) => {
                self.change(true, |settings| {
                    ensure!(
                        settings.profiles.iter().any(|profile| profile.id == id),
                        "Xray profile not found"
                    );
                    settings.active = if settings.active.as_deref() == Some(id.as_str()) {
                        None
                    } else {
                        Some(id)
                    };
                    Ok(())
                })?;
            }
            Command::Remove(id) => {
                let changed = self.settings.active.as_deref() == Some(id.as_str());
                self.change(changed, |settings| {
                    settings.remove_profile(&id);
                    Ok(())
                })?;
            }
            Command::Port(port) => self.change(true, |settings| {
                settings.socks_port = port
                    .trim()
                    .parse()
                    .context("Enter a port between 1 and 65535")?;
                Ok(())
            })?,
            Command::Dns(text) => self.change(true, |settings| {
                settings.dns = profile::parse_dns(&text)?;
                Ok(())
            })?,
            Command::PinHost => self.change(true, Settings::pin_selected)?,
            Command::RemoveHost(host) => self.change(true, |settings| {
                settings.hosts.remove(&host);
                Ok(())
            })?,
            Command::Geo {
                ips,
                domains,
                geoip,
                geosite,
                hours,
            } => {
                let geoip = profile::https_url(&geoip)?.to_string();
                let geosite = profile::https_url(&geosite)?.to_string();
                let sources_changed =
                    self.settings.geoip_url != geoip || self.settings.geosite_url != geosite;
                self.change(true, |settings| {
                    settings.direct_ips = profile::parse_tags(&ips, "geoip")?;
                    settings.direct_domains = profile::parse_tags(&domains, "geosite")?;
                    settings.geoip_url = geoip;
                    settings.geosite_url = geosite;
                    settings.geo_refresh_hours = hours
                        .trim()
                        .parse()
                        .context("Enter a geo refresh interval in hours")?;
                    if sources_changed {
                        settings.geo_refreshed_at = 0;
                    }
                    Ok(())
                })?;
                if sources_changed {
                    self.geo_status = "Sources saved. Refresh to download these databases.".into();
                    self.last_geo_attempt = profile::now();
                }
            }
            Command::RefreshGeo => self.refresh_geo()?,
            Command::Record(record) => {
                self.change(false, |settings| {
                    settings.log_recording = record;
                    Ok(())
                })?;
                self.activity.set_recording(record);
            }
        }
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        let installed = self.installed.as_ref().context("Install Xray-core first")?;
        let profile = self.settings.selected()?;
        let outbound = profile.outbound()?;
        let geo_directory = assets::geo_directory(&self.directory)?
            .or_else(|| installed.executable.parent().map(Path::to_path_buf))
            .context("Missing Xray database directory")?;
        let settings = runtime::Settings {
            socks_port: self.settings.socks_port,
            upstream: &profile.host,
            upstream_port: profile.port,
            upstream_ip: self.settings.hosts.get(&profile.host).copied(),
            outbound: &outbound,
            dns_servers: &self.settings.dns,
            direct_domains: &self.settings.direct_domains,
            direct_ips: &self.settings.direct_ips,
            geo_directory: &geo_directory,
        };
        self.runtime = Some(Runtime::start(
            installed,
            settings,
            self.bypass.clone(),
            self.activity.clone(),
        )?);
        self.pending = false;
        self.runtime_geo = Some(geo_directory);
        self.status = format!("SOCKS5 listening on 127.0.0.1:{}", self.settings.socks_port);
        Ok(())
    }

    fn refresh_geo(&mut self) -> Result<()> {
        ensure!(self.installed.is_some(), "Install Xray-core first");
        self.last_geo_attempt = profile::now();
        assets::refresh_geo(
            &self.directory,
            &self.settings.geoip_url,
            &self.settings.geosite_url,
        )?;
        let _ = assets::prune_geo(&self.directory, self.runtime_geo.as_deref());
        self.change(true, |settings| {
            settings.geo_refreshed_at = profile::now();
            Ok(())
        })?;
        self.geo_status = "Databases downloaded successfully".into();
        Ok(())
    }

    fn poll(&mut self) -> Option<String> {
        if let Some(runtime) = &mut self.runtime {
            match runtime.running() {
                Ok(true) => {}
                result => {
                    self.runtime.take();
                    self.runtime_geo = None;
                    let _ = assets::prune_geo(&self.directory, None);
                    self.pending = false;
                    self.status = "Stopped".into();
                    return Some(result.err().map_or_else(
                        || "Xray exited unexpectedly. Check Logs for details.".into(),
                        |error| error.to_string(),
                    ));
                }
            }
        }
        let hours = u64::from(self.settings.geo_refresh_hours);
        let now = profile::now();
        if self.installed.is_some()
            && hours > 0
            && now.saturating_sub(self.settings.geo_refreshed_at) >= hours * 3600
            && now.saturating_sub(self.last_geo_attempt) >= 3600
        {
            if let Err(error) = self.refresh_geo() {
                self.geo_status = "Geo database refresh failed".into();
                return Some(error.to_string());
            }
            return Some(String::new());
        }
        None
    }
}

fn newer(latest: &str, installed: &str) -> bool {
    semver::Version::parse(latest.trim_start_matches('v'))
        .ok()
        .zip(semver::Version::parse(installed.trim_start_matches('v')).ok())
        .is_some_and(|(latest, installed)| latest > installed)
}

struct View {
    settings: Settings,
    version: String,
    latest: String,
    status: String,
    geo_status: String,
    started: Option<std::time::Instant>,
    error: String,
}

impl View {
    fn new(controller: &Controller, error: String) -> Self {
        let status = if controller.pending {
            "Restart Xray to apply saved changes".into()
        } else {
            controller.status.clone()
        };
        Self {
            settings: controller.settings.clone(),
            version: controller
                .installed
                .as_ref()
                .map_or_else(String::new, |core| core.version.clone()),
            latest: controller
                .latest
                .as_ref()
                .map_or_else(String::new, |release| release.version.clone()),
            status,
            geo_status: controller.geo_status.clone(),
            started: controller.runtime.as_ref().map(Runtime::started_at),
            error,
        }
    }

    fn apply(self, ui: &MainWindow, command_done: bool) {
        let xray = ui.global::<XrayModule>();
        xray.set_installed(!self.version.is_empty());
        xray.set_version(self.version.into());
        xray.set_latest_version(self.latest.into());
        xray.set_running(self.started.is_some());
        xray.set_status(self.status.into());
        xray.set_geo_status(self.geo_status.into());
        xray.set_error(self.error.into());
        xray.set_port(self.settings.socks_port.to_string().into());
        xray.set_dns(if self.settings.dns.is_empty() {
            "Default".into()
        } else {
            self.settings.dns.join(", ").into()
        });
        xray.set_geo_ip_tags(self.settings.direct_ips.join(", ").into());
        xray.set_geo_site_tags(self.settings.direct_domains.join(", ").into());
        xray.set_geo_ip_url(self.settings.geoip_url.into());
        xray.set_geo_site_url(self.settings.geosite_url.into());
        xray.set_geo_refresh_hours(self.settings.geo_refresh_hours.to_string().into());
        xray.set_profiles(model(
            self.settings
                .profiles
                .into_iter()
                .map(|profile| XrayProfileRow {
                    active: self.settings.active.as_deref() == Some(profile.id.as_str()),
                    id: profile.id.into(),
                    name: profile.name.into(),
                    summary: format!("VLESS · {}:{}", profile.host, profile.port).into(),
                    subscription: profile.subscription.is_some(),
                })
                .collect(),
        ));
        xray.set_hosts(model(
            self.settings
                .hosts
                .into_iter()
                .map(|(host, address)| XrayHostRow {
                    host: host.into(),
                    address: address.to_string().into(),
                })
                .collect(),
        ));
        xray.set_log_recording(self.settings.log_recording);
        if command_done {
            xray.set_busy(false);
        }
    }
}

fn spawn_worker(
    mut controller: Controller,
    weak: slint::Weak<MainWindow>,
    started: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
) -> std::io::Result<mpsc::SyncSender<Command>> {
    let (sender, receiver) = mpsc::sync_channel(4);
    thread::Builder::new()
        .name("xray-module".into())
        .spawn(move || {
            loop {
                let interval = if controller.runtime.is_some() {
                    Duration::from_secs(1)
                } else {
                    Duration::from_secs(60)
                };
                let (result, command_done) = match receiver.recv_timeout(interval) {
                    Ok(command) => (
                        Some(
                            controller
                                .perform(command)
                                .err()
                                .map_or_else(String::new, |error| error.to_string()),
                        ),
                        true,
                    ),
                    Err(mpsc::RecvTimeoutError::Timeout) => (controller.poll(), false),
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };
                if let Some(error) = result {
                    let view = View::new(&controller, error);
                    *started.lock().unwrap() = view.started;
                    let weak = weak.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            view.apply(&ui, command_done);
                            ui.global::<XrayModule>().invoke_refresh_activity();
                        }
                    });
                }
            }
        })?;
    Ok(sender)
}

pub(super) fn wire(ui: &MainWindow, directory: PathBuf, bypass: Arc<Bypass>) -> Result<()> {
    let activity = Arc::new(Activity::default());
    let controller = Controller::load(directory, bypass, activity.clone())?;
    let installed = controller.installed.is_some();
    let started = Arc::new(std::sync::Mutex::new(None));
    View::new(&controller, String::new()).apply(ui, true);
    let initial = RefCell::new(Some(controller));
    let sender = OnceCell::new();
    let weak = ui.as_weak();
    let worker_started = started.clone();
    let start_worker = move || {
        initial.borrow_mut().take().and_then(|controller| {
            spawn_worker(controller, weak.clone(), worker_started.clone()).ok()
        })
    };
    if installed {
        let _ = sender.set(start_worker());
    }
    let xray = ui.global::<XrayModule>();
    let weak = ui.as_weak();
    let send = std::rc::Rc::new(move |command| {
        if let Some(ui) = weak.upgrade() {
            let xray = ui.global::<XrayModule>();
            if xray.get_busy() {
                return;
            }
            if sender
                .get_or_init(&start_worker)
                .as_ref()
                .is_some_and(|sender| sender.try_send(command).is_ok())
            {
                xray.set_busy(true);
                xray.set_error("".into());
            } else {
                xray.set_error("The Xray module worker is unavailable".into());
            }
        }
    });
    macro_rules! bind {
        ($callback:ident, $command:expr) => {{
            let send = send.clone();
            xray.$callback(move || send($command));
        }};
        ($callback:ident, $constructor:path, string) => {{
            let send = send.clone();
            xray.$callback(move |value| send($constructor(value.to_string())));
        }};
    }
    bind!(on_install, Command::Install);
    bind!(on_check_updates, Command::CheckUpdates);
    bind!(on_install_update, Command::InstallUpdate);
    bind!(on_toggle, Command::Toggle);
    bind!(on_pin_host, Command::PinHost);
    bind!(on_refresh_geo, Command::RefreshGeo);
    bind!(on_import_profile, Command::Import, string);
    bind!(
        on_refresh_subscription,
        Command::RefreshSubscription,
        string
    );
    bind!(on_activate_profile, Command::Activate, string);
    bind!(on_remove_profile, Command::Remove, string);
    bind!(on_save_port, Command::Port, string);
    bind!(on_save_dns, Command::Dns, string);
    bind!(on_remove_host, Command::RemoveHost, string);
    {
        let send = send.clone();
        xray.on_save_geo(move |ips, domains, geoip, geosite, hours| {
            send(Command::Geo {
                ips: ips.to_string(),
                domains: domains.to_string(),
                geoip: geoip.to_string(),
                geosite: geosite.to_string(),
                hours: hours.to_string(),
            })
        });
    }
    xray.on_set_log_recording(move |record| send(Command::Record(record)));
    let weak = ui.as_weak();
    let clear = activity.clone();
    xray.on_clear_connections(move || {
        clear.clear_connections();
        if let Some(ui) = weak.upgrade() {
            ui.global::<XrayModule>().invoke_refresh_activity();
        }
    });
    let weak = ui.as_weak();
    let clear = activity.clone();
    xray.on_clear_logs(move || {
        clear.clear_logs();
        if let Some(ui) = weak.upgrade() {
            ui.global::<XrayModule>().invoke_refresh_activity();
        }
    });
    let weak = ui.as_weak();
    xray.on_filter_connections(move || {
        if let Some(ui) = weak.upgrade() {
            ui.global::<XrayModule>().invoke_refresh_activity();
        }
    });
    let weak = ui.as_weak();
    xray.on_filter_logs(move || {
        if let Some(ui) = weak.upgrade() {
            ui.global::<XrayModule>().invoke_refresh_activity();
        }
    });
    let weak = ui.as_weak();
    xray.on_refresh_activity(move || {
        if let Some(ui) = weak.upgrade()
            && ui.get_page() == 6
            && ui.window().is_visible()
            && !ui.window().is_minimized()
        {
            render_activity(&ui, &activity, *started.lock().unwrap());
        }
    });
    Ok(())
}

fn render_activity(ui: &MainWindow, activity: &Activity, started: Option<std::time::Instant>) {
    let xray = ui.global::<XrayModule>();
    if xray.get_section() == 0 {
        let stats = activity.stats();
        xray.set_uptime(started.map_or_else(
            || "00:00:00".into(),
            |started| uptime(started.elapsed()).into(),
        ));
        xray.set_connection_count(stats.accepted.min(i32::MAX as u64) as i32);
        xray.set_upload(stats.proxied.to_string().into());
        xray.set_download(stats.direct.to_string().into());
    }
    if xray.get_section() == 5 {
        let query = xray.get_connection_query().to_lowercase();
        let entries = activity.connections();
        xray.set_connection_total(entries.len() as i32);
        let rows: Vec<_> = entries
            .into_iter()
            .filter(|row| {
                query.is_empty()
                    || [&row.destination, &row.source, &row.route, &row.protocol]
                        .into_iter()
                        .any(|value| value.to_lowercase().contains(&query))
            })
            .map(|row| XrayConnectionRow {
                time: row.time.into(),
                protocol: row.protocol.into(),
                destination: row.destination.into(),
                source: row.source.into(),
                route: row.route.into(),
                detail: row.status.into(),
            })
            .collect();
        use slint::Model;
        let previous = xray.get_connections();
        if previous.row_count() != rows.len() || !previous.iter().eq(rows.iter().cloned()) {
            xray.set_connections(model(rows));
        }
    }
    if xray.get_section() == 6 {
        let entries = activity.logs();
        let total = entries.len();
        let mut visible = 0;
        let mut text = String::new();
        for row in entries {
            let error = row.level == "Error";
            let is_access = row.access;
            if (xray.get_log_errors_only() && !error)
                || (xray.get_log_verbosity() == 0
                    && !is_access
                    && matches!(row.level.as_str(), "Info" | "Debug"))
                || (xray.get_log_source() == 1 && is_access)
                || (xray.get_log_source() == 2 && !is_access)
            {
                continue;
            }
            use std::fmt::Write;
            if visible > 0 {
                text.push('\n');
            }
            let _ = write!(text, "{}  {}  {}", row.time, row.level, row.message);
            visible += 1;
        }
        xray.set_log_total(total as i32);
        xray.set_log_visible_count(visible);
        if xray.get_log_text().as_str() != text {
            xray.set_log_text(text.into());
        }
    }
}
