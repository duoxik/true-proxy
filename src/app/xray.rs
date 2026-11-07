use super::{model, uptime};
use crate::{
    MainWindow, XrayConnectionRow, XrayHostRow, XrayModule, XrayProfileRow, XraySubscriptionGroup,
};
use anyhow::{Context, Result, ensure};
use slint::{ComponentHandle, Model, ModelRc, SharedString};
use std::{
    cell::{Cell, OnceCell, RefCell},
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, mpsc},
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
    RefreshHosts,
    Geo {
        ips: Vec<String>,
        domains: Vec<String>,
        geoip: String,
        geosite: String,
        hours: String,
    },
    RefreshGeo,
    LoadGeoTags,
    Record(bool),
}

impl Command {
    fn manages_core(&self) -> bool {
        matches!(
            self,
            Self::Install | Self::CheckUpdates | Self::InstallUpdate
        )
    }
}

type GeoCatalog = (Vec<String>, Vec<String>);
type SharedGeoCatalog = Arc<Mutex<Option<GeoCatalog>>>;

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
    geo_catalog: SharedGeoCatalog,
    last_geo_attempt: u64,
}

impl Controller {
    fn load(
        directory: PathBuf,
        bypass: Arc<Bypass>,
        activity: Arc<Activity>,
        geo_catalog: SharedGeoCatalog,
    ) -> Result<Self> {
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
            geo_catalog,
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
        self.save_settings(next, runtime_change)
    }

    fn save_settings(&mut self, next: Settings, runtime_change: bool) -> Result<()> {
        let upstream = |settings: &Settings| {
            settings
                .selected()
                .ok()
                .map(|profile| (profile.port, settings.upstream_ip(profile)))
        };
        let upstream_changed =
            self.settings.active != next.active || upstream(&self.settings) != upstream(&next);
        next.save(&self.settings_path)?;
        self.settings = next;
        self.pending |= self.runtime.is_some() && (runtime_change || upstream_changed);
        Ok(())
    }

    fn refresh_hosts(&mut self, all: bool) -> Result<(bool, usize)> {
        let mut next = self.settings.clone();
        let domains = next
            .host_domains()
            .into_iter()
            .filter(|host| all || !next.hosts.contains_key(*host))
            .map(str::to_owned)
            .collect();
        next.prune_hosts();
        let failed = next.resolve_hosts(domains);
        let changed = next.hosts != self.settings.hosts;
        if changed {
            self.save_settings(next, false)?;
        }
        Ok((changed, failed))
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
                self.reload_geo_tags(true);
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
                self.change(false, |settings| {
                    let domains = settings.import(&input)?;
                    settings.resolve_hosts(domains);
                    Ok(())
                })?;
            }
            Command::RefreshSubscription(id) => {
                self.change(false, |settings| {
                    let domains = settings.refresh_subscription(&id)?;
                    settings.resolve_hosts(domains);
                    Ok(())
                })?;
            }
            Command::Activate(id) => {
                self.change(true, |settings| {
                    let profile = settings
                        .profiles
                        .iter()
                        .find(|profile| profile.id == id)
                        .context("Xray profile not found")?;
                    if settings.active.as_deref() == Some(id.as_str()) {
                        settings.active = None;
                    } else {
                        let missing_host = settings
                            .upstream_ip(profile)
                            .is_none()
                            .then(|| profile.host.clone());
                        settings.active = Some(id);
                        if let Some(host) = missing_host {
                            settings.resolve_hosts(std::iter::once(host).collect());
                        }
                    }
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
            Command::RefreshHosts => {
                let (_, failed) = self.refresh_hosts(true)?;
                ensure!(
                    failed == 0,
                    "Could not resolve {failed} VPN server addresses. Previously saved addresses were kept."
                );
            }
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
                    settings.direct_ips = ips;
                    settings.direct_domains = domains;
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
            Command::LoadGeoTags => self.reload_geo_tags(false),
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
        let upstream_ip = self.settings.upstream_ip(profile).context(
            "The VPN server has no saved IP address. Open X-RAY → DNS and select Refresh.",
        )?;
        let outbound = profile.outbound()?;
        let geo_directory = assets::geo_directory(&self.directory)?
            .or_else(|| installed.executable.parent().map(Path::to_path_buf))
            .context("Missing Xray database directory")?;
        let settings = runtime::Settings {
            socks_port: self.settings.socks_port,
            upstream: &profile.host,
            upstream_port: profile.port,
            upstream_ip: Some(upstream_ip),
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
        self.reload_geo_tags(true);
        self.change(true, |settings| {
            settings.geo_refreshed_at = profile::now();
            Ok(())
        })?;
        self.geo_status = "Databases downloaded successfully".into();
        Ok(())
    }

    fn reload_geo_tags(&self, only_if_loaded: bool) {
        if only_if_loaded && self.geo_catalog.lock().unwrap().is_none() {
            return;
        }
        let tags = assets::geo_tags(&self.directory).unwrap_or_default();
        *self.geo_catalog.lock().unwrap() = Some(tags);
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
}

impl View {
    fn new(controller: &Controller) -> Self {
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
        xray.set_port(self.settings.socks_port.to_string().into());
        xray.set_dns(if self.settings.dns.is_empty() {
            "Default".into()
        } else {
            self.settings.dns.join(", ").into()
        });
        xray.set_geo_ip_url(self.settings.geoip_url.as_str().into());
        xray.set_geo_site_url(self.settings.geosite_url.as_str().into());
        xray.set_geo_refresh_hours(self.settings.geo_refresh_hours.to_string().into());
        xray.set_hosts(model(
            self.settings
                .host_domains()
                .into_iter()
                .map(|host| XrayHostRow {
                    host: host.into(),
                    address: self
                        .settings
                        .hosts
                        .get(host)
                        .map_or_else(|| "—".to_owned(), |address| address.to_string())
                        .into(),
                })
                .collect(),
        ));
        let mut manual = Vec::new();
        let mut groups = BTreeMap::<&str, Vec<XrayProfileRow>>::new();
        for profile in &self.settings.profiles {
            let row = XrayProfileRow {
                active: self.settings.active.as_deref() == Some(profile.id.as_str()),
                id: profile.id.as_str().into(),
                name: profile.name.as_str().into(),
                summary: format!("VLESS · {}:{}", profile.host, profile.port).into(),
            };
            if let Some(source) = &profile.subscription {
                groups.entry(source.as_str()).or_default().push(row);
            } else {
                manual.push(row);
            }
        }
        xray.set_profiles(model(manual));
        xray.set_subscriptions(model(
            self.settings
                .subscription_ids()
                .enumerate()
                .filter_map(|(index, id)| {
                    Some(XraySubscriptionGroup {
                        id: id.into(),
                        name: format!("Subscription {}", index + 1).into(),
                        profiles: model(groups.remove(id)?),
                    })
                })
                .collect(),
        ));
        xray.set_log_recording(self.settings.log_recording);
        if command_done {
            xray.set_busy(false);
        }
    }
}

fn set_error(xray: &XrayModule<'_>, manages_core: bool, error: String) {
    if manages_core {
        xray.set_module_error(error.into());
    } else {
        xray.set_error(error.into());
    }
}

fn refresh_geo_suggestions(xray: &XrayModule<'_>) {
    xray.invoke_filter_geo_tags(false, xray.get_geo_ip_query());
    xray.invoke_filter_geo_tags(true, xray.get_geo_site_query());
}

fn spawn_worker(
    mut controller: Controller,
    weak: slint::Weak<MainWindow>,
    started: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
) -> std::io::Result<mpsc::SyncSender<Command>> {
    let (sender, receiver) = mpsc::sync_channel::<Command>(4);
    thread::Builder::new()
        .name("xray-module".into())
        .spawn(move || {
            let host_migration = match controller.refresh_hosts(false) {
                Ok((true, _)) => Some(String::new()),
                Ok((false, _)) => None,
                Err(error) => Some(error.to_string()),
            };
            if let Some(error) = host_migration {
                let view = View::new(&controller);
                let weak = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        view.apply(&ui, false);
                        ui.global::<XrayModule>().set_error(error.into());
                    }
                });
            }
            loop {
                let interval = if controller.runtime.is_some() {
                    Duration::from_secs(1)
                } else {
                    Duration::from_secs(60)
                };
                let (result, command_done, manages_core) = match receiver.recv_timeout(interval) {
                    Ok(command) => {
                        let catalog_only = matches!(command, Command::LoadGeoTags);
                        let manages_core = command.manages_core();
                        let error = controller
                            .perform(command)
                            .err()
                            .map_or_else(String::new, |error| error.to_string());
                        if catalog_only {
                            let weak = weak.clone();
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Some(ui) = weak.upgrade() {
                                    refresh_geo_suggestions(&ui.global::<XrayModule>());
                                }
                            });
                            continue;
                        }
                        (Some(error), true, manages_core)
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => (controller.poll(), false, false),
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };
                if let Some(error) = result {
                    let view = View::new(&controller);
                    *started.lock().unwrap() = view.started;
                    let weak = weak.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            view.apply(&ui, command_done);
                            let xray = ui.global::<XrayModule>();
                            set_error(&xray, manages_core, error);
                            refresh_geo_suggestions(&xray);
                            xray.invoke_refresh_activity();
                        }
                    });
                }
            }
        })?;
    Ok(sender)
}

pub(super) fn wire(ui: &MainWindow, directory: PathBuf, bypass: Arc<Bypass>) -> Result<()> {
    let activity = Arc::new(Activity::default());
    let geo_catalog = SharedGeoCatalog::default();
    let controller = Controller::load(directory, bypass, activity.clone(), geo_catalog.clone())?;
    let installed = controller.installed.is_some();
    let started = Arc::new(std::sync::Mutex::new(None));
    View::new(&controller).apply(ui, true);
    let xray = ui.global::<XrayModule>();
    xray.set_geo_ip_selected(geo_draft(&controller.settings.direct_ips, "geoip:"));
    xray.set_geo_site_selected(geo_draft(&controller.settings.direct_domains, "geosite:"));
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
    let queue = std::rc::Rc::new(move |command: Command| {
        sender
            .get_or_init(&start_worker)
            .as_ref()
            .is_some_and(|sender| sender.try_send(command).is_ok())
    });
    let geo_queue = queue.clone();
    wire_geo_editor(ui, geo_catalog, move |command| geo_queue(command));
    let weak = ui.as_weak();
    let send = std::rc::Rc::new(move |command: Command| {
        if let Some(ui) = weak.upgrade() {
            let xray = ui.global::<XrayModule>();
            if xray.get_busy() {
                return;
            }
            let manages_core = command.manages_core();
            if queue(command) {
                xray.set_busy(true);
                set_error(&xray, manages_core, String::new());
            } else {
                set_error(
                    &xray,
                    manages_core,
                    "The Xray module worker is unavailable".into(),
                );
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
    bind!(on_refresh_hosts, Command::RefreshHosts);
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
    {
        let send = send.clone();
        let weak = ui.as_weak();
        xray.on_save_geo(move |geoip, geosite, hours| {
            if let Some(ui) = weak.upgrade() {
                let xray = ui.global::<XrayModule>();
                send(Command::Geo {
                    ips: xray
                        .get_geo_ip_selected()
                        .iter()
                        .map(|tag| format!("geoip:{tag}"))
                        .collect(),
                    domains: xray
                        .get_geo_site_selected()
                        .iter()
                        .map(|tag| format!("geosite:{tag}"))
                        .collect(),
                    geoip: geoip.to_string(),
                    geosite: geosite.to_string(),
                    hours: hours.to_string(),
                });
            }
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

fn geo_draft(tags: &[String], prefix: &str) -> ModelRc<SharedString> {
    model(
        tags.iter()
            .map(|tag| tag.strip_prefix(prefix).unwrap_or(tag).into())
            .collect(),
    )
}

fn geo_selection(xray: &XrayModule<'_>, geosite: bool) -> ModelRc<SharedString> {
    if geosite {
        xray.get_geo_site_selected()
    } else {
        xray.get_geo_ip_selected()
    }
}

fn set_geo_selection(xray: &XrayModule<'_>, geosite: bool, tags: Vec<SharedString>) {
    if geosite {
        xray.set_geo_site_selected(model(tags));
    } else {
        xray.set_geo_ip_selected(model(tags));
    }
}

fn wire_geo_editor(
    ui: &MainWindow,
    catalog: SharedGeoCatalog,
    queue: impl Fn(Command) -> bool + 'static,
) {
    let xray = ui.global::<XrayModule>();
    let weak = ui.as_weak();
    let requested = Cell::new(false);
    xray.on_filter_geo_tags(move |geosite, query| {
        let Some(ui) = weak.upgrade() else { return };
        let xray = ui.global::<XrayModule>();
        let query = query.trim().to_ascii_lowercase();
        let prefix = if geosite { "geosite:" } else { "geoip:" };
        let needle = query.strip_prefix(prefix).unwrap_or(&query);
        let selected = geo_selection(&xray, geosite);
        let suggestions = if needle.is_empty() {
            Vec::new()
        } else {
            let catalog = catalog.lock().unwrap();
            if let Some((ips, sites)) = catalog.as_ref() {
                let tags = if geosite { sites } else { ips };
                tags.iter()
                    .filter(|tag| tag.starts_with(needle))
                    .chain(
                        tags.iter()
                            .filter(|tag| !tag.starts_with(needle) && tag.contains(needle)),
                    )
                    .filter(|tag| !selected.iter().any(|saved| saved.as_str() == tag.as_str()))
                    .take(6)
                    .map(|tag| tag.as_str().into())
                    .collect()
            } else {
                drop(catalog);
                if !requested.get() && queue(Command::LoadGeoTags) {
                    requested.set(true);
                }
                Vec::new()
            }
        };
        if geosite {
            xray.set_geo_site_suggestions(model(suggestions));
        } else {
            xray.set_geo_ip_suggestions(model(suggestions));
        }
    });
    let weak = ui.as_weak();
    xray.on_select_geo_tag(move |geosite, tag| {
        let Some(ui) = weak.upgrade() else { return };
        let xray = ui.global::<XrayModule>();
        let kind = if geosite { "geosite" } else { "geoip" };
        let normalized = tag.trim().to_ascii_lowercase();
        let Ok(parsed) = profile::parse_tags(&normalized, kind) else {
            xray.set_error("Enter a valid geo tag".into());
            return;
        };
        let [tag] = parsed.as_slice() else {
            xray.set_error("Enter one geo tag at a time".into());
            return;
        };
        let bare = &tag[kind.len() + 1..];
        let mut tags: Vec<_> = geo_selection(&xray, geosite).iter().collect();
        if !tags.iter().any(|tag| tag.as_str() == bare) {
            if tags.len() >= 32 {
                xray.set_error("Enter at most 32 geo tags per field".into());
                return;
            }
            tags.push(bare.into());
            set_geo_selection(&xray, geosite, tags);
        }
        if geosite {
            xray.set_geo_site_query("".into());
        } else {
            xray.set_geo_ip_query("".into());
        }
        xray.invoke_filter_geo_tags(geosite, "".into());
    });
    let weak = ui.as_weak();
    xray.on_remove_geo_tag(move |geosite, tag| {
        let Some(ui) = weak.upgrade() else { return };
        let xray = ui.global::<XrayModule>();
        let tags = geo_selection(&xray, geosite)
            .iter()
            .filter(|saved| saved != &tag)
            .collect();
        set_geo_selection(&xray, geosite, tags);
        refresh_geo_suggestions(&xray);
    });
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
