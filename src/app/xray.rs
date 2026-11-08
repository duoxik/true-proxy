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
    rc::Rc,
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
    Restart,
    Import(String),
    RefreshSubscription(String),
    Activate(String),
    Remove(String),
    RefreshHosts,
    SaveDraft(i32, SettingsDraft),
    RefreshGeo,
    LoadGeoTags,
    Record(bool),
}

struct SettingsDraft {
    port: String,
    dns: String,
    ips: Vec<String>,
    domains: Vec<String>,
    geoip: String,
    geosite: String,
    hours: String,
}

impl SettingsDraft {
    fn read(xray: &XrayModule<'_>) -> Self {
        Self {
            port: xray.get_port().to_string(),
            dns: xray.get_dns().to_string(),
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
            geoip: xray.get_geo_ip_url().to_string(),
            geosite: xray.get_geo_site_url().to_string(),
            hours: xray.get_geo_refresh_hours().to_string(),
        }
    }

    fn apply(self, settings: &mut Settings) -> Result<()> {
        let mut error = None;
        let port = self
            .port
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0);
        update_field(
            &mut settings.socks_port,
            port.context("Enter a SOCKS port between 1 and 65535."),
            &mut error,
        );
        let dns = if self.dns.trim().is_empty() {
            Err(anyhow::anyhow!("Enter a DNS resolver or Default."))
        } else {
            profile::parse_dns(&self.dns)
        };
        update_field(&mut settings.dns, dns, &mut error);
        update_field(
            &mut settings.geoip_url,
            profile::https_url(&self.geoip)
                .map(|url| url.to_string())
                .context("Enter a valid GeoIP database URL."),
            &mut error,
        );
        update_field(
            &mut settings.geosite_url,
            profile::https_url(&self.geosite)
                .map(|url| url.to_string())
                .context("Enter a valid Geosite database URL."),
            &mut error,
        );
        let hours = self
            .hours
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|hours| *hours <= 720);
        update_field(
            &mut settings.geo_refresh_hours,
            hours.context("Enter a refresh interval between 0 and 720 hours."),
            &mut error,
        );
        settings.direct_ips = self.ips;
        settings.direct_domains = self.domains;
        error.map_or(Ok(()), Err)
    }
}

fn update_field<T>(target: &mut T, input: Result<T>, error: &mut Option<anyhow::Error>) {
    match input {
        Ok(value) => *target = value,
        Err(field_error) => {
            error.get_or_insert(field_error);
        }
    }
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
    runtime_port: Option<u16>,
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
            runtime_port: None,
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
            Command::Toggle => self.set_running(self.runtime.is_none())?,
            Command::Restart => {
                ensure!(self.runtime.is_some(), "Xray is already stopped.");
                self.stop();
                self.set_running(true)?;
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
            Command::RefreshHosts => {
                let (_, failed) = self.refresh_hosts(true)?;
                ensure!(
                    failed == 0,
                    "Could not resolve {failed} VPN server addresses. Previously saved addresses were kept."
                );
            }
            Command::SaveDraft(_, draft) => self.save_draft(draft)?,
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

    fn save_draft(&mut self, draft: SettingsDraft) -> Result<()> {
        let mut next = self.settings.clone();
        let validation = draft.apply(&mut next);
        let runtime_changed = next.socks_port != self.settings.socks_port
            || next.dns != self.settings.dns
            || next.direct_ips != self.settings.direct_ips
            || next.direct_domains != self.settings.direct_domains;
        let sources_changed = next.geoip_url != self.settings.geoip_url
            || next.geosite_url != self.settings.geosite_url;
        if sources_changed {
            next.geo_refreshed_at = 0;
        }
        if runtime_changed
            || sources_changed
            || next.geo_refresh_hours != self.settings.geo_refresh_hours
        {
            self.save_settings(next, runtime_changed)?;
            if sources_changed {
                self.geo_status = "Sources saved. Select Update Databases to download them.".into();
                self.last_geo_attempt = profile::now();
            }
        }
        validation
    }

    fn remember_enabled(&mut self, enabled: bool) -> Result<()> {
        if self.settings.enabled != enabled {
            self.change(false, |settings| {
                settings.enabled = enabled;
                Ok(())
            })
            .context("Could not save the Xray state")?;
        }
        Ok(())
    }

    fn remember_failure(&mut self, error: anyhow::Error) -> anyhow::Error {
        match self.remember_enabled(false) {
            Ok(()) => error,
            Err(save) => anyhow::anyhow!("{error:#}. {save:#}"),
        }
    }

    fn set_running(&mut self, enabled: bool) -> Result<()> {
        if !enabled {
            self.stop();
            return self.remember_enabled(false);
        }
        if let Err(error) = self.start() {
            return Err(self.remember_failure(error));
        }
        if let Err(error) = self.remember_enabled(true) {
            self.stop();
            return Err(error);
        }
        Ok(())
    }

    fn stop(&mut self) {
        if let Some(mut runtime) = self.runtime.take() {
            runtime.stop();
        }
        self.runtime_geo = None;
        self.runtime_port = None;
        let _ = assets::prune_geo(&self.directory, None);
        self.pending = false;
        self.status = "Stopped".into();
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
        self.runtime_port = Some(self.settings.socks_port);
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
                    self.stop();
                    let error = result.err().unwrap_or_else(|| {
                        anyhow::anyhow!("Xray exited unexpectedly. Check Logs for details.")
                    });
                    return Some(self.remember_failure(error).to_string());
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
    pending: bool,
    listener_port: u16,
    geo_status: String,
    started: Option<std::time::Instant>,
}

impl View {
    fn new(controller: &Controller) -> Self {
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
            status: controller.status.clone(),
            pending: controller.pending,
            listener_port: controller
                .runtime_port
                .unwrap_or(controller.settings.socks_port),
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
        xray.set_pending(self.pending);
        xray.set_listener_port(self.listener_port.to_string().into());
        xray.set_geo_status(self.geo_status.into());
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
    on_restored: Option<impl FnOnce(&MainWindow) + Send + 'static>,
) -> std::io::Result<mpsc::SyncSender<Command>> {
    let (sender, receiver) = mpsc::sync_channel::<Command>(4);
    thread::Builder::new()
        .name("xray-module".into())
        .spawn(move || {
            let (migrated, migration_error) = match controller.refresh_hosts(false) {
                Ok((changed, _)) => (changed, None),
                Err(error) => (false, Some(error)),
            };
            let restoring = on_restored.is_some();
            let error = if restoring {
                controller.set_running(true).err().or(migration_error)
            } else {
                migration_error
            };
            if restoring || migrated || error.is_some() {
                let view = View::new(&controller);
                *started.lock().unwrap() = view.started;
                let weak = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        view.apply(&ui, restoring);
                        let xray = ui.global::<XrayModule>();
                        xray.set_error(
                            error
                                .map_or_else(String::new, |error| error.to_string())
                                .into(),
                        );
                        xray.invoke_refresh_activity();
                        if let Some(on_restored) = on_restored {
                            on_restored(&ui);
                        }
                    }
                });
            }
            loop {
                let interval = if controller.runtime.is_some() {
                    Duration::from_secs(1)
                } else {
                    Duration::from_secs(60)
                };
                let (result, command_done, manages_core, revision) = match receiver
                    .recv_timeout(interval)
                {
                    Ok(command) => {
                        let catalog_only = matches!(command, Command::LoadGeoTags);
                        let manages_core = command.manages_core();
                        let revision = match &command {
                            Command::SaveDraft(revision, _) => Some(*revision),
                            _ => None,
                        };
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
                        (Some(error), true, manages_core, revision)
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => (controller.poll(), false, false, None),
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
                            if let Some(revision) = revision {
                                if revision == xray.get_settings_revision() {
                                    xray.set_settings_saving(false);
                                    xray.set_settings_error(error.into());
                                }
                            } else {
                                set_error(&xray, manages_core, error);
                            }
                            refresh_geo_suggestions(&xray);
                            xray.invoke_refresh_activity();
                        }
                    });
                }
            }
        })?;
    Ok(sender)
}

pub(super) fn wire(
    ui: &MainWindow,
    directory: PathBuf,
    bypass: Arc<Bypass>,
    paused: bool,
    on_restored: impl FnOnce(&MainWindow) + Send + 'static,
) -> Result<bool> {
    let activity = Arc::new(Activity::new(bypass.clone()));
    let geo_catalog = SharedGeoCatalog::default();
    let controller = Controller::load(directory, bypass, activity.clone(), geo_catalog.clone())?;
    let installed = controller.installed.is_some();
    let restoring = installed && controller.settings.enabled && !paused;
    let started = Arc::new(std::sync::Mutex::new(None));
    View::new(&controller).apply(ui, true);
    let xray = ui.global::<XrayModule>();
    let settings = &controller.settings;
    xray.set_port(settings.socks_port.to_string().into());
    xray.set_dns(if settings.dns.is_empty() {
        "Default".into()
    } else {
        settings.dns.join(", ").into()
    });
    xray.set_geo_ip_url(settings.geoip_url.as_str().into());
    xray.set_geo_site_url(settings.geosite_url.as_str().into());
    xray.set_geo_refresh_hours(settings.geo_refresh_hours.to_string().into());
    xray.set_geo_ip_selected(geo_draft(&controller.settings.direct_ips, "geoip:"));
    xray.set_geo_site_selected(geo_draft(&controller.settings.direct_domains, "geosite:"));
    let initial = RefCell::new(Some((controller, restoring.then_some(on_restored))));
    let sender = OnceCell::new();
    let weak = ui.as_weak();
    let worker_started = started.clone();
    let start_worker = move || {
        let (controller, on_restored) = initial.borrow_mut().take()?;
        spawn_worker(
            controller,
            weak.clone(),
            worker_started.clone(),
            on_restored,
        )
        .ok()
    };
    if installed {
        let worker = start_worker().context("Could not start the Xray worker")?;
        let _ = sender.set(Some(worker));
        if restoring {
            xray.set_busy(true);
            xray.set_status("Starting Xray…".into());
        }
    }
    let queue = Rc::new(move |command: Command| {
        sender
            .get_or_init(&start_worker)
            .as_ref()
            .is_some_and(|sender| sender.try_send(command).is_ok())
    });
    let save_queue = queue.clone();
    wire_autosave(ui, move |command| save_queue(command));
    let geo_queue = queue.clone();
    wire_geo_editor(ui, geo_catalog, move |command| geo_queue(command));
    let weak = ui.as_weak();
    let send = Rc::new(move |command: Command| {
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
    bind!(on_restart, Command::Restart);
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
    Ok(restoring)
}

fn geo_draft(tags: &[String], prefix: &str) -> ModelRc<SharedString> {
    model(
        tags.iter()
            .map(|tag| tag.strip_prefix(prefix).unwrap_or(tag).into())
            .collect(),
    )
}

fn schedule_save(ui: &MainWindow, timer: &slint::Timer) {
    let weak = ui.as_weak();
    timer.start(
        slint::TimerMode::SingleShot,
        Duration::from_millis(350),
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.global::<XrayModule>().invoke_commit_settings();
            }
        },
    );
}

fn wire_autosave(ui: &MainWindow, queue: impl Fn(Command) -> bool + 'static) {
    let xray = ui.global::<XrayModule>();
    let timer = Rc::new(slint::Timer::default());
    let weak = ui.as_weak();
    xray.on_settings_edited({
        let timer = timer.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                let xray = ui.global::<XrayModule>();
                xray.set_settings_revision(xray.get_settings_revision().wrapping_add(1));
                xray.set_settings_saving(true);
                schedule_save(&ui, &timer);
            }
        }
    });
    let weak = ui.as_weak();
    xray.on_commit_settings(move || {
        let Some(ui) = weak.upgrade() else { return };
        let xray = ui.global::<XrayModule>();
        if !xray.get_settings_saving() {
            return;
        }
        if xray.get_busy() {
            schedule_save(&ui, &timer);
            return;
        }
        let draft = SettingsDraft::read(&xray);
        if queue(Command::SaveDraft(xray.get_settings_revision(), draft)) {
            xray.set_busy(true);
        } else {
            xray.set_settings_saving(false);
            xray.set_settings_error("Could not save Xray settings. Try editing again.".into());
        }
    });
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
            xray.invoke_settings_edited();
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
        xray.invoke_settings_edited();
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
                    || [
                        row.destination.as_str(),
                        row.observed_domain.as_deref().unwrap_or_default(),
                        row.source.as_str(),
                        row.route.as_str(),
                        row.protocol.as_str(),
                    ]
                    .into_iter()
                    .any(|value| value.to_lowercase().contains(&query))
            })
            .map(|row| XrayConnectionRow {
                time: row.time.into(),
                protocol: row.protocol.into(),
                destination: row.destination.into(),
                observed_domain: row.observed_domain.unwrap_or_default().into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_autosave_preserves_invalid_fields_and_keeps_valid_edits() {
        let mut settings = Settings::default();
        let draft = SettingsDraft {
            port: "2082".into(),
            dns: "tcp://".into(),
            ips: vec!["geoip:private".into()],
            domains: settings.direct_domains.clone(),
            geoip: settings.geoip_url.clone(),
            geosite: settings.geosite_url.clone(),
            hours: "48".into(),
        };
        assert!(draft.apply(&mut settings).is_err());
        assert_eq!(settings.socks_port, 2082);
        assert!(settings.dns.is_empty());
        assert_eq!(settings.direct_ips, ["geoip:private"]);
        assert_eq!(settings.geo_refresh_hours, 48);
    }

    #[test]
    fn xray_remembers_state_across_exit_and_clears_it_on_stop_or_failure() {
        let directory =
            std::env::temp_dir().join(format!("true-proxy-xray-state-{}", super::super::id()));
        let path = directory.join("settings.json");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(&path, "{}").unwrap();
        let load = || {
            Controller::load(
                directory.clone(),
                Arc::new(Bypass::default()),
                Arc::new(Activity::default()),
                SharedGeoCatalog::default(),
            )
            .unwrap()
        };

        let mut controller = load();
        assert!(!controller.settings.enabled);
        controller.remember_enabled(true).unwrap();
        drop(controller);

        let mut controller = load();
        assert!(controller.settings.enabled);
        controller.set_running(false).unwrap();
        assert!(!Settings::load(&path).unwrap().enabled);

        controller.remember_enabled(true).unwrap();
        let mut controller = load();
        assert!(controller.set_running(true).is_err());
        assert!(controller.runtime.is_none());
        assert!(!Settings::load(&path).unwrap().enabled);

        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
