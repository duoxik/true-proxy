use super::{model, uptime};
use crate::{
    MainWindow, XrayConnectionRow, XrayHostRow, XrayModule, XrayPortRow, XrayPortUser,
    XrayProfileRow, XraySubscriptionGroup,
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

mod port_editor;

use port_editor::PortEdit;
pub(super) use port_editor::wire_port_editor;

enum Command {
    Install,
    CheckUpdates,
    InstallUpdate,
    Toggle,
    Restart,
    Import(String),
    InstallHpwnr(Option<String>),
    CheckHpwnrUpdates,
    UpdateHpwnr,
    RefreshSubscription(String),
    Activate(String),
    AssignPort(String, String),
    AddPort,
    RemovePort(String),
    Remove(String),
    RefreshHosts,
    SaveDraft(i32, SettingsDraft),
    SaveDnsExit(String),
    SavePort(PortEdit, i32),
    RefreshGeo,
    LoadGeoTags,
    Record(bool),
}

struct SettingsDraft {
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
        update_field(&mut settings.dns, parse_dns_draft(&self.dns), &mut error);
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

pub(super) fn parse_dns_draft(input: &str) -> Result<Vec<String>> {
    ensure!(!input.trim().is_empty(), "Enter a DNS resolver or Default.");
    profile::parse_dns(input)
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

fn same_runtime_settings(applied: &Settings, saved: &Settings) -> bool {
    applied
        .ports
        .iter()
        .map(|p| (&p.id, p.number))
        .eq(saved.ports.iter().map(|p| (&p.id, p.number)))
        && applied.dns == saved.dns
        && (applied.dns.is_empty() || applied.dns_exit_profile_id == saved.dns_exit_profile_id)
        && applied.direct_ips == saved.direct_ips
        && applied.direct_domains == saved.direct_domains
        && applied.geo_refreshed_at == saved.geo_refreshed_at
        && applied.enabled_profiles().count() == saved.enabled_profiles().count()
        && applied.enabled_profiles().all(|old| {
            saved.enabled_profiles().any(|new| {
                old.id == new.id
                    && old.same_outbound(new)
                    && applied.upstream_ip(old) == saved.upstream_ip(new)
                    && old.port_id == new.port_id
                    && applied.effective_port(old) == saved.effective_port(new)
            })
        })
}

fn check_dns_exit(settings: &Settings) -> Result<()> {
    if let Some(error) = settings.dns_exit_error() {
        anyhow::bail!(error);
    }
    Ok(())
}

pub(super) fn set_dns_exit(settings: &mut Settings, id: String) -> Result<()> {
    ensure!(
        id.is_empty() || settings.enabled_profiles().any(|profile| profile.id == id),
        "Choose an enabled profile for DNS exits through."
    );
    settings.dns_exit_profile_id = (!id.is_empty()).then_some(id);
    Ok(())
}

struct Controller {
    directory: PathBuf,
    settings_path: PathBuf,
    settings: Settings,
    installed: Option<Installed>,
    hpwnr_installed: Option<Installed>,
    hpwnr_latest: Option<Release>,
    hpwnr_update_status: String,
    latest: Option<Release>,
    runtime: Option<Runtime>,
    runtime_geo: Option<PathBuf>,
    applied: Option<Settings>,
    failed_ports: Vec<LivePort>,
    delete_error: Option<(String, String)>,
    replacement: Option<String>,
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
        let hpwnr_installed = assets::hpwnr_installation(&directory).ok().flatten();
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
            hpwnr_installed,
            hpwnr_latest: None,
            hpwnr_update_status: String::new(),
            latest: None,
            runtime: None,
            runtime_geo: None,
            applied: None,
            failed_ports: Vec::new(),
            delete_error: None,
            replacement: None,
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
        next.save(&self.settings_path)?;
        if let Some(applied) = &self.applied {
            self.pending = !same_runtime_settings(applied, &next) || runtime_change;
        }
        if !self.failed_ports.is_empty() && !same_runtime_settings(&self.settings, &next) {
            self.failed_ports.clear();
        }
        self.delete_error = None;
        self.settings = next;
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
            Command::InstallHpwnr(import) => {
                let release = assets::latest_hpwnr()?;
                self.hpwnr_installed = Some(assets::install_hpwnr(&self.directory, &release)?);
                self.hpwnr_update_status = "Installed".into();
                if let Some(input) = import {
                    self.perform(Command::Import(input))?;
                }
            }
            Command::CheckHpwnrUpdates => {
                let release = assets::latest_hpwnr()?;
                let available = self
                    .hpwnr_installed
                    .as_ref()
                    .is_none_or(|installed| newer(&release.version, &installed.version));
                self.hpwnr_update_status = if available {
                    "An hpwnr update is available."
                } else {
                    "You're using the latest hpwnr version."
                }
                .into();
                self.hpwnr_latest = available.then_some(release);
            }
            Command::UpdateHpwnr => {
                let release = self
                    .hpwnr_latest
                    .as_ref()
                    .context("Check for hpwnr updates first")?;
                self.hpwnr_installed = Some(assets::install_hpwnr(&self.directory, release)?);
                self.hpwnr_latest = None;
                self.hpwnr_update_status = "hpwnr updated successfully.".into();
            }
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
                check_dns_exit(&self.settings)?;
                for profile in self.settings.enabled_profiles() {
                    let port = self.settings.effective_port(profile);
                    if let Err(error) = self.check_port(port) {
                        self.failed_ports = vec![LivePort {
                            id: profile.port_id.clone(),
                            number: port,
                            error: Some(format!("{error:#}")),
                        }];
                        return Err(error);
                    }
                    self.settings.upstream_ip(profile).context(
                        "Refresh VPN server addresses in X-RAY → DNS before restarting Xray",
                    )?;
                }
                if self.settings.enabled_profiles().next().is_none() {
                    return self.set_running(false);
                }
                self.stop();
                self.set_running(true)?;
            }
            Command::Import(input) => {
                let directory = self.directory.clone();
                self.change(false, |settings| {
                    let domains = settings.import_with_assets(&input, &directory)?;
                    settings.resolve_hosts(domains);
                    Ok(())
                })?;
            }
            Command::RefreshSubscription(id) => {
                let directory = self.directory.clone();
                self.change(false, |settings| {
                    let domains = settings.refresh_subscription_with_assets(&id, &directory)?;
                    settings.resolve_hosts(domains);
                    Ok(())
                })?;
            }
            Command::Activate(id) => {
                let mut next = self.settings.clone();
                let replaced = next.toggle_profile(&id)?;
                self.save_profile_change(next, &id, replaced)?;
            }
            Command::AssignPort(id, port_id) => {
                let mut next = self.settings.clone();
                let replaced = next.set_profile_port(&id, &port_id)?;
                self.save_profile_change(next, &id, replaced)?;
            }
            Command::AddPort => {
                let owned = self.owned_numbers();
                self.change(false, |settings| settings.add_port(&owned).map(|_| ()))?;
            }
            Command::RemovePort(id) => {
                let mut next = self.settings.clone();
                if let Err(error) = next.remove_port(&id) {
                    self.delete_error = Some((id, error.to_string()));
                } else {
                    self.save_settings(next, false)?;
                }
            }
            Command::Remove(id) => {
                self.change(false, |settings| {
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
            Command::SaveDnsExit(id) => {
                self.change(false, |settings| set_dns_exit(settings, id))?
            }
            Command::SavePort(edit, _) => {
                let mut next = self.settings.clone();
                edit.apply(&mut next, &self.owned_numbers())?;
                self.save_settings(next, false)?;
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

    fn owned_numbers(&self) -> Vec<u16> {
        self.applied
            .iter()
            .flat_map(|settings| {
                settings
                    .enabled_profiles()
                    .map(|p| settings.effective_port(p))
            })
            .filter(|port| {
                self.runtime
                    .as_ref()
                    .is_some_and(|run| run.owns_listener(*port))
            })
            .collect()
    }

    fn save_profile_change(
        &mut self,
        mut next: Settings,
        id: &str,
        replaced: Option<String>,
    ) -> Result<()> {
        let profile = next
            .profiles
            .iter()
            .find(|profile| profile.id == id)
            .context("Profile not found")?;
        let port = next.port(&profile.port_id)?;
        let message = replaced.map(|name| format!("Replaced {name} on {}", port.name));
        if profile.enabled {
            self.check_port(port.number)?;
            if next.upstream_ip(profile).is_none() {
                next.resolve_hosts(std::iter::once(profile.host.clone()).collect());
            }
        }
        self.save_settings(next, false)?;
        self.replacement = message;
        Ok(())
    }

    fn save_draft(&mut self, draft: SettingsDraft) -> Result<()> {
        let mut next = self.settings.clone();
        let validation = draft.apply(&mut next);
        let runtime_changed = next.dns != self.settings.dns
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
            self.save_settings(next, false)?;
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
        check_dns_exit(&self.settings)?;
        if let Err(error) = self.start() {
            self.failed_ports = live_ports(&self.settings, Some(format!("{error:#}")));
            if let Some(failed) = error.downcast_ref::<runtime::ListenerUnavailable>() {
                self.failed_ports.retain(|port| port.number == failed.port);
            }
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
        self.applied = None;
        self.failed_ports.clear();
        let _ = assets::prune_geo(&self.directory, None);
        self.pending = false;
        self.status = "Stopped".into();
    }

    fn check_port(&self, port: u16) -> Result<()> {
        if self
            .runtime
            .as_ref()
            .is_some_and(|runtime| runtime.owns_listener(port))
        {
            return Ok(());
        }
        runtime::check_listener_port(port)
    }

    fn start(&mut self) -> Result<()> {
        let installed = self.installed.as_ref().context("Install Xray-core first")?;
        let listeners = self
            .settings
            .enabled_profiles()
            .map(|profile| {
                let upstream_ip = self.settings.upstream_ip(profile).with_context(|| {
                    format!(
                        "No saved IP address for {}. Open X-RAY → DNS and select Refresh.",
                        profile.name
                    )
                })?;
                Ok(runtime::Listener {
                    port_id: profile.port_id.clone(),
                    profile_id: profile.id.clone(),
                    port: self.settings.effective_port(profile),
                    upstream: profile.host.clone(),
                    upstream_port: profile.port,
                    upstream_ip: Some(upstream_ip),
                    outbound: profile.outbound()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !listeners.is_empty(),
            "Turn on a profile in Profiles first."
        );
        let geo_directory = assets::geo_directory(&self.directory)?
            .or_else(|| installed.executable.parent().map(Path::to_path_buf))
            .context("Missing Xray database directory")?;
        let settings = runtime::Settings {
            listeners: &listeners,
            dns_servers: &self.settings.dns,
            dns_exit_profile_id: self.settings.dns_exit_profile_id.as_deref(),
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
        self.applied = Some(self.settings.clone());
        self.failed_ports.clear();
        self.status.clear();
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
                    let error = result.err().unwrap_or_else(|| {
                        anyhow::anyhow!("Xray exited unexpectedly. Check Logs for details.")
                    });
                    let failed = self
                        .applied
                        .as_ref()
                        .map(|settings| live_ports(settings, Some(format!("{error:#}"))))
                        .unwrap_or_default();
                    self.stop();
                    self.failed_ports = failed;
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

#[derive(Clone)]
struct LivePort {
    id: String,
    number: u16,
    error: Option<String>,
}

fn live_ports(settings: &Settings, error: Option<String>) -> Vec<LivePort> {
    settings
        .enabled_profiles()
        .map(|profile| LivePort {
            id: profile.port_id.clone(),
            number: settings.effective_port(profile),
            error: error.clone(),
        })
        .collect()
}

fn show_ports(
    ui: &MainWindow,
    settings: &Settings,
    live: &[LivePort],
    delete_error: Option<&(String, String)>,
    next_free: Option<u16>,
) {
    let xray = ui.global::<XrayModule>();
    let mut labels = Vec::new();
    let mut rows = Vec::new();
    let listening: Vec<_> = live
        .iter()
        .filter(|p| p.error.is_none())
        .map(|p| i32::from(p.number))
        .collect();
    let summary = match listening.as_slice() {
        [] => "No ports listening".into(),
        [number] => format!("127.0.0.1:{number}"),
        ports => format!("{} ports listening", ports.len()),
    };
    xray.set_listener_summary(summary.into());
    xray.set_listening_numbers(model(listening));
    for port in &settings.ports {
        labels.push(format!("{} · {}", port.name, port.number).into());
        let mut users = Vec::new();
        let mut used_count = 0;
        let mut enabled = false;
        for profile in settings.profiles.iter().filter(|p| p.port_id == port.id) {
            used_count += 1;
            enabled |= profile.enabled;
            if users.len() < 3 {
                users.push(XrayPortUser {
                    id: profile.id.as_str().into(),
                    name: profile.name.as_str().into(),
                });
            }
        }
        let running = live.iter().find(|p| p.error.is_none() && p.id == port.id);
        let failure = live
            .iter()
            .find(|p| p.id == port.id && p.number == port.number && p.error.is_some());
        let (status, detail) = if let Some(reason) = failure.and_then(|p| p.error.as_deref()) {
            ("Error", reason.to_owned())
        } else if let Some(actual) = running {
            if actual.number == port.number {
                (
                    "Listening",
                    if enabled {
                        String::new()
                    } else {
                        "Will stop on restart.".into()
                    },
                )
            } else {
                (
                    "Idle",
                    format!("Listening on {} until restart.", actual.number),
                )
            }
        } else {
            (
                "Idle",
                if enabled {
                    "The selected profile has not started on this port.".into()
                } else {
                    String::new()
                },
            )
        };
        rows.push(XrayPortRow {
            id: port.id.as_str().into(),
            name: port.name.as_str().into(),
            number: port.number.to_string().into(),
            is_default: port.is_default,
            status: status.into(),
            status_detail: detail.into(),
            used_count,
            users: model(users),
            delete_error: delete_error
                .filter(|(id, _)| id == &port.id)
                .map_or("", |(_, err)| err.as_str())
                .into(),
        });
    }
    xray.set_ports(update_rows(xray.get_ports(), rows, |a, b| a.id == b.id));
    xray.set_port_labels(model(labels));
    xray.set_next_free_port(
        next_free
            .map_or_else(|| "unavailable".into(), |number| number.to_string())
            .into(),
    );
    xray.invoke_port_owners_changed();
}

pub(super) fn show_preview_ports(
    ui: &MainWindow,
    settings: &Settings,
    delete_error: Option<&(String, String)>,
) {
    show_ports(
        ui,
        settings,
        &[],
        delete_error,
        settings.next_free_port(&[]).ok(),
    );
}

struct View {
    settings: Settings,
    version: String,
    latest: String,
    status: String,
    pending: bool,
    ports: Vec<LivePort>,
    delete_error: Option<(String, String)>,
    next_free: Option<u16>,
    geo_status: String,
    started: Option<std::time::Instant>,
    hpwnr_installed: bool,
    hpwnr_version: String,
    hpwnr_latest: String,
    hpwnr_update_status: String,
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
            ports: controller
                .applied
                .iter()
                .flat_map(|settings| live_ports(settings, None))
                .chain(controller.failed_ports.iter().cloned())
                .collect(),
            delete_error: controller.delete_error.clone(),
            next_free: controller.installed.as_ref().and_then(|_| {
                controller
                    .settings
                    .next_free_port(&controller.owned_numbers())
                    .ok()
            }),
            geo_status: controller.geo_status.clone(),
            started: controller.runtime.as_ref().map(Runtime::started_at),
            hpwnr_installed: controller.hpwnr_installed.is_some(),
            hpwnr_version: controller
                .hpwnr_installed
                .as_ref()
                .map_or_else(String::new, |installed| installed.version.clone()),
            hpwnr_latest: controller
                .hpwnr_latest
                .as_ref()
                .map_or_else(String::new, |release| release.version.clone()),
            hpwnr_update_status: controller.hpwnr_update_status.clone(),
        }
    }

    fn apply(self, ui: &MainWindow, command_done: bool) {
        let xray = ui.global::<XrayModule>();
        xray.set_hpwnr_installed(self.hpwnr_installed);
        xray.set_hpwnr_version(self.hpwnr_version.into());
        xray.set_hpwnr_latest_version(self.hpwnr_latest.into());
        xray.set_hpwnr_update_status(self.hpwnr_update_status.into());
        xray.set_installed(!self.version.is_empty());
        xray.set_version(self.version.into());
        xray.set_latest_version(self.latest.into());
        xray.set_running(self.started.is_some());
        xray.set_status(self.status.into());
        xray.set_pending(self.pending);
        show_ports(
            ui,
            &self.settings,
            &self.ports,
            self.delete_error.as_ref(),
            self.next_free,
        );
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
        show_profiles(ui, &self.settings);
        xray.set_log_recording(self.settings.log_recording);
        if command_done {
            xray.set_busy(false);
        }
    }
}

pub(super) fn show_profiles(ui: &MainWindow, settings: &Settings) {
    let xray = ui.global::<XrayModule>();

    xray.set_enabled_count(settings.enabled_profiles().count() as i32);
    let mut manual = Vec::new();
    let mut groups = BTreeMap::<&str, Vec<XrayProfileRow>>::new();
    let mut selected = XrayProfileRow::default();
    for profile in &settings.profiles {
        let row = XrayProfileRow {
            active: profile.enabled,
            port_index: settings
                .ports
                .iter()
                .position(|port| port.id == profile.port_id)
                .expect("validated port binding") as i32,
            id: profile.id.as_str().into(),
            name: profile.name.as_str().into(),
            summary: format!("VLESS · {}:{}", profile.host, profile.port).into(),
        };
        if row.active && selected.id.is_empty() {
            selected = row.clone();
        }
        if let Some(source) = &profile.subscription {
            groups.entry(source.as_str()).or_default().push(row);
        } else {
            manual.push(row);
        }
    }
    xray.set_selected_profile(selected);
    let old_profiles = xray.get_profiles();
    xray.set_profiles(update_rows(old_profiles, manual, |a, b| a.id == b.id));
    let old_groups = xray.get_subscriptions();
    let subscriptions = settings
        .subscription_ids()
        .enumerate()
        .map(|(index, id)| {
            let profiles = groups.remove(id).unwrap_or_default();
            let previous = old_groups.row_data(index).filter(|group| group.id == id);
            XraySubscriptionGroup {
                id: id.into(),
                name: format!("Subscription {}", index + 1).into(),
                active_removed: settings.active_profile_removed(Some(id)),
                profiles: update_rows(
                    previous.map_or_else(ModelRc::default, |group| group.profiles),
                    profiles,
                    |a, b| a.id == b.id,
                ),
            }
        })
        .collect();
    xray.set_subscriptions(update_rows(old_groups, subscriptions, |a, b| a.id == b.id));
    let mut names = vec!["Not selected".into()];
    let mut ids = vec![SharedString::default()];
    for profile in settings.enabled_profiles() {
        names.push(format!("{} · :{}", profile.name, settings.effective_port(profile)).into());
        ids.push(profile.id.as_str().into());
    }
    xray.set_dns_exit_profiles(model(names));
    xray.set_dns_exit_profile_ids(model(ids));
    xray.set_dns_exit_profile_id(
        settings
            .dns_exit_profile_id
            .as_deref()
            .unwrap_or_default()
            .into(),
    );
    xray.set_dns_exit_index(dns_exit_index(&xray));
    xray.set_dns_exit_error(settings.dns_exit_error().unwrap_or_default().into());
    xray.set_dns_exit_warning(settings.dns_exit_warning().unwrap_or_default().into());
}

fn update_rows<T: Clone + PartialEq + 'static>(
    previous: ModelRc<T>,
    rows: Vec<T>,
    same_row: impl Fn(&T, &T) -> bool,
) -> ModelRc<T> {
    // Updating existing rows keeps the TextInput and its focus alive after autosave.
    if previous.as_any().is::<slint::VecModel<T>>()
        && previous.row_count() == rows.len()
        && previous
            .iter()
            .zip(&rows)
            .all(|(old, row)| same_row(&old, row))
    {
        for (index, row) in rows.into_iter().enumerate() {
            if previous.row_data(index).as_ref() != Some(&row) {
                previous.set_row_data(index, row);
            }
        }
        previous
    } else {
        model(rows)
    }
}

fn dns_exit_index(xray: &XrayModule<'_>) -> i32 {
    let selected = xray.get_dns_exit_profile_id();
    xray.get_dns_exit_profile_ids()
        .iter()
        .position(|id| id == selected)
        .unwrap_or_default() as i32
}

fn wire_import(ui: &MainWindow, send: Rc<dyn Fn(Command)>) {
    let pending = Rc::new(RefCell::new(None::<String>));
    let xray = ui.global::<XrayModule>();
    let weak = ui.as_weak();
    let request = pending.clone();
    let import = send.clone();
    xray.on_import_profile(move |input| {
        let Some(ui) = weak.upgrade() else { return };
        let xray = ui.global::<XrayModule>();
        if xray.get_busy() {
            return;
        }
        let required = true_proxy::xray::hpwnr::encrypted(&input) && !xray.get_hpwnr_installed();
        xray.set_hpwnr_required(required);
        *request.borrow_mut() = required.then(|| input.to_string());
        if !required {
            import(Command::Import(input.to_string()));
        }
    });
    let weak = ui.as_weak();
    let request = pending.clone();
    xray.on_confirm_hpwnr(move || {
        let Some(ui) = weak.upgrade() else { return };
        let xray = ui.global::<XrayModule>();
        if xray.get_busy() {
            return;
        }
        xray.set_hpwnr_required(false);
        if let Some(input) = request.borrow_mut().take() {
            if xray.get_profile_input() == input {
                send(Command::InstallHpwnr(Some(input)));
            } else {
                xray.set_error("The link changed. Select Import again to continue.".into());
            }
        }
    });
    let weak = ui.as_weak();
    xray.on_cancel_hpwnr(move || {
        pending.borrow_mut().take();
        if let Some(ui) = weak.upgrade() {
            ui.global::<XrayModule>().set_hpwnr_required(false);
        }
    });
}

fn set_error(xray: &XrayModule<'_>, manages_core: bool, hpwnr: bool, error: String) {
    if hpwnr {
        if !error.is_empty() {
            xray.set_hpwnr_update_status("".into());
        }
        xray.set_hpwnr_error(error.into());
    } else if manages_core {
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
                        xray.invoke_process_port_edits();
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
                let (result, command_done, manages_core, hpwnr, revision, port_edit) =
                    match receiver.recv_timeout(interval) {
                        Ok(command) => {
                            let port_edit = match &command {
                                Command::SavePort(edit, revision) => {
                                    Some((edit.id.clone(), edit.number, *revision))
                                }
                                _ => None,
                            };
                            let catalog_only = matches!(command, Command::LoadGeoTags);
                            let manages_core = command.manages_core();
                            let hpwnr = matches!(
                                command,
                                Command::InstallHpwnr(_)
                                    | Command::CheckHpwnrUpdates
                                    | Command::UpdateHpwnr
                            );
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
                            let command_done = port_edit.is_none();
                            (
                                Some(error),
                                command_done,
                                manages_core,
                                hpwnr,
                                revision,
                                port_edit,
                            )
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            (controller.poll(), false, false, false, None, None)
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                if let Some(error) = result {
                    let replacement = controller.replacement.take();
                    let view = View::new(&controller);
                    *started.lock().unwrap() = view.started;
                    let weak = weak.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            view.apply(&ui, command_done);
                            if let Some(message) = replacement {
                                super::show_toast(&ui, message, false);
                            }
                            let xray = ui.global::<XrayModule>();
                            let port_done = port_edit.is_some();
                            if let Some((owner, profile, revision)) = port_edit {
                                xray.invoke_finish_port_edit(
                                    owner.into(),
                                    profile,
                                    revision,
                                    error.into(),
                                );
                            } else if let Some(revision) = revision {
                                if revision == xray.get_settings_revision() {
                                    xray.set_settings_saving(false);
                                    xray.set_settings_error(error.into());
                                }
                            } else {
                                set_error(&xray, manages_core, hpwnr, error);
                            }
                            if command_done || port_done {
                                xray.invoke_process_port_edits();
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
    let restoring = installed
        && controller.settings.enabled
        && !paused
        && controller.settings.dns_exit_error().is_none();
    let started = Arc::new(std::sync::Mutex::new(None));
    View::new(&controller).apply(ui, true);
    let xray = ui.global::<XrayModule>();
    let settings = &controller.settings;
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
    let port_queue = queue.clone();
    wire_port_editor(ui, move |_, edit, revision| {
        port_queue(Command::SavePort(edit, revision))
    });
    let weak = ui.as_weak();
    let send: Rc<dyn Fn(Command)> = Rc::new(move |command: Command| {
        if let Some(ui) = weak.upgrade() {
            let xray = ui.global::<XrayModule>();
            if xray.get_busy() {
                return;
            }
            let manages_core = command.manages_core();
            let checking_hpwnr = matches!(command, Command::CheckHpwnrUpdates);
            let hpwnr = matches!(
                command,
                Command::InstallHpwnr(_) | Command::CheckHpwnrUpdates | Command::UpdateHpwnr
            );
            if queue(command) {
                xray.set_busy(true);
                set_error(&xray, manages_core, hpwnr, String::new());
                if checking_hpwnr {
                    xray.set_hpwnr_update_status("Checking for updates…".into());
                }
            } else {
                set_error(
                    &xray,
                    manages_core,
                    hpwnr,
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
    let weak = ui.as_weak();
    let save = send.clone();
    xray.on_save_dns_exit(move |id| {
        let Some(ui) = weak.upgrade() else { return };
        let xray = ui.global::<XrayModule>();
        if id != xray.get_dns_exit_profile_id() {
            save(Command::SaveDnsExit(id.into()));
            if !xray.get_busy() {
                xray.set_dns_exit_index(dns_exit_index(&xray));
            }
        }
    });
    bind!(on_refresh_hosts, Command::RefreshHosts);
    bind!(on_refresh_geo, Command::RefreshGeo);
    bind!(on_install_hpwnr, Command::InstallHpwnr(None));
    bind!(on_check_hpwnr_updates, Command::CheckHpwnrUpdates);
    bind!(on_update_hpwnr, Command::UpdateHpwnr);
    wire_import(ui, send.clone());
    bind!(
        on_refresh_subscription,
        Command::RefreshSubscription,
        string
    );
    bind!(on_activate_profile, Command::Activate, string);
    bind!(on_remove_profile, Command::Remove, string);
    bind!(on_add_port, Command::AddPort);
    bind!(on_remove_port, Command::RemovePort, string);
    let assign = send.clone();
    xray.on_assign_profile_port(move |id, port_id| {
        assign(Command::AssignPort(id.into(), port_id.into()))
    });
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
    fn encrypted_import_requires_confirmation_and_cancel_never_queues_downloads() {
        use i_slint_backend_testing::{AccessibleRole, ElementHandle};
        use slint::platform::PointerEventButton;
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1240., 780.));
        ui.set_page(6);
        let commands = Rc::new(RefCell::new(Vec::new()));
        let queue = commands.clone();
        wire_import(
            &ui,
            Rc::new(move |command| queue.borrow_mut().push(command)),
        );
        let xray = ui.global::<XrayModule>();
        xray.set_installed(true);
        xray.set_section(1);
        ui.show().unwrap();
        let click = |label| {
            ElementHandle::find_by_accessible_label(&ui, label)
                .find(|element| element.accessible_role() == Some(AccessibleRole::Button))
                .unwrap()
                .mock_single_click(PointerEventButton::Left)
        };
        let encrypted = "v2raytun://crypt/abcd";
        xray.set_profile_input(encrypted.into());
        click("Import");
        assert!(xray.get_hpwnr_required());
        assert!(commands.borrow().is_empty());
        click("Cancel");
        xray.invoke_confirm_hpwnr();
        assert!(!xray.get_hpwnr_required());
        assert!(commands.borrow().is_empty());
        xray.invoke_import_profile(encrypted.into());
        click("Install and Import");
        assert!(
            matches!(commands.borrow_mut().pop(), Some(Command::InstallHpwnr(Some(input))) if input == encrypted)
        );
        xray.set_hpwnr_installed(true);
        xray.invoke_import_profile(encrypted.into());
        assert!(
            matches!(commands.borrow_mut().pop(), Some(Command::Import(input)) if input == encrypted)
        );
        xray.set_hpwnr_installed(false);
        xray.invoke_import_profile(encrypted.into());
        xray.set_profile_input("vless://changed".into());
        xray.invoke_confirm_hpwnr();
        assert!(commands.borrow().is_empty());
    }

    #[test]
    fn xray_autosave_preserves_invalid_fields_and_keeps_valid_edits() {
        let mut settings = Settings::default();
        let draft = SettingsDraft {
            dns: "tcp://".into(),
            ips: vec!["geoip:private".into()],
            domains: settings.direct_domains.clone(),
            geoip: settings.geoip_url.clone(),
            geosite: settings.geosite_url.clone(),
            hours: "48".into(),
        };
        assert!(draft.apply(&mut settings).is_err());
        assert!(settings.dns.is_empty());
        assert_eq!(settings.direct_ips, ["geoip:private"]);
        assert_eq!(settings.geo_refresh_hours, 48);
    }

    #[test]
    fn changing_dns_exit_persists_the_profile_id_and_leaves_the_applied_config_pending() {
        let directory =
            std::env::temp_dir().join(format!("true-proxy-dns-exit-{}", super::super::id()));
        let mut controller = Controller::load(
            directory.clone(),
            Arc::new(Bypass::default()),
            Arc::new(Activity::default()),
            SharedGeoCatalog::default(),
        )
        .unwrap();
        for host in ["192.0.2.1", "192.0.2.2"] {
            controller.settings.import(&format!(
                "vless://00000000-0000-4000-8000-000000000001@{host}:443?security=tls&type=tcp#Tunnel"
            )).unwrap();
        }
        let first = controller.settings.profiles[0].id.clone();
        let second = controller.settings.profiles[1].id.clone();
        let us = controller.settings.add_port(&[]).unwrap();
        controller.settings.set_profile_port(&second, &us).unwrap();
        controller.settings.toggle_profile(&second).unwrap();
        controller.settings.dns.push("1.1.1.1".into());
        set_dns_exit(&mut controller.settings, first.clone()).unwrap();
        controller.applied = Some(controller.settings.clone());

        controller
            .perform(Command::SaveDnsExit(second.clone()))
            .unwrap();
        let saved = Settings::load(&controller.settings_path).unwrap();
        assert_eq!(saved.dns_exit_profile_id.as_ref(), Some(&second));
        assert_eq!(controller.applied.unwrap().dns_exit_profile_id, Some(first));
        assert!(controller.pending);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn changing_profiles_keeps_live_port_rows_until_restart_and_rejects_occupied_edits() {
        let directory =
            std::env::temp_dir().join(format!("true-proxy-port-view-{}", super::super::id()));
        let mut controller = Controller::load(
            directory.clone(),
            Arc::new(Bypass::default()),
            Arc::new(Activity::default()),
            SharedGeoCatalog::default(),
        )
        .unwrap();
        for (host, name) in [("192.0.2.1", "First"), ("192.0.2.2", "Second")] {
            controller.settings.import(&format!(
                "vless://00000000-0000-4000-8000-000000000001@{host}:443?security=tls&type=tcp#{name}"
            )).unwrap();
        }
        let second = controller.settings.profiles[1].id.clone();
        let first_port = controller.settings.default_port().clone();
        controller.perform(Command::AddPort).unwrap();
        controller.applied = Some(controller.settings.clone());
        controller
            .perform(Command::Activate(second.clone()))
            .unwrap();
        assert!(controller.pending);
        assert_eq!(
            controller.replacement.as_deref(),
            Some("Replaced First on Default")
        );
        let snapshot = View::new(&controller);
        assert_eq!(
            snapshot.ports.len(),
            1,
            "Idle ports must have no live listener"
        );
        assert_eq!(snapshot.ports[0].id, first_port.id);
        assert_eq!(snapshot.ports[0].number, first_port.number);
        let saved = Settings::load(&controller.settings_path).unwrap();
        assert_eq!(saved.enabled_profiles().next().unwrap().id, second);
        let occupied = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = occupied.local_addr().unwrap().port();
        assert!(
            controller
                .perform(Command::SavePort(
                    PortEdit {
                        id: first_port.id.clone(),
                        number: true,
                        value: port.to_string()
                    },
                    0
                ))
                .is_err()
        );
        assert_eq!(
            Settings::load(&controller.settings_path)
                .unwrap()
                .default_port()
                .number,
            first_port.number
        );
        drop(occupied);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_cold_start_bind_error_identifies_only_the_occupied_listener() {
        use std::net::{Ipv4Addr, UdpSocket};
        let directory = std::env::temp_dir().join(format!("xray-occupied-{}", super::super::id()));
        let mut controller = Controller::load(
            directory.clone(),
            Arc::new(Bypass::default()),
            Arc::new(Activity::default()),
            SharedGeoCatalog::default(),
        )
        .unwrap();
        for host in ["192.0.2.1", "192.0.2.2"] {
            controller.settings.import(&format!("vless://00000000-0000-4000-8000-000000000001@{host}:443?security=tls&type=tcp#Node")).unwrap();
        }
        let first_port = controller.settings.default_port().id.clone();
        let free = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let number = free.local_addr().unwrap().port();
        drop(free);
        controller
            .settings
            .set_port_number(&first_port, number, &[])
            .unwrap();
        let other = controller.settings.add_port(&[]).unwrap();
        let profile = controller.settings.profiles[1].id.clone();
        controller
            .settings
            .set_profile_port(&profile, &other)
            .unwrap();
        controller.settings.toggle_profile(&profile).unwrap();
        let occupied = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        // A different program acquired this saved endpoint before startup.
        controller
            .settings
            .ports
            .iter_mut()
            .find(|port| port.id == other)
            .unwrap()
            .number = occupied.local_addr().unwrap().port();
        controller.installed = Some(Installed {
            version: "fixture".into(),
            executable: directory.join("unused.exe"),
            sha256: String::new(),
        });
        let error = controller.set_running(true).unwrap_err();
        assert!(
            error
                .downcast_ref::<runtime::ListenerUnavailable>()
                .is_some()
        );
        assert_eq!(controller.failed_ports.len(), 1);
        assert_eq!(controller.failed_ports[0].id, other);
        assert!(
            controller.failed_ports[0]
                .error
                .as_deref()
                .unwrap()
                .contains("UDP")
        );
        drop(occupied);
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
