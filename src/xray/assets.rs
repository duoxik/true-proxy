//! Optional Xray executable and geodata installed in immutable snapshots.
use anyhow::{Context, Result, ensure};
use semver::Version;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

mod geodata;

const CORE_MANIFEST: &str = "core.json";
const GEO_MANIFEST: &str = "geodata.json";
const MAX_ARCHIVE: u64 = 64 * 1024 * 1024;
const MAX_GEODATA: u64 = 128 * 1024 * 1024;
const MAX_METADATA: u64 = 512 * 1024;
const CORE_ASSET: &str = "Xray-windows-64.zip";
const CORE_REPOSITORY: &str = "XTLS/Xray-core";
const GEO_REPOSITORY: &str = "XTLS/Xray-rules-dat";
pub(super) const HPWNR_FILE: &str = "hpwnr-v1.0.3.exe";
pub(super) const HPWNR_SHA256: &str =
    "ee7a63670cf7a6fb84b24712c40746d2181dcb02df1b5b59914f4651db301094";
const HPWNR_SIZE: u64 = 2_036_736;
const HPWNR_URL: &str =
    "https://github.com/Omegaplexx/hpwnr/releases/download/v1.0.3/hpwnr-windows-x64.exe";
pub const GEO_SOURCE: &str = "https://github.com/XTLS/Xray-rules-dat";
pub const DEFAULT_GEOIP_URL: &str =
    "https://github.com/XTLS/Xray-rules-dat/releases/latest/download/geoip-lite.dat";
pub const DEFAULT_GEOSITE_URL: &str =
    "https://github.com/XTLS/Xray-rules-dat/releases/latest/download/geosite.dat";

#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    asset: VerifiedAsset,
}

#[derive(Clone, Debug)]
pub struct Installed {
    pub version: String,
    pub executable: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Debug)]
struct VerifiedAsset {
    id: u64,
    size: u64,
    sha256: String,
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

#[derive(Deserialize)]
struct GithubAsset {
    id: u64,
    name: String,
    size: u64,
    digest: Option<String>,
    state: String,
}

impl GithubRelease {
    fn asset(&self, name: &str, max: u64) -> Result<VerifiedAsset> {
        let mut matching = self.assets.iter().filter(|entry| entry.name == name);
        let asset = matching.next().context("GitHub release asset is missing")?;
        ensure!(matching.next().is_none(), "Ambiguous GitHub release asset");
        ensure!(
            asset.state == "uploaded" && asset.id > 0 && (1..=max).contains(&asset.size),
            "Invalid GitHub release asset"
        );
        let sha256 = asset
            .digest
            .as_deref()
            .and_then(|digest| digest.strip_prefix("sha256:"))
            .context("GitHub did not provide a SHA-256 digest")?;
        crate::updates::validate_digest(sha256)?;
        Ok(VerifiedAsset {
            id: asset.id,
            size: asset.size,
            sha256: sha256.to_ascii_lowercase(),
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CoreRecord {
    version: String,
    archive_sha256: String,
    executable_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GeoRecord {
    directory: String,
}

pub fn latest() -> Result<Release> {
    let release = github_release(CORE_REPOSITORY)?;
    let version = release
        .tag_name
        .strip_prefix('v')
        .unwrap_or(&release.tag_name);
    let version = stable_version(version)?.to_string();
    Ok(Release {
        version,
        asset: release.asset(CORE_ASSET, MAX_ARCHIVE)?,
    })
}

pub fn installed_hpwnr(root: &Path) -> Result<Option<PathBuf>> {
    let target = root.join(HPWNR_FILE);
    match fs::symlink_metadata(&target) {
        Ok(_) => {
            plain_directory(root)?;
            plain_file(&target)?;
            ensure!(
                fs::metadata(&target)?.len() == HPWNR_SIZE,
                "Invalid hpwnr size"
            );
            verify_file(&target, HPWNR_SHA256)?;
            crate::updates::validate_pe(&target)?;
            Ok(Some(target))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Download only after an explicit module installation request.
pub fn hpwnr(root: &Path) -> Result<PathBuf> {
    let target = root.join(HPWNR_FILE);
    match fs::symlink_metadata(&target) {
        Ok(_) => {
            plain_directory(root)?;
            plain_file(&target)?;
            if let Ok(Some(installed)) = installed_hpwnr(root) {
                return Ok(installed);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let stage = Stage::new(root, "decoder")?;
    let binary = stage.path.join(HPWNR_FILE);
    let size = download_file(HPWNR_URL, Some(true), HPWNR_SIZE, &binary)?;
    ensure!(size == HPWNR_SIZE, "Invalid hpwnr download size");
    verify_file(&binary, HPWNR_SHA256)?;
    crate::updates::validate_pe(&binary)?;
    crate::platform::replace_file(&binary, &target)?;
    Ok(target)
}

pub fn installed(root: &Path) -> Result<Option<Installed>> {
    let Some(record) = read_record::<CoreRecord>(&root.join(CORE_MANIFEST))? else {
        return Ok(None);
    };
    plain_directory(root)?;
    stable_version(&record.version)?;
    crate::updates::validate_digest(&record.archive_sha256)?;
    crate::updates::validate_digest(&record.executable_sha256)?;
    let directory = root.join(core_directory_name(&record.archive_sha256));
    plain_directory(&directory)?;
    let executable = directory.join("xray.exe");
    plain_file(&executable)?;
    Ok(Some(Installed {
        version: record.version,
        executable,
        sha256: record.executable_sha256,
    }))
}

/// Install into a new directory, then publish the selection with one rename.
/// Older executable snapshots are never overwritten.
pub fn install(root: &Path, release: &Release) -> Result<Installed> {
    let version = stable_version(&release.version)?;
    let previous = installed(root).ok().flatten();
    if let Some(previous) = &previous {
        ensure!(
            version >= stable_version(&previous.version)?,
            "The available Xray release is older than the installed version"
        );
    }
    let stage = Stage::new(root, "install")?;
    let archive = stage.path.join("package.zip");
    download_verified(CORE_REPOSITORY, &release.asset, &archive)?;
    extract_core(&archive, &stage.path)?;
    fs::remove_file(archive)?;
    let executable = stage.path.join("xray.exe");
    crate::updates::validate_pe(&executable)?;
    let executable_sha256 = hash_file(&executable)?;
    let target = root.join(core_directory_name(&release.asset.sha256));
    if target.exists() {
        plain_directory(&target)?;
        let existing = target.join("xray.exe");
        plain_file(&existing)?;
        verify_file(&existing, &executable_sha256)?;
        geodata::validate(&target.join("geoip.dat"), geodata::Kind::Ip)?;
        geodata::validate(&target.join("geosite.dat"), geodata::Kind::Site)?;
    } else {
        fs::rename(&stage.path, &target).context("Could not activate the verified Xray files")?;
    }
    write_record(
        &root.join(CORE_MANIFEST),
        &CoreRecord {
            version: release.version.clone(),
            archive_sha256: release.asset.sha256.clone(),
            executable_sha256,
        },
    )?;
    prune_cores(root, &target, previous.as_ref());
    installed(root)?.context("The Xray installation was not saved")
}

/// A refreshed pair takes precedence over the databases bundled with the core.
pub fn geo_directory(root: &Path) -> Result<Option<PathBuf>> {
    if let Some(record) = read_record::<GeoRecord>(&root.join(GEO_MANIFEST))? {
        let directory = geo_snapshot_path(root, &record.directory)?;
        plain_directory(&directory)?;
        plain_file(&directory.join("geoip.dat"))?;
        plain_file(&directory.join("geosite.dat"))?;
        return Ok(Some(directory));
    }
    Ok(installed(root)?.and_then(|core| core.executable.parent().map(Path::to_path_buf)))
}

/// Return the GeoIP and Geosite categories in the selected database pair.
pub fn geo_tags(root: &Path) -> Result<(Vec<String>, Vec<String>)> {
    let directory = geo_directory(root)?.context("No Xray geodata is installed")?;
    let ip = geodata::tags(&directory.join("geoip.dat"), geodata::Kind::Ip)
        .context("Could not read GeoIP tags")?;
    let site = geodata::tags(&directory.join("geosite.dat"), geodata::Kind::Site)
        .context("Could not read Geosite tags")?;
    Ok((ip, site))
}

/// Download and validate both files before switching the selected pair.
pub fn refresh_geo(root: &Path, geoip_url: &str, geosite_url: &str) -> Result<()> {
    let defaults = geoip_url == DEFAULT_GEOIP_URL || geosite_url == DEFAULT_GEOSITE_URL;
    let upstream = defaults
        .then(|| github_release(GEO_REPOSITORY))
        .transpose()?;
    let stage = Stage::new(root, "geo")?;
    for (url, default, asset, local, kind) in [
        (
            geoip_url,
            DEFAULT_GEOIP_URL,
            "geoip-lite.dat",
            "geoip.dat",
            geodata::Kind::Ip,
        ),
        (
            geosite_url,
            DEFAULT_GEOSITE_URL,
            "geosite.dat",
            "geosite.dat",
            geodata::Kind::Site,
        ),
    ] {
        let file = stage.path.join(local);
        if let Some(release) = upstream.as_ref().filter(|_| url == default) {
            let asset = release.asset(asset, MAX_ARCHIVE)?;
            download_verified(GEO_REPOSITORY, &asset, &file)?;
        } else {
            download_file(url, None, MAX_GEODATA, &file)?;
        }
        geodata::validate(&file, kind).with_context(|| format!("Invalid {local}"))?;
    }
    let directory = stage
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .context("Invalid geodata directory")?
        .to_owned();
    write_record(&root.join(GEO_MANIFEST), &GeoRecord { directory })?;
    stage.keep();
    Ok(())
}

/// Remove older geodata snapshots after the caller identifies the directory
/// still in use by a running child. The current selection is always preserved.
pub fn prune_geo(root: &Path, in_use: Option<&Path>) -> Result<()> {
    let Some(current) = read_record::<GeoRecord>(&root.join(GEO_MANIFEST))? else {
        return Ok(());
    };
    let selected = geo_snapshot_path(root, &current.directory)?;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(path) = geo_snapshot_path(root, name) else {
            continue;
        };
        if path != selected && Some(path.as_path()) != in_use && plain_directory(&path).is_ok() {
            remove_known_files(&path, &["geoip.dat", "geosite.dat"]);
        }
    }
    Ok(())
}

pub fn get_subscription(url: &str) -> Result<Vec<u8>> {
    const MAX_SUBSCRIPTION: u64 = 1024 * 1024;
    let mut data = Vec::new();
    let status = get(url, None, MAX_SUBSCRIPTION, |chunk| {
        data.extend_from_slice(chunk);
        Ok(())
    })?;
    ensure!(status == 200, "Subscription returned HTTP {status}");
    ensure!(!data.is_empty(), "The subscription is empty");
    Ok(data)
}

fn stable_version(version: &str) -> Result<Version> {
    ensure!(version.len() <= 64, "Invalid Xray version");
    let version = Version::parse(version).context("Invalid Xray version")?;
    ensure!(version.pre.is_empty(), "Xray release is not stable");
    Ok(version)
}

fn core_directory_name(archive_sha256: &str) -> String {
    format!("core-{archive_sha256}")
}

fn github_release(repository: &str) -> Result<GithubRelease> {
    let url = format!("https://api.github.com/repos/{repository}/releases/latest");
    let mut bytes = Vec::new();
    let status = get(&url, Some(false), MAX_METADATA, |chunk| {
        bytes.extend_from_slice(chunk);
        Ok(())
    })?;
    ensure!(status == 200, "GitHub release check returned HTTP {status}");
    let release: GithubRelease =
        serde_json::from_slice(&bytes).context("Invalid GitHub Releases response")?;
    ensure!(
        !release.draft && !release.prerelease,
        "The release is not stable"
    );
    Ok(release)
}

fn download_verified(repository: &str, asset: &VerifiedAsset, target: &Path) -> Result<()> {
    let url = format!(
        "https://api.github.com/repos/{repository}/releases/assets/{}",
        asset.id
    );
    let size = download_file(&url, Some(true), asset.size, target)?;
    ensure!(
        size == asset.size,
        "GitHub asset size does not match the release"
    );
    verify_file(target, &asset.sha256)
}

fn download_file(url: &str, github: Option<bool>, max: u64, target: &Path) -> Result<u64> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)?;
    let mut size = 0;
    let status = get(url, github, max, |chunk| {
        size += chunk.len() as u64;
        Ok(file.write_all(chunk)?)
    })?;
    ensure!(status == 200, "Download returned HTTP {status}");
    ensure!(size > 0, "The downloaded file is empty");
    file.sync_all()?;
    Ok(size)
}

#[cfg(windows)]
fn get(
    url: &str,
    github: Option<bool>,
    max: u64,
    receive: impl FnMut(&[u8]) -> Result<()>,
) -> Result<u32> {
    use crate::platform::windows::http;
    match github {
        Some(binary) => http::get(url, binary, max, receive),
        None => http::get_https(url, max, receive),
    }
}

#[cfg(not(windows))]
fn get(_: &str, _: Option<bool>, _: u64, _: impl FnMut(&[u8]) -> Result<()>) -> Result<u32> {
    anyhow::bail!("Xray module downloads are currently available only on Windows")
}

#[cfg(windows)]
fn hash_file(path: &Path) -> Result<String> {
    crate::platform::windows::update::sha256(path)
}

#[cfg(not(windows))]
fn hash_file(_: &Path) -> Result<String> {
    anyhow::bail!("The Xray module is currently available only on Windows")
}

fn verify_file(path: &Path, expected: &str) -> Result<()> {
    crate::updates::validate_digest(expected)?;
    ensure!(
        hash_file(path)?.eq_ignore_ascii_case(expected),
        "The Xray asset SHA-256 did not match"
    );
    Ok(())
}

#[cfg(windows)]
fn extract_core(path: &Path, target: &Path) -> Result<()> {
    let mut zip = zip::ZipArchive::new(io::BufReader::new(File::open(path)?))
        .context("The Xray release is not a valid ZIP archive")?;
    ensure!(
        zip.len() <= 128,
        "The Xray archive contains too many entries"
    );
    for (name, limit) in [
        ("xray.exe", crate::updates::MAX_EXE_SIZE),
        ("geoip.dat", MAX_GEODATA),
        ("geosite.dat", MAX_GEODATA),
        ("LICENSE", 256 * 1024),
    ] {
        let file = zip
            .by_name(name)
            .with_context(|| format!("Missing {name} in the Xray archive"))?;
        let size = file.size();
        ensure!(
            file.is_file() && !file.is_symlink() && (1..=limit).contains(&size),
            "Invalid {name} in the Xray archive"
        );
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(target.join(name))?;
        let written = io::copy(&mut file.take(limit + 1), &mut output)?;
        ensure!(written == size, "Invalid extracted size for {name}");
        output.sync_all()?;
    }
    geodata::validate(&target.join("geoip.dat"), geodata::Kind::Ip)?;
    geodata::validate(&target.join("geosite.dat"), geodata::Kind::Site)
}

#[cfg(not(windows))]
fn extract_core(_: &Path, _: &Path) -> Result<()> {
    anyhow::bail!("The Xray module is currently available only on Windows")
}

fn plain_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !is_reparse(&metadata),
        "Invalid Xray asset file"
    );
    Ok(())
}

fn plain_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !is_reparse(&metadata),
        "Invalid Xray asset directory"
    );
    Ok(())
}

fn is_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    metadata.is_symlink()
}

fn read_record<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match plain_file(path) {
        Ok(()) => {}
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|err| err.kind() == io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    }
    let mut bytes = Vec::new();
    File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4096, "Xray asset metadata is too large");
    Ok(Some(
        serde_json::from_slice(&bytes).context("Invalid Xray asset metadata")?,
    ))
}

fn write_record(path: &Path, record: &impl Serialize) -> Result<()> {
    let id = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temporary = path.with_extension(format!("{id}-{}.part", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        serde_json::to_writer(&mut file, record)?;
        file.sync_all()?;
        drop(file);
        crate::platform::replace_file(&temporary, path)
    })();
    let _ = fs::remove_file(temporary);
    result
}

fn geo_snapshot_path(root: &Path, name: &str) -> Result<PathBuf> {
    let (time, pid) = name
        .strip_prefix("geo-")
        .and_then(|name| name.split_once('-'))
        .context("Invalid geodata snapshot")?;
    ensure!(
        time.bytes().all(|byte| byte.is_ascii_digit())
            && pid.bytes().all(|byte| byte.is_ascii_digit())
            && time.parse::<u128>().is_ok()
            && pid.parse::<u32>().is_ok(),
        "Invalid geodata snapshot"
    );
    Ok(root.join(name))
}

fn prune_cores(root: &Path, selected: &Path, previous: Option<&Installed>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let previous = previous.and_then(|item| item.executable.parent());
    for entry in entries.flatten() {
        let name = entry.file_name();
        let path = entry.path();
        if name
            .to_str()
            .and_then(|name| name.strip_prefix("core-"))
            .is_some_and(|hash| crate::updates::validate_digest(hash).is_ok())
            && path != selected
            && Some(path.as_path()) != previous
            && plain_directory(&path).is_ok()
            && fs::remove_file(path.join("xray.exe")).is_ok()
        {
            // A child holds its executable without FILE_SHARE_DELETE. If it
            // is still running, leave its bundled geodata and license intact.
            remove_known_files(&path, &["geoip.dat", "geosite.dat", "LICENSE"]);
        }
    }
}

struct Stage {
    path: PathBuf,
    keep: bool,
}

impl Stage {
    fn new(root: &Path, prefix: &str) -> Result<Self> {
        ensure!(root.is_absolute(), "The Xray directory must be absolute");
        fs::create_dir_all(root)?;
        plain_directory(root)?;
        let id = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = root.join(format!("{prefix}-{id}-{}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(Self { path, keep: false })
    }

    fn keep(mut self) {
        self.keep = true;
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if !self.keep && plain_directory(&self.path).is_ok() {
            remove_known_files(
                &self.path,
                &[
                    "package.zip",
                    "xray.exe",
                    "geoip.dat",
                    "geosite.dat",
                    "LICENSE",
                    HPWNR_FILE,
                ],
            );
        }
    }
}

#[cfg(test)]
#[test]
#[ignore = "downloads the pinned hpwnr executable from GitHub into a temporary directory"]
fn imports_encrypted_v2raytun_with_upstream_hpwnr() -> Result<()> {
    use super::{hpwnr::resolve, profile::Settings, runtime::run_link_decoder};

    let stage = Stage::new(&std::env::temp_dir(), "true-proxy-hpwnr-test")?;
    let binary = hpwnr(&stage.path)?;
    let encrypt = |link: &str, key: &str| -> Result<String> {
        let output = run_link_decoder(
            &binary,
            HPWNR_SHA256,
            &format!("hpwnr.exe {link} v2r {key}"),
        )?;
        let encrypted = String::from_utf8(output)?;
        ensure!(encrypted.starts_with("v2raytun://crypt/"));
        Ok(encrypted)
    };

    let subscription = "https://example.test/list?token=a+b%2Fc";
    for key in ["crypt3", "crypt4", "key3"] {
        assert_eq!(
            resolve(&stage.path, &encrypt(subscription, key)?)?,
            subscription
        );
    }
    let node = "vless://00000000-0000-4000-8000-000000000001@vpn.example.test:443?type=tcp&security=tls#Test";
    let mut settings = Settings::default();
    settings.import_with_assets(&encrypt(node, "crypt3")?, &stage.path)?;
    assert_eq!(settings.selected()?.name, "Test");

    // A size-matched replacement must be rejected before it can be launched.
    let mut damaged = fs::read(&binary)?;
    damaged[0] ^= 1;
    let encrypted = encrypt(node, "crypt3")?;
    fs::write(&binary, damaged)?;
    let error = settings
        .import_with_assets(&encrypted, &stage.path)
        .unwrap_err();
    assert!(error.to_string().contains("SHA-256"));
    assert_eq!(settings.profiles.len(), 1);
    Ok(())
}

fn remove_known_files(path: &Path, names: &[&str]) {
    for name in names {
        let _ = fs::remove_file(path.join(name));
    }
    let _ = fs::remove_dir(path);
}
