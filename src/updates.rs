//! GitHub release policy and bounded staging, independent of the UI/network engine.
use anyhow::{Context, Result, ensure};
#[cfg(windows)]
pub mod installer;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const REPOSITORY: &str = "duoxik/true-proxy";
pub const API: &str = "https://api.github.com/repos/duoxik/true-proxy/releases/latest";
pub const MAX_EXE_SIZE: u64 = 64 * 1024 * 1024;
pub const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Release {
    pub version: String,
    pub asset_id: u64,
    pub size: u64,
    pub sha256: String,
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

pub fn parse_release(bytes: &[u8]) -> Result<Option<Release>> {
    ensure!(bytes.len() <= 512 * 1024, "Слишком большой ответ GitHub");
    let raw: GithubRelease =
        serde_json::from_slice(bytes).context("Некорректный ответ GitHub Releases")?;
    if raw.draft || raw.prerelease {
        return Ok(None);
    }
    let version = Version::parse(raw.tag_name.strip_prefix('v').unwrap_or(&raw.tag_name))
        .context("Некорректная версия релиза")?;
    if !version.pre.is_empty() {
        return Ok(None);
    }
    let mut assets = raw
        .assets
        .into_iter()
        .filter(|asset| asset.name == "TrueProxy.exe" && asset.state == "uploaded");
    let Some(asset) = assets.next() else {
        return Ok(None);
    };
    ensure!(
        assets.next().is_none(),
        "В релизе несколько файлов TrueProxy.exe"
    );
    ensure!(
        asset.id > 0 && (1024..=MAX_EXE_SIZE).contains(&asset.size),
        "Некорректный размер обновления"
    );
    let digest = asset
        .digest
        .as_deref()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .context("GitHub не предоставил SHA-256 обновления")?;
    validate_digest(digest)?;
    Ok(Some(Release {
        version: version.to_string(),
        asset_id: asset.id,
        size: asset.size,
        sha256: digest.to_ascii_lowercase(),
    }))
}

pub fn is_newer(release: &Release, installed: &str) -> Result<bool> {
    Ok(Version::parse(&release.version)? > Version::parse(installed)?)
}
pub fn validate_digest(digest: &str) -> Result<()> {
    ensure!(
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Некорректный SHA-256 обновления"
    );
    Ok(())
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Preferences {
    pub automatic: bool,
}
impl Default for Preferences {
    fn default() -> Self {
        Self { automatic: true }
    }
}
impl Preferences {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        ensure!(
            fs::metadata(path)?.len() < 4096,
            "Слишком большой файл настроек обновлений"
        );
        serde_json::from_slice(&fs::read(path)?)
            .context("Не удалось прочитать настройки обновлений")
    }
    pub fn save(self, path: &Path) -> Result<()> {
        fs::create_dir_all(path.parent().context("Не задана папка настроек")?)?;
        let temporary = path.with_extension("tmp");
        let mut file = fs::File::create(&temporary)?;
        file.write_all(&serde_json::to_vec(&self)?)?;
        file.sync_all()?;
        drop(file);
        crate::platform::replace_file(&temporary, path)
    }
}

/// A URL is never accepted from release prose; only HTTPS GitHub download hosts.
pub fn split_https(url: &str) -> Result<(&str, &str)> {
    ensure!(
        url.is_ascii()
            && !url
                .bytes()
                .any(|byte| byte <= b' ' || byte == 127 || byte == b'\\' || byte == b'#'),
        "Некорректная ссылка обновления"
    );
    let remainder = url
        .strip_prefix("https://")
        .context("Обновления требуют HTTPS")?;
    let (host, path) = remainder
        .split_once('/')
        .context("Некорректная ссылка обновления")?;
    ensure!(
        matches!(
            host,
            "api.github.com"
                | "github.com"
                | "release-assets.githubusercontent.com"
                | "objects.githubusercontent.com"
        ),
        "Ссылка обновления ведёт за пределы GitHub"
    );
    Ok((host, &url[url.len() - path.len() - 1..]))
}

#[cfg(windows)]
pub fn latest() -> Result<Option<Release>> {
    let mut bytes = Vec::new();
    let status = crate::platform::windows::http::get(API, false, 512 * 1024, |chunk| {
        bytes.extend_from_slice(chunk);
        Ok(())
    })?;
    if status == 404 {
        return Ok(None);
    }
    ensure!(
        status == 200,
        "GitHub ответил HTTP {status}; повторите проверку позже"
    );
    parse_release(&bytes)
}
#[cfg(not(windows))]
pub fn latest() -> Result<Option<Release>> {
    anyhow::bail!("Проверка обновлений пока поддерживается только в Windows")
}

pub fn validate_pe(path: &Path) -> Result<()> {
    let mut file = fs::File::open(path)?;
    let mut dos = [0u8; 64];
    file.read_exact(&mut dos)?;
    ensure!(&dos[..2] == b"MZ", "Обновление не является Windows EXE");
    let offset = u32::from_le_bytes(dos[60..64].try_into()?);
    ensure!(
        (64..=1024 * 1024).contains(&offset),
        "Некорректный EXE-заголовок"
    );
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(offset as u64))?;
    let mut pe = [0u8; 24];
    file.read_exact(&mut pe)?;
    ensure!(
        &pe[..4] == b"PE\0\0" && pe[4..6] == [0x64, 0x86],
        "Обновление должно быть Windows x64 EXE"
    );
    ensure!(
        u16::from_le_bytes(pe[22..24].try_into()?) & 0x2002 == 2,
        "Обновление не является исполняемым приложением"
    );
    Ok(())
}

pub struct Staged {
    pub directory: PathBuf,
    pub release: Release,
}
impl Staged {
    pub fn payload(&self) -> PathBuf {
        self.directory.join("payload.exe")
    }
}

pub fn stage_directory(root: &Path) -> Result<PathBuf> {
    fs::create_dir_all(root)?;
    // Only known files in our own staging folders are removed. No recursive deletes.
    let mut previous = fs::read_dir(root)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("true-proxy-update-"))
                && entry
                    .file_type()
                    .is_ok_and(|kind| kind.is_dir() && !kind.is_symlink())
                && !is_reparse(&entry.path())
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    previous.sort();
    for directory in previous.iter().take(previous.len().saturating_sub(1)) {
        for name in [
            "payload.exe",
            "payload.part",
            "updater.exe",
            "previous.exe",
            "ready",
            "error.txt",
        ] {
            let _ = fs::remove_file(directory.join(name));
        }
        let _ = fs::remove_dir(directory);
    }
    ensure!(
        fs::read_dir(root)?.count() < 8,
        "Не удалось очистить папку обновлений; освободите её перед загрузкой"
    );
    let id = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let directory = root.join(format!("true-proxy-update-{id}-{}", std::process::id()));
    fs::create_dir(&directory)?;
    Ok(directory)
}

fn is_reparse(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        fs::symlink_metadata(path).map_or(true, |metadata| metadata.file_attributes() & 0x400 != 0)
    }
    #[cfg(not(windows))]
    {
        fs::symlink_metadata(path).map_or(true, |metadata| metadata.file_type().is_symlink())
    }
}

#[cfg(windows)]
pub fn download(
    release: &Release,
    root: &Path,
    mut progress: impl FnMut(u64, u64),
) -> Result<Staged> {
    ensure!(
        (1024..=MAX_EXE_SIZE).contains(&release.size),
        "Некорректный размер обновления"
    );
    validate_digest(&release.sha256)?;
    let directory = stage_directory(root)?;
    let partial = directory.join("payload.part");
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial)?;
        let mut received = 0;
        let mut last = std::time::Instant::now();
        let url = format!(
            "https://api.github.com/repos/{REPOSITORY}/releases/assets/{}",
            release.asset_id
        );
        let status = crate::platform::windows::http::get(&url, true, release.size, |bytes| {
            file.write_all(bytes)?;
            received += bytes.len() as u64;
            if last.elapsed() >= Duration::from_millis(500) {
                progress(received, release.size);
                last = std::time::Instant::now();
            }
            Ok(())
        })?;
        ensure!(
            status == 200,
            "Не удалось скачать обновление: HTTP {status}"
        );
        ensure!(
            received == release.size,
            "Обновление загружено не полностью"
        );
        file.sync_all()?;
        drop(file);
        verify_file(&partial, &release.sha256)?;
        validate_pe(&partial)?;
        fs::rename(&partial, directory.join("payload.exe"))?;
        progress(received, release.size);
        Ok(Staged {
            directory: directory.clone(),
            release: release.clone(),
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(partial);
    }
    result
}

#[cfg(windows)]
pub fn verify_file(path: &Path, expected: &str) -> Result<()> {
    validate_digest(expected)?;
    ensure!(
        crate::platform::windows::update::sha256(path)?.eq_ignore_ascii_case(expected),
        "SHA-256 обновления не совпадает; установка отменена"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn json() -> serde_json::Value {
        serde_json::json!({"tag_name":"v0.10.0", "draft":false, "prerelease":false,
        "assets":[{"id":42,"name":"TrueProxy.exe","state":"uploaded","size":12000000,"digest":format!("sha256:{}", "ab".repeat(32))}]})
    }
    #[test]
    fn release_selection_uses_semver_and_requires_verified_executable() {
        let mut json = json();
        let parsed = parse_release(&serde_json::to_vec(&json).unwrap())
            .unwrap()
            .unwrap();
        assert!(is_newer(&parsed, "0.9.0").unwrap());
        assert!(!is_newer(&parsed, "0.10.0").unwrap());
        assert!(!is_newer(&parsed, "1.0.0").unwrap());
        json["assets"][0]["digest"] = serde_json::Value::Null;
        assert!(parse_release(&serde_json::to_vec(&json).unwrap()).is_err());
        json = self::json();
        json["draft"] = true.into();
        assert!(
            parse_release(&serde_json::to_vec(&json).unwrap())
                .unwrap()
                .is_none()
        );
        json = self::json();
        json["prerelease"] = true.into();
        assert!(
            parse_release(&serde_json::to_vec(&json).unwrap())
                .unwrap()
                .is_none()
        );
        json = self::json();
        json["assets"][0]["size"] = (MAX_EXE_SIZE + 1).into();
        assert!(parse_release(&serde_json::to_vec(&json).unwrap()).is_err());
    }
    #[test]
    fn update_links_cannot_downgrade_https_or_leave_github() {
        assert_eq!(
            split_https("https://release-assets.githubusercontent.com/file?x=1").unwrap(),
            ("release-assets.githubusercontent.com", "/file?x=1")
        );
        for link in [
            "http://github.com/x",
            "https://github.com.evil/x",
            "https://github.com@evil/x",
            "https://evil/x",
            "https://github.com/x\r\n",
            "https://github.com/x#y",
            "https://github.com\\evil/x",
        ] {
            assert!(split_https(link).is_err(), "{link}");
        }
    }

    #[test]
    fn automatic_preference_persists_and_corrupt_file_is_not_overwritten() {
        let directory =
            std::env::temp_dir().join(format!("true-proxy-update-prefs-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("updates.json");
        assert!(Preferences::load(&path).unwrap().automatic);
        Preferences { automatic: false }.save(&path).unwrap();
        assert!(!Preferences::load(&path).unwrap().automatic);
        fs::write(&path, b"broken").unwrap();
        assert!(Preferences::load(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"broken");
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
