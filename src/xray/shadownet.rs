//! ShadowNet subscription device identity. No hardware identifiers are collected.

use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    path::Path,
};
use url::Url;

pub(super) fn matches(url: &Url) -> bool {
    url.host_str()
        .is_some_and(|host| host == "shadow-net.site" || host.ends_with(".shadow-net.site"))
}

pub(super) fn device_id(root: &Path) -> Result<String> {
    let path = root.join("subscription-device.dpapi");
    match File::open(&path) {
        Ok(file) => return read_id(file),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("Could not read the subscription device identity"),
    }
    fs::create_dir_all(root)?;
    let id = generate_id()?;
    let protected = crate::platform::windows::protect_secret(&id)?;
    let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            return read_id(File::open(path)?);
        }
        Err(error) => return Err(error).context("Could not save the subscription device identity"),
    };
    // Persist before any request can register this device with the provider.
    // An unreadable identity is an error, never a reason to silently rotate it.
    file.write_all(protected.as_bytes())?;
    file.sync_all()?;
    Ok(id)
}

fn read_id(file: File) -> Result<String> {
    let mut protected = String::new();
    file.take(4097).read_to_string(&mut protected)?;
    ensure!(
        protected.len() <= 4096,
        "Invalid subscription device identity"
    );
    let id = crate::platform::unprotect(&protected)
        .context("Could not open the saved subscription device identity")?;
    ensure!(
        id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Invalid subscription device identity"
    );
    Ok(id)
}

#[cfg(windows)]
fn generate_id() -> Result<String> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    let mut bytes = [0u8; 32];
    // SAFETY: the output buffer is valid for all 32 bytes; the system RNG is used.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    ensure!(
        status >= 0,
        "Could not generate the subscription device identity"
    );
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(not(windows))]
fn generate_id() -> Result<String> {
    anyhow::bail!("Subscription device identity is currently available only on Windows")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_stable_and_protected_and_corruption_never_rotates_it() {
        let root = std::env::temp_dir().join(format!("true-proxy-hwid-{}", generate_id().unwrap()));
        let first = device_id(&root).unwrap();
        assert_eq!(device_id(&root).unwrap(), first);
        let path = root.join("subscription-device.dpapi");
        assert!(!fs::read_to_string(&path).unwrap().contains(&first));
        fs::write(&path, "damaged").unwrap();
        assert!(device_id(&root).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "damaged");
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn only_the_exact_provider_domain_and_its_subdomains_match() {
        assert!(matches(
            &Url::parse("https://sub.shadow-net.site/example").unwrap()
        ));
        assert!(!matches(
            &Url::parse("https://shadow-net.site.evil.test/example").unwrap()
        ));
        assert!(!matches(
            &Url::parse("https://notshadow-net.site/example").unwrap()
        ));
    }
}
