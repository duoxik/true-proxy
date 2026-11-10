//! Local v2RayTun link decryption through the verified upstream CLI.

use super::{assets, runtime::run_link_decoder};
use anyhow::{Context, Result, ensure};
use percent_encoding::percent_decode_str;
use std::{borrow::Cow, path::Path};

pub fn encrypted(input: &str) -> bool {
    input
        .trim()
        .split_once("://")
        .is_some_and(|(scheme, path)| {
            scheme.eq_ignore_ascii_case("v2raytun")
                && path
                    .split('/')
                    .next()
                    .is_some_and(|action| action.eq_ignore_ascii_case("crypt"))
        })
}

pub(super) fn resolve<'a>(root: &Path, input: &'a str) -> Result<Cow<'a, str>> {
    let input = input.trim();
    let Some((scheme, path)) = input.split_once("://") else {
        return Ok(Cow::Borrowed(input));
    };
    let (action, payload) = path.split_once('/').unwrap_or((path, ""));
    if !scheme.eq_ignore_ascii_case("v2raytun") || !action.eq_ignore_ascii_case("crypt") {
        return Ok(Cow::Borrowed(input));
    }

    ensure!(
        payload.len() <= 24 * 1024,
        "The encrypted v2RayTun link is too long"
    );
    let payload = percent_decode_str(payload)
        .decode_utf8()
        .context("Invalid encoding in the encrypted v2RayTun link")?;
    // The CLI accepts one positional argument. Restrict it to the base64 alphabets
    // so Windows cannot parse any part of the link as a separate argument.
    ensure!(
        !payload.is_empty()
            && payload
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/_-=".contains(&b)),
        "Invalid encrypted v2RayTun link"
    );
    let binary = assets::installed_hpwnr(root)?
        .context("Install the hpwnr module to import encrypted v2RayTun links")?;
    let output = run_link_decoder(
        &binary,
        assets::HPWNR_SHA256,
        &format!("hpwnr.exe v2raytun://crypt/{payload}"),
    )?;
    Ok(Cow::Owned(plaintext(&output)?.to_owned()))
}

fn plaintext(output: &[u8]) -> Result<&str> {
    let output = std::str::from_utf8(output)
        .context("hpwnr did not return a valid link")?
        .trim_end_matches(['\r', '\n']);
    ensure!(
        !output.chars().any(char::is_control)
            && output.split_once("://").is_some_and(|(scheme, _)| {
                scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("vless")
            }),
        "The encrypted v2RayTun link must contain a single HTTPS subscription or VLESS link"
    );
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_import_bypasses_decoder_and_malformed_ciphertext_is_rejected() {
        let root = Path::new("");
        let url = "v2raytun://import/https://example.test/list";
        assert_eq!(resolve(root, url).unwrap(), url);
        for input in ["v2raytun://crypt", "v2raytun://crypt/abc%22%20fetch"] {
            assert!(
                resolve(root, input)
                    .unwrap_err()
                    .to_string()
                    .contains("Invalid encrypted")
            );
        }
    }

    #[test]
    fn decoder_output_must_be_a_single_supported_link() {
        let url = "https://example.test/list?token=a+b%2Fc";
        assert_eq!(plaintext(format!("{url}\r\n").as_bytes()).unwrap(), url);
        assert!(plaintext(b"http://example.test/list").is_err());
        assert!(plaintext(b"https://example.test/a\nhttps://example.test/b").is_err());
    }

    #[test]
    fn missing_module_never_downloads_during_import() {
        let root = std::env::temp_dir().join(format!("hpwnr-absent-{}", std::process::id()));
        assert!(!root.exists());
        assert!(encrypted("V2RayTun://CRYPT/abcd"));
        assert!(!encrypted("v2raytun://import/https://example.test"));
        assert!(
            resolve(&root, "v2raytun://crypt/abcd")
                .unwrap_err()
                .to_string()
                .contains("Install the hpwnr module")
        );
        assert!(!root.exists(), "import must not create a download stage");
    }
}
