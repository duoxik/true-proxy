//! Rule editor input normalization, independent of the UI and network backend.
use anyhow::{Result, bail, ensure};
use std::path::Path;

pub fn entries(kind: i32, input: &str) -> Result<Vec<String>> {
    let separator = |c| c == '\n' || c == ';' || (kind != 1 && c == ',');
    input
        .split(separator)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|value| {
            Ok(match kind {
                0 => {
                    ensure!(
                        !value.contains(['/', '\\', '*', '?']),
                        "Укажите имя EXE, например destiny2.exe, или добавьте полный путь отдельно"
                    );
                    value.to_string()
                }
                1 => {
                    ensure!(
                        Path::new(value).is_absolute(),
                        "Укажите полный путь приложения"
                    );
                    value.to_string()
                }
                2 => {
                    let wildcard = value.starts_with("*.");
                    let domain = value
                        .strip_prefix("*.")
                        .unwrap_or(value)
                        .trim_end_matches('.')
                        .to_ascii_lowercase();
                    ensure!(
                        !domain.is_empty()
                            && domain.len() <= 253
                            && domain.split('.').all(|label| !label.is_empty()
                                && label.len() <= 63
                                && label
                                    .bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')),
                        "Укажите домен без https://, пути и порта"
                    );
                    if wildcard {
                        format!("*.{domain}")
                    } else {
                        domain
                    }
                }
                3 => {
                    if let Ok(ip) = value.parse::<std::net::IpAddr>() {
                        format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 })
                    } else {
                        value
                            .parse::<ipnet::IpNet>()
                            .map_err(|_| anyhow::anyhow!("Некорректный IP или CIDR: {value}"))?
                            .to_string()
                    }
                }
                4 => {
                    let range = crate::config::PortRange::parse(value)?;
                    if range.start == range.end {
                        range.start.to_string()
                    } else {
                        format!("{}-{}", range.start, range.end)
                    }
                }
                _ => bail!("Неизвестный тип условия"),
            })
        })
        .collect()
}

pub fn append(values: &mut Vec<String>, additions: Vec<String>) {
    for value in additions {
        if !values.iter().any(|old| old.eq_ignore_ascii_case(&value)) {
            values.push(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domains_make_exact_and_subdomain_semantics_explicit() {
        assert_eq!(
            entries(2, "*.SteamServer.NET.").unwrap(),
            ["*.steamserver.net"]
        );
        assert_eq!(entries(2, "steamserver.net").unwrap(), ["steamserver.net"]);
        assert!(entries(2, "https://example.com/path").is_err());
        assert!(entries(2, "*.*.example.com").is_err());
    }
    #[test]
    fn list_input_is_deduplicated_and_validated() {
        let mut values = vec!["Discord.exe".to_string()];
        append(
            &mut values,
            entries(0, "discord.exe\nsteam.exe; destiny2.exe").unwrap(),
        );
        assert_eq!(values, ["Discord.exe", "steam.exe", "destiny2.exe"]);
        assert_eq!(
            entries(3, "1.2.3.4, 10.0.0.0/8").unwrap(),
            ["1.2.3.4/32", "10.0.0.0/8"]
        );
        assert!(entries(4, "443, 9000-8000").is_err());
    }
}
