use super::{Port, new_id};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn number(value: &Value) -> Result<u16> {
    value
        .as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .filter(|n| *n != 0)
        .context("Invalid port in the saved Xray settings")
}

/// Both older formats are converted before deserializing the current model.
/// Each distinct listener number keeps its endpoint, even when shared by profiles.
pub(super) fn upgrade_ports(document: &mut Value) -> Result<bool> {
    let object = document.as_object_mut().context("Invalid Xray settings")?;
    if object.contains_key("ports") {
        return Ok(false);
    }
    let manual = object.remove("manual_default_port");
    let single = object.remove("socks_port");
    ensure!(
        manual.is_none() || single.is_none(),
        "Conflicting legacy Xray port settings"
    );
    let grouped = manual.is_some();
    let old_number = manual
        .or(single)
        .as_ref()
        .map(number)
        .transpose()?
        .unwrap_or(2081);
    let default = Port {
        number: old_number,
        ..Port::default()
    };
    let default_id = default.id.clone();
    let mut ports = vec![default];
    let mut by_number = BTreeMap::from([(old_number, default_id.clone())]);
    let mut named_port = |number, name| {
        by_number
            .entry(number)
            .or_insert_with(|| {
                let id = new_id();
                ports.push(Port {
                    id: id.clone(),
                    name,
                    number,
                    is_default: false,
                });
                id
            })
            .clone()
    };
    if old_number < 1024 {
        object.insert("grandfathered_port".into(), json!(old_number));
    }
    let mut groups = BTreeMap::new();
    if grouped && let Some(sources) = object.get_mut("subscriptions") {
        for (index, source) in sources
            .as_array_mut()
            .context("Invalid Xray subscription list")?
            .iter_mut()
            .enumerate()
        {
            let source = source
                .as_object_mut()
                .context("Invalid Xray subscription")?;
            let listener = source
                .remove("default_port")
                .context("Missing subscription port")?;
            let id = source
                .get("id")
                .and_then(Value::as_str)
                .context("Missing subscription ID")?;
            // Subscriptions have no stored display name. The UI numbers them in this order.
            groups.insert(
                id.to_owned(),
                named_port(number(&listener)?, format!("Subscription {}", index + 1)),
            );
        }
    }
    let active: Option<String> =
        serde_json::from_value(object.remove("active").unwrap_or(Value::Null))?;
    let mut found_active = false;
    if let Some(profiles) = object.get_mut("profiles") {
        for profile in profiles
            .as_array_mut()
            .context("Invalid Xray profile list")?
        {
            let profile = profile.as_object_mut().context("Invalid Xray profile")?;
            let binding = if grouped {
                if let Some(value) = profile
                    .remove("custom_port")
                    .filter(|value| !value.is_null())
                {
                    let number = number(&value)?;
                    named_port(number, format!("Port {number}"))
                } else if let Some(source) = profile.get("subscription").and_then(Value::as_str) {
                    groups
                        .get(source)
                        .context("Unknown Xray subscription")?
                        .clone()
                } else {
                    default_id.clone()
                }
            } else {
                let enabled = active.is_some()
                    && profile.get("id").and_then(Value::as_str) == active.as_deref();
                found_active |= enabled;
                profile.insert("enabled".into(), json!(enabled));
                default_id.clone()
            };
            profile.insert("port_id".into(), json!(binding));
        }
    }
    ensure!(
        active.is_none() || found_active,
        "The active Xray profile is missing"
    );
    object.insert("ports".into(), serde_json::to_value(ports)?);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::profile::Settings;

    #[test]
    fn grouped_and_overridden_numbers_become_named_bindings() {
        let mut doc = json!({
            "manual_default_port": 3010,
            "subscriptions": [{"id":"s", "protected_url":"", "default_port":3020}],
            "profiles":[
                {"id":"a", "name":"Manual", "host":"a.test", "port":443, "protected":"", "subscription":null, "enabled":true},
                {"id":"b", "name":"Group", "host":"b.test", "port":443, "protected":"", "subscription":"s", "enabled":true},
                {"id":"c", "name":"Custom", "host":"c.test", "port":443, "protected":"", "subscription":"s", "custom_port":3030},
                {"id":"d", "name":"Shared", "host":"d.test", "port":443, "protected":"", "subscription":null, "custom_port":3030}
            ]
        });
        assert!(upgrade_ports(&mut doc).unwrap());
        assert!(!upgrade_ports(&mut doc).unwrap());
        let settings: Settings = serde_json::from_value(doc).unwrap();
        settings.validate().unwrap();
        assert_eq!(settings.default_port().number, 3010);
        assert_eq!(settings.ports.len(), 3);
        assert_eq!(settings.enabled_profiles().count(), 2);
        assert_eq!(settings.effective_port(&settings.profiles[1]), 3020);
        assert_eq!(
            settings.port(&settings.profiles[1].port_id).unwrap().name,
            "Subscription 1"
        );
        assert_eq!(settings.effective_port(&settings.profiles[2]), 3030);
        assert_eq!(settings.profiles[3].port_id, settings.profiles[2].port_id);
        let saved = serde_json::to_string(&settings).unwrap();
        for legacy in ["manual_default_port", "custom_port", "default_port"] {
            assert!(!saved.contains(legacy));
        }
    }
}
