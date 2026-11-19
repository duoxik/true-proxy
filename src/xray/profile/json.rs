//! Import independent VLESS servers from Xray JSON subscription responses.

use super::{MAX_PROFILES, Node, parse_node};
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use url::Url;

pub(super) fn parse_nodes(text: &str) -> Result<Vec<Node>> {
    let document: Value = serde_json::from_str(text).context("Invalid Xray JSON subscription")?;
    let configs = match &document {
        Value::Array(configs) => configs.as_slice(),
        Value::Object(_) => std::slice::from_ref(&document),
        _ => bail!("Expected an Xray configuration or array of configurations"),
    };
    ensure!(
        configs.len() <= MAX_PROFILES,
        "Subscription contains more than 128 configurations"
    );
    let mut nodes = Vec::new();
    for config in configs {
        let outbounds = config
            .get("outbounds")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_else(|| std::slice::from_ref(config));
        ensure!(outbounds.len() <= MAX_PROFILES, "Too many Xray outbounds");
        // A balancer must not silently become a manually selected server.
        if config
            .pointer("/routing/balancers")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
        {
            continue;
        }
        let start = nodes.len();
        for outbound in outbounds {
            if let Ok(mut node) = parse_outbound(outbound) {
                node.source_id = provider_id(outbound);
                if let Some(name) = config
                    .get("remarks")
                    .or_else(|| config.get("name"))
                    .and_then(Value::as_str)
                {
                    let name: String = name.chars().filter(|c| !c.is_control()).take(80).collect();
                    if !name.is_empty() {
                        node.name = name;
                    }
                }
                nodes.push(node);
                ensure!(
                    nodes.len() <= MAX_PROFILES,
                    "Subscription contains more than 128 supported nodes"
                );
            }
        }
        if nodes.len() == start + 1 && nodes[start].source_id.is_none() {
            nodes[start].source_id = provider_id(config);
        }
    }
    ensure!(
        !nodes.is_empty(),
        "No independent VLESS RAW/TCP profiles with TLS or REALITY were found in the JSON subscription"
    );
    Ok(nodes)
}

fn provider_id(value: &Value) -> Option<String> {
    match value.get("profileId").or_else(|| value.get("id"))? {
        Value::String(id) if !id.trim().is_empty() => Some(id.clone()),
        Value::Number(id) => Some(id.to_string()),
        _ => None,
    }
}

fn parse_outbound(outbound: &Value) -> Result<Node> {
    ensure!(outbound["protocol"] == "vless", "Expected a VLESS outbound");
    ensure!(
        outbound.get("proxySettings").is_none()
            && outbound
                .pointer("/streamSettings/sockopt/dialerProxy")
                .is_none(),
        "Proxy chains are not supported"
    );
    let settings = &outbound["settings"];
    let server = if let Some(servers) = settings["vnext"].as_array() {
        ensure!(servers.len() == 1, "Expected one VLESS server");
        &servers[0]
    } else {
        settings
    };
    let user = if let Some(users) = server["users"].as_array() {
        ensure!(users.len() == 1, "Expected one VLESS user");
        &users[0]
    } else {
        server
    };
    let address = server["address"]
        .as_str()
        .context("Missing VLESS address")?;
    let port = server["port"]
        .as_u64()
        .filter(|port| (1..=65535).contains(port))
        .context("Invalid VLESS port")? as u16;
    let mut url = Url::parse("vless://placeholder@invalid.test:443")?;
    let host = address
        .parse::<std::net::Ipv6Addr>()
        .map(|ip| format!("[{ip}]"))
        .unwrap_or_else(|_| address.to_owned());
    url::Host::parse(&host).context("Invalid VLESS address")?;
    url.set_host(Some(&host))?;
    url.set_port(Some(port))
        .map_err(|_| anyhow::anyhow!("Invalid VLESS port"))?;
    url.set_username(user["id"].as_str().context("Missing VLESS UUID")?)
        .map_err(|_| anyhow::anyhow!("Invalid VLESS UUID"))?;
    let stream = &outbound["streamSettings"];
    let security = stream["security"].as_str().unwrap_or("");
    let transport = if security == "reality" {
        &stream["realitySettings"]
    } else {
        &stream["tlsSettings"]
    };
    ensure!(
        transport["allowInsecure"] != true,
        "TLS verification is required"
    );
    ensure!(
        transport.get("pinnedPeerCertificateChainSha256").is_none()
            && transport.get("pinnedPeerCertSha256").is_none(),
        "TLS certificate pinning in JSON profiles is not supported"
    );
    ensure!(
        stream
            .pointer("/tcpSettings/header/type")
            .and_then(Value::as_str)
            .is_none_or(|header| header == "none")
            && stream
                .pointer("/rawSettings/header/type")
                .and_then(Value::as_str)
                .is_none_or(|header| header == "none"),
        "Only plain RAW/TCP is supported"
    );
    let mut query = url.query_pairs_mut();
    query
        .append_pair("type", stream["network"].as_str().unwrap_or("tcp"))
        .append_pair("security", security);
    for (key, value) in [
        ("encryption", user["encryption"].as_str().unwrap_or("none")),
        ("flow", user["flow"].as_str().unwrap_or("")),
        ("sni", transport["serverName"].as_str().unwrap_or(address)),
        (
            "fp",
            transport["fingerprint"]
                .as_str()
                .unwrap_or(if security == "reality" { "chrome" } else { "" }),
        ),
        (
            "pbk",
            transport["publicKey"]
                .as_str()
                .or_else(|| transport["password"].as_str())
                .unwrap_or(""),
        ),
        ("sid", transport["shortId"].as_str().unwrap_or("")),
        ("spx", transport["spiderX"].as_str().unwrap_or("")),
        ("pqv", transport["mldsa65Verify"].as_str().unwrap_or("")),
    ] {
        query.append_pair(key, value);
    }
    if let Some(alpn) = transport["alpn"].as_array() {
        let values = alpn
            .iter()
            .map(|value| value.as_str().context("Invalid TLS ALPN"))
            .collect::<Result<Vec<_>>>()?;
        query.append_pair("alpn", &values.join(","));
    }
    drop(query);
    parse_node(url.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> Value {
        json!({"remarks":"Riga", "inbounds":[{"listen":"0.0.0.0"}], "outbounds":[
            {"protocol":"vless", "settings":{"vnext":[{"address":"vpn.example.test","port":443,"users":[{
                "id":"00000000-0000-4000-8000-000000000001", "encryption":"none", "flow":"xtls-rprx-vision"
            }]}]}, "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"cert.example.test","alpn":["h2"]}}},
            {"protocol":"freedom"}, {"protocol":"blackhole"}
        ]})
    }

    #[test]
    fn imports_json_regions_with_existing_vless_validation_and_protected_storage() {
        let first = config();
        let mut second = first.clone();
        second["remarks"] = json!("Berlin");
        second["outbounds"][0]["settings"]["vnext"][0]["address"] = json!("de.example.test");
        let text = json!([first, second]).to_string();
        let mut settings = super::super::Settings::default();
        settings.import(&text).unwrap();
        assert_eq!(settings.profiles.len(), 2);
        assert_eq!(settings.profiles[0].name, "Riga");
        assert_eq!(settings.profiles[1].name, "Berlin");
        let outbound = settings.profiles[0].outbound().unwrap();
        assert_eq!(
            outbound["streamSettings"]["tlsSettings"]["serverName"],
            "cert.example.test"
        );
        assert!(outbound.get("inbounds").is_none());
        assert!(
            !serde_json::to_string(&settings)
                .unwrap()
                .contains("00000000-0000-4000-8000-000000000001")
        );
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&text);
        assert_eq!(
            super::super::parse_nodes(encoded.as_bytes()).unwrap().len(),
            2
        );
    }

    #[test]
    fn provider_ids_are_scoped_to_individual_json_nodes() {
        let mut document = config();
        document["id"] = json!("provider-node");
        assert_eq!(
            parse_nodes(&document.to_string()).unwrap()[0]
                .source_id
                .as_deref(),
            Some("provider-node")
        );
        let mut second = document["outbounds"][0].clone();
        second["id"] = json!(2);
        document["outbounds"].as_array_mut().unwrap().push(second);
        let nodes = parse_nodes(&document.to_string()).unwrap();
        assert_eq!(nodes[0].source_id, None);
        assert_eq!(nodes[1].source_id.as_deref(), Some("2"));
    }

    #[test]
    fn preserves_reality_keys_and_ipv6_server_addresses() {
        let mut document = config();
        document["outbounds"][0]["settings"]["vnext"][0]["address"] = json!("2001:db8::1");
        document["outbounds"][0]["streamSettings"] = json!({
            "network":"raw", "security":"reality", "realitySettings":{
                "serverName":"cert.example.test", "fingerprint":"chrome",
                "publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "shortId":"ab12"
            }
        });
        let nodes = parse_nodes(&document.to_string()).unwrap();
        assert_eq!(nodes[0].host, "2001:db8::1");
        let reality = &nodes[0].outbound["streamSettings"]["realitySettings"];
        assert_eq!(
            reality["password"],
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert_eq!(reality["shortId"], "ab12");
    }

    #[test]
    fn rejects_unsafe_or_dependent_profiles_without_changing_existing_settings() {
        for invalid in ["insecure", "chain", "balancer", "transport", "uuid"] {
            let mut document = config();
            match invalid {
                "insecure" => {
                    document["outbounds"][0]["streamSettings"]["tlsSettings"]["allowInsecure"] =
                        json!(true)
                }
                "chain" => document["outbounds"][0]["proxySettings"] = json!({"tag":"hop"}),
                "balancer" => {
                    document["routing"] = json!({"balancers":[{"tag":"auto","selector":["proxy"]}]})
                }
                "transport" => document["outbounds"][0]["streamSettings"]["network"] = json!("ws"),
                "uuid" => {
                    document["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"] =
                        json!("invalid")
                }
                _ => unreachable!(),
            }
            let mut settings = super::super::Settings::default();
            settings.import(&config().to_string()).unwrap();
            let before = serde_json::to_string(&settings).unwrap();
            assert!(settings.import(&document.to_string()).is_err(), "{invalid}");
            assert_eq!(serde_json::to_string(&settings).unwrap(), before);
        }
    }
}
