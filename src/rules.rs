use crate::config::{Action, Config, Protocol, Rule};
use std::net::SocketAddr;

pub struct Flow<'a> {
    pub process_name: &'a str,
    pub process_path: &'a str,
    pub destination: SocketAddr,
    pub protocol: Protocol,
    pub domains: &'a [String],
}

pub fn matches(rule: &Rule, flow: &Flow<'_>) -> bool {
    if !rule.enabled || (rule.protocol != Protocol::Both && rule.protocol != flow.protocol) {
        return false;
    }
    if !rule.process_names.is_empty()
        && !rule
            .process_names
            .iter()
            .any(|n| process_eq(n, flow.process_name))
    {
        return false;
    }
    if !rule.process_paths.is_empty()
        && !rule
            .process_paths
            .iter()
            .any(|p| process_eq(p, flow.process_path))
    {
        return false;
    }
    if !rule.networks.is_empty()
        && !rule
            .networks
            .iter()
            .any(|n| n.contains(&flow.destination.ip()))
    {
        return false;
    }
    if !rule.ports.is_empty()
        && !rule
            .ports
            .iter()
            .any(|p| (p.start..=p.end).contains(&flow.destination.port()))
    {
        return false;
    }
    if (!rule.domains.is_empty() || !rule.domain_suffixes.is_empty())
        && !flow.domains.iter().any(|domain| {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            rule.domains.iter().any(|n| n.eq_ignore_ascii_case(&domain))
                || rule.domain_suffixes.iter().any(|n| {
                    let n = n.to_ascii_lowercase();
                    domain == n
                        || domain
                            .strip_suffix(&n)
                            .is_some_and(|prefix| prefix.ends_with('.'))
                })
        })
    {
        return false;
    }
    true
}

fn process_eq(left: &str, right: &str) -> bool {
    if cfg!(windows) {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}

pub fn resolve(config: &Config, flow: &Flow<'_>) -> Action {
    // DNS stays with Windows/the application's chosen resolver, regardless of
    // legacy DNS settings. Encrypted DNS remains ordinary TCP/UDP traffic.
    if flow.destination.port() == 53 {
        return Action::Direct;
    }
    let matched = config.rules.iter().find(|r| matches(r, flow));
    let action = matched.map(|r| &r.action).unwrap_or(&config.default_action);
    action.clone()
}

pub fn explanation(config: &Config, flow: &Flow<'_>) -> String {
    let protocol = if flow.protocol == Protocol::Tcp {
        "TCP"
    } else {
        "UDP"
    };
    if flow.destination.port() == 53 {
        return format!("{protocol} · DNS Windows");
    }
    let matched = config.rules.iter().find(|rule| matches(rule, flow));
    let rule = matched
        .map(|rule| rule.name.as_str())
        .unwrap_or("по умолчанию");
    let domains = if flow.domains.is_empty() {
        "имя DNS неизвестно".into()
    } else {
        flow.domains.join(", ")
    };
    format!("{protocol} · {rule} · {domains}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnsPolicy;
    fn rule() -> Rule {
        Rule {
            id: "r".into(),
            name: "Browser".into(),
            enabled: true,
            process_names: vec!["browser.exe".into()],
            process_paths: vec![],
            domains: vec![],
            domain_suffixes: vec![],
            networks: vec![],
            ports: vec![],
            protocol: Protocol::Both,
            action: Action::Proxy("vpn".into()),
            dns: DnsPolicy::Inherit,
        }
    }
    fn flow<'a>(domains: &'a [String]) -> Flow<'a> {
        Flow {
            process_name: "browser.exe",
            process_path: "",
            destination: "1.2.3.4:443".parse().unwrap(),
            protocol: Protocol::Tcp,
            domains,
        }
    }
    #[test]
    fn first_enabled_match_wins() {
        let mut c = Config::default();
        let mut a = rule();
        a.enabled = false;
        a.action = Action::Block;
        c.rules = vec![a, rule()];
        assert_eq!(resolve(&c, &flow(&[])), Action::Proxy("vpn".into()));
        c.rules[0].enabled = true;
        assert_eq!(resolve(&c, &flow(&[])), Action::Block);
    }
    #[test]
    fn conditions_are_and_values_are_or() {
        let mut r = rule();
        r.process_names.push("another.exe".into());
        r.ports = vec![
            crate::config::PortRange::parse("80").unwrap(),
            crate::config::PortRange::parse("443").unwrap(),
        ];
        assert!(matches(&r, &flow(&[])));
        r.protocol = Protocol::Udp;
        assert!(!matches(&r, &flow(&[])));
    }
    #[test]
    fn domain_suffix_respects_label_boundary() {
        let mut r = rule();
        r.domain_suffixes.push("example.com".into());
        for (d, expected) in [
            ("example.com", true),
            ("www.example.com", true),
            ("notexample.com", false),
            ("example.com.evil", false),
        ] {
            assert_eq!(matches(&r, &flow(&[d.into()])), expected);
        }
        assert!(!matches(&r, &flow(&[])));
    }
    #[test]
    fn dns_uses_system_resolver_for_tcp_and_udp_even_with_legacy_options() {
        let mut c = Config::default();
        let mut f = flow(&[]);
        f.destination.set_port(53);
        c.rules = vec![rule()];
        c.dns.enabled = true;
        c.rules[0].dns = DnsPolicy::Proxy;
        assert_eq!(resolve(&c, &f), Action::Direct);
        f.protocol = Protocol::Udp;
        assert_eq!(resolve(&c, &f), Action::Direct);
    }
    #[test]
    fn rule_dns_override_and_block() {
        let mut c = Config::default();
        let mut r = rule();
        r.dns = DnsPolicy::Direct;
        c.rules = vec![r];
        let mut f = flow(&[]);
        f.destination.set_port(53);
        assert_eq!(resolve(&c, &f), Action::Direct);
        c.rules[0].action = Action::Block;
        assert_eq!(resolve(&c, &f), Action::Direct);
    }
}
