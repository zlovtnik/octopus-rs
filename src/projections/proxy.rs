//! Private retained proxy evidence and separately whitelisted search material.
use crate::util::utf16_length;
use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
    sync::OnceLock,
};

pub const AUTHORITY_VERSION: &str = "proxy-authority-v1";
pub const EVIDENCE_VERSION: &str = "proxy-evidence-v1";
pub const TEMPLATE_VERSION: &str = "proxy-event-v2";
pub const ALLOWED_EVENTS: &[&str] = &[
    "block",
    "http_blocked",
    "session.blocked",
    "http_proxied",
    "http_error",
    "tunnel_open",
    "tunnel_close",
];
pub const CLASSIFICATIONS: &[&str] = &[
    "ads_tracker",
    "analytics",
    "cdn",
    "essential_api",
    "auth",
    "unknown",
];

fn ascii(host: &str) -> Option<String> {
    Uts46::new()
        .to_ascii(
            host.as_bytes(),
            AsciiDenyList::STD3,
            Hyphens::Check,
            DnsLength::Verify,
        )
        .ok()
        .map(|v| v.to_lowercase())
}
fn rules() -> &'static HashSet<String> {
    static RULES: OnceLock<HashSet<String>> = OnceLock::new();
    RULES.get_or_init(|| {
        include_str!("../../resources/processor/public_suffix_list.dat")
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.starts_with("//"))
            .map(|rule| {
                let (prefix, host) = if let Some(host) = rule.strip_prefix('!') {
                    ("!", host)
                } else if let Some(host) = rule.strip_prefix("*.") {
                    ("*.", host)
                } else {
                    ("", rule)
                };
                format!(
                    "{prefix}{}",
                    ascii(host).expect("pinned PSL rule must normalize")
                )
            })
            .collect()
    })
}
pub fn registrable_domain(host: &str) -> Option<String> {
    let labels: Vec<_> = host.split('.').collect();
    let rules = rules();
    let exception =
        (0..labels.len()).find(|i| rules.contains(&format!("!{}", labels[*i..].join("."))));
    let suffix = exception.map(|i| labels.len() - i - 1).unwrap_or_else(|| {
        (0..labels.len()).fold(1, |size, i| {
            let candidate = labels[i..].join(".");
            let exact = if rules.contains(&candidate) {
                labels.len() - i
            } else {
                1
            };
            let wildcard = if i > 0 && rules.contains(&format!("*.{candidate}")) {
                labels.len() - i + 1
            } else {
                1
            };
            size.max(exact).max(wildcard)
        })
    });
    (labels.len() > suffix).then(|| labels[labels.len() - suffix - 1..].join("."))
}
fn ipv6(host: &str) -> Option<String> {
    if !host.contains(':')
        || !host
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
    {
        return None;
    }
    if host.contains('.') && host.rsplit(':').next()?.parse::<Ipv4Addr>().is_err() {
        return None;
    }
    let parts = host.parse::<Ipv6Addr>().ok()?.segments();
    let runs: Vec<_> = (0..8)
        .filter(|i| parts[*i] == 0 && (*i == 0 || parts[*i - 1] != 0))
        .map(|i| (i, parts[i..].iter().take_while(|p| **p == 0).count()))
        .filter(|(_, n)| *n >= 2)
        .collect();
    let run = runs
        .into_iter()
        .min_by_key(|(start, n)| (std::cmp::Reverse(*n), *start));
    let labels: Vec<_> = parts.iter().map(|v| format!("{v:x}")).collect();
    Some(match run {
        None => labels.join(":"),
        Some((start, n)) => format!(
            "{}::{}",
            labels[..start].join(":"),
            labels[start + n..].join(":")
        ),
    })
}
pub fn normalize_authority(raw: Option<&str>, source: &str, sanitized: bool) -> Value {
    let mut evidence = json!({"authority_raw":null,"host_raw":null,"host_normalized":null,"port":null,"authority_normalized":null,"registrable_domain":null,"normalization_version":AUTHORITY_VERSION,"parse_status":"invalid","authority_source":source,"sanitization_status":if sanitized{"sanitized"}else{"not_sanitized"}});
    let Some(value) = raw.filter(|v| !v.is_empty()) else {
        evidence["authority_raw"] = json!(raw);
        evidence["parse_status"] = json!("missing");
        return evidence;
    };
    if value.len() > 1024
        || value
            .chars()
            .any(|c| c <= '\u{1f}' || ('\u{7f}'..='\u{9f}').contains(&c))
        || value.contains('@')
    {
        return evidence;
    }
    evidence["authority_raw"] = json!(value);
    if sanitized || value.to_lowercase().starts_with("hmac:") {
        evidence["parse_status"] = json!("sanitized");
        evidence["sanitization_status"] = json!("sanitized");
        return evidence;
    }
    if ![
        "http_authority",
        "connect_authority",
        "quic_authority",
        "sni",
        "original_destination",
        "legacy_host",
        "query",
    ]
    .contains(&source)
        || value
            .chars()
            .any(|c| "/\\?#%".contains(c) || c.is_whitespace())
    {
        return evidence;
    }
    let bracketed = value.starts_with('[');
    let split = if bracketed {
        value.find(']').and_then(|end| {
            let tail = &value[end + 1..];
            if tail.is_empty() {
                Some((&value[1..end], None))
            } else {
                tail.strip_prefix(':')
                    .map(|port| (&value[1..end], Some(port)))
            }
        })
    } else if value.bytes().filter(|c| *c == b':').count() == 1 {
        value
            .rsplit_once(':')
            .map(|(host, port)| (host, Some(port)))
    } else {
        Some((value, None))
    };
    let Some((host, port_text)) = split else {
        return evidence;
    };
    let port = port_text
        .filter(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|p| p.parse::<u16>().ok())
        .filter(|p| *p > 0);
    if port_text.is_some() && port.is_none() {
        return evidence;
    }
    evidence["host_raw"] = json!(host);
    let parsed = if let Some(v) = ipv6(host) {
        Some((v, "valid_ipv6"))
    } else if let Ok(v) = host.parse::<Ipv4Addr>() {
        if bracketed {
            None
        } else {
            Some((v.to_string(), "valid_ipv4"))
        }
    } else if bracketed || host.contains([':', '[', ']']) {
        None
    } else {
        ascii(host)
            .map(|s| s.strip_suffix('.').unwrap_or(&s).to_owned())
            .filter(|s| {
                !s.is_empty()
                    && s.len() <= 253
                    && !s.chars().all(|c| c.is_ascii_digit() || c == '.')
            })
            .map(|s| (s, "valid_dns"))
    };
    if let Some((name, status)) = parsed {
        let endpoint = if status == "valid_ipv6" {
            format!("[{name}]")
        } else {
            name.clone()
        } + &port.map(|p| format!(":{p}")).unwrap_or_default();
        evidence["host_normalized"] = json!(name);
        evidence["port"] = json!(port);
        evidence["authority_normalized"] = json!(endpoint);
        evidence["parse_status"] = json!(status);
        if status == "valid_dns" {
            evidence["registrable_domain"] = json!(registrable_domain(&name));
        }
    }
    evidence
}
fn choice<'a>(v: &'a Value, name: &str, allowed: &[&str], default: &'a str) -> &'a str {
    v.get(name)
        .and_then(Value::as_str)
        .filter(|v| allowed.contains(v))
        .unwrap_or(default)
}
fn nonnegative(v: &Value, name: &str) -> Value {
    v.get(name)
        .and_then(Value::as_i64)
        .filter(|v| *v >= 0)
        .map_or(Value::Null, |v| json!(v))
}
fn timestamp(v: &Value, name: &str) -> Value {
    v.get(name)
        .and_then(Value::as_str)
        .filter(|s| s.parse::<chrono::DateTime<chrono::FixedOffset>>().is_ok())
        .map_or(Value::Null, |v| json!(v))
}

pub fn proxy_evidence(row: &Value) -> Value {
    let raw = row["authority_raw"]
        .as_str()
        .or_else(|| row["host_raw"].as_str())
        .or_else(|| row["host"].as_str());
    let source = row["authority_source"].as_str().unwrap_or("legacy_host");
    let sanitized = row["sanitization_status"].as_str() == Some("sanitized");
    let mut evidence = normalize_authority(raw, source, sanitized);
    if source == "legacy_host" {
        evidence["port"] = Value::Null;
        evidence["authority_normalized"] = Value::Null;
    }
    if row["authority_truncated"].as_bool().unwrap_or(false)
        || row["host_truncated"].as_bool().unwrap_or(false)
    {
        for key in [
            "host_normalized",
            "authority_normalized",
            "port",
            "registrable_domain",
        ] {
            evidence[key] = Value::Null;
        }
        evidence["parse_status"] = json!("invalid");
    }
    let modern = row["evidence_version"].as_str() == Some(EVIDENCE_VERSION);
    let measurement = &row["measurement"];
    let supported = modern && measurement["version"].as_str() == Some("proxy-measurement-v1");
    let declared = if supported {
        choice(
            measurement,
            "bytes_status",
            &["measured_terminal", "partial", "unavailable"],
            "legacy_unknown",
        )
    } else {
        "legacy_unknown"
    };
    let valid = ["bytes_up", "bytes_down"]
        .iter()
        .all(|key| row[*key].as_i64().is_some_and(|v| v >= 0));
    let status = if ["measured_terminal", "partial"].contains(&declared) && !valid {
        "unavailable_invalid_counters"
    } else {
        declared
    };
    let bytes = ["measured_terminal", "partial"].contains(&status);
    let tls = &row["tls_evidence"];
    let attribution = &row["attribution"];
    let safe = json!({"authority_status":if source=="legacy_host"{"legacy_unknown"}else{"observed"},"evidence_version":if modern{EVIDENCE_VERSION}else{"legacy_unknown"},
      "measurement":{"bytes_status":status,"source":if supported{choice(measurement,"source",&["successful_socket_writes","unavailable"],"legacy_unknown")}else{"legacy_unknown"},
        "termination":if supported{choice(measurement,"termination",&["measured_terminal","partial","unavailable"],"legacy_unknown")}else{"legacy_unknown"},
        "bytes_up":if bytes{nonnegative(row,"bytes_up")}else{Value::Null},"bytes_down":if bytes{nonnegative(row,"bytes_down")}else{Value::Null},
        "duration_status":if supported{choice(measurement,"duration_status",&["connection_elapsed","header_latency","unavailable"],"legacy_unknown")}else{"legacy_unknown"},"duration_ms":if supported{nonnegative(row,"duration_ms")}else{Value::Null},"byte_unit":"bytes","directions":"up_client_to_destination_down_destination_to_client"},
      "tls":{"semantics":"clienthello_offers_not_negotiated","parse_status":choice(tls,"parse_status",&["parsed","incomplete","non_tls_or_invalid","parse_failure","non_tls","read_error","timeout","unavailable"],"legacy_unknown"),
        "parser_version":if modern{choice(tls,"parser_version",&["proxy-clienthello-v1","proxy-clienthello-v2"],"legacy_unknown")}else{"legacy_unknown"},
        "offered_version":tls["offered_version"].as_str().filter(|s|["TLS1.0","TLS1.1","TLS1.2","TLS1.3"].contains(s)),
        "offered_alpn":tls["offered_alpn"].as_str().filter(|s|!s.is_empty()&&s.len()<=64&&s.bytes().all(|b|b.is_ascii_alphanumeric()||b",./_-".contains(&b)))},
      "attribution":{"method":choice(attribution,"method",&["device_token","peer_claim","unknown"],"legacy_unknown"),"valid_from":timestamp(attribution,"valid_from"),"valid_until":timestamp(attribution,"valid_until"),"mapping_revision":timestamp(attribution,"mapping_revision"),
        "peer_reference":attribution["peer_reference"].as_str().filter(|s|s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))),"reference_scope":"process_wireguard_peer","reference_rotation":"process_restart_or_key_change","reference_expiry":"process_lifetime"},
      "coalescing":{"status":choice(&row["coalescing"],"status",&["emitted","not_applied","capacity_bypass"],"legacy_unknown"),"suppressed_previous_window":nonnegative(&row["coalescing"],"suppressed_previous_window"),"attempts":"unknown"}});
    evidence
        .as_object_mut()
        .expect("authority object")
        .extend(safe.as_object().expect("safe object").clone());
    evidence
}
pub fn public_evidence(mut evidence: Value) -> Value {
    if let Some(object) = evidence.as_object_mut() {
        object.remove("authority_raw");
        object.remove("host_raw");
    }
    evidence
}
pub fn safe_host(host: Option<&str>, sanitized: bool) -> Option<String> {
    host.filter(|v| {
        let token = v.strip_prefix("hmac:").is_some_and(|v| {
            !v.is_empty()
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        }) && v.len() <= 1024;
        token
            || (!sanitized
                && normalize_authority(Some(v), "legacy_host", false)["host_normalized"]
                    .is_string())
    })
    .map(str::to_owned)
}

pub fn policy_valid(policy: &Value) -> bool {
    policy.as_object().is_some_and(|o| {
        o.is_empty()
            || (o.keys().all(|k| {
                ["version", "lexical", "cohorts", "threat_feed", "asn_cache"].contains(&k.as_str())
            }) && o.get("version").and_then(Value::as_str)
                == Some("proxy-intelligence-policy-v1")
                && o.iter()
                    .filter(|(k, _)| k.as_str() != "version")
                    .all(|(_, v)| v.is_object())
                && policy.to_string().len() <= 1048576)
    })
}
pub fn policy_component(policy: &Value, name: &str) -> Value {
    if policy_valid(policy) {
        policy.get(name).cloned().unwrap_or_else(|| json!({}))
    } else {
        json!({"invalid_envelope":true})
    }
}

pub fn authority_length(value: &str) -> usize {
    utf16_length(value)
}
