use super::LoadError;
use crate::util::{inspect_payload, sha256_hex, stable_uuid};
use chrono::DateTime;
use md5::{Digest, Md5};
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkTarget {
    ProxyEvents,
    ProxyPayloadAudit,
    WirelessAudit,
    WirelessBandwidth,
    RogueAp,
    DeauthFlood,
    SignalAnomaly,
    PmfAttack,
    ClientInventory,
    ProbeRequests,
    AttackSequence,
    SequenceAlert,
    HandshakeAlert,
}
impl SinkTarget {
    pub const ALL: [Self; 13] = [
        Self::ProxyEvents,
        Self::ProxyPayloadAudit,
        Self::WirelessAudit,
        Self::WirelessBandwidth,
        Self::RogueAp,
        Self::DeauthFlood,
        Self::SignalAnomaly,
        Self::PmfAttack,
        Self::ClientInventory,
        Self::ProbeRequests,
        Self::AttackSequence,
        Self::SequenceAlert,
        Self::HandshakeAlert,
    ];
    pub const STREAMS: &'static [&'static str] = &[
        "proxy.events",
        "proxy.payload_audit",
        "wireless.audit",
        "audit.wireless.bandwidth",
        "wireless.rogue_ap",
        "wireless.alert.rogue_ap",
        "wireless.deauth_flood",
        "wireless.alert.deauth_flood",
        "wireless.signal_anomaly",
        "wireless.alert.signal_anomaly",
        "wireless.pmf_attack",
        "wireless.alert.pmf_attack",
        "wireless.client_inventory",
        "wireless.client.inventory",
        "wireless.probe_requests",
        "wireless.probe.flush",
        "wireless.attack_sequence",
        "wireless.alert.attack_sequence",
        "wireless.sequence",
        "wireless.alert.sequence",
        "wireless.sequence_alert",
        "wifi.alert.handshake",
        "wireless.alert.handshake",
        "wireless.handshake",
    ];
    pub fn from_stream(s: &str) -> Option<Self> {
        Some(match s {
            "proxy.events" => Self::ProxyEvents,
            "proxy.payload_audit" => Self::ProxyPayloadAudit,
            "wireless.audit" => Self::WirelessAudit,
            "audit.wireless.bandwidth" => Self::WirelessBandwidth,
            "wireless.rogue_ap" | "wireless.alert.rogue_ap" => Self::RogueAp,
            "wireless.deauth_flood" | "wireless.alert.deauth_flood" => Self::DeauthFlood,
            "wireless.signal_anomaly" | "wireless.alert.signal_anomaly" => Self::SignalAnomaly,
            "wireless.pmf_attack" | "wireless.alert.pmf_attack" => Self::PmfAttack,
            "wireless.client_inventory" | "wireless.client.inventory" => Self::ClientInventory,
            "wireless.probe_requests" | "wireless.probe.flush" => Self::ProbeRequests,
            "wireless.attack_sequence" | "wireless.alert.attack_sequence" => Self::AttackSequence,
            "wireless.sequence" | "wireless.alert.sequence" | "wireless.sequence_alert" => {
                Self::SequenceAlert
            }
            "wifi.alert.handshake" | "wireless.alert.handshake" | "wireless.handshake" => {
                Self::HandshakeAlert
            }
            _ => return None,
        })
    }
    pub fn checksum_tag(self) -> &'static str {
        match self {
            Self::ProxyEvents => "proxy.events",
            Self::ProxyPayloadAudit => "proxy.payload_audit",
            Self::WirelessAudit => "wireless.audit",
            Self::WirelessBandwidth => "audit.wireless.bandwidth",
            Self::RogueAp => "wireless.alert.rogue_ap",
            Self::DeauthFlood => "wireless.alert.deauth_flood",
            Self::SignalAnomaly => "wireless.alert.signal_anomaly",
            Self::PmfAttack => "wireless.alert.pmf_attack",
            Self::ClientInventory => "wireless.client.inventory",
            Self::ProbeRequests => "wireless.probe.flush",
            Self::AttackSequence => "wireless.alert.attack_sequence",
            Self::SequenceAlert => "wireless.alert.sequence",
            Self::HandshakeAlert => "wireless.alert.handshake",
        }
    }
}

pub fn checksum(target: SinkTarget, payload: &str) -> String {
    let mut bytes = target.checksum_tag().as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(payload.as_bytes());
    sha256_hex(bytes)
}

/// Validates the complete JSON first, then retains only one row and envelope scalars.
pub struct PayloadRows<'a> {
    input: &'a str,
    position: usize,
    array: bool,
    max_bytes: usize,
    pending: Option<&'a str>,
    parents: Vec<(&'static str, Value)>,
    done: bool,
}
impl<'a> PayloadRows<'a> {
    pub fn new(target: SinkTarget, payload: &'a str, max_bytes: usize) -> Result<Self, LoadError> {
        inspect_payload(payload).map_err(|_| LoadError::Invalid("invalid JSON payload"))?;
        let payload = payload.trim();
        let mut parents = Vec::new();
        let input = if matches!(
            target,
            SinkTarget::ClientInventory | SinkTarget::ProbeRequests
        ) {
            let fields: std::collections::BTreeMap<String, &serde_json::value::RawValue> =
                serde_json::from_str(payload)
                    .map_err(|_| LoadError::Invalid("payload must be an object envelope"))?;
            if target == SinkTarget::ClientInventory {
                for key in ["sensor_id", "location_id"] {
                    if let Some(raw) = fields.get(key) {
                        parents.push((
                            key,
                            serde_json::from_str(raw.get())
                                .map_err(|_| LoadError::Invalid("invalid envelope field"))?,
                        ));
                    }
                }
                if let Some(raw) = fields
                    .get("snapshot_at")
                    .or_else(|| fields.get("observed_at"))
                {
                    parents.push((
                        "snapshot_at",
                        serde_json::from_str(raw.get())
                            .map_err(|_| LoadError::Invalid("invalid snapshot timestamp"))?,
                    ));
                }
            }
            let key = if target == SinkTarget::ClientInventory {
                "clients"
            } else {
                "probes"
            };
            let array = fields
                .get(key)
                .ok_or(LoadError::Invalid("missing payload row array"))?
                .get();
            if !array.starts_with('[') {
                return Err(LoadError::Invalid("payload rows must be an array"));
            }
            array
        } else {
            payload
        };
        let array = input.starts_with('[');
        Ok(Self {
            input,
            position: usize::from(array),
            array,
            max_bytes,
            pending: None,
            parents,
            done: false,
        })
    }
    pub fn peek(&mut self) -> Result<Option<&'a str>, LoadError> {
        if self.pending.is_some() {
            return Ok(self.pending);
        }
        if self.done {
            return Ok(None);
        }
        let bytes = self.input.as_bytes();
        while self.position < bytes.len()
            && (bytes[self.position].is_ascii_whitespace() || bytes[self.position] == b',')
        {
            self.position += 1;
        }
        if self.position >= bytes.len() || (self.array && bytes[self.position] == b']') {
            self.done = true;
            return Ok(None);
        }
        let start = self.position;
        let mut depth = 0usize;
        let mut quoted = false;
        let mut escaped = false;
        let mut end = self.input.len();
        for (relative, byte) in bytes[start..].iter().copied().enumerate() {
            if quoted {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quoted = false;
                }
            } else {
                match byte {
                    b'"' => quoted = true,
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        if depth == 0 {
                            end = start + relative;
                            break;
                        }
                        depth -= 1;
                    }
                    b',' if depth == 0 => {
                        end = start + relative;
                        break;
                    }
                    _ => {}
                }
            }
        }
        let row = self.input[start..end].trim();
        if row.len() > self.max_bytes {
            return Err(LoadError::Invalid(
                "single PostgreSQL row exceeds byte limit",
            ));
        }
        self.pending = Some(row);
        Ok(self.pending)
    }
    pub fn advance(&mut self) {
        if let Some(raw) = self.pending.take() {
            self.position = raw.as_ptr() as usize - self.input.as_ptr() as usize + raw.len();
            if !self.array {
                self.done = true;
            }
        }
    }
    pub fn with_parents(&self, mut row: Value) -> Result<Value, LoadError> {
        if !self.parents.is_empty() {
            let object = row
                .as_object_mut()
                .ok_or(LoadError::Invalid("each client must be an object"))?;
            for (key, value) in &self.parents {
                object.insert((*key).into(), value.clone());
            }
        }
        Ok(row)
    }
}

/// The private record is validated by its target-specific transform before SQL uses it.
#[derive(Clone, Debug)]
pub struct TransformedRow {
    pub target: SinkTarget,
    pub(crate) record: Value,
    pub(crate) blocked: Option<Value>,
}
impl TransformedRow {
    pub fn record(&self) -> &Value {
        &self.record
    }
}

fn string(row: &Value, key: &str) -> Option<String> {
    row.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}
fn required_string(row: &Value, key: &str) -> Result<String, LoadError> {
    row.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(LoadError::Invalid("missing required string"))
}
fn long(row: &Value, key: &str) -> Option<i64> {
    crate::dq::long(row, key).ok()
}
fn required_long(row: &Value, key: &str) -> Result<i64, LoadError> {
    long(row, key).ok_or(LoadError::Invalid("missing required long"))
}
fn boolean(row: &Value, key: &str) -> bool {
    row.get(key) == Some(&Value::Bool(true)) || long(row, key).is_some_and(|n| n != 0)
}
fn timestamp(row: &Value, key: &str) -> Option<String> {
    row.get(key)
        .and_then(Value::as_str)
        .filter(|s| DateTime::parse_from_rfc3339(s).is_ok())
        .map(str::to_owned)
}
fn required_timestamp(row: &Value, key: &str) -> Result<String, LoadError> {
    timestamp(row, key).ok_or(LoadError::Invalid("missing or invalid timestamp"))
}
fn detected(row: &Value) -> Result<String, LoadError> {
    timestamp(row, "detected_at")
        .or_else(|| timestamp(row, "observed_at"))
        .ok_or(LoadError::Invalid("missing alert timestamp"))
}
fn alias(row: &Value, first: &str, second: &str) -> Result<String, LoadError> {
    string(row, first)
        .or_else(|| string(row, second))
        .ok_or(LoadError::Invalid("missing required string alias"))
}
fn array(row: &Value, key: &str) -> Value {
    row.get(key)
        .filter(|v| v.is_array())
        .cloned()
        .unwrap_or(Value::Null)
}
fn array_text(row: &Value, key: &str) -> Value {
    let a = array(row, key);
    if a.is_null() {
        a
    } else {
        Value::String(a.to_string())
    }
}
fn copy_strings(out: &mut Value, row: &Value, keys: &[&str]) {
    for key in keys {
        out[*key] = json!(string(row, key));
    }
}
fn copy_longs(out: &mut Value, row: &Value, keys: &[&str]) {
    for key in keys {
        out[*key] = json!(long(row, key));
    }
}
fn name_uuid(value: &str) -> String {
    let mut bytes: [u8; 16] = Md5::digest(value.as_bytes()).into();
    bytes[6] = (bytes[6] & 15) | 48;
    bytes[8] = (bytes[8] & 63) | 128;
    uuid::Uuid::from_bytes(bytes).to_string()
}
fn band(channel: i64) -> &'static str {
    if (1..=14).contains(&channel) {
        "2.4GHz"
    } else if (1..=233).contains(&channel) {
        "5GHz"
    } else {
        "unknown"
    }
}

pub fn transform(
    target: SinkTarget,
    row: &Value,
    sequence: i64,
) -> Result<TransformedRow, LoadError> {
    if sequence < 0 {
        return Err(LoadError::Invalid("negative row sequence"));
    }
    let mut out = json!({"row_sequence":sequence});
    let mut blocked = None;
    match target {
        SinkTarget::ProxyEvents => {
            let raw = row.to_string();
            let event_id = match string(row, "event_id") {
                Some(s) => uuid::Uuid::parse_str(&s)
                    .map_err(|_| LoadError::Invalid("invalid event UUID"))?
                    .to_string(),
                None => name_uuid(&raw),
            };
            let time = required_timestamp(row, "time")?;
            let kind = required_string(row, "type")?;
            let host = required_string(row, "host")?;
            let category = string(row, "classification")
                .or_else(|| string(row, "category"))
                .filter(|s| {
                    matches!(
                        s.as_str(),
                        "ads_tracker" | "analytics" | "cdn" | "essential_api" | "auth" | "unknown"
                    )
                })
                .unwrap_or_else(|| "unknown".into());
            out = json!({"event_id":event_id,"event_time":time,"event_timestamp_utc":time,"event_type":kind,"host":host,"payload":row,"raw_json":raw,"row_sequence":sequence.checked_add(1).ok_or(LoadError::Invalid("row sequence overflow"))?,"bytes_up":long(row,"bytes_up").unwrap_or(0),"bytes_down":long(row,"bytes_down").unwrap_or(0),"blocked":boolean(row,"blocked"),"classification":category,"identity_source":string(row,"identity_source").unwrap_or_else(||"unknown".into())});
            copy_strings(
                &mut out,
                row,
                &[
                    "peer_ip",
                    "wg_pubkey",
                    "device_id",
                    "peer_hostname",
                    "client_ua",
                    "obfuscation_profile",
                    "correlation_id",
                    "reason",
                ],
            );
            copy_longs(
                &mut out,
                row,
                &["status_code", "event_sequence", "duration_ms"],
            );
            out["wireguard_pubkey"] = out["wg_pubkey"].clone();
            out["registered_device_id"] = json!(string(row, "device_id")
                .and_then(|s| uuid::Uuid::parse_str(&s).ok())
                .map(|u| u.to_string()));
            out["causation_id"] = json!(string(row, "parent_event_id"));
            out["evidence"] = crate::projections::proxy_evidence(row);
            if boolean(row, "blocked") {
                let metrics = &row["metrics"];
                let fallback = if kind == "block" || kind == "session.blocked" {
                    50 + host.len() as i64
                } else {
                    0
                };
                blocked = Some(
                    json!({"host":host,"blocked_attempts":1,"blocked_bytes":long(row,"blocked_bytes_delta_approx").or_else(||long(metrics,"blocked_bytes_delta_approx")).filter(|n|*n>=0).unwrap_or(fallback),"frequency_hz":row.get("frequency_hz").or_else(||metrics.get("frequency_hz")).and_then(Value::as_f64).unwrap_or(0.0),"risk_score":row.get("risk_score").or_else(||metrics.get("risk_score")).and_then(Value::as_f64).unwrap_or(0.0).clamp(-999999.9999,999999.9999),"category":string(row,"category"),"verdict":string(row,"verdict").unwrap_or_else(||"BLOCKED".into()),"tarpit_held_ms":long(row,"tarpit_held_ms").unwrap_or(0),"iat_ms":long(row,"iat_ms").or_else(||long(metrics,"iat_ms")),"consecutive_blocks":long(row,"consecutive_blocks").or_else(||long(metrics,"consecutive_blocks")).or_else(||long(row,"attempt_count")).or_else(||long(metrics,"attempt_count")).unwrap_or(0),"last_verdict":string(row,"last_verdict"),"tls_ver":string(&row["fingerprint"],"tls_ver"),"alpn":string(&row["fingerprint"],"alpn"),"ja3_lite":string(&row["fingerprint"],"ja3_lite"),"resolved_ip":string(row,"resolved_ip"),"asn_org":string(row,"asn_org"),"updated_at":time,"first_seen":time,"last_event_id":event_id}),
                );
            }
        }
        SinkTarget::ProxyPayloadAudit => {
            out = json!({"correlation_id":string(row,"correlation_id").unwrap_or_else(||name_uuid(&row.to_string())),"host":required_string(row,"host")?,"direction":string(row,"direction").unwrap_or_else(||"UP".into()).to_uppercase(),"captured_at":required_timestamp(row,"observed_at")?,"byte_offset":long(row,"byte_offset").unwrap_or(0),"is_encrypted":boolean(row,"is_encrypted"),"truncated":boolean(row,"truncated"),"http_status":long(row,"http_status").or_else(||long(row,"status_code")),"http_method":string(row,"method"),"http_path":string(row,"path")});
            copy_strings(
                &mut out,
                row,
                &["payload_object_key", "content_type", "peer_ip", "notes"],
            );
        }
        SinkTarget::WirelessAudit => {
            let channel = required_long(row, "channel")?;
            out = json!({"row_sequence":sequence,"event_type":required_string(row,"event_type")?,"observed_at":required_timestamp(row,"observed_at")?,"sensor_id":required_string(row,"sensor_id")?,"location_id":required_string(row,"location_id")?,"interface":required_string(row,"interface")?,"channel":channel,"band":band(channel),"frame_subtype":required_string(row,"frame_subtype")?,"ssid":row.get("ssid").and_then(Value::as_str),"raw_len":required_long(row,"raw_len")?,"security_flags":long(row,"security_flags").unwrap_or(0),"identity_source":string(row,"identity_source").unwrap_or_else(||"unknown".into()),"tags":array_text(row,"tags"),"anomaly_reasons":array_text(row,"anomaly_reasons"),"raw_json":row.to_string()});
            out["raw_json"] = row.clone();
            copy_strings(
                &mut out,
                row,
                &[
                    "frame_type",
                    "bssid",
                    "source_mac",
                    "destination_mac",
                    "transmitter_mac",
                    "receiver_mac",
                    "destination_bssid",
                    "device_id",
                    "username",
                    "reg_domain",
                ],
            );
            copy_longs(&mut out, row, &["signal_dbm", "sequence_number"]);
            for (dest, src) in [
                ("is_retry", "retry"),
                ("is_more_data", "more_data"),
                ("is_power_save", "power_save"),
                ("is_protected", "protected"),
                ("is_to_ds", "to_ds"),
                ("is_from_ds", "from_ds"),
                ("is_handshake", "handshake_captured"),
            ] {
                out[dest] = json!(boolean(row, src));
            }
        }
        SinkTarget::WirelessBandwidth => {
            let channel = required_long(row, "channel")?;
            out = json!({"row_sequence":sequence,"schema_version":long(row,"schema_version").unwrap_or(1),"window_start":required_timestamp(row,"window_start")?,"window_end":required_timestamp(row,"window_end")?,"sensor_id":required_string(row,"sensor_id")?,"location_id":required_string(row,"location_id")?,"interface":required_string(row,"interface")?,"channel":channel,"band":band(channel),"source_mac":required_string(row,"source_mac")?,"destination_bssid":required_string(row,"destination_bssid")?,"bytes":required_long(row,"bytes")?,"frame_count":required_long(row,"frame_count")?,"external_bssid":boolean(row,"external_bssid"),"threshold_exceeded":boolean(row,"threshold_exceeded"),"window_is_partial":boolean(row,"window_is_partial"),"published_at":timestamp(row,"published_at")});
            copy_strings(&mut out, row, &["ssid"]);
            copy_longs(
                &mut out,
                row,
                &[
                    "strongest_signal_dbm",
                    "inter_arrival_p50_ms",
                    "wall_clock_delta_ms",
                ],
            );
            for key in ["retry_count", "more_data_count", "power_save_count"] {
                out[key] = json!(long(row, key).unwrap_or(0));
            }
            for (dest, src) in [
                ("hist_under_100", "under_100"),
                ("hist_100_500", "range_100_500"),
                ("hist_500_1000", "range_500_1000"),
                ("hist_1000_1500", "range_1000_1500"),
            ] {
                out[dest] = json!(long(&row["frame_size_histogram"], src).unwrap_or(0));
            }
        }
        SinkTarget::ClientInventory => {
            out = json!({"sensor_id":required_string(row,"sensor_id")?,"location_id":required_string(row,"location_id")?,"snapshot_at":required_timestamp(row,"snapshot_at")?,"client_mac":alias(row,"client_mac","source_mac")?,"last_seen":required_timestamp(row,"last_seen")?,"first_seen":required_timestamp(row,"first_seen")?,"signal_dbm":long(row,"signal_dbm").or_else(||long(row,"last_signal_dbm")),"is_authorized":boolean(row,"is_authorized")});
            copy_strings(
                &mut out,
                row,
                &["bssid", "ssid", "device_id", "username", "identity_source"],
            );
        }
        SinkTarget::ProbeRequests => {
            out = json!({"row_sequence":sequence,"client_mac":required_string(row,"client_mac")?,"ssid":required_string(row,"ssid")?,"known_bssid":string(row,"known_bssid"),"first_seen":required_timestamp(row,"first_seen")?,"last_seen":required_timestamp(row,"last_seen")?,"probe_count":required_long(row,"probe_count")?});
        }
        _ => {
            out = alert(target, row, sequence)?;
        }
    }
    Ok(TransformedRow {
        target,
        record: out,
        blocked,
    })
}

fn alert(target: SinkTarget, row: &Value, sequence: i64) -> Result<Value, LoadError> {
    let sensor = required_string(row, "sensor_id")?;
    let location = required_string(row, "location_id")?;
    let mut out = json!({"row_sequence":sequence,"detected_at":detected(row)?,"sensor_id":sensor,"location_id":location,"primary_mac":null,"secondary_mac":null,"ssid":string(row,"ssid"),"signal_dbm":null,"interface":null,"channel":null,"details_json":{},"raw_json":null});
    let (kind, subject, severity, tag) = match target {
        SinkTarget::RogueAp => {
            let mac = alias(row, "rogue_bssid", "bssid")?;
            out["interface"] = json!(required_string(row, "interface")?);
            out["channel"] = json!(required_long(row, "channel")?);
            out["primary_mac"] = json!(mac);
            out["signal_dbm"] = json!(long(row, "signal_dbm"));
            let reason = array(row, "reasons").as_array().is_some_and(|a| {
                a.iter()
                    .any(|v| v == "ssid_impersonation" || v == "bssid_spoofing")
            });
            out["details_json"] =
                json!({"ssid_impersonation":i64::from(boolean(row,"ssid_impersonation")||reason)});
            out["raw_json"] = json!(row.to_string());
            ("access_point", mac, "high", "rogue_ap")
        }
        SinkTarget::DeauthFlood => {
            let attacker = string(row, "attacker_mac").or_else(|| string(row, "source_mac"));
            let bssid = string(row, "target_bssid").or_else(|| string(row, "bssid"));
            out["interface"] = json!(required_string(row, "interface")?);
            out["channel"] = json!(long(row, "channel").unwrap_or(0));
            out["primary_mac"] = json!(attacker);
            out["secondary_mac"] = json!(bssid);
            out["ssid"] = json!(string(row, "target_ssid").or_else(|| string(row, "ssid")));
            out["signal_dbm"] = json!(long(row, "signal_dbm"));
            out["details_json"] = json!({"deauth_count":long(row,"deauth_count").or_else(||long(row,"frame_count")).ok_or(LoadError::Invalid("missing deauth count"))?,"window_secs":required_long(row,"window_secs")?,"threshold":long(row,"threshold").unwrap_or(0)});
            out["raw_json"] = json!(row.to_string());
            let (k, id) = subject(
                bssid
                    .map(|s| ("access_point", s))
                    .or_else(|| attacker.map(|s| ("station", s))),
                &sensor,
            );
            (k, id, "high", "deauth_flood")
        }
        SinkTarget::SignalAnomaly => {
            let mac = required_string(row, "source_mac")?;
            out["primary_mac"] = json!(mac);
            out["secondary_mac"] = json!(string(row, "bssid"));
            out["channel"] = json!(required_long(row, "channel")?);
            out["signal_dbm"] = json!(required_long(row, "observed_dbm")?);
            out["details_json"] = json!({"baseline_dbm":required_long(row,"baseline_dbm")?,"observed_dbm":required_long(row,"observed_dbm")?,"dbm_delta":required_long(row,"dbm_delta")?.wrapping_abs(),"configured_delta":required_long(row,"configured_delta")?});
            ("station", mac, "medium", "signal_anomaly")
        }
        SinkTarget::PmfAttack => {
            let mac = alias(row, "target_mac", "source_mac")?;
            let bssid = string(row, "target_bssid").or_else(|| string(row, "bssid"));
            out["primary_mac"] = json!(mac);
            out["secondary_mac"] = json!(bssid);
            out["channel"] = json!(long(row, "channel"));
            out["details_json"] = json!({"attack_tag":required_string(row,"attack_tag")?});
            if let Some(n) = long(row, "reconnect_window_ms") {
                out["details_json"]["reconnect_window_ms"] = json!(n);
            }
            (
                "access_point",
                bssid.unwrap_or(mac),
                "critical",
                "pmf_attack",
            )
        }
        SinkTarget::AttackSequence | SinkTarget::SequenceAlert => {
            out["ssid"] = json!(row.get("ssid").and_then(Value::as_str));
            let mut details = json!({"first_event_at":utc_time(&required_timestamp(row,"first_event_at")?)?,"last_event_at":utc_time(&required_timestamp(row,"last_event_at")?)?});
            for key in ["factor_breakdown", "explanation"] {
                let value = array(row, key);
                if !value.is_null() {
                    details[key] = value;
                }
            }
            let (kind, id, severity, tag) = if target == SinkTarget::AttackSequence {
                let a = array(row, "attack_chain");
                if !a.is_null() {
                    details["attack_chain"] = a;
                }
                let (k, id) = subject(string(row, "ssid").map(|s| ("network", s)), &sensor);
                (k, id, "critical", "attack_sequence")
            } else {
                details["session_key"] = json!(required_string(row, "session_key")?);
                details["attack_tag"] = json!(required_string(row, "attack_tag")?);
                let a = array(row, "sequence");
                if !a.is_null() {
                    details["sequence"] = a;
                }
                let mac = string(row, "source_mac");
                let bssid = string(row, "bssid");
                out["primary_mac"] = json!(mac);
                out["secondary_mac"] = json!(bssid);
                let (k, id) = subject(
                    mac.map(|s| ("station", s))
                        .or_else(|| bssid.map(|s| ("access_point", s))),
                    &sensor,
                );
                (k, id, "high", "sequence_alert")
            };
            out["details_json"] = details;
            out["raw_json"] = json!(row.to_string());
            (kind, id, severity, tag)
        }
        SinkTarget::HandshakeAlert => {
            let bssid = required_string(row, "bssid")?;
            out["interface"] = json!(required_string(row, "interface")?);
            out["primary_mac"] = json!(required_string(row, "client_mac")?);
            out["secondary_mac"] = json!(bssid);
            out["ssid"] = Value::Null;
            out["signal_dbm"] = json!(long(row, "signal_dbm"));
            out["details_json"] = match string(row, "pmkid") {
                Some(s) => json!({"pmkid_sha256":sha256_hex(s)}),
                None => json!({}),
            };
            ("access_point", bssid, "medium", "handshake")
        }
        _ => return Err(LoadError::Invalid("target is not an alert")),
    };
    out["subject_kind"] = json!(kind);
    out["subject_id"] = json!(subject);
    out["severity"] = json!(severity);
    out["alert_type"] = json!(tag);
    out["evidence"] = json!({"event_type":tag,"sensor_id":sensor,"location_id":location,"primary_mac":out["primary_mac"],"secondary_mac":out["secondary_mac"],"ssid":out["ssid"],"signal_dbm":out["signal_dbm"],"details":out["details_json"]});
    Ok(out)
}
fn subject(preferred: Option<(&'static str, String)>, sensor: &str) -> (&'static str, String) {
    preferred
        .filter(|(_, s)| !crate::util::java_trim(s).is_empty())
        .unwrap_or_else(|| ("sensor", sensor.into()))
}
fn utc_time(time: &str) -> Result<String, LoadError> {
    let time = DateTime::parse_from_rfc3339(time)
        .map_err(|_| LoadError::Invalid("invalid timestamp"))?
        .with_timezone(&chrono::Utc);
    let text = time.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
    Ok(if text.ends_with(":00Z") {
        format!("{}Z", &text[..text.len() - 4])
    } else {
        text
    })
}

pub(crate) fn alert_identity(batch: &str, row: &mut Value) {
    let sequence = row["row_sequence"]
        .as_i64()
        .expect("validated row sequence");
    let source = stable_uuid("wireless-alert-source", &[batch, &sequence.to_string()]);
    row["source_event_id"] = json!(source);
    row["alert_id"] = json!(stable_uuid(
        "wireless-alert",
        &[&source, row["alert_type"].as_str().expect("alert type")]
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_targets_and_aliases() {
        for target in SinkTarget::ALL {
            assert_eq!(SinkTarget::from_stream(target.checksum_tag()), Some(target));
        }
        assert_eq!(
            SinkTarget::from_stream("wireless.handshake"),
            Some(SinkTarget::HandshakeAlert)
        );
        assert!(SinkTarget::from_stream("unknown").is_none());
    }
    #[test]
    fn bounded_streaming_envelopes() {
        let payload = r#"{"clients":[{"client_mac":"aa","sensor_id":"ignored"},{"client_mac":"bb"}],"sensor_id":"sensor","observed_at":"2026-01-01T00:00:00Z"}"#;
        let mut rows = PayloadRows::new(SinkTarget::ClientInventory, payload, 100).unwrap();
        let first: Value = serde_json::from_str(rows.peek().unwrap().unwrap()).unwrap();
        let first = rows.with_parents(first).unwrap();
        assert_eq!(first["sensor_id"], "sensor");
        assert_eq!(first["snapshot_at"], "2026-01-01T00:00:00Z");
        rows.advance();
        assert!(rows.peek().unwrap().unwrap().contains("bb"));
        rows.advance();
        assert!(rows.peek().unwrap().is_none());
        assert!(PayloadRows::new(SinkTarget::ProxyEvents, "[{}]garbage", 100).is_err());
        let mut rows =
            PayloadRows::new(SinkTarget::ProxyEvents, "[{\"long\":\"value\"}]", 3).unwrap();
        assert!(rows.peek().is_err());
    }
    #[test]
    fn deterministic_proxy_and_alert_validation() {
        let p = json!({"type":"block","host":"é.example","time":"2026-01-01T00:00:00Z","blocked":1,"risk_score":1e9});
        let r = transform(SinkTarget::ProxyEvents, &p, 4).unwrap();
        assert_eq!(r.record["row_sequence"], 5);
        assert_eq!(r.blocked.as_ref().unwrap()["blocked_bytes"], 60);
        assert_eq!(r.blocked.as_ref().unwrap()["risk_score"], 999999.9999);
        assert_eq!(r.record["classification"], "unknown");
        assert_eq!(
            transform(SinkTarget::ProxyEvents, &p, 4).unwrap().record["event_id"],
            r.record["event_id"]
        );
        assert!(transform(SinkTarget::ProxyEvents, &p, -1).is_err());
        assert!(transform(SinkTarget::WirelessAudit, &json!({}), 0).is_err());
    }
}
