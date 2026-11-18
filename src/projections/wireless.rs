use super::ProjectionError;
use crate::{
    config::{SensorCalibration, WirelessProjectionConfig},
    domain::BrokerRecordMetadata,
    postgres::PgTransaction,
    util::utf16_length,
};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use md5::{Digest, Md5};
use serde_json::{json, Map, Value};

#[derive(Clone, Debug, PartialEq)]
pub struct WirelessObservation {
    pub sensor_id: String,
    pub observed_at: DateTime<Utc>,
    pub source_mac: Option<String>,
    pub bssid: Option<String>,
    pub transmitter_mac: Option<String>,
    pub ssid: Option<String>,
    pub signal_dbm: Option<i32>,
    pub frequency_mhz: Option<i32>,
    pub channel: Option<i32>,
    pub frame_type: String,
    pub protocol: String,
    pub retry: bool,
    pub protected: bool,
    pub handshake: bool,
}

fn field<'a>(v: &'a Value, name: &str, parent: &str) -> Option<&'a Value> {
    v.get(name).or_else(|| v.get(parent)?.get(name))
}
fn string(v: &Value, name: &str, parent: &str) -> Option<String> {
    field(v, name, parent)?.as_str().map(str::to_owned)
}
fn integer(v: &Value, name: &str, parent: &str) -> Option<i32> {
    field(v, name, parent)?.as_i64()?.try_into().ok()
}
fn boolean(v: &Value, name: &str, parent: &str) -> bool {
    field(v, name, parent)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}
fn mac(v: &Value, name: &str) -> Option<String> {
    let value = string(v, name, "mac")?.to_lowercase();
    let valid = value.len() == 17
        && value.bytes().enumerate().all(|(i, b)| {
            if i % 3 == 2 {
                b == b':'
            } else {
                b.is_ascii_hexdigit()
            }
        })
        && u8::from_str_radix(&value[..2], 16).is_ok_and(|octet| octet & 1 == 0)
        && value != "00:00:00:00:00:00";
    valid.then_some(value)
}
pub fn decode_wireless(raw: &str) -> Result<WirelessObservation, ProjectionError> {
    let value = serde_json::from_str(raw).map_err(|_| ProjectionError::Invalid("wireless JSON"))?;
    WirelessObservation::from_value(&value)
}
impl WirelessObservation {
    pub fn from_value(v: &Value) -> Result<Self, ProjectionError> {
        let sensor_id = string(v, "sensor_id", "")
            .filter(|s| !s.is_empty() && utf16_length(s) <= 64)
            .ok_or(ProjectionError::Invalid("sensor_id"))?;
        let observed_at = string(v, "observed_at", "")
            .and_then(|s| s.parse::<DateTime<Utc>>().ok())
            .ok_or(ProjectionError::Invalid("observed_at"))?;
        if field(v, "schema_version", "").is_some()
            && !matches!(integer(v, "schema_version", ""), Some(1 | 2))
        {
            return Err(ProjectionError::Invalid(
                "unsupported wireless schema version",
            ));
        }
        let ssid = string(v, "ssid", "");
        if ssid.as_deref().is_some_and(|value| value.contains('\0')) {
            return Err(ProjectionError::Invalid("ssid contains a NUL character"));
        }
        Ok(Self {
            sensor_id,
            observed_at,
            source_mac: mac(v, "source_mac"),
            bssid: mac(v, "bssid"),
            transmitter_mac: mac(v, "transmitter_mac"),
            ssid: ssid.filter(|s| utf16_length(s) <= 256),
            signal_dbm: integer(v, "signal_dbm", "rf").filter(|v| (-127..0).contains(v)),
            frequency_mhz: integer(v, "frequency_mhz", "rf"),
            channel: integer(v, "channel_number", "rf").or_else(|| integer(v, "channel", "")),
            frame_type: string(v, "frame_type", "mac")
                .filter(|s| utf16_length(s) <= 32)
                .unwrap_or_else(|| "unknown".into()),
            protocol: string(v, "app_protocol", "")
                .or_else(|| string(v, "protocol", "application"))
                .filter(|s| utf16_length(s) <= 64)
                .unwrap_or_else(|| "unknown".into()),
            retry: boolean(v, "retry", "mac"),
            protected: boolean(v, "protected", "mac"),
            handshake: boolean(v, "handshake_captured", ""),
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct RadioSamples {
    pub count: i64,
    pub sum: f64,
    pub squares: f64,
}
impl RadioSamples {
    pub fn add(self, rssi: i32) -> Self {
        let rssi = f64::from(rssi);
        Self {
            count: self.count + 1,
            sum: self.sum + rssi,
            squares: self.squares + rssi * rssi,
        }
    }
    pub fn mean(self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum / self.count as f64
        }
    }
    pub fn stddev(self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            ((self.squares - self.sum * self.sum / self.count as f64) / (self.count - 1) as f64)
                .max(0.0)
                .sqrt()
        }
    }
}
fn instant(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}
pub fn calibrated_range(
    samples: RadioSamples,
    calibration: &SensorCalibration,
    frequency: i32,
    channel: i32,
    first: DateTime<Utc>,
    last: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Option<Value> {
    if samples.count < i64::from(calibration.minimum_samples)
        || samples.stddev() > calibration.maximum_stddev_db
        || !calibration.frequencies_mhz.contains(&frequency)
        || !calibration.channels.contains(&channel)
        || first < calibration.valid_from
        || last >= calibration.valid_until
        || now < calibration.valid_from
        || now >= calibration.valid_until
        || last < now - Duration::seconds(300)
        || last > now
    {
        return None;
    }
    let meters = calibration.reference_meters
        * 10.0_f64.powf(
            (calibration.reference_rssi - samples.mean()) / (10.0 * calibration.path_loss_exponent),
        );
    let error_db =
        calibration.uncertainty_db + 1.96 * samples.stddev() / (samples.count as f64).sqrt();
    let factor = 10.0_f64.powf(error_db / (10.0 * calibration.path_loss_exponent));
    Some(
        json!({"meters":meters,"error_meters":meters*(factor-1.0),"lower_meters":meters/factor,
        "upper_meters":meters*factor,"confidence":"model_estimate","calibration_version":calibration.version,
        "sample_count":samples.count,"observed_at":instant(last),"valid_until":instant(calibration.valid_until.min(last+Duration::seconds(300)))}),
    )
}

pub fn wireless_id(parts: &[&str]) -> String {
    let mut digest = Md5::new();
    for part in parts {
        digest.update(format!("{}:{part}", utf16_length(part)).as_bytes());
    }
    let mut bytes: [u8; 16] = digest.finalize().into();
    bytes[6] = (bytes[6] & 0x0f) | 0x30;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

pub async fn project(
    tx: &mut PgTransaction,
    event: &WirelessObservation,
    m: &BrokerRecordMetadata,
    config: &WirelessProjectionConfig,
) -> Result<bool, ProjectionError> {
    let now: DateTime<Utc> = tx.query("SELECT CURRENT_TIMESTAMP", &[]).await?[0].get(0);
    let inserted = tx.execute("INSERT INTO octopus_core.wireless_projection_group_receipts (group_id,topic,partition_id,offset_id,payload_sha256,disposition,observed_at) VALUES ($1,$2,$3,$4,$5,'received',$6) ON CONFLICT DO NOTHING", &[&m.consumer_group,&m.topic,&m.partition,&m.offset,&m.payload_sha256,&event.observed_at]).await?;
    let stored: String = tx.query("SELECT payload_sha256 FROM octopus_core.wireless_projection_group_receipts WHERE group_id=$1 AND topic=$2 AND partition_id=$3 AND offset_id=$4", &[&m.consumer_group,&m.topic,&m.partition,&m.offset]).await?[0].get(0);
    if stored != m.payload_sha256 {
        return Err(ProjectionError::CoordinateConflict);
    }
    let fresh = inserted > 0 && tx.execute("INSERT INTO octopus_core.wireless_projection_hashes (payload_sha256) VALUES ($1) ON CONFLICT DO NOTHING", &[&m.payload_sha256]).await? > 0;
    let eligible = fresh
        && event.observed_at >= now - Duration::days(7)
        && event.observed_at <= now + Duration::seconds(60);
    let calibrations = config
        .calibrations()
        .map_err(|_| ProjectionError::Invalid("calibrations"))?;
    let mut current = calibrations
        .iter()
        .filter(|c| c.sensor_id == event.sensor_id && now >= c.valid_from && now < c.valid_until);
    let first = current.next();
    let calibration = if current.next().is_none() {
        first
    } else {
        None
    };
    if eligible {
        update_projection(tx, event, calibration, config.ranges_enabled, now).await?;
    }
    if inserted > 0 {
        let disposition = if !fresh {
            "duplicate"
        } else if eligible {
            "projected"
        } else {
            "outside_window"
        };
        tx.execute("UPDATE octopus_core.wireless_projection_group_receipts SET disposition=$5 WHERE group_id=$1 AND topic=$2 AND partition_id=$3 AND offset_id=$4", &[&m.consumer_group,&m.topic,&m.partition,&m.offset,&disposition]).await?;
    }
    Ok(eligible)
}

#[allow(clippy::too_many_arguments)]
async fn node(
    tx: &mut PgTransaction,
    id: &str,
    kind: &str,
    label: &str,
    payload: Value,
    location: Option<&str>,
    sensor: Option<&str>,
    mac: Option<&str>,
    ssid: Option<&str>,
    observed: DateTime<Utc>,
) -> Result<(), ProjectionError> {
    tx.execute("INSERT INTO atheros_search.wireless_topology_nodes (node_id,node_kind,label,node_payload,location_id,sensor_id,normalized_mac,normalized_ssid,observed_at,projection_run_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'wireless-stream-v1') ON CONFLICT(node_id) DO UPDATE SET label=EXCLUDED.label,node_payload=EXCLUDED.node_payload,location_id=EXCLUDED.location_id,sensor_id=EXCLUDED.sensor_id,normalized_ssid=EXCLUDED.normalized_ssid,observed_at=EXCLUDED.observed_at,updated_at=CURRENT_TIMESTAMP WHERE EXCLUDED.observed_at>=wireless_topology_nodes.observed_at", &[&id,&kind,&label,&payload,&location,&sensor,&mac,&ssid,&observed]).await?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
async fn edge(
    tx: &mut PgTransaction,
    id: &str,
    source: &str,
    target: &str,
    kind: &str,
    label: &str,
    evidence: Value,
    observed: DateTime<Utc>,
    expires: Option<DateTime<Utc>>,
) -> Result<(), ProjectionError> {
    tx.execute("INSERT INTO atheros_search.wireless_topology_edges (edge_id,source_node_id,target_node_id,edge_kind,label,evidence,observed_at,projection_run_id,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'wireless-stream-v1',$8) ON CONFLICT(edge_id) DO UPDATE SET evidence=EXCLUDED.evidence,observed_at=EXCLUDED.observed_at,expires_at=EXCLUDED.expires_at,updated_at=CURRENT_TIMESTAMP WHERE wireless_topology_edges.observed_at IS NULL OR EXCLUDED.observed_at>=wireless_topology_edges.observed_at", &[&id,&source,&target,&kind,&label,&evidence,&observed,&expires]).await?;
    Ok(())
}
async fn update_projection(
    tx: &mut PgTransaction,
    e: &WirelessObservation,
    c: Option<&SensorCalibration>,
    ranges: bool,
    now: DateTime<Utc>,
) -> Result<(), ProjectionError> {
    let location = c.map(|c| c.location_id.as_str());
    let sensor_node = format!("sensor:{}", e.sensor_id);
    node(
        tx,
        &sensor_node,
        "sensor",
        &e.sensor_id,
        json!({}),
        location,
        Some(&e.sensor_id),
        None,
        None,
        e.observed_at,
    )
    .await?;
    if let Some(loc) = location {
        node(
            tx,
            &format!("location:{loc}"),
            "location",
            loc,
            json!({}),
            Some(loc),
            None,
            None,
            None,
            e.observed_at,
        )
        .await?;
        edge(
            tx,
            &wireless_id(&["contains", loc, &sensor_node]),
            &format!("location:{loc}"),
            &sensor_node,
            "containment",
            "Configured sensor location",
            json!({}),
            e.observed_at,
            None,
        )
        .await?;
    }
    if let Some(ap) = &e.bssid {
        node(
            tx,
            &format!("ap:{ap}"),
            "access_point",
            e.ssid.as_deref().unwrap_or(ap),
            json!({"bssid":ap,"ssid":e.ssid}),
            None,
            None,
            Some(ap),
            e.ssid.as_deref(),
            e.observed_at,
        )
        .await?;
        if let Some(c) = c.filter(|c| c.access_points.contains(ap)) {
            edge(
                tx,
                &wireless_id(&["contains", &c.location_id, &format!("ap:{ap}")]),
                &format!("location:{}", c.location_id),
                &format!("ap:{ap}"),
                "containment",
                "Reviewed AP location",
                json!({}),
                e.observed_at,
                None,
            )
            .await?;
        }
    }
    if let Some(mac) = e
        .source_mac
        .as_ref()
        .filter(|mac| Some(*mac) != e.bssid.as_ref())
    {
        tx.execute("INSERT INTO atheros_search.devices(mac,first_seen,last_seen) VALUES($1,$2,$2) ON CONFLICT(mac) DO UPDATE SET first_seen=LEAST(devices.first_seen,EXCLUDED.first_seen),last_seen=GREATEST(devices.last_seen,EXCLUDED.last_seen),updated_at=CURRENT_TIMESTAMP", &[&mac,&e.observed_at]).await?;
        node(
            tx,
            &format!("device:{mac}"),
            "device",
            mac,
            json!({"mac":mac}),
            None,
            None,
            Some(mac),
            None,
            e.observed_at,
        )
        .await?;
        if let Some(ap) = &e.bssid {
            summarize(tx, e, mac, ap, c, ranges, now).await?;
        }
    }
    Ok(())
}

fn increment(value: &mut Value, keys: &[String]) {
    if let Some(object) = value.as_object_mut() {
        for key in keys {
            let count = object.get(key).and_then(Value::as_i64).unwrap_or(0);
            object.insert(key.clone(), json!(count.wrapping_add(1)));
        }
    }
}
pub fn add_radio(mut value: Value, e: &WirelessObservation) -> Value {
    let (Some(rssi), Some(frequency), Some(channel)) = (e.signal_dbm, e.frequency_mhz, e.channel)
    else {
        return value;
    };
    if e.source_mac.is_none()
        || e.source_mac != e.transmitter_mac
        || !(2300..=7200).contains(&frequency)
        || !(1..=233).contains(&channel)
    {
        return value;
    }
    let Some(object) = value.as_object_mut() else {
        return value;
    };
    let key = format!("{frequency}/{channel}");
    if !object.contains_key(&key) && object.len() >= 64 {
        return value;
    }
    let old = object.get(&key).cloned().unwrap_or_else(|| json!({}));
    let samples = RadioSamples {
        count: old["sample_count"].as_i64().unwrap_or(0),
        sum: old["sum"].as_f64().unwrap_or(0.0),
        squares: old["squares"].as_f64().unwrap_or(0.0),
    }
    .add(rssi);
    let first = old["first_seen"]
        .as_str()
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .filter(|v| *v < e.observed_at)
        .unwrap_or(e.observed_at);
    let last = old["last_seen"]
        .as_str()
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .filter(|v| *v > e.observed_at)
        .unwrap_or(e.observed_at);
    object.insert(key,json!({"sample_count":samples.count,"sum":samples.sum,"squares":samples.squares,"mean_dbm":samples.mean(),"stddev_db":samples.stddev(),"frequency_mhz":frequency,"channel":channel,"first_seen":instant(first),"last_seen":instant(last)}));
    value
}
async fn summarize(
    tx: &mut PgTransaction,
    e: &WirelessObservation,
    mac: &str,
    ap: &str,
    c: Option<&SensorCalibration>,
    ranges: bool,
    now: DateTime<Utc>,
) -> Result<(), ProjectionError> {
    let start = DateTime::from_timestamp(e.observed_at.timestamp().div_euclid(300) * 300, 0)
        .ok_or(ProjectionError::Invalid("window timestamp"))?;
    let end = start + Duration::seconds(300);
    let expires = end + Duration::days(7);
    let id = wireless_id(&[&e.sensor_id, ap, mac, &instant(start)]);
    let location = c.map(|c| c.location_id.as_str());
    let inserted=tx.execute("INSERT INTO atheros_search.wireless_observation_summaries (summary_id,sensor_id,bssid,source_mac,window_start,window_end,first_seen,last_seen,frame_count,counters,radio,location_id,ssid,expires_at) VALUES($1::text::uuid,$2,$3,$4,$5,$6,$7,$7,1,'{}'::jsonb,'{}'::jsonb,$8,$9,$10) ON CONFLICT DO NOTHING", &[&id,&e.sensor_id,&ap,&mac,&start,&end,&e.observed_at,&location,&e.ssid,&expires]).await?;
    let rows=tx.query("SELECT frame_count,counters,radio,first_seen,last_seen FROM atheros_search.wireless_observation_summaries WHERE summary_id=$1::text::uuid FOR UPDATE", &[&id]).await?;
    let row = &rows[0];
    let count = if inserted == 1 {
        1
    } else {
        row.get::<_, i64>(0) + 1
    };
    let mut counters: Value = row.get(1);
    let frame = if ["management", "control", "data"].contains(&e.frame_type.as_str()) {
        e.frame_type.as_str()
    } else {
        "unknown"
    };
    let protocol = e.protocol.to_lowercase();
    let protocol = if [
        "dns", "mdns", "dhcp", "ssdp", "http", "https", "tls", "eapol", "arp", "tcp", "udp",
    ]
    .contains(&protocol.as_str())
    {
        protocol.as_str()
    } else {
        "other"
    };
    let mut keys = vec![
        "frames".into(),
        format!("frame:{frame}"),
        format!("protocol:{protocol}"),
    ];
    if e.retry {
        keys.push("retry".into());
    }
    if e.protected {
        keys.push("protected".into());
    }
    if e.handshake {
        keys.push("handshake".into());
    }
    increment(&mut counters, &keys);
    let radio = add_radio(row.get(2), e);
    let first = e.observed_at.min(row.get(3));
    let last = e.observed_at.max(row.get(4));
    tx.execute("UPDATE atheros_search.wireless_observation_summaries SET frame_count=$2,counters=$3,radio=$4,first_seen=$5,last_seen=$6,updated_at=CURRENT_TIMESTAMP WHERE summary_id=$1::text::uuid", &[&id,&count,&counters,&radio,&first,&last]).await?;
    let mut evidence = json!({"summary_id":id,"sensor_id":e.sensor_id,"window_start":instant(start),"window_end":instant(end),"expires_at":instant(expires),"projection_watermark":instant(last),"projected_at":instant(now),"frame_count":count});
    edge(
        tx,
        &format!("observation:{id}"),
        &format!("device:{mac}"),
        &format!("ap:{ap}"),
        "observed_association",
        "Observed association; connection and ownership unverified",
        evidence.clone(),
        last,
        Some(expires),
    )
    .await?;
    tx.execute(
        "DELETE FROM atheros_search.wireless_topology_edges WHERE edge_id=$1",
        &[&format!("range:{id}")],
    )
    .await?;
    if let Some(c) = c.filter(|_| ranges) {
        let estimates: Vec<_> = radio
            .as_object()
            .into_iter()
            .flat_map(Map::values)
            .filter_map(|bin| {
                calibrated_range(
                    RadioSamples {
                        count: bin["sample_count"].as_i64()?,
                        sum: bin["sum"].as_f64()?,
                        squares: bin["squares"].as_f64()?,
                    },
                    c,
                    bin["frequency_mhz"].as_i64()?.try_into().ok()?,
                    bin["channel"].as_i64()?.try_into().ok()?,
                    bin["first_seen"].as_str()?.parse().ok()?,
                    bin["last_seen"].as_str()?.parse().ok()?,
                    now,
                )
            })
            .collect();
        if estimates.len() == 1 {
            evidence["range"] = estimates[0].clone();
            edge(
                tx,
                &format!("range:{id}"),
                &format!("sensor:{}", e.sensor_id),
                &format!("device:{mac}"),
                "calibrated_range",
                "Estimated sensor-to-device range",
                evidence,
                last,
                Some(expires),
            )
            .await?;
        }
    }
    Ok(())
}

pub async fn delete_document(tx: &mut PgTransaction, id: &str) -> Result<(), ProjectionError> {
    for table in [
        "embedding_jobs",
        "search_vectors_device",
        "search_vectors_behaviour",
        "embeddings",
        "search_document_tokens",
        "search_document_tags",
        "search_documents",
    ] {
        tx.execute(
            &format!("DELETE FROM atheros_search.{table} WHERE document_id=$1"),
            &[&id],
        )
        .await?;
    }
    Ok(())
}
pub async fn expire(tx: &mut PgTransaction, limit: i32) -> Result<i32, ProjectionError> {
    let limit = i64::from(limit.max(1));
    let ids=tx.query("SELECT summary_id::text FROM atheros_search.wireless_observation_summaries WHERE expires_at<=CURRENT_TIMESTAMP ORDER BY expires_at,summary_id LIMIT $1 FOR UPDATE SKIP LOCKED", &[&limit]).await?;
    for row in &ids {
        let id: String = row.get(0);
        let documents=tx.query("SELECT document_id FROM atheros_search.search_documents WHERE source_kind='observation_window' AND source_key=$1 FOR UPDATE", &[&id]).await?;
        for document in documents {
            delete_document(tx, &document.get::<_, String>(0)).await?;
        }
        tx.execute(
            "DELETE FROM atheros_search.wireless_topology_edges WHERE edge_id IN($1,$2)",
            &[&format!("observation:{id}"), &format!("range:{id}")],
        )
        .await?;
        tx.execute("DELETE FROM atheros_search.wireless_observation_summaries WHERE summary_id=$1::text::uuid", &[&id]).await?;
    }
    let mut remaining = limit;
    for (table, columns) in [
        (
            "wireless_projection_group_receipts",
            "group_id,topic,partition_id,offset_id",
        ),
        (
            "wireless_projection_receipts",
            "topic,partition_id,offset_id",
        ),
        ("wireless_projection_hashes", "payload_sha256"),
    ] {
        while remaining > 0 {
            let batch = remaining.min(5000);
            let deleted=tx.execute(&format!("DELETE FROM octopus_core.{table} WHERE ({columns}) IN(SELECT {columns} FROM octopus_core.{table} WHERE expires_at<=CURRENT_TIMESTAMP ORDER BY expires_at,{columns} LIMIT $1 FOR UPDATE SKIP LOCKED)"), &[&batch]).await?;
            remaining -= deleted as i64;
            if deleted < batch as u64 {
                break;
            }
        }
    }
    Ok(ids.len() as i32)
}
