use super::{rows::alert_identity, LoadError, SinkTarget, TransformedRow};
use crate::postgres::PgTransaction;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

pub(super) async fn insert_chunk(
    tx: &mut PgTransaction,
    batch: &str,
    target: SinkTarget,
    rows: &[TransformedRow],
) -> Result<(), LoadError> {
    // Preserve Scala's earliest observation per sensor within each bounded chunk.
    if target == SinkTarget::WirelessAudit {
        let mut sensors = std::collections::BTreeMap::<String, &Value>::new();
        for row in rows {
            let r = &row.record;
            let key = r["sensor_id"].as_str().expect("validated sensor");
            let time = |v: &Value| {
                DateTime::parse_from_rfc3339(
                    v["observed_at"].as_str().expect("validated timestamp"),
                )
                .expect("validated timestamp")
            };
            if sensors.get(key).is_none_or(|old| time(r) <= time(old)) {
                sensors.insert(key.into(), r);
            }
        }
        for r in sensors.values() {
            tx.execute("INSERT INTO wireless_sensors(sensor_id,location_id,interface,reg_domain,first_seen_at,last_seen_at) SELECT r.sensor_id,r.location_id,r.interface,$2::text,r.observed_at,r.observed_at FROM jsonb_populate_record(NULL::wireless_audit_frames,$1) r ON CONFLICT(sensor_id) DO UPDATE SET location_id=EXCLUDED.location_id,interface=EXCLUDED.interface,reg_domain=EXCLUDED.reg_domain,last_seen_at=EXCLUDED.last_seen_at WHERE EXCLUDED.last_seen_at>=wireless_sensors.last_seen_at",&[r,&r["reg_domain"].as_str()]).await?;
        }
    }
    for row in rows {
        if row.target != target {
            return Err(LoadError::Invariant("mixed targets in typed load chunk"));
        }
        let mut r = row.record.clone();
        r["batch_id"] = json!(batch);
        match target {
            SinkTarget::ProxyEvents => {
                insert_proxy(tx, &r, row.blocked.as_ref()).await?;
            }
            SinkTarget::ProxyPayloadAudit => {
                insert_record(tx,"proxy_payload_audit","correlation_id,host,direction,captured_at,byte_offset,payload_object_key,content_type,http_method,http_status,http_path,is_encrypted,truncated,peer_ip,notes",&r,"(correlation_id,direction,byte_offset) DO UPDATE SET correlation_id=EXCLUDED.correlation_id").await?;
            }
            SinkTarget::WirelessAudit => {
                insert_record(tx,"wireless_audit_frames","batch_id,row_sequence,event_type,observed_at,sensor_id,location_id,interface,channel,band,frame_type,frame_subtype,bssid,source_mac,destination_mac,transmitter_mac,receiver_mac,destination_bssid,ssid,signal_dbm,sequence_number,raw_len,is_retry,is_more_data,is_power_save,is_protected,is_to_ds,is_from_ds,is_handshake,security_flags,device_id,username,identity_source,tags,anomaly_reasons,raw_json",&r,"(batch_id,row_sequence) DO UPDATE SET batch_id=EXCLUDED.batch_id").await?;
            }
            SinkTarget::WirelessBandwidth => {
                insert_record(tx,"wireless_bandwidth_windows","batch_id,row_sequence,schema_version,window_start,window_end,sensor_id,location_id,interface,channel,band,source_mac,destination_bssid,ssid,bytes,frame_count,retry_count,more_data_count,power_save_count,strongest_signal_dbm,hist_under_100,hist_100_500,hist_500_1000,hist_1000_1500,inter_arrival_p50_ms,external_bssid,threshold_exceeded,wall_clock_delta_ms,window_is_partial,published_at",&r,"(batch_id,row_sequence) DO UPDATE SET batch_id=EXCLUDED.batch_id").await?;
            }
            SinkTarget::ClientInventory => {
                r["created_at"] = r["snapshot_at"].clone();
                insert_record(tx,"wireless_client_inventory","sensor_id,location_id,snapshot_at,client_mac,bssid,ssid,device_id,username,identity_source,last_seen,first_seen,signal_dbm,is_authorized,created_at",&r,"(sensor_id,snapshot_at,client_mac) DO UPDATE SET location_id=EXCLUDED.location_id,bssid=EXCLUDED.bssid,ssid=EXCLUDED.ssid,device_id=EXCLUDED.device_id,username=EXCLUDED.username,identity_source=EXCLUDED.identity_source,last_seen=GREATEST(wireless_client_inventory.last_seen,EXCLUDED.last_seen),first_seen=LEAST(wireless_client_inventory.first_seen,EXCLUDED.first_seen),signal_dbm=EXCLUDED.signal_dbm,is_authorized=EXCLUDED.is_authorized").await?;
            }
            SinkTarget::ProbeRequests => {
                r["created_at"] = r["first_seen"].clone();
                insert_record(tx,"wireless_probe_requests","batch_id,row_sequence,client_mac,ssid,known_bssid,first_seen,last_seen,probe_count,created_at",&r,"(batch_id,row_sequence) DO UPDATE SET batch_id=EXCLUDED.batch_id").await?;
            }
            _ => {
                alert_identity(batch, &mut r);
                let now = Utc::now().to_rfc3339();
                r["created_at"] = json!(now);
                r["updated_at"] = json!(now);
                insert_alert(tx, &r, false).await?;
            }
        }
    }
    if target == SinkTarget::WirelessBandwidth {
        bandwidth_alerts(tx, batch, rows).await?;
    }
    Ok(())
}

/// Table/column/conflict arguments are code-owned constants; row values are bound parameters.
async fn insert_record(
    tx: &mut PgTransaction,
    table: &str,
    columns: &str,
    row: &Value,
    conflict: &str,
) -> Result<(), LoadError> {
    let sql=format!("INSERT INTO {table}({columns}) SELECT {columns} FROM jsonb_populate_record(NULL::{table},$1) r ON CONFLICT {conflict}");
    tx.execute(&sql, &[row]).await?;
    Ok(())
}

async fn insert_alert(
    tx: &mut PgTransaction,
    row: &Value,
    bandwidth: bool,
) -> Result<(), LoadError> {
    let columns = if bandwidth {
        "alert_id,alert_type,subject_kind,subject_id,severity,evidence,source_event_id,batch_id,row_sequence,alert_date,detected_at,sensor_id,location_id,primary_mac,secondary_mac,ssid,signal_dbm,details_json,raw_json,created_at,updated_at,bytes"
    } else {
        "alert_id,alert_type,subject_kind,subject_id,severity,evidence,source_event_id,batch_id,row_sequence,detected_at,sensor_id,location_id,interface,channel,primary_mac,secondary_mac,ssid,signal_dbm,details_json,raw_json,created_at,updated_at"
    };
    let conflict = if bandwidth {
        "(source_event_id,alert_type) DO UPDATE SET subject_kind=EXCLUDED.subject_kind,subject_id=EXCLUDED.subject_id,severity=EXCLUDED.severity,evidence=EXCLUDED.evidence,batch_id=EXCLUDED.batch_id,row_sequence=EXCLUDED.row_sequence,detected_at=EXCLUDED.detected_at,location_id=EXCLUDED.location_id,ssid=EXCLUDED.ssid,bytes=EXCLUDED.bytes,details_json=EXCLUDED.details_json,updated_at=CURRENT_TIMESTAMP"
    } else {
        "(source_event_id,alert_type) DO UPDATE SET subject_kind=EXCLUDED.subject_kind,subject_id=EXCLUDED.subject_id,severity=EXCLUDED.severity,evidence=EXCLUDED.evidence,batch_id=EXCLUDED.batch_id,row_sequence=EXCLUDED.row_sequence,detected_at=EXCLUDED.detected_at,sensor_id=EXCLUDED.sensor_id,location_id=EXCLUDED.location_id,interface=EXCLUDED.interface,channel=EXCLUDED.channel,primary_mac=EXCLUDED.primary_mac,secondary_mac=EXCLUDED.secondary_mac,ssid=EXCLUDED.ssid,signal_dbm=EXCLUDED.signal_dbm,details_json=EXCLUDED.details_json,raw_json=EXCLUDED.raw_json,updated_at=EXCLUDED.updated_at"
    };
    insert_record(tx, "wireless_alerts", columns, row, conflict).await
}

async fn bandwidth_alerts(
    tx: &mut PgTransaction,
    batch: &str,
    rows: &[TransformedRow],
) -> Result<(), LoadError> {
    let mut groups =
        std::collections::BTreeMap::<(String, String, String, String), Vec<&Value>>::new();
    for row in rows {
        let r = &row.record;
        if r["threshold_exceeded"] != true {
            continue;
        }
        let time =
            DateTime::parse_from_rfc3339(r["window_start"].as_str().expect("validated timestamp"))
                .expect("validated timestamp");
        let key = (
            r["sensor_id"].as_str().expect("sensor").into(),
            r["source_mac"].as_str().expect("MAC").into(),
            r["destination_bssid"].as_str().expect("BSSID").into(),
            time.date_naive().to_string(),
        );
        groups.entry(key).or_default().push(r);
    }
    for group in groups.values() {
        let timestamp = |r: &Value| {
            DateTime::parse_from_rfc3339(r["window_start"].as_str().expect("validated timestamp"))
                .expect("validated timestamp")
        };
        let first = group
            .iter()
            .min_by_key(|r| timestamp(r))
            .expect("nonempty group");
        let last = group
            .iter()
            .max_by_key(|r| timestamp(r))
            .expect("nonempty group");
        let sequence = group
            .iter()
            .map(|r| r["row_sequence"].as_i64().expect("sequence"))
            .min()
            .expect("group");
        let bytes = group.iter().fold(0i64, |n, r| {
            n.wrapping_add(r["bytes"].as_i64().expect("bytes"))
        });
        let details =
            json!({"aggregated_rows":group.len(),"total_bytes":bytes,"threshold":"exceeded"});
        let now = Utc::now().to_rfc3339();
        let mut r = json!({"batch_id":batch,"row_sequence":sequence,"alert_type":"bandwidth_threshold","subject_kind":"station","subject_id":last["source_mac"],"severity":"medium","detected_at":first["window_start"],"alert_date":timestamp(first).date_naive().to_string(),"sensor_id":last["sensor_id"],"location_id":last["location_id"],"primary_mac":last["source_mac"],"secondary_mac":last["destination_bssid"],"ssid":last["ssid"],"signal_dbm":last["strongest_signal_dbm"],"details_json":details,"raw_json":null,"created_at":now,"updated_at":now,"bytes":bytes});
        r["evidence"] = json!({"event_type":"bandwidth_threshold","sensor_id":r["sensor_id"],"location_id":r["location_id"],"primary_mac":r["primary_mac"],"secondary_mac":r["secondary_mac"],"ssid":r["ssid"],"signal_dbm":r["signal_dbm"],"details":details});
        alert_identity(batch, &mut r);
        insert_alert(tx, &r, true).await?;
    }
    Ok(())
}

async fn insert_proxy(
    tx: &mut PgTransaction,
    row: &Value,
    blocked: Option<&Value>,
) -> Result<(), LoadError> {
    let rows=tx.query("WITH inserted AS (INSERT INTO proxy_events(event_id,event_time,event_type,host,peer_ip,wireguard_pubkey,registered_device_id,bytes_up,bytes_down,status_code,blocked,classification,correlation_id,causation_id,payload,batch_id,row_sequence,event_timestamp_utc,wg_pubkey,device_id,identity_source,peer_hostname,client_ua,obfuscation_profile,event_sequence,duration_ms,reason,raw_json,evidence) SELECT event_id,event_time,event_type,host,peer_ip,wireguard_pubkey,registered_device_id,bytes_up,bytes_down,status_code,blocked,classification,correlation_id,causation_id,payload,batch_id,row_sequence,event_timestamp_utc,wg_pubkey,device_id,identity_source,peer_hostname,client_ua,obfuscation_profile,event_sequence,duration_ms,reason,raw_json,evidence FROM jsonb_populate_record(NULL::proxy_events,$1) ON CONFLICT(event_id) DO UPDATE SET source_conflicts=proxy_events.source_conflicts||jsonb_build_object(encode(sha256(convert_to(proxy_events.payload::text,'UTF8')),'hex'),proxy_events.correlation_id,encode(sha256(convert_to(EXCLUDED.payload::text,'UTF8')),'hex'),EXCLUDED.correlation_id),observation_revision=nextval('octopus_core.proxy_events_observation_revision_seq') WHERE proxy_events.payload IS DISTINCT FROM EXCLUDED.payload AND NOT jsonb_exists(proxy_events.source_conflicts,encode(sha256(convert_to(EXCLUDED.payload::text,'UTF8')),'hex')) RETURNING event_id,observation_revision,source_conflicts), dirty AS (INSERT INTO proxy_preparation_dirty(event_id,source_revision) SELECT event_id,observation_revision FROM inserted ON CONFLICT(event_id) DO UPDATE SET source_revision=GREATEST(proxy_preparation_dirty.source_revision,EXCLUDED.source_revision),updated_at=CURRENT_TIMESTAMP) SELECT source_conflicts='{}'::jsonb FROM inserted",&[row]).await?;
    if let Some(blocked) = blocked.filter(|_| rows.first().is_some_and(|r| r.get::<_, bool>(0))) {
        tx.execute("INSERT INTO proxy_blocked_host_rollups(host,blocked_attempts,blocked_bytes,frequency_hz,verdict,category,risk_score,tarpit_held_ms,iat_ms,consecutive_blocks,last_verdict,tls_ver,alpn,ja3_lite,resolved_ip,asn_org,updated_at,first_seen,last_event_id) SELECT host,blocked_attempts,blocked_bytes,frequency_hz,verdict,category,risk_score,tarpit_held_ms,iat_ms,consecutive_blocks,last_verdict,tls_ver,alpn,ja3_lite,resolved_ip,asn_org,updated_at,first_seen,last_event_id FROM jsonb_populate_record(NULL::proxy_blocked_host_rollups,$1) ON CONFLICT(host) DO UPDATE SET blocked_attempts=proxy_blocked_host_rollups.blocked_attempts+1,blocked_bytes=proxy_blocked_host_rollups.blocked_bytes+EXCLUDED.blocked_bytes,tarpit_held_ms=proxy_blocked_host_rollups.tarpit_held_ms+COALESCE(EXCLUDED.tarpit_held_ms,0),first_seen=LEAST(proxy_blocked_host_rollups.first_seen,EXCLUDED.first_seen),frequency_hz=CASE WHEN (EXCLUDED.updated_at,EXCLUDED.last_event_id)>(proxy_blocked_host_rollups.updated_at,proxy_blocked_host_rollups.last_event_id) THEN EXCLUDED.frequency_hz ELSE proxy_blocked_host_rollups.frequency_hz END,verdict=CASE WHEN (EXCLUDED.updated_at,EXCLUDED.last_event_id)>(proxy_blocked_host_rollups.updated_at,proxy_blocked_host_rollups.last_event_id) THEN EXCLUDED.verdict ELSE proxy_blocked_host_rollups.verdict END,category=CASE WHEN (EXCLUDED.updated_at,EXCLUDED.last_event_id)>(proxy_blocked_host_rollups.updated_at,proxy_blocked_host_rollups.last_event_id) THEN EXCLUDED.category ELSE proxy_blocked_host_rollups.category END,risk_score=CASE WHEN (EXCLUDED.updated_at,EXCLUDED.last_event_id)>(proxy_blocked_host_rollups.updated_at,proxy_blocked_host_rollups.last_event_id) THEN EXCLUDED.risk_score ELSE proxy_blocked_host_rollups.risk_score END,iat_ms=CASE WHEN (EXCLUDED.updated_at,EXCLUDED.last_event_id)>(proxy_blocked_host_rollups.updated_at,proxy_blocked_host_rollups.last_event_id) THEN EXCLUDED.iat_ms ELSE proxy_blocked_host_rollups.iat_ms END,consecutive_blocks=CASE WHEN (EXCLUDED.updated_at,EXCLUDED.last_event_id)>(proxy_blocked_host_rollups.updated_at,proxy_blocked_host_rollups.last_event_id) THEN EXCLUDED.consecutive_blocks ELSE proxy_blocked_host_rollups.consecutive_blocks END,last_verdict=CASE WHEN (EXCLUDED.updated_at,EXCLUDED.last_event_id)>(proxy_blocked_host_rollups.updated_at,proxy_blocked_host_rollups.last_event_id) THEN EXCLUDED.last_verdict ELSE proxy_blocked_host_rollups.last_verdict END,tls_ver=CASE WHEN (EXCLUDED.updated_at,EXCLUDED.last_event_id)>(proxy_blocked_host_rollups.updated_at,proxy_blocked_host_rollups.last_event_id) THEN EXCLUDED.tls_ver ELSE proxy_blocked_host_rollups.tls_ver END,alpn=CASE WHEN (EXCLUDED.updated_at,EXCLUDED.last_event_id)>(proxy_blocked_host_rollups.updated_at,proxy_blocked_host_rollups.last_event_id) THEN EXCLUDED.alpn ELSE proxy_blocked_host_rollups.alpn END,ja3_lite=CASE WHEN (EXCLUDED.updated_at,EXCLUDED.last_event_id)>(proxy_blocked_host_rollups.updated_at,proxy_blocked_host_rollups.last_event_id) THEN EXCLUDED.ja3_lite ELSE proxy_blocked_host_rollups.ja3_lite END,resolved_ip=CASE WHEN (EXCLUDED.updated_at,EXCLUDED.last_event_id)>(proxy_blocked_host_rollups.updated_at,proxy_blocked_host_rollups.last_event_id) THEN EXCLUDED.resolved_ip ELSE proxy_blocked_host_rollups.resolved_ip END,asn_org=CASE WHEN (EXCLUDED.updated_at,EXCLUDED.last_event_id)>(proxy_blocked_host_rollups.updated_at,proxy_blocked_host_rollups.last_event_id) THEN EXCLUDED.asn_org ELSE proxy_blocked_host_rollups.asn_org END,last_event_id=CASE WHEN (EXCLUDED.updated_at,EXCLUDED.last_event_id)>(proxy_blocked_host_rollups.updated_at,proxy_blocked_host_rollups.last_event_id) THEN EXCLUDED.last_event_id ELSE proxy_blocked_host_rollups.last_event_id END,updated_at=GREATEST(proxy_blocked_host_rollups.updated_at,EXCLUDED.updated_at)",&[blocked]).await?;
    }
    Ok(())
}
