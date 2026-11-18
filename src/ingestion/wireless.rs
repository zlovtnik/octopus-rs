//! The retained wireless intake projection. Paths and columns are static code;
//! only payload/key values are parameters. PostgreSQL performs the same guarded
//! extraction and casts as the Scala WirelessProjectionSql implementation.

use crate::postgres::{PgError, PgTransaction};

fn extracted(path: &str) -> String {
    format!("jsonb_path_query_first(source.payload, '{path}'::jsonpath)")
}

fn text(paths: &[&str], maximum: u32, present: bool) -> String {
    coalesce(paths.iter().map(|path| {
        let value = extracted(path);
        let raw = format!("({value} #>> '{{}}')");
        let projected = if present { raw.clone() } else { format!("NULLIF({raw},'')") };
        format!("CASE WHEN jsonb_typeof({value})='string' AND CHAR_LENGTH({raw})<={maximum} THEN {projected} ELSE NULL END")
    }))
}

fn integer(paths: &[&str], wide: bool) -> String {
    let (positive, negative) = if wide {
        ("9223372036854775807", "9223372036854775808")
    } else {
        ("2147483647", "2147483648")
    };
    coalesce(paths.iter().map(|path| {
        let value = extracted(path);
        let raw = format!("TRIM({value} #>> '{{}}')");
        let magnitude = format!("COALESCE(NULLIF(TRIM(LEADING '0' FROM TRIM(LEADING '-' FROM TRIM(LEADING '+' FROM {raw}))),''),'0')");
        let limit = format!("CASE WHEN LEFT({raw},1)='-' THEN '{negative}' ELSE '{positive}' END");
        format!("CAST(CASE WHEN jsonb_typeof({value}) IN ('number','string') AND {raw} ~ '^[+-]?[0-9]+$' AND (CHAR_LENGTH({magnitude})<CHAR_LENGTH({limit}) OR (CHAR_LENGTH({magnitude})=CHAR_LENGTH({limit}) AND {magnitude}<={limit})) THEN {raw} ELSE NULL END AS BIGINT)")
    }))
}

fn boolean(paths: &[&str]) -> String {
    coalesce(paths.iter().map(|path| {
        let value = extracted(path);
        format!("CASE WHEN jsonb_typeof({value}) IN ('boolean','number','string') THEN CASE LOWER(TRIM({value} #>> '{{}}')) WHEN 'true' THEN true WHEN 'false' THEN false WHEN '1' THEN true WHEN '0' THEN false ELSE NULL END ELSE NULL END")
    }))
}

fn double(path: &str) -> String {
    let value = extracted(path);
    let raw = format!("TRIM({value} #>> '{{}}')");
    let scientific = format!("({raw} ~ '^[+-]?[0-9]+([.][0-9]+)?[eE][+-]?[0-9]{{1,3}}$')");
    let exponent = format!(
        "CAST(CASE WHEN {scientific} THEN split_part(LOWER({raw}),'e',2) ELSE NULL END AS INTEGER)"
    );
    let mantissa = format!("CAST(CASE WHEN {scientific} THEN split_part(LOWER({raw}),'e',1) ELSE NULL END AS DECIMAL(38,16))");
    format!("CAST(CASE WHEN jsonb_typeof({value}) IN ('number','string') AND ({raw} ~ '^[+-]?([0-9]+([.][0-9]*)?|[.][0-9]+)$' OR ({scientific} AND {exponent} BETWEEN -324 AND 308 AND ({exponent}<308 OR ABS({mantissa})<=1.7976931348623157))) THEN {raw} ELSE NULL END AS DOUBLE PRECISION)")
}

fn coalesce(values: impl Iterator<Item = String>) -> String {
    format!("COALESCE({})", values.collect::<Vec<_>>().join(","))
}

fn projection_sql() -> String {
    let mut assignments = Vec::new();
    macro_rules! strings {
        ($($column:literal: $max:literal => [$($path:literal),+]);+ $(;)?) => {$(
            assignments.push(format!("{}={}",$column,text(&[$($path),+],$max,false)));
        )+};
    }
    strings! {
        "sensor_id":64=>["$.sensor_id"];
        "location_id":128=>["$.location_id"];
        "username":255=>["$.username"];
        "event_type":64=>["$.event_type","$.type"];
        "frame_type":32=>["$.frame_type","$.mac.frame_type"];
        "frame_subtype":64=>["$.frame_subtype","$.mac.frame_subtype"];
        "signal_status":64=>["$.signal_status","$.rf.signal_status"];
        "qos_ack_policy_label":64=>["$.qos_ack_policy_label","$.qos.ack_policy_label"];
        "llc_oui":16=>["$.llc_oui","$.llc_snap.oui"];
        "ethertype_name":64=>["$.ethertype_name","$.llc_snap.ethertype_name"];
        "src_ip":45=>["$.src_ip","$.network.src_ip"];
        "dst_ip":45=>["$.dst_ip","$.network.dst_ip"];
        "ip_protocol_name":64=>["$.ip_protocol_name","$.network.protocol_name"];
        "transport_protocol":32=>["$.transport_protocol","$.transport.protocol"];
        "app_protocol":64=>["$.app_protocol","$.application.protocol"];
        "ssdp_message_type":64=>["$.ssdp_message_type","$.application.ssdp.message_type"];
        "ssdp_st":512=>["$.ssdp_st","$.application.ssdp.st"];
        "ssdp_mx":64=>["$.ssdp_mx","$.application.ssdp.mx"];
        "ssdp_usn":512=>["$.ssdp_usn","$.application.ssdp.usn"];
        "dhcp_requested_ip":45=>["$.dhcp_requested_ip","$.application.dhcp.requested_ip"];
        "dhcp_hostname":253=>["$.dhcp_hostname","$.application.dhcp.hostname"];
        "dhcp_vendor_class":255=>["$.dhcp_vendor_class","$.application.dhcp.vendor_class"];
        "dns_query_name":253=>["$.dns_query_name","$.application.dns.query_names[0]"];
        "mdns_name":253=>["$.mdns_name","$.application.mdns.query_names[0]"];
        "session_key":255=>["$.session_key","$.correlation.session_key"];
        "retransmit_key":255=>["$.retransmit_key","$.correlation.retransmit_key"];
        "frame_fingerprint":255=>["$.frame_fingerprint","$.correlation.frame_fingerprint"];
        "payload_visibility":64=>["$.payload_visibility","$.correlation.payload_visibility"];
        "identity_source":64=>["$.identity_source"];
        "wps_device_name":255=>["$.wps_device_name"];
        "wps_manufacturer":255=>["$.wps_manufacturer"];
        "wps_model_name":255=>["$.wps_model_name"];
        "device_fingerprint":255=>["$.device_fingerprint"]
    }
    assignments.push(format!("ssid={}", text(&["$.ssid"], 256, true)));
    for (column, paths, maximum) in [
        ("source_mac", vec!["$.source_mac", "$.mac.source_mac"], 17),
        (
            "transmitter_mac",
            vec!["$.transmitter_mac", "$.mac.transmitter_mac"],
            17,
        ),
        (
            "receiver_mac",
            vec!["$.receiver_mac", "$.mac.receiver_mac"],
            17,
        ),
        ("bssid", vec!["$.bssid", "$.mac.bssid"], 17),
        (
            "destination_bssid",
            vec![
                "$.destination_bssid",
                "$.destination_mac",
                "$.mac.destination_mac",
                "$.mac.bssid",
            ],
            17,
        ),
        (
            "adjacent_mac_hint",
            vec!["$.adjacent_mac_hint", "$.mac.adjacent_mac_hint"],
            512,
        ),
    ] {
        assignments.push(format!("{column}=LOWER({})", text(&paths, maximum, false)));
    }
    macro_rules! integers {
        ($($column:literal => [$($path:literal),+]);+ $(;)?) => {$(
            assignments.push(format!("{}={}",$column,integer(&[$($path),+],false)));
        )+};
    }
    integers! {
        "signal_dbm"=>["$.signal_dbm","$.rf.signal_dbm"];
        "noise_dbm"=>["$.noise_dbm","$.rf.noise_dbm"];
        "frequency_mhz"=>["$.frequency_mhz","$.rf.frequency_mhz"];
        "channel_flags"=>["$.channel_flags","$.rf.channel_flags.raw"];
        "data_rate_kbps"=>["$.data_rate_kbps","$.rf.data_rate_kbps"];
        "antenna_id"=>["$.antenna_id","$.rf.antenna_id"];
        "fragment_number"=>["$.fragment_number","$.mac.fragment_number"];
        "channel_number"=>["$.channel_number","$.channel","$.rf.channel_number"];
        "qos_tid"=>["$.qos_tid","$.qos.tid"];
        "qos_ack_policy"=>["$.qos_ack_policy","$.qos.ack_policy"];
        "ethertype"=>["$.ethertype","$.llc_snap.ethertype"];
        "ip_ttl"=>["$.ip_ttl","$.network.ttl"];
        "ip_protocol"=>["$.ip_protocol","$.network.protocol"];
        "src_port"=>["$.src_port","$.transport.src_port"];
        "dst_port"=>["$.dst_port","$.transport.dst_port"];
        "transport_length"=>["$.transport_length","$.transport.length"];
        "transport_checksum"=>["$.transport_checksum","$.transport.checksum"]
    }
    for (column, paths) in [
        ("tsft", vec!["$.tsft", "$.rf.tsft"]),
        (
            "tsft_delta_us",
            vec!["$.tsft_delta_us", "$.correlation.tsft_delta_us"],
        ),
        (
            "wall_clock_delta_ms",
            vec!["$.wall_clock_delta_ms", "$.correlation.wall_clock_delta_ms"],
        ),
    ] {
        assignments.push(format!("{column}={}", integer(&paths, true)));
    }
    for (column, paths, default) in [
        ("schema_version", vec!["$.schema_version"], 1),
        ("raw_len", vec!["$.raw_len", "$.rf.raw_len"], 0),
        ("frame_control_flags", vec!["$.frame_control_flags"], 0),
        ("security_flags", vec!["$.security_flags"], 0),
    ] {
        assignments.push(format!(
            "{column}=COALESCE({},{default})",
            integer(&paths, false)
        ));
    }
    for (column, paths, default) in [
        ("qos_eosp", vec!["$.qos_eosp", "$.qos.eosp"], false),
        ("qos_amsdu", vec!["$.qos_amsdu", "$.qos.amsdu"], false),
        (
            "mixed_encryption",
            vec!["$.mixed_encryption", "$.anomalies.mixed_encryption"],
            false,
        ),
        (
            "large_frame",
            vec!["$.large_frame", "$.anomalies.large_frame"],
            true,
        ),
        (
            "dedupe_or_replay_suspect",
            vec![
                "$.dedupe_or_replay_suspect",
                "$.anomalies.dedupe_or_replay_suspect",
            ],
            true,
        ),
        ("more_data", vec!["$.more_data", "$.mac.more_data"], true),
        ("retry", vec!["$.retry", "$.mac.retry"], true),
        ("power_save", vec!["$.power_save", "$.mac.power_save"], true),
        ("protected", vec!["$.protected", "$.mac.protected"], true),
        ("handshake_captured", vec!["$.handshake_captured"], true),
    ] {
        let value = boolean(&paths);
        assignments.push(format!(
            "{column}={}",
            if default {
                format!("COALESCE({value},false)")
            } else {
                value
            }
        ));
    }
    assignments.push(format!("risk_score={}", double("$.risk_score")));
    let tags = extracted("$.tags");
    assignments.push(format!(
        "tags=CASE WHEN jsonb_typeof({tags})='array' THEN {tags} ELSE NULL END"
    ));
    assignments.push("updated_at=CURRENT_TIMESTAMP".into());
    format!("UPDATE sync_events SET {} FROM (SELECT CAST($1 AS text)::jsonb AS payload) source WHERE dedupe_key=$2 AND stream_name='wireless.audit' AND payload_archived=false AND sync_events.payload IS NOT NULL AND NOT EXISTS(SELECT 1 FROM sync_event_tombstones tombstone WHERE tombstone.dedupe_key=sync_events.dedupe_key AND tombstone.stream_name=sync_events.stream_name AND tombstone.expires_at>CURRENT_TIMESTAMP)",assignments.join(","))
}

pub(super) async fn hydrate(
    tx: &mut PgTransaction,
    key: &str,
    payload: &str,
) -> Result<(), PgError> {
    static QUERY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    tx.execute(QUERY.get_or_init(projection_sql), &[&payload, &key])
        .await?;
    tx.execute("UPDATE sync_events SET wireless_search_text=NULLIF(LOWER(CONCAT_WS(' ',sensor_id,source_mac,bssid,destination_bssid,ssid,wps_device_name,wps_manufacturer,wps_model_name,device_fingerprint,app_protocol,src_ip,dst_ip,username)),'') WHERE dedupe_key=$1 AND stream_name='wireless.audit' AND payload_archived=false AND payload IS NOT NULL AND NOT EXISTS(SELECT 1 FROM sync_event_tombstones tombstone WHERE tombstone.dedupe_key=sync_events.dedupe_key AND tombstone.stream_name=sync_events.stream_name AND tombstone.expires_at>CURRENT_TIMESTAMP)", &[&key]).await?;
    Ok(())
}
