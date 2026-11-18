use chrono::{Duration, Utc};
use octopus::{
    config::WirelessProjectionConfig,
    domain::{BrokerConsumerContract, BrokerRecordMetadata},
    projections::{
        intelligence::{self, ProjectionFrame},
        proxy,
        wireless::{self, decode_wireless, RadioSamples},
        ProjectionError, ProjectionStore,
    },
    util::sha256_hex,
};
use serde_json::{json, Value};
mod support;

fn metadata(raw: &str, offset: i64, group: &str) -> BrokerRecordMetadata {
    let contract = BrokerConsumerContract::from(group, "wireless.audit").unwrap();
    BrokerRecordMetadata {
        topic: "wireless.audit".into(),
        partition: 0,
        offset,
        consumer_group: group.into(),
        group_version: contract.group_version,
        artifact_sha256: contract.contract_sha256,
        message_key: None,
        payload_sha256: sha256_hex(raw),
    }
}
fn frame(time: &str) -> ProjectionFrame {
    ProjectionFrame {
        dedupe_key: time.into(),
        source_mac: "aa:bb:cc:dd:ee:ff".into(),
        location_id: Some("lab".into()),
        sensor_id: Some("sensor-1".into()),
        observed_at: time.parse().unwrap(),
        frame_type: Some("data".into()),
        frame_subtype: Some("data".into()),
        signal_dbm: None,
        retry: false,
        protected: false,
        bssid: Some("11:22:33:44:55:66".into()),
        app_protocol: Some("dns".into()),
        adjacent_mac_hint: None,
        tsft_delta_us: None,
        wall_clock_delta_ms: None,
        session_key: None,
    }
}
#[test]
fn decoder_preserves_top_level_precedence_and_rejects_non_unicast_macs() {
    let v = json!({"sensor_id":"s","observed_at":"2026-08-03T10:00:00Z","source_mac":"bad","mac":{"source_mac":"aa:bb:cc:dd:ee:ff","transmitter_mac":"AA:BB:CC:DD:EE:FF"},"ssid":"","signal_dbm":null,"rf":{"signal_dbm":-50}});
    let e = decode_wireless(&v.to_string()).unwrap();
    assert_eq!(e.source_mac, None);
    assert_eq!(e.transmitter_mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    assert_eq!(e.signal_dbm, None);
    assert_eq!(e.ssid.as_deref(), Some(""));
    assert!(decode_wireless("{}").is_err());
    assert!(decode_wireless(
        &json!({"sensor_id":"s","observed_at":"2026-08-03T10:00:00Z","schema_version":3})
            .to_string()
    )
    .is_err());
    let e=decode_wireless(&json!({"sensor_id":"s","observed_at":"2026-08-03T10:00:00Z","source_mac":"01:00:00:00:00:01","bssid":"00:00:00:00:00:00"}).to_string()).unwrap();
    assert!(e.source_mac.is_none() && e.bssid.is_none());
}
#[test]
fn statistical_core_window_boundaries_and_stable_identity_match_contract() {
    assert_eq!(
        intelligence::percentile(&[-90.0, -70.0, -50.0], 0.5),
        Some(-70.0)
    );
    assert_eq!(intelligence::percentile(&[], 0.5), None);
    assert_eq!(
        intelligence::median_absolute_deviation(&[10.0, 30.0]),
        Some(10.0)
    );
    assert_eq!(
        intelligence::weighted_risk(&[(120.0, 0.5), (-3.0, 4.0), (10.0, -1.0)]),
        50.0
    );
    assert_eq!(
        intelligence::cosine_similarity(&[1.0, 0.0], &[0.0, 1.0]),
        Some(0.0)
    );
    assert_eq!(intelligence::cosine_similarity(&[], &[]), None);
    assert_eq!(
        intelligence::frame_token(Some("management"), Some(" assoc-request ")),
        "association_request"
    );
    let p = intelligence::transition_probabilities(&["beacon", "data", "beacon", "other"]);
    assert_eq!(p[&("beacon".into(), "data".into())], 0.5);
    let mut a = frame("2026-08-03T10:45:00Z");
    a.signal_dbm = Some(-50);
    a.retry = true;
    a.protected = true;
    a.tsft_delta_us = Some(10);
    a.wall_clock_delta_ms = Some(2);
    a.session_key = Some("s1".into());
    a.frame_subtype = Some("deauth".into());
    let mut b = frame("2026-08-03T10:05:00Z");
    b.signal_dbm = Some(-70);
    b.tsft_delta_us = Some(30);
    b.wall_clock_delta_ms = Some(6);
    b.session_key = Some("s1".into());
    b.frame_subtype = Some("beacon".into());
    let values = intelligence::behavior(&[a.clone(), b.clone()]);
    assert_eq!(values, intelligence::behavior(&[b.clone(), a.clone()]));
    assert_eq!(values[0].signal_average, Some(-60.0));
    assert_eq!(values[0].retry_count, 1);
    assert_eq!(
        intelligence::timing(&[a.clone(), b.clone()])[0].wall_p50,
        Some(4.0)
    );
    assert_eq!(
        intelligence::sequences(&[a, b])[0].tokens,
        vec!["beacon", "deauthentication"]
    );
    assert_eq!(
        intelligence::behavior(&[frame("1969-12-31T23:59:59Z")])[0]
            .window_start
            .timestamp(),
        -3600
    );
    let edges = vec![
        ("b".into(), "c".into(), 0.91),
        ("a".into(), "b".into(), 0.95),
        ("b".into(), "a".into(), 0.4),
    ];
    let clusters = intelligence::identity_clusters(&edges);
    assert_eq!(clusters[0].members, vec!["a", "b", "c"]);
    assert_eq!(clusters[0].confidence, 0.91);
    assert_eq!(
        intelligence::dns_threat("blocked.example", 4, 396, 2, Utc::now()).score,
        800.0
    );
    let risk = intelligence::ap_risk("ap", [4.0, 3.0, 2.0, 1.0, 0.5]).unwrap();
    assert!((risk.composite - 0.9).abs() < 1e-10);
    assert!(intelligence::ap_risk("ap", [f64::NAN, 0.0, 0.0, 0.0, 0.0]).is_err());
}
#[test]
fn authority_psl_whitelists_and_private_evidence_stay_distinct() {
    let a = proxy::normalize_authority(Some("BÜCHER.Example.:443"), "http_authority", false);
    assert_eq!(a["host_normalized"], "xn--bcher-kva.example");
    assert_eq!(a["port"], 443);
    let a = proxy::normalize_authority(Some("[::ffff:192.0.2.1]:443"), "connect_authority", false);
    assert_eq!(a["host_normalized"], "::ffff:c000:201");
    for value in [
        "bad..host",
        "1.02.3.4",
        "x@y",
        "example.com:0",
        "example.com:65536",
        "[example.com]",
        "x/y",
    ] {
        assert_eq!(
            proxy::normalize_authority(Some(value), "query", false)["parse_status"],
            "invalid",
            "{value}"
        );
    }
    assert_eq!(
        proxy::registrable_domain("a.b.co.uk").as_deref(),
        Some("b.co.uk")
    );
    assert_eq!(
        proxy::registrable_domain("a.www.ck").as_deref(),
        Some("www.ck")
    );
    assert_eq!(
        proxy::registrable_domain("x.foo.ck").as_deref(),
        Some("x.foo.ck")
    );
    let legacy =
        proxy::proxy_evidence(&json!({"host":"example.com:443","bytes_up":0,"bytes_down":0}));
    assert_eq!(legacy["port"], Value::Null);
    assert_eq!(legacy["measurement"]["bytes_status"], "legacy_unknown");
    assert_eq!(legacy["measurement"]["bytes_up"], Value::Null);
    let measured = proxy::proxy_evidence(
        &json!({"host":"example.com","evidence_version":"proxy-evidence-v1","measurement":{"version":"proxy-measurement-v1","bytes_status":"measured_terminal"},"bytes_up":-1,"bytes_down":0}),
    );
    assert_eq!(
        measured["measurement"]["bytes_status"],
        "unavailable_invalid_counters"
    );
    assert!(proxy::public_evidence(legacy)
        .get("authority_raw")
        .is_none());
    assert_eq!(
        proxy::safe_host(Some("hmac:token"), true).as_deref(),
        Some("hmac:token")
    );
    assert!(proxy::safe_host(Some("example.com"), true).is_none());
    assert!(proxy::policy_valid(&json!({})));
    assert!(!proxy::policy_valid(
        &json!({"version":"proxy-intelligence-policy-v1","extra":{}})
    ));
}
#[test]
fn radio_contexts_are_bounded_and_never_attribute_receiver_signal() {
    let mut event=decode_wireless(&json!({"sensor_id":"s","observed_at":"2026-08-03T10:00:00Z","source_mac":"aa:bb:cc:dd:ee:ff","transmitter_mac":"aa:bb:cc:dd:ee:ff","signal_dbm":-50,"frequency_mhz":2412,"channel":1}).to_string()).unwrap();
    let radio = wireless::add_radio(json!({}), &event);
    assert_eq!(radio["2412/1"]["sample_count"], 1);
    assert_eq!(radio["2412/1"]["mean_dbm"], -50.0);
    event.transmitter_mac = None;
    assert_eq!(wireless::add_radio(radio.clone(), &event), radio);
    let sample = RadioSamples::default().add(-50).add(-70);
    assert_eq!(sample.mean(), -60.0);
    assert!((sample.stddev() - 200.0_f64.sqrt()).abs() < 1e-10);
}
#[tokio::test]
async fn compact_projection_replay_conflict_window_and_expiry_are_atomic() {
    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let runtime = fixture.runtime.clone();
    let store = ProjectionStore::with_wireless(
        runtime.clone(),
        WirelessProjectionConfig {
            mode: "projected".into(),
            ..WirelessProjectionConfig::default()
        },
    );
    let mut event = json!({"sensor_id":"native","observed_at":Utc::now().to_rfc3339(),"source_mac":"aa:bb:cc:dd:ee:ff","transmitter_mac":"aa:bb:cc:dd:ee:ff","bssid":"22:33:44:55:66:77","ssid":"test","signal_dbm":-50,"frequency_mhz":2412,"channel":1,"app_protocol":"dns"});
    let raw = event.to_string();
    let m = metadata(&raw, 1, "wireless-projection-v1");
    assert!(store
        .project_wireless_record(event.clone(), &m)
        .await
        .unwrap());
    assert!(!store
        .project_wireless_record(event.clone(), &m)
        .await
        .unwrap());
    let m2 = metadata(&raw, 2, "wireless-projection-v2");
    assert!(!store
        .project_wireless_record(event.clone(), &m2)
        .await
        .unwrap());
    let mut conflict = m.clone();
    conflict.payload_sha256 = "f".repeat(64);
    assert!(matches!(
        store
            .project_wireless_record(event.clone(), &conflict)
            .await,
        Err(ProjectionError::CoordinateConflict)
    ));
    let mut tx = runtime.begin_worker().await.unwrap();
    assert_eq!(
        tx.query(
            "SELECT frame_count FROM atheros_search.wireless_observation_summaries",
            &[]
        )
        .await
        .unwrap()[0]
            .get::<_, i64>(0),
        1
    );
    tx.commit().await.unwrap();
    event["observed_at"] = json!((Utc::now() - Duration::days(8)).to_rfc3339());
    assert!(!store
        .project_wireless_record(
            event.clone(),
            &metadata(&event.to_string(), 3, "wireless-projection-v1")
        )
        .await
        .unwrap());
    fixture.admin("UPDATE atheros_search.wireless_observation_summaries SET expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second'; UPDATE octopus_core.wireless_projection_group_receipts SET expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second'; UPDATE octopus_core.wireless_projection_hashes SET expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second';");
    assert_eq!(store.expire_wireless_projections(10).await.unwrap(), 1);
    let mut tx = runtime.begin_worker().await.unwrap();
    assert_eq!(tx.query("SELECT count(*) FROM atheros_search.wireless_topology_edges WHERE edge_kind='observed_association'",&[]).await.unwrap()[0].get::<_,i64>(0),0);
    tx.commit().await.unwrap();
}
#[tokio::test]
async fn scheduled_projection_queries_execute_against_canonical_grants() {
    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let store = ProjectionStore::new(fixture.runtime.clone());
    assert_eq!(store.normalize_wireless_frames(10).await.unwrap(), 0);
    assert_eq!(store.project_wireless_inventory(10).await.unwrap(), 0);
    assert_eq!(store.project_behavior(10).await.unwrap(), 0);
    assert_eq!(store.project_timing(10).await.unwrap(), 0);
    assert_eq!(store.project_sequences(10).await.unwrap(), 0);
    assert_eq!(store.project_baselines(10).await.unwrap(), 0);
    assert_eq!(store.project_cluster_candidates(10, 0.98).await.unwrap(), 0);
    assert_eq!(store.project_approved_identities(0).await.unwrap(), 0);
    assert_eq!(store.project_dns_threats(10).await.unwrap(), 0);
    assert_eq!(store.project_risk(10).await.unwrap(), 0);
    store.project_infrastructure_graph(10).await.unwrap();
    assert!(store.generate_rf_alerts(10).await.unwrap().is_empty());
    fixture.admin("INSERT INTO octopus_core.sync_events(dedupe_key,stream_name,observed_at,payload_ref,payload,status,attempt_count,producer,source_mac,bssid,signal_dbm,frame_type,frame_subtype,sensor_id,ssid) VALUES('frame-one','wireless.audit',CURRENT_TIMESTAMP,'{}','{}','completed',1,'test','aa:bb:cc:dd:ee:ff','22:33:44:55:66:77',-50,'data','data','native','test');");
    assert_eq!(store.normalize_wireless_frames(10).await.unwrap(), 7);
    assert!(store.project_wireless_inventory(10).await.unwrap() > 0);
    assert_eq!(store.project_wireless_inventory(10).await.unwrap(), 0);
    assert_eq!(store.project_behavior(10).await.unwrap(), 1);
    assert_eq!(store.project_behavior(10).await.unwrap(), 0);
    assert_eq!(store.project_timing(10).await.unwrap(), 1);
    assert_eq!(store.project_baselines(10).await.unwrap(), 1);
    assert!(store.project_risk(10).await.unwrap() > 0);
    store.project_infrastructure_graph(10).await.unwrap();
}
