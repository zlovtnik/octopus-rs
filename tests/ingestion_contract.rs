use octopus::{
    domain::{
        BrokerConsumerContract, BrokerRecordMetadata, IngestionDisposition,
        ResolvedScanRequestRecord, ScanRequestRecord,
    },
    ingestion::{load_eligible, IngestionStore, IntakeError},
    postgres::PgRuntime,
    util::sha256_hex,
};
mod support;
use support::Fixture;

fn record(stream: &str, key: &str, payload: &str, time: &str) -> ResolvedScanRequestRecord {
    let wire=serde_json::json!({"stream_name":stream,"dedupe_key":key,"payload_ref":payload,"observed_at":time}).to_string();
    ResolvedScanRequestRecord::from(
        ScanRequestRecord::decode_wire(&wire).unwrap(),
        payload.into(),
    )
    .unwrap()
}
fn metadata(record: &ResolvedScanRequestRecord, offset: i64) -> BrokerRecordMetadata {
    let contract = BrokerConsumerContract::from("native-intake-v1", "sync.scan.request").unwrap();
    BrokerRecordMetadata {
        topic: "sync.scan.request".into(),
        partition: 0,
        offset,
        consumer_group: "native-intake-v1".into(),
        group_version: contract.group_version,
        artifact_sha256: contract.contract_sha256,
        message_key: None,
        payload_sha256: record.source().source_record_sha256().into(),
    }
}
async fn count(runtime: &PgRuntime, table: &str) -> i64 {
    // All names here are test constants, never wire-derived identifiers.
    let mut tx = runtime.begin_worker().await.unwrap();
    let value = tx
        .query(&format!("SELECT count(*) FROM {table}"), &[])
        .await
        .unwrap()[0]
        .get(0);
    tx.commit().await.unwrap();
    value
}

#[test]
fn typed_stream_aliases_and_unknown_intake_are_distinct() {
    for stream in [
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
    ] {
        assert!(load_eligible(stream), "{stream}");
    }
    for stream in [
        "custom.raw",
        "wireless.sensor.heartbeat",
        "proxy.events ",
        "",
    ] {
        assert!(!load_eligible(stream));
    }
}

#[tokio::test]
async fn later_delivery_creates_first_batch_for_newly_enabled_stream() {
    let Some(fixture) = Fixture::start().await else {
        return;
    };
    let stream = "wireless.alert.rogue_ap";
    let event = record(stream, "newly-enabled", "{}", "2026-11-01T00:00:00Z");
    let store = IngestionStore::new(fixture.runtime.clone());
    let status = || async {
        let mut tx = fixture.runtime.begin_worker().await.unwrap();
        let rows = tx.query(
            "SELECT e.status,b.status FROM sync_events e LEFT JOIN sync_batches b USING (stream_name,dedupe_key) WHERE e.stream_name=$1 AND e.dedupe_key=$2",
            &[&stream, &event.source().dedupe_key()],
        ).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(rows.len(), 1);
        (
            rows[0].get::<_, String>(0),
            rows[0].get::<_, Option<String>>(1),
        )
    };

    let excluded = store.clone().with_load_streams(&["proxy.events".into()]);
    excluded
        .record_scan_request_with_evidence(&event, &metadata(&event, 1))
        .await
        .unwrap();
    assert_eq!(status().await, ("completed".into(), None));

    let enabled = store.with_load_streams(&["proxy.events".into(), stream.into()]);
    let admitted = enabled
        .record_scan_request_with_evidence(&event, &metadata(&event, 1))
        .await
        .unwrap();
    assert_eq!(admitted.disposition, IngestionDisposition::Deduplicated);
    assert_eq!(status().await, ("batched".into(), Some("pending".into())));
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let evidence = tx
        .query(
            "SELECT evidence.disposition, offsets.next_offset
             FROM ingestion_evidence evidence JOIN consumer_offsets offsets
             USING (topic, partition_id, group_id) WHERE evidence.record_offset=1",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].get::<_, String>(0), "processed");
    assert_eq!(evidence[0].get::<_, i64>(1), 2);
    tx.commit().await.unwrap();

    fixture.admin("UPDATE octopus_core.sync_batches SET status='completed'; UPDATE octopus_core.sync_events SET status='completed'");
    let replay = enabled
        .record_scan_request_with_evidence(&event, &metadata(&event, 3))
        .await
        .unwrap();
    assert_eq!(replay.disposition, IngestionDisposition::Deduplicated);
    assert_eq!(replay.batch_id, admitted.batch_id);
    assert_eq!(
        status().await,
        ("completed".into(), Some("completed".into()))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn canonical_intake_is_atomic_replay_safe_and_monotonic() {
    let Some(fixture) = Fixture::start().await else {
        return;
    };
    let runtime = fixture.runtime.clone();
    let store = IngestionStore::new(runtime.clone());
    let raw = record(
        "custom.raw",
        "raw-1",
        r#"{"event_kind":"custom","rows":[1,2]}"#,
        "2026-11-01T00:00:00Z",
    );
    let meta = metadata(&raw, 1);
    assert_eq!(
        store
            .record_scan_request_with_evidence(&raw, &meta)
            .await
            .unwrap()
            .disposition,
        IngestionDisposition::Processed
    );
    assert_eq!(
        store
            .record_scan_request_with_evidence(&raw, &meta)
            .await
            .unwrap()
            .disposition,
        IngestionDisposition::Deduplicated
    );
    assert_eq!(count(&runtime, "sync_events").await, 1);
    assert_eq!(count(&runtime, "sync_jobs").await, 0);
    let mut tx = runtime.begin_worker().await.unwrap();
    let row = &tx
        .query(
            "SELECT status,payload_sha256 FROM sync_events WHERE dedupe_key='raw-1'",
            &[],
        )
        .await
        .unwrap()[0];
    assert_eq!(row.get::<_, String>(0), "completed");
    assert_eq!(row.get::<_, String>(1), sha256_hex(raw.payload_json()));
    tx.commit().await.unwrap();

    let proxy = record(
        "proxy.events",
        "proxy-1",
        r#"{"url":"example"}"#,
        "2026-11-01T00:00:00Z",
    );
    let proxy_meta = metadata(&proxy, 2);
    let result = store
        .record_scan_request_with_evidence(&proxy, &proxy_meta)
        .await
        .unwrap();
    let replay = store
        .record_scan_request_with_evidence(&proxy, &proxy_meta)
        .await
        .unwrap();
    assert_eq!(result.job_id, replay.job_id);
    assert_eq!(result.batch_id, replay.batch_id);
    assert_eq!(count(&runtime, "sync_jobs").await, 1);
    assert_eq!(count(&runtime, "sync_batches").await, 1);
    let conflict = record("custom.raw", "different-key", "{}", "2026-11-01T00:00:00Z");
    let mut conflict_meta = metadata(&conflict, 1);
    assert!(matches!(
        store
            .record_scan_request_with_evidence(&conflict, &conflict_meta)
            .await,
        Err(IntakeError::Invariant(_))
    ));
    assert_eq!(count(&runtime, "sync_events").await, 2);
    conflict_meta.payload_sha256 = "bad".into();
    assert!(matches!(
        store
            .record_scan_request_with_evidence(&conflict, &conflict_meta)
            .await,
        Err(IntakeError::InvalidRecord(_))
    ));

    let first = record("custom.raw", "must-rollback", "{}", "2026-11-01T00:00:00Z");
    let changed = record(
        "custom.raw",
        "raw-1",
        r#"{"changed":true}"#,
        "2026-11-01T00:00:00Z",
    );
    assert!(matches!(
        store
            .record_scan_requests_with_evidence(&[
                (&first, &metadata(&first, 3)),
                (&changed, &metadata(&changed, 4))
            ])
            .await,
        Err(IntakeError::Invariant(_))
    ));
    assert_eq!(count(&runtime, "sync_events").await, 2);
    assert_eq!(count(&runtime, "ingestion_evidence").await, 2);

    let hb = record(
        "wireless.sensor.heartbeat",
        "hb-1",
        r#"{"sensor_id":"s1","location_id":"new","capabilities":{"bands":2}}"#,
        "2026-11-03T00:00:00Z",
    );
    let old = record(
        "wireless.sensor.heartbeat",
        "hb-2",
        r#"{"sensor_id":"s1","location_id":"old","capabilities":{"bands":1}}"#,
        "2026-11-02T00:00:00Z",
    );
    store
        .record_scan_request_with_evidence(&hb, &metadata(&hb, 5))
        .await
        .unwrap();
    store
        .record_scan_request_with_evidence(&old, &metadata(&old, 6))
        .await
        .unwrap();
    fixture.admin("UPDATE octopus_core.sensors SET status='disabled' WHERE sensor_id='s1'");
    let newest = record(
        "wireless.sensor.heartbeat",
        "hb-3",
        r#"{"sensor_id":"s1"}"#,
        "2026-11-04T00:00:00Z",
    );
    store
        .record_scan_request_with_evidence(&newest, &metadata(&newest, 7))
        .await
        .unwrap();
    let mut tx = runtime.begin_worker().await.unwrap();
    let rows=tx.query("SELECT location_id,capabilities,status,first_seen_at::text,last_heartbeat_at::text FROM sensors WHERE sensor_id='s1'",&[]).await.unwrap();
    assert_eq!(rows[0].get::<_, String>(0), "new");
    assert_eq!(
        rows[0].get::<_, serde_json::Value>(1),
        serde_json::json!({"bands":2})
    );
    assert_eq!(rows[0].get::<_, String>(2), "disabled");
    assert!(rows[0].get::<_, String>(3).starts_with("2026-11-02"));
    assert!(rows[0].get::<_, String>(4).starts_with("2026-11-04"));
    tx.commit().await.unwrap();

    let payload = r#"{"type":"probe","sensor_id":"wireless-s1","ssid":"","mac":{"source_mac":"AA:BB:CC:DD:EE:FF"},"rf":{"signal_dbm":"-55","tsft":"9223372036854775807"},"risk_score":"1e-2","large_frame":"true","tags":["a"]}"#;
    let wireless = record(
        "wireless.audit",
        &sha256_hex(payload),
        payload,
        "2026-11-01T00:00:00Z",
    );
    store
        .record_scan_request_with_evidence(&wireless, &metadata(&wireless, 8))
        .await
        .unwrap();
    let mut tx = runtime.begin_worker().await.unwrap();
    let rows=tx.query("SELECT sensor_id,event_type,schema_version,source_mac,ssid,signal_dbm,tsft,risk_score,large_frame,wireless_search_text FROM sync_events WHERE stream_name='wireless.audit'",&[]).await.unwrap();
    assert_eq!(rows[0].get::<_, String>(0), "wireless-s1");
    assert_eq!(rows[0].get::<_, String>(1), "probe");
    assert_eq!(rows[0].get::<_, i32>(2), 1);
    assert_eq!(rows[0].get::<_, String>(3), "aa:bb:cc:dd:ee:ff");
    assert_eq!(rows[0].get::<_, String>(4), "");
    assert_eq!(rows[0].get::<_, i32>(5), -55);
    assert_eq!(rows[0].get::<_, i64>(6), i64::MAX);
    assert_eq!(rows[0].get::<_, f64>(7), 0.01);
    assert!(rows[0].get::<_, bool>(8));
    assert!(rows[0].get::<_, String>(9).contains("wireless-s1"));
    tx.commit().await.unwrap();

    fixture.admin("INSERT INTO octopus_core.sync_event_tombstones(dedupe_key,stream_name,observed_at,expires_at) VALUES ('gone','custom.raw',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '1 day')");
    let gone = record("custom.raw", "gone", "{}", "2026-11-01T00:00:00Z");
    assert_eq!(
        store
            .record_scan_request_with_evidence(&gone, &metadata(&gone, 9))
            .await
            .unwrap()
            .disposition,
        IngestionDisposition::Deduplicated
    );
    let mut tx = runtime.begin_worker().await.unwrap();
    assert_eq!(
        tx.query(
            "SELECT count(*) FROM sync_events WHERE dedupe_key='gone'",
            &[]
        )
        .await
        .unwrap()[0]
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        tx.query(
            "SELECT next_offset FROM consumer_offsets WHERE group_id='native-intake-v1'",
            &[]
        )
        .await
        .unwrap()[0]
            .get::<_, i64>(0),
        10
    );
    tx.commit().await.unwrap();
    // The compatibility API keeps the first stream/key occurrence, while its
    // empty input never needs a connection or evidence row.
    assert_eq!(store.record_scan_requests(&[]).await.unwrap(), 0);
    let first = record("custom.raw", "compat-first", "{}", "2026-11-01T00:00:00Z");
    let second = record("custom.raw", "compat-first", "[]", "2026-11-01T00:00:00Z");
    assert_eq!(
        store
            .record_scan_requests(&[first.clone(), second])
            .await
            .unwrap(),
        1
    );
    assert_eq!(store.record_scan_requests(&[first]).await.unwrap(), 0);

    // Two different events racing for one coordinate may never leave an orphan
    // event from the losing transaction behind the winner's durable evidence.
    let left = record("custom.raw", "race-left", "{}", "2026-11-01T00:00:00Z");
    let right = record("custom.raw", "race-right", "{}", "2026-11-01T00:00:00Z");
    let left_meta = metadata(&left, 42);
    let right_meta = metadata(&right, 42);
    let (left_result, right_result) = tokio::join!(
        store.record_scan_request_with_evidence(&left, &left_meta),
        store.record_scan_request_with_evidence(&right, &right_meta),
    );
    let (winner, winning_record, loser, winning_meta) = match (left_result, right_result) {
        (Ok(winner), Err(IntakeError::Invariant(_))) => (winner, &left, &right, &left_meta),
        (Err(IntakeError::Invariant(_)), Ok(winner)) => (winner, &right, &left, &right_meta),
        other => panic!("expected one success and one coordinate conflict, got {other:?}"),
    };
    assert_eq!(winner.dedupe_key, winning_record.source().dedupe_key());
    let mut tx = runtime.begin_worker().await.unwrap();
    let events = tx.query(
        "SELECT dedupe_key FROM sync_events WHERE stream_name='custom.raw' AND dedupe_key IN ($1,$2)",
        &[&winner.dedupe_key, &loser.source().dedupe_key()],
    ).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].get::<_, String>(0), winner.dedupe_key);
    let evidence = tx.query(
        "SELECT dedupe_key,payload_sha256 FROM ingestion_evidence WHERE topic=$1 AND partition_id=$2 AND record_offset=42 AND group_id=$3",
        &[&winning_meta.topic, &winning_meta.partition, &winning_meta.consumer_group],
    ).await.unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].get::<_, String>(0), winner.dedupe_key);
    assert_eq!(evidence[0].get::<_, String>(1), winning_meta.payload_sha256);
    tx.commit().await.unwrap();
    runtime.close();
}
