mod support;
use octopus::{
    dispatch::DispatchStore,
    domain::{BrokerConsumerContract, BrokerRecordMetadata, SyncLoad},
    load::{checksum, LoadStore, SinkTarget},
    util::sha256_hex,
};
use serde_json::{json, Value};

const TIME: &str = "2026-01-02T03:04:05Z";

async fn seed(f: &support::Fixture, stream: &str, payload: &Value) -> SyncLoad {
    let id = uuid::Uuid::new_v4().to_string();
    let reference = format!(
        "inline://json/{}",
        openssl::base64::encode_block(payload.to_string().as_bytes())
            .trim_end_matches('=')
            .replace('+', "-")
            .replace('/', "_")
    );
    let mut tx = f.runtime.begin_worker().await.unwrap();
    tx.execute(
        "INSERT INTO sync_jobs(job_id,dedupe_key,stream_name,status) VALUES(CAST($1 AS text),CAST($1 AS text),$2,'pending')",
        &[&id, &stream],
    )
    .await
    .unwrap();
    tx.execute("INSERT INTO sync_batches(batch_id,job_id,dedupe_key,stream_name,payload_ref,cursor_start,cursor_end) VALUES(CAST($1 AS text),CAST($1 AS text),CAST($1 AS text),$2,$3,'0','1')",&[&id,&stream,&reference]).await.unwrap();
    tx.execute("INSERT INTO sync_events(dedupe_key,stream_name,payload_ref,observed_at,status) VALUES($1,$2,$3,CURRENT_TIMESTAMP,'batched')",&[&id,&stream,&reference]).await.unwrap();
    tx.commit().await.unwrap();
    DispatchStore::new(f.runtime.clone())
        .enqueue_pending(100, 5)
        .await
        .unwrap();
    SyncLoad {
        job_id: id.clone(),
        batch_id: id,
        batch_no: Some(0),
        stream_name: stream.into(),
        payload_ref: reference,
        cursor_start: "0".into(),
        cursor_end: "1".into(),
        attempt: 1,
    }
}
fn metadata(
    topic: &str,
    group: &str,
    key: String,
    offset: i64,
    payload: &str,
) -> BrokerRecordMetadata {
    let contract = BrokerConsumerContract::from(group, topic).unwrap();
    BrokerRecordMetadata {
        topic: topic.into(),
        partition: 0,
        offset,
        consumer_group: group.into(),
        group_version: contract.group_version,
        artifact_sha256: contract.contract_sha256,
        message_key: Some(key),
        payload_sha256: sha256_hex(payload),
    }
}
fn examples() -> Vec<(SinkTarget, Value, &'static str)> {
    let mut alert = json!({"detected_at":TIME,"sensor_id":"sensor-a","location_id":"lab","interface":"wlan0","channel":6,"bssid":"00:11:22:33:44:55","source_mac":"00:11:22:33:44:66","signal_dbm":-50,"ssid":"network","frame_count":9,"window_secs":5,"baseline_dbm":-40,"observed_dbm":-70,"dbm_delta":-30,"configured_delta":20,"attack_tag":"pmf","first_event_at":TIME,"last_event_at":TIME,"session_key":"session","client_mac":"00:11:22:33:44:66"});
    let mut out = vec![
        (
            SinkTarget::ProxyEvents,
            json!({"type":"block","host":"example.org","time":TIME,"blocked":true}),
            "proxy_events",
        ),
        (
            SinkTarget::ProxyPayloadAudit,
            json!({"host":"example.org","observed_at":TIME}),
            "proxy_payload_audit",
        ),
        (
            SinkTarget::WirelessAudit,
            json!({"event_type":"frame","observed_at":TIME,"sensor_id":"sensor-a","location_id":"lab","interface":"wlan0","channel":6,"frame_subtype":"beacon","raw_len":128}),
            "wireless_audit_frames",
        ),
        (
            SinkTarget::WirelessBandwidth,
            json!({"window_start":TIME,"window_end":TIME,"sensor_id":"sensor-a","location_id":"lab","interface":"wlan0","channel":6,"source_mac":"00:11:22:33:44:66","destination_bssid":"00:11:22:33:44:55","bytes":1000,"frame_count":10,"threshold_exceeded":true}),
            "wireless_bandwidth_windows",
        ),
        (
            SinkTarget::ClientInventory,
            json!({"clients":[{"client_mac":"00:11:22:33:44:66","first_seen":TIME,"last_seen":TIME}],"sensor_id":"sensor-a","location_id":"lab","observed_at":TIME}),
            "wireless_client_inventory",
        ),
        (
            SinkTarget::ProbeRequests,
            json!({"probes":[{"client_mac":"00:11:22:33:44:66","ssid":"network","first_seen":TIME,"last_seen":TIME,"probe_count":3}]}),
            "wireless_probe_requests",
        ),
    ];
    for target in [
        SinkTarget::RogueAp,
        SinkTarget::DeauthFlood,
        SinkTarget::SignalAnomaly,
        SinkTarget::PmfAttack,
        SinkTarget::AttackSequence,
        SinkTarget::SequenceAlert,
        SinkTarget::HandshakeAlert,
    ] {
        out.push((target, alert.clone(), "wireless_alerts"));
    }
    // Keep object shape explicit for future added target fields.
    alert.as_object_mut().unwrap().clear();
    out
}

#[tokio::test]
async fn thirteen_sinks_authorization_replay_atomicity_and_result_fences() {
    let Some(f) = support::Fixture::start().await else {
        return;
    };
    let store = LoadStore::new(f.runtime.clone(), f.directory().to_path_buf(), 1, 4096);
    for (index, (target, payload, table)) in examples().into_iter().enumerate() {
        let load = seed(&f, target.checksum_tag(), &payload).await;
        let mut unauthorized = load.clone();
        unauthorized.payload_ref = "outbox://missing".into();
        assert!(store
            .handle(&unauthorized)
            .await
            .unwrap_err()
            .is_unauthorized());
        let result = store.handle(&load).await.unwrap();
        assert_eq!(
            result.status, "success",
            "{target:?}: {}",
            result.error_text
        );
        assert_eq!(result.row_count, 1);
        assert_eq!(result.checksum, checksum(target, &payload.to_string()));
        assert_eq!(store.handle(&load).await.unwrap().status, "success");
        let m = metadata(
            "sync.oracle.load",
            "octopus-load-postgres-v1",
            format!("{}:1", load.batch_id),
            index as i64,
            &serde_json::to_string(&load).unwrap(),
        );
        store
            .record_load_result_with_evidence(&load, &result, &m)
            .await
            .unwrap();
        store
            .record_load_result_with_evidence(&load, &result, &m)
            .await
            .unwrap();
        let mut changed = m.clone();
        changed.payload_sha256 = "a".repeat(64);
        assert!(store
            .record_load_result_with_evidence(&load, &result, &changed)
            .await
            .unwrap_err()
            .is_invariant());
        let rm = metadata(
            "sync.oracle.result",
            "octopus-result-postgres-v1",
            format!("{}:1", load.batch_id),
            index as i64,
            &serde_json::to_string(&result).unwrap(),
        );
        store
            .record_result_with_evidence(&result, &rm)
            .await
            .unwrap();
        store
            .record_result_with_evidence(&result, &rm)
            .await
            .unwrap();
        let mut forged = result.clone();
        forged.row_count = 2;
        assert!(store
            .record_result_with_evidence(&forged, &rm)
            .await
            .unwrap_err()
            .is_unauthorized());
        let mut tx = f.runtime.begin_worker().await.unwrap();
        let state: String = tx
            .query(
                "SELECT status FROM sync_batches WHERE batch_id=$1",
                &[&load.batch_id],
            )
            .await
            .unwrap()[0]
            .get(0);
        assert_eq!(state, "completed");
        let count: i64 = tx
            .query(&format!("SELECT count(*) FROM {table}"), &[])
            .await
            .unwrap()[0]
            .get(0);
        assert!(count > 0);
        tx.commit().await.unwrap();
    }
    let good = json!({"type":"block","host":"atomic.example","time":TIME,"blocked":true});
    let load = seed(&f, "proxy.events", &json!([good,{"type":"block"}])).await;
    let result = store.handle(&load).await.unwrap();
    assert_eq!(result.status, "failed");
    let mut tx = f.runtime.begin_worker().await.unwrap();
    let count: i64 = tx
        .query(
            "SELECT count(*) FROM proxy_events WHERE host='atomic.example'",
            &[],
        )
        .await
        .unwrap()[0]
        .get(0);
    assert_eq!(count, 0, "later transform error rolls back earlier chunks");
    tx.commit().await.unwrap();
}

#[test]
fn local_payload_paths_and_encoding() {
    use octopus::load::{resolve_local_payload, LoadError};
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("event.json"), "{\"ok\":true}").unwrap();
    assert_eq!(
        resolve_local_payload("outbox://event.json", dir.path()).unwrap(),
        "{\"ok\":true}"
    );
    assert_eq!(
        resolve_local_payload("inline://json/e30", dir.path()).unwrap(),
        "{}"
    );
    assert_eq!(
        resolve_local_payload("inline://json/MQ", dir.path()).unwrap(),
        "1"
    );
    assert_eq!(
        resolve_local_payload("outbox://absent/../event.json", dir.path()).unwrap(),
        "{\"ok\":true}"
    );
    assert!(matches!(
        resolve_local_payload("outbox://missing", dir.path()),
        Err(LoadError::MissingPayload)
    ));
    for bad in [
        "outbox://../escape",
        "outbox:///etc/passwd",
        "http://host/payload",
        "inline://json/!",
    ] {
        assert!(resolve_local_payload(bad, dir.path()).is_err());
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("escape")).unwrap();
        assert!(resolve_local_payload("outbox://escape", dir.path()).is_err());
    }
}

#[tokio::test]
async fn retry_and_terminal_failure_are_attempt_fenced() {
    use octopus::domain::PostgresResult;
    let Some(f) = support::Fixture::start().await else {
        return;
    };
    let store = LoadStore::new(f.runtime.clone(), f.directory().to_path_buf(), 500, 4096);
    let load = seed(
        &f,
        "proxy.events",
        &json!({"type":"block","host":"retry.example","time":TIME}),
    )
    .await;
    let failure = PostgresResult::failure(
        load.job_id.clone(),
        load.batch_id.clone(),
        "retryable".into(),
        "database unavailable".into(),
        TIME.into(),
    );
    let key = format!("{}:1", load.batch_id);
    let lm = metadata(
        "sync.oracle.load",
        "octopus-load-postgres-v1",
        key.clone(),
        0,
        &serde_json::to_string(&load).unwrap(),
    );
    store
        .record_load_result_with_evidence(&load, &failure, &lm)
        .await
        .unwrap();
    let rm = metadata(
        "sync.oracle.result",
        "octopus-result-postgres-v1",
        key,
        0,
        &serde_json::to_string(&failure).unwrap(),
    );
    store
        .record_result_with_evidence(&failure, &rm)
        .await
        .unwrap();
    let mut tx = f.runtime.begin_worker().await.unwrap();
    let rows = tx
        .query(
            "SELECT status,attempt_count FROM sync_batches WHERE batch_id=$1",
            &[&load.batch_id],
        )
        .await
        .unwrap();
    assert_eq!(rows[0].get::<_, String>(0), "pending");
    assert_eq!(rows[0].get::<_, i32>(1), 1);
    let retry:Value=tx.query("SELECT payload FROM outbox_events WHERE source_type='sync_batch_retry' AND source_id=$1",&[&format!("{}:2",load.batch_id)]).await.unwrap()[0].get(0);
    tx.commit().await.unwrap();
    let retry: SyncLoad = serde_json::from_value(retry).unwrap();
    assert_eq!(retry.attempt, 2);
    let mut stale = rm.clone();
    stale.offset = 1;
    store
        .record_result_with_evidence(&failure, &stale)
        .await
        .unwrap();
    let result = store.handle(&retry).await.unwrap();
    assert_eq!(result.status, "success");
    let key = format!("{}:2", load.batch_id);
    let lm = metadata(
        "sync.oracle.load",
        "octopus-load-postgres-v1",
        key.clone(),
        2,
        &serde_json::to_string(&retry).unwrap(),
    );
    store
        .record_load_result_with_evidence(&retry, &result, &lm)
        .await
        .unwrap();
    let rm = metadata(
        "sync.oracle.result",
        "octopus-result-postgres-v1",
        key,
        2,
        &serde_json::to_string(&result).unwrap(),
    );
    store
        .record_result_with_evidence(&result, &rm)
        .await
        .unwrap();
    let terminal = seed(
        &f,
        "proxy.events",
        &json!({"type":"block","host":"terminal.example","time":TIME}),
    )
    .await;
    let mut tx = f.runtime.begin_worker().await.unwrap();
    tx.execute(
        "UPDATE sync_batches SET max_attempts=1 WHERE batch_id=$1",
        &[&terminal.batch_id],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let failure = PostgresResult::failure(
        terminal.job_id.clone(),
        terminal.batch_id.clone(),
        "retryable".into(),
        "unavailable".into(),
        TIME.into(),
    );
    let key = format!("{}:1", terminal.batch_id);
    let lm = metadata(
        "sync.oracle.load",
        "octopus-load-postgres-v1",
        key.clone(),
        3,
        &serde_json::to_string(&terminal).unwrap(),
    );
    store
        .record_load_result_with_evidence(&terminal, &failure, &lm)
        .await
        .unwrap();
    let rm = metadata(
        "sync.oracle.result",
        "octopus-result-postgres-v1",
        key,
        3,
        &serde_json::to_string(&failure).unwrap(),
    );
    store
        .record_result_with_evidence(&failure, &rm)
        .await
        .unwrap();
    let mut tx = f.runtime.begin_worker().await.unwrap();
    let rows=tx.query("SELECT b.status,j.status,(SELECT count(*) FROM sync_errors e WHERE e.batch_id=b.batch_id) FROM sync_batches b JOIN sync_jobs j USING(job_id) WHERE b.batch_id=$1",&[&terminal.batch_id]).await.unwrap();
    assert_eq!(rows[0].get::<_, String>(0), "failed");
    assert_eq!(rows[0].get::<_, String>(1), "failed");
    assert_eq!(rows[0].get::<_, i64>(2), 1);
    tx.commit().await.unwrap();
}
