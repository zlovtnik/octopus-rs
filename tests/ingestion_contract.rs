use octopus::{
    config::PostgresConfig,
    domain::{
        BrokerConsumerContract, BrokerRecordMetadata, IngestionDisposition,
        ResolvedScanRequestRecord, ScanRequestRecord,
    },
    ingestion::{load_eligible, IngestionStore, IntakeError},
    postgres::PgRuntime,
    util::sha256_hex,
};
use std::{
    path::PathBuf,
    process::{Command, Output},
    sync::Arc,
    time::Duration,
};

const IMAGE: &str = "pgvector/pgvector:0.8.6-pg16-bookworm@sha256:ccc6e83d6e35e931dc7c5def2022729d5a6c370318d099181995567ff1fb4d6b";

fn checked(command: &mut Command) -> Output {
    let output = command.output().expect("test command must start");
    assert!(
        output.status.success(),
        "test fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

struct Fixture {
    name: String,
    network: String,
    directory: tempfile::TempDir,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", "-v", &self.name])
            .output();
        let _ = Command::new("docker")
            .args(["network", "rm", &self.network])
            .output();
    }
}
impl Fixture {
    async fn start() -> Option<(Self, Arc<PgRuntime>)> {
        let available = Command::new("docker")
            .arg("info")
            .output()
            .is_ok_and(|out| out.status.success());
        if !available {
            assert_ne!(
                std::env::var("OCTOPUS_REQUIRE_DOCKER").as_deref(),
                Ok("true"),
                "required Docker is unavailable"
            );
            eprintln!("Docker unavailable; native ingestion integration not exercised");
            return None;
        }
        let name = format!("native-intake-{}", uuid::Uuid::new_v4());
        let fixture = Self {
            network: format!("{name}-net"),
            name,
            directory: tempfile::tempdir().unwrap(),
        };
        checked(Command::new("docker").args(["network", "create", &fixture.network]));
        checked(Command::new("docker").args([
            "run",
            "-d",
            "--name",
            &fixture.name,
            "--network",
            &fixture.network,
            "-e",
            "POSTGRES_PASSWORD=integration-admin",
            "-e",
            "POSTGRES_DB=sync",
            "-p",
            "127.0.0.1::5432",
            IMAGE,
        ]));
        let mut ready = false;
        for _ in 0..120 {
            if Command::new("docker")
                .args([
                    "exec",
                    &fixture.name,
                    "pg_isready",
                    "-h",
                    "127.0.0.1",
                    "-U",
                    "postgres",
                    "-d",
                    "sync",
                ])
                .output()
                .is_ok_and(|out| out.status.success())
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert!(ready, "scratch database did not start");
        fixture.admin("CREATE EXTENSION pgcrypto; CREATE EXTENSION vector; CREATE EXTENSION pg_stat_statements; CREATE ROLE schema_owner LOGIN PASSWORD 'integration-schema-owner'; CREATE ROLE octopus_runtime LOGIN PASSWORD 'integration-runtime'; CREATE ROLE atheros_search_runtime LOGIN; CREATE ROLE schema_migrator_runtime LOGIN; CREATE ROLE keycloak_runtime LOGIN; GRANT CREATE ON DATABASE sync TO schema_owner;");
        fixture.admin("ALTER ROLE octopus_runtime IN DATABASE sync SET search_path TO octopus_core, atheros_search; ALTER ROLE atheros_search_runtime IN DATABASE sync SET search_path TO atheros_search; ALTER ROLE schema_migrator_runtime IN DATABASE sync SET search_path TO schema_migrator; ALTER ROLE keycloak_runtime IN DATABASE sync SET search_path TO keycloak;");
        fixture.provision();
        let output = checked(Command::new("docker").args(["port", &fixture.name, "5432/tcp"]));
        let port = String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let manifest =
            std::fs::read_to_string(root.join("sql/postgres/octopus_core/manifest.yaml")).unwrap();
        let checksum = manifest
            .lines()
            .find_map(|line| line.strip_prefix("manifest_sha256: "))
            .unwrap()
            .to_string();
        let cfg = PostgresConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            port,
            user: "octopus_runtime".into(),
            password: "integration-runtime".into(),
            database: "sync".into(),
            ssl_mode: "disable".into(),
            manifest_sha256: checksum,
            pool_size: 4,
            healthcheck_reserve: 1,
            ..PostgresConfig::default()
        };
        let runtime = Arc::new(
            PgRuntime::connect(&cfg)
                .await
                .expect("canonical executor must satisfy native preflight"),
        );
        Some((fixture, runtime))
    }

    fn admin(&self, sql: &str) {
        checked(Command::new("docker").args([
            "exec",
            &self.name,
            "psql",
            "-U",
            "postgres",
            "-d",
            "sync",
            "--set=ON_ERROR_STOP=1",
            "--command",
            sql,
        ]));
    }

    fn provision(&self) {
        use std::os::unix::fs::PermissionsExt;
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let path = self.directory.path();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let bin = path.join("bin");
        std::fs::create_dir(&bin).unwrap();
        let wrapper = bin.join("psql");
        std::fs::write(
            &wrapper,
            "#!/bin/sh\nPGSSLMODE=disable exec /usr/bin/psql \"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(wrapper, std::fs::Permissions::from_mode(0o555)).unwrap();
        let ca = path.join("ca.crt");
        std::fs::write(&ca, "integration-test-placeholder\n").unwrap();
        std::fs::set_permissions(ca, std::fs::Permissions::from_mode(0o444)).unwrap();
        let mut command = Command::new("docker");
        command.args([
            "run",
            "--rm",
            "--network",
            &self.network,
            "--user",
            "65532:65532",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=67108864",
        ]);
        for (key, value) in [
            (
                "PATH",
                "/test-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            ),
            ("POSTGRES_HOST", self.name.as_str()),
            ("POSTGRES_PORT", "5432"),
            ("POSTGRES_DATABASE", "sync"),
            ("POSTGRES_SCHEMA_OWNER_USER", "schema_owner"),
            ("POSTGRES_SCHEMA_OWNER_PASSWORD", "integration-schema-owner"),
            ("POSTGRES_OCTOPUS_ACCOUNT", "octopus_runtime"),
            ("POSTGRES_ATHEROS_SEARCH_ACCOUNT", "atheros_search_runtime"),
            (
                "POSTGRES_SCHEMA_MIGRATOR_ACCOUNT",
                "schema_migrator_runtime",
            ),
            ("POSTGRES_KEYCLOAK_ACCOUNT", "keycloak_runtime"),
            ("PGSSLMODE", "verify-full"),
            ("POSTGRES_SSL_SERVER_NAME", self.name.as_str()),
            ("PGSSLROOTCERT", "/test-ca/ca.crt"),
        ] {
            command.args(["--env", &format!("{key}={value}")]);
        }
        command.args([
            "--volume",
            &format!("{}:/workspace:ro", root.display()),
            "--volume",
            &format!("{}:/test-bin:ro", bin.display()),
            "--volume",
            &format!("{}:/test-ca:ro", path.display()),
            "--entrypoint",
            "/workspace/k8s/postgres-schema-executor/entrypoint.sh",
            IMAGE,
        ]);
        checked(&mut command);
    }
}

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

#[tokio::test(flavor = "multi_thread")]
async fn canonical_intake_is_atomic_replay_safe_and_monotonic() {
    let Some((fixture, runtime)) = Fixture::start().await else {
        return;
    };
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
    let before = count(&runtime, "sync_events").await;
    let left = record("custom.raw", "race-left", "{}", "2026-11-01T00:00:00Z");
    let right = record("custom.raw", "race-right", "{}", "2026-11-01T00:00:00Z");
    let left_meta = metadata(&left, 42);
    let right_meta = metadata(&right, 42);
    let (left_result, right_result) = tokio::join!(
        store.record_scan_request_with_evidence(&left, &left_meta),
        store.record_scan_request_with_evidence(&right, &right_meta),
    );
    assert!(matches!(
        (&left_result, &right_result),
        (Ok(_), Err(IntakeError::Invariant(_))) | (Err(IntakeError::Invariant(_)), Ok(_))
    ));
    assert_eq!(count(&runtime, "sync_events").await, before + 1);
    runtime.close();
}
