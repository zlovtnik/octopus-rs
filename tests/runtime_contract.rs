//! Real five-lane broker/application exercise, distinct from librdkafka mocks.
mod support;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_util::future::BoxFuture;
use octopus::{
    config::{AppConfig, KafkaCfg},
    dispatch::DispatchStore,
    domain::{BrokerRecordMetadata, PostgresResult, SyncLoad},
    ingestion::IngestionStore,
    kafka::{consumer_settings, producer, CommitObserver, Poison},
    load::LoadStore,
    postgres::PostgresErrorClass,
    processor::ProcessorId,
    projections::{decode_wireless, ProjectionError, ProjectionStore, WirelessObservation},
    runtime::{
        consumer_workloads_observed, Backpressure, DispatchOutcome, OutboxPublisher, Planner,
        RuntimeError, WirelessProjectionHandler, HEARTBEAT_TOPIC,
    },
    supervision::Supervisor,
    util::sha256_hex,
};
use rdkafka::{
    admin::{AdminClient, AdminOptions, NewTopic, TopicReplication},
    client::DefaultClientContext,
    consumer::{BaseConsumer, Consumer},
    producer::FutureRecord,
    ClientConfig, Message, Offset, TopicPartitionList,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    process::Command,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;

const REDPANDA:&str="redpandadata/redpanda:v24.2.7@sha256:82a69763bef8d8b55ea5a520fa1b38f993908ef68946819ca1aed43541824c48";
#[derive(Default)]
struct Committed(AtomicU64);
impl CommitObserver for Committed {
    fn committed(&self, _: &str, _: &str, _: i32, _: i64, records: u64) {
        self.0.fetch_add(records, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_outbox_waits_for_broker_ack_and_retries_after_outage() {
    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let broker = Broker::start().await;
    let cfg = KafkaCfg {
        bootstrap_servers: broker.bootstrap.clone(),
        topic_replication_factor: 1,
        topic_partitions: 1,
        ..KafkaCfg::default()
    };
    broker
        .create_topics(&[cfg.load_topic.clone(), cfg.result_topic.clone()])
        .await;
    let dispatch = DispatchStore::new(fixture.runtime.clone());
    let publisher =
        OutboxPublisher::new(dispatch.clone(), &cfg, "runtime-publisher".into(), 5, 1, 10).unwrap();
    fixture.admin("INSERT INTO octopus_core.outbox_events(outbox_id,source_type,source_id,event_type,destination_topic,message_key,payload) VALUES(gen_random_uuid(),'test','result-1','result','sync.oracle.result','result-1','{\"value\":1}')");
    support::checked(Command::new("docker").args(["pause", &broker.name]));
    struct Resume(String);
    impl Drop for Resume {
        fn drop(&mut self) {
            let _ = Command::new("docker").args(["unpause", &self.0]).output();
        }
    }
    let resume = Resume(broker.name.clone());
    assert_eq!(
        publisher.dispatch_next().await.unwrap(),
        DispatchOutcome::StopDraining
    );
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let row=tx.query("SELECT status,published_at IS NULL,attempt_count FROM outbox_events WHERE source_id='result-1'",&[]).await.unwrap();
    // The publish deadline leaves an unacknowledged lease for backlog recovery.
    assert_eq!(row[0].get::<_, String>(0), "leased");
    assert!(row[0].get::<_, bool>(1));
    assert_eq!(row[0].get::<_, i32>(2), 1);
    tx.commit().await.unwrap();
    fixture.admin("UPDATE octopus_core.outbox_events SET lease_expires_at=clock_timestamp()-INTERVAL '1 second' WHERE source_id='result-1'");
    assert_eq!(dispatch.recover_expired().await.unwrap(), 1);
    drop(resume);
    assert_eq!(
        publisher.dispatch_next().await.unwrap(),
        DispatchOutcome::Dispatched
    );
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let row=tx.query("SELECT status,published_at IS NOT NULL,attempt_count FROM outbox_events WHERE source_id='result-1'",&[]).await.unwrap();
    assert_eq!(row[0].get::<_, String>(0), "published");
    assert!(row[0].get::<_, bool>(1));
    assert_eq!(row[0].get::<_, i32>(2), 2);
    tx.commit().await.unwrap();
    // Malformed load identity is parked before publication.
    fixture.admin("INSERT INTO octopus_core.outbox_events(outbox_id,source_type,source_id,event_type,destination_topic,message_key,payload) VALUES(gen_random_uuid(),'test','malformed-load','load','sync.oracle.load','malformed:1','{\"batch_id\":\"invalid\"}')");
    assert_eq!(
        publisher.dispatch_next().await.unwrap(),
        DispatchOutcome::ContinueDraining
    );
    let observer: BaseConsumer = consumer_settings(&cfg, "runtime-publisher-proof-v1")
        .unwrap()
        .create()
        .unwrap();
    let (_, high) = observer
        .fetch_watermarks(&cfg.load_topic, 0, Duration::from_secs(5))
        .unwrap();
    assert_eq!(high, 0);
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let row=tx.query("SELECT status,published_at IS NOT NULL FROM outbox_events WHERE source_id='malformed-load'",&[]).await.unwrap();
    assert_eq!(row[0].get::<_, String>(0), "failed");
    assert!(!row[0].get::<_, bool>(1));
    tx.commit().await.unwrap();
}
struct Broker {
    name: String,
    bootstrap: String,
}
impl Drop for Broker {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", "-v", &self.name])
            .output();
    }
}
impl Broker {
    fn try_start() -> Option<Self> {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let name = format!("native-redpanda-{}", uuid::Uuid::new_v4());
        let bootstrap = format!("127.0.0.1:{port}");
        let broker = Self { name, bootstrap };
        let output = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &broker.name,
                "-p",
                &format!("127.0.0.1:{port}:9092"),
                REDPANDA,
                "redpanda",
                "start",
                "--mode",
                "dev-container",
                "--smp",
                "1",
                "--memory",
                "512M",
                "--reserve-memory",
                "0M",
                "--overprovisioned",
                "--check=false",
                "--kafka-addr",
                "0.0.0.0:9092",
                "--advertise-kafka-addr",
                &broker.bootstrap,
            ])
            .output()
            .unwrap();
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("port is already allocated")
                || stderr.contains("address already in use")
            {
                return None;
            }
            panic!("Redpanda fixture startup failed: {stderr}");
        }
        Some(broker)
    }

    async fn start() -> Self {
        let broker = (0..5)
            .find_map(|_| Self::try_start())
            .expect("could not allocate Redpanda port");
        let consumer: BaseConsumer = ClientConfig::new()
            .set("bootstrap.servers", &broker.bootstrap)
            .set("group.id", "native-redpanda-preflight-v1")
            .create()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if consumer
                    .fetch_metadata(None, Duration::from_millis(250))
                    .is_ok_and(|m| !m.brokers().is_empty())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("Redpanda did not become ready");
        broker
    }
    async fn create_topics(&self, topics: &[String]) {
        let admin: AdminClient<DefaultClientContext> = ClientConfig::new()
            .set("bootstrap.servers", &self.bootstrap)
            .create()
            .unwrap();
        let declarations = topics
            .iter()
            .map(|name| NewTopic::new(name, 1, TopicReplication::Fixed(1)))
            .collect::<Vec<_>>();
        let results = admin
            .create_topics(
                &declarations,
                &AdminOptions::new().operation_timeout(Some(Duration::from_secs(10))),
            )
            .await
            .unwrap();
        for result in results {
            result.unwrap();
        }
    }
}
struct Wireless(ProjectionStore);
impl WirelessProjectionHandler for Wireless {
    fn decode(&self, raw: &str) -> Result<WirelessObservation, Poison> {
        decode_wireless(raw).map_err(|e| Poison::invalid(e.to_string()))
    }
    fn project<'a>(
        &'a self,
        observation: WirelessObservation,
        metadata: BrokerRecordMetadata,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            self.0
                .project_wireless_observation(observation, &metadata)
                .await
                .map(|_| ())
                .map_err(|error| match error {
                    ProjectionError::CoordinateConflict => {
                        RuntimeError::Invariant("wireless coordinate changed".into())
                    }
                    ProjectionError::Invalid(_) => RuntimeError::Permanent(error.to_string()),
                    ProjectionError::Database(ref e)
                        if PostgresErrorClass::classify(e) == PostgresErrorClass::Retryable =>
                    {
                        RuntimeError::Retryable("projection database unavailable".into())
                    }
                    _ => RuntimeError::Permanent(error.to_string()),
                })
        })
    }
}
fn offset(consumer: &BaseConsumer, topic: &str) -> Option<i64> {
    let mut request = TopicPartitionList::new();
    request.add_partition(topic, 0);
    consumer
        .committed_offsets(request, Duration::from_millis(200))
        .ok()?
        .find_partition(topic, 0)?
        .offset()
        .to_raw()
}
async fn await_offset(consumer: &BaseConsumer, topic: &str, expected: i64) {
    tokio::time::timeout(Duration::from_secs(60), async {
        while offset(consumer, topic) != Some(expected) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("offset for {topic} did not converge to {expected}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_consumers_use_real_redpanda_and_commit_only_after_postgres_or_dlq() {
    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let broker = Broker::start().await;
    let mut cfg = AppConfig::default();
    cfg.kafka = KafkaCfg {
        bootstrap_servers: broker.bootstrap.clone(),
        topic_replication_factor: 1,
        topic_partitions: 1,
        locked_batch_window_ms: 20,
        ..KafkaCfg::default()
    };
    cfg.wireless.projection.mode = "projected".into();
    cfg.runtime.consumers_enabled = true;
    cfg.ingest.load_stream_names = vec!["proxy.events".into()];
    let bindings = [
        (
            cfg.kafka.scan_consumer.clone(),
            cfg.kafka.scan_topic.clone(),
        ),
        (
            cfg.kafka.load_consumer.clone(),
            cfg.kafka.load_topic.clone(),
        ),
        (
            cfg.kafka.result_consumer.clone(),
            cfg.kafka.result_topic.clone(),
        ),
        (
            cfg.kafka.wireless_heartbeat_consumer.clone(),
            HEARTBEAT_TOPIC.into(),
        ),
        (
            cfg.kafka.wireless_audit_consumer.clone(),
            cfg.kafka.wireless_audit_topic.clone(),
        ),
    ];
    let topics = bindings
        .iter()
        .flat_map(|(_, topic)| [topic.clone(), format!("{topic}.dlq")])
        .collect::<Vec<_>>();
    broker.create_topics(&topics).await;
    let observers = bindings
        .iter()
        .map(|(group, topic)| {
            let observer: BaseConsumer = consumer_settings(&cfg.kafka, group)
                .unwrap()
                .create()
                .unwrap();
            (topic.clone(), observer)
        })
        .collect::<Vec<_>>();
    let ingest = IngestionStore::new(fixture.runtime.clone());
    let load = Arc::new(LoadStore::new(
        fixture.runtime.clone(),
        fixture.directory().into(),
        32,
        1024 * 1024,
    ));
    let wireless = Arc::new(Wireless(ProjectionStore::with_wireless(
        fixture.runtime.clone(),
        cfg.wireless.projection.clone(),
    )));
    let backpressure = Backpressure::new(fixture.runtime.clone(), 100, 4).unwrap();
    let committed = Arc::new(Committed::default());
    let workloads = consumer_workloads_observed(
        &cfg,
        ingest,
        load,
        wireless,
        backpressure,
        Some(committed.clone()),
    )
    .unwrap();
    assert_eq!(workloads.len(), 5);
    let supervisor = Supervisor::create(
        cfg.processors.clone(),
        BTreeSet::from(ProcessorId::KAFKA_CONSUMERS),
        fixture.runtime.clone(),
    )
    .await
    .unwrap();
    let stop = CancellationToken::new();
    let cancelled = stop.clone();
    let runner = supervisor.clone();
    let task = tokio::spawn(async move { runner.run(workloads, cancelled).await });
    let producer = producer(&cfg.kafka).unwrap();
    let observed = chrono::Utc::now().to_rfc3339();
    let scan=json!({"stream_name":"wireless.alert.rogue_ap","dedupe_key":"runtime-1","observed_at":observed,"payload_ref":"inline://json/eyJldmVudF90eXBlIjoidW5rbm93biJ9"}).to_string();
    let heartbeat =
        json!({"event_id":"heartbeat-1","sensor_id":"runtime-sensor","observed_at":observed})
            .to_string();
    let load = serde_json::to_string(&SyncLoad {
        job_id: "unowned-job".into(),
        batch_id: "unowned-batch".into(),
        batch_no: None,
        stream_name: "proxy.events".into(),
        payload_ref: "outbox://must-not-read".into(),
        cursor_start: "0".into(),
        cursor_end: "1".into(),
        attempt: 1,
    })
    .unwrap();
    let result = serde_json::to_string(&PostgresResult::success(
        "unowned-job".into(),
        "unowned-batch".into(),
        0,
        "hash".into(),
        observed.clone(),
    ))
    .unwrap();
    let wireless=json!({"sensor_id":"runtime-sensor","observed_at":observed,"schema_version":1,"source_mac":"02:11:22:33:44:55","bssid":"02:11:22:33:44:66","ssid":"runtime","signal_dbm":-52}).to_string();
    for (topic, body) in [
        (cfg.kafka.scan_topic.as_str(), &scan),
        (cfg.kafka.load_topic.as_str(), &load),
        (cfg.kafka.result_topic.as_str(), &result),
        (HEARTBEAT_TOPIC, &heartbeat),
        (cfg.kafka.wireless_audit_topic.as_str(), &wireless),
    ] {
        producer
            .send(
                FutureRecord::to(topic).key("runtime").payload(body),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
    }
    for (topic, observer) in &observers {
        await_offset(observer, topic, 1).await;
    }
    let dlq: BaseConsumer = consumer_settings(&cfg.kafka, "runtime-test-dlq-observer-v1")
        .unwrap()
        .create()
        .unwrap();
    for (source, original) in [
        (&cfg.kafka.load_topic, &load),
        (&cfg.kafka.result_topic, &result),
    ] {
        let topic = format!("{source}{}", cfg.kafka.dlq_suffix);
        let mut assignment = TopicPartitionList::new();
        assignment
            .add_partition_offset(&topic, 0, Offset::Beginning)
            .unwrap();
        dlq.assign(&assignment).unwrap();
        let record = dlq
            .poll(Duration::from_secs(10))
            .expect("missing DLQ delivery")
            .unwrap();
        let envelope: Value = serde_json::from_slice(record.payload().unwrap()).unwrap();
        assert_eq!(envelope["topic"], source.as_str());
        assert_eq!(envelope["partition"], 0);
        assert_eq!(envelope["offset"], 0);
        assert_eq!(envelope["original"], original.as_str());
    }
    assert!(supervisor.ready());
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let counts=tx.query("SELECT (SELECT count(*) FROM sync_events WHERE stream_name='wireless.alert.rogue_ap' AND status='completed'),(SELECT count(*) FROM sensors WHERE sensor_id='runtime-sensor'),(SELECT count(*) FROM wireless_projection_group_receipts WHERE group_id=$1),(SELECT count(*) FROM sync_batches WHERE stream_name='wireless.alert.rogue_ap')",&[&cfg.kafka.wireless_audit_consumer]).await.unwrap();
    assert_eq!(counts[0].get::<_, i64>(0), 1);
    assert_eq!(counts[0].get::<_, i64>(1), 1);
    assert_eq!(counts[0].get::<_, i64>(2), 1);
    assert_eq!(counts[0].get::<_, i64>(3), 0);
    let heartbeat_record = tx.query(
        "SELECT
            EXISTS(SELECT 1 FROM sync_events WHERE stream_name=$1 AND dedupe_key='heartbeat-1' AND status='completed'),
            EXISTS(SELECT 1 FROM sync_batches WHERE stream_name=$1),
            EXISTS(SELECT 1 FROM ingestion_evidence WHERE topic=$1 AND group_id=$2
                   AND partition_id=0 AND record_offset=0 AND dedupe_key='heartbeat-1' AND payload_sha256=$3),
            (SELECT next_offset FROM consumer_offsets WHERE topic=$1 AND group_id=$2 AND partition_id=0)",
        &[&HEARTBEAT_TOPIC, &cfg.kafka.wireless_heartbeat_consumer, &sha256_hex(&heartbeat)],
    ).await.unwrap();
    assert!(heartbeat_record[0].get::<_, bool>(0));
    assert!(!heartbeat_record[0].get::<_, bool>(1));
    assert!(heartbeat_record[0].get::<_, bool>(2));
    assert_eq!(heartbeat_record[0].get::<_, i64>(3), 1);
    tx.commit().await.unwrap();

    // Hold the ingestion table so we can observe intake before releasing it.
    let mut blocker = fixture.runtime.begin_worker().await.unwrap();
    blocker
        .execute("LOCK TABLE sync_events IN ACCESS EXCLUSIVE MODE", &[])
        .await
        .unwrap();
    let next = scan.replace("runtime-1", "runtime-2");
    producer
        .send(
            FutureRecord::to(&cfg.kafka.scan_topic)
                .key("runtime")
                .payload(&next),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut observer = fixture.runtime.begin_worker().await.unwrap();
            let waiting: bool = observer.query(
                "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation='octopus_core.sync_events'::regclass AND NOT granted)",
                &[],
            ).await.unwrap()[0].get(0);
            observer.commit().await.unwrap();
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }).await.expect("scan did not start processing");
    assert_eq!(offset(&observers[0].1, &cfg.kafka.scan_topic), Some(1));
    assert_eq!(committed.0.load(Ordering::SeqCst), 5);
    blocker.rollback().await.unwrap();
    await_offset(&observers[0].1, &cfg.kafka.scan_topic, 2).await;
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let persisted: bool = tx.query(
        "SELECT EXISTS(SELECT 1 FROM sync_events WHERE stream_name='wireless.alert.rogue_ap' AND dedupe_key='runtime-2' AND status='completed')",
        &[],
    ).await.unwrap()[0].get(0);
    tx.commit().await.unwrap();
    assert!(persisted);
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert_eq!(committed.0.load(Ordering::SeqCst), 6);
    assert!(
        !supervisor.ready(),
        "terminated consumers cannot remain ready"
    );
    // Restart the same five groups and prove only the newly appended heartbeat
    // is handled; prior broker coordinates remain one durable receipt each.
    let backpressure = Backpressure::new(fixture.runtime.clone(), 100, 4).unwrap();
    let workloads = consumer_workloads_observed(
        &cfg,
        IngestionStore::new(fixture.runtime.clone()),
        Arc::new(LoadStore::new(
            fixture.runtime.clone(),
            fixture.directory().into(),
            32,
            1024 * 1024,
        )),
        Arc::new(Wireless(ProjectionStore::with_wireless(
            fixture.runtime.clone(),
            cfg.wireless.projection.clone(),
        ))),
        backpressure,
        Some(committed.clone()),
    )
    .unwrap();
    let stop = CancellationToken::new();
    let cancelled = stop.clone();
    let runner = supervisor.clone();
    let task = tokio::spawn(async move { runner.run(workloads, cancelled).await });
    let next = heartbeat.replace("heartbeat-1", "heartbeat-2");
    producer
        .send(
            FutureRecord::to(HEARTBEAT_TOPIC)
                .key("runtime")
                .payload(&next),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    await_offset(&observers[3].1, HEARTBEAT_TOPIC, 2).await;
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let count: i64 = tx
        .query(
            "SELECT count(*) FROM ingestion_evidence WHERE group_id=$1",
            &[&cfg.kafka.wireless_heartbeat_consumer],
        )
        .await
        .unwrap()[0]
        .get(0);
    assert_eq!(count, 2);
    tx.commit().await.unwrap();
    drain_retained_batches(&fixture, &cfg, &observers[1].1, &observers[2].1).await;
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(committed.0.load(Ordering::SeqCst), 9);
}

async fn drain_retained_batches(
    fixture: &support::Fixture,
    config: &AppConfig,
    load_observer: &BaseConsumer,
    result_observer: &BaseConsumer,
) {
    let mut prior = config.clone();
    prior
        .ingest
        .load_stream_names
        .push(" wireless.audit ".into());
    let dispatch = DispatchStore::new(fixture.runtime.clone());
    dispatch
        .ensure_cursors(&prior.ingest.load_stream_names)
        .await
        .unwrap();
    let payload = json!({
        "event_type": "frame",
        "observed_at": chrono::Utc::now().to_rfc3339(),
        "sensor_id": "retained-sensor",
        "location_id": "lab",
        "interface": "wlan0",
        "channel": 6,
        "frame_subtype": "beacon",
        "raw_len": 128
    });
    let reference = format!(
        "inline://json/{}",
        URL_SAFE_NO_PAD.encode(payload.to_string())
    );
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let cursors = tx
        .query(
            "SELECT stream_name FROM sync_cursors WHERE btrim(stream_name)='wireless.audit'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(cursors.len(), 1);
    assert_eq!(cursors[0].get::<_, String>(0), "wireless.audit");
    tx.execute(
        "INSERT INTO sync_events(dedupe_key,stream_name,payload_ref,observed_at,status)
         VALUES('retained','wireless.audit',$1,CURRENT_TIMESTAMP,'pending')",
        &[&reference],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let prior_planner = Planner::new(fixture.runtime.clone(), &prior);
    assert_eq!(prior_planner.process_ingest().await.unwrap(), 1);

    // The narrower policy stops planning new excluded work but drains batches
    // the previous policy already admitted.
    fixture.admin("INSERT INTO octopus_core.sync_events(dedupe_key,stream_name,payload_ref,observed_at,status) VALUES('new-excluded','wireless.audit','inline://json/e30',CURRENT_TIMESTAMP,'pending')");
    let current_planner = Planner::new(fixture.runtime.clone(), config);
    assert_eq!(current_planner.process_ingest().await.unwrap(), 0);
    assert_eq!(
        current_planner.reconcile_excluded_pending().await.unwrap(),
        1
    );
    assert_eq!(dispatch.enqueue_pending(10, 5).await.unwrap(), 1);
    assert_eq!(dispatch.enqueue_pending(10, 5).await.unwrap(), 0);
    let publisher = OutboxPublisher::new(
        dispatch,
        &config.kafka,
        "retained-publisher".into(),
        30,
        1,
        10,
    )
    .unwrap();
    assert_eq!(
        publisher.dispatch_next().await.unwrap(),
        DispatchOutcome::Dispatched
    );
    await_offset(load_observer, &config.kafka.load_topic, 2).await;
    assert_eq!(
        publisher.dispatch_next().await.unwrap(),
        DispatchOutcome::Dispatched
    );
    await_offset(result_observer, &config.kafka.result_topic, 2).await;

    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let rows = tx.query(
        "SELECT batch.status, batch.row_count, event.status FROM sync_batches batch
         JOIN sync_events event ON event.stream_name=batch.stream_name AND event.dedupe_key=batch.dedupe_key
         WHERE batch.stream_name='wireless.audit' AND batch.dedupe_key='retained'",
        &[],
    ).await.unwrap();
    assert_eq!(rows[0].get::<_, String>(0), "completed");
    assert_eq!(rows[0].get::<_, i32>(1), 1);
    assert_eq!(rows[0].get::<_, String>(2), "completed");
    let excluded = tx
        .query(
            "SELECT status, EXISTS(SELECT 1 FROM sync_batches WHERE dedupe_key='new-excluded')
         FROM sync_events WHERE stream_name='wireless.audit' AND dedupe_key='new-excluded'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(excluded[0].get::<_, String>(0), "completed");
    assert!(!excluded[0].get::<_, bool>(1));
    tx.commit().await.unwrap();
}
