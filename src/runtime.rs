//! Concrete locked consumer adapters. Only the broker boundary commits offsets.

use crate::{
    config::{AppConfig, KafkaCfg},
    dispatch::DispatchStore,
    domain::{
        BrokerRecordMetadata, PostgresResult, ResolvedScanRequestRecord, ScanRequestRecord,
        SyncLoad,
    },
    ingestion::{IngestionStore, IntakeError},
    kafka::{
        self, BatchHandler, BoundaryError, BrokerRecord, LockedConsumer, LockedRecord, Poison,
    },
    load::{LoadError, LoadStore},
    postgres::PgRuntime,
    processor::ProcessorId,
    supervision::{Workload, WorkloadError},
    util::{java_is_blank, sha256_hex, utf16_length},
};
use futures_util::future::BoxFuture;
use rdkafka::{
    consumer::{BaseConsumer, Consumer},
    message::{Header, OwnedHeaders},
    producer::{FutureProducer, FutureRecord},
};
use serde_json::Value;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub const HEARTBEAT_TOPIC: &str = "wireless.sensor.heartbeat";
pub mod planning;
pub use planning::Planner;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("permanent record failure: {0}")]
    Permanent(String),
    #[error("retryable runtime failure: {0}")]
    Retryable(String),
    #[error("durable invariant conflict: {0}")]
    Invariant(String),
}
impl RuntimeError {
    fn boundary(&self) -> BoundaryError {
        match self {
            Self::Permanent(_) => BoundaryError::Invariant("permanent failure was not parked"),
            Self::Retryable(_) => BoundaryError::Retryable("runtime dependency failed"),
            Self::Invariant(_) => BoundaryError::Invariant("durable evidence conflict"),
        }
    }
}

/// Direct wireless projection keeps its own receipt/hash transaction. The
/// assembly supplies the production projection implementation, never raw intake.
pub trait WirelessProjectionHandler: Send + Sync + 'static {
    fn decode(&self, raw: &str) -> Result<Value, Poison>;
    fn project<'a>(
        &'a self,
        value: Value,
        metadata: BrokerRecordMetadata,
    ) -> BoxFuture<'a, Result<(), RuntimeError>>;
}

#[derive(Clone)]
pub struct Backpressure {
    runtime: Arc<PgRuntime>,
    budget: i64,
    suspended: watch::Sender<bool>,
}
impl Backpressure {
    pub fn new(
        runtime: Arc<PgRuntime>,
        ingest_batch_size: i32,
        multiplier: i32,
    ) -> Result<Self, RuntimeError> {
        if ingest_batch_size <= 0 || multiplier <= 0 {
            return Err(RuntimeError::Permanent(
                "backpressure budget must be positive".into(),
            ));
        }
        let (suspended, _) = watch::channel(false);
        Ok(Self {
            runtime,
            budget: i64::from(ingest_batch_size) * i64::from(multiplier),
            suspended,
        })
    }
    pub fn budget(&self) -> i64 {
        self.budget
    }
    pub fn suspended(&self) -> bool {
        *self.suspended.borrow()
    }
    pub async fn await_permit(&self) -> Result<(), BoundaryError> {
        let mut changed = self.suspended.subscribe();
        loop {
            if !*changed.borrow_and_update() {
                return Ok(());
            }
            changed.changed().await.map_err(|_| BoundaryError::Task)?;
        }
    }
    /// Failed count reads preserve the previous admission state. Result/load
    /// consumers never wait here, so they can drain the backlog while suspended.
    pub async fn check_and_act(&self) -> Result<i64, crate::postgres::PgError> {
        let mut tx = self.runtime.begin_worker().await?;
        let count: i64 = tx
            .query(
                "SELECT COUNT(*) FROM sync_events e WHERE e.status IN ('pending','processing') OR (e.status='batched' AND EXISTS (SELECT 1 FROM sync_batches b WHERE b.stream_name=e.stream_name AND b.dedupe_key=e.dedupe_key AND b.status IN ('pending','dispatched','running')))",
                &[],
            )
            .await?[0]
            .get(0);
        tx.commit().await?;
        let previous = self.suspended();
        self.suspended.send_replace(if count >= self.budget {
            true
        } else if count <= self.budget / 2 {
            false
        } else {
            previous
        });
        Ok(count)
    }
    pub async fn run(&self, interval: Duration, stop: CancellationToken) {
        loop {
            tokio::select! {biased;_=stop.cancelled()=>return,_=self.check_and_act()=>{}}
            tokio::select! {_=stop.cancelled()=>return,_=tokio::time::sleep(interval)=>{}}
        }
    }
}

#[derive(Clone)]
struct Parking {
    producer: FutureProducer,
    group: String,
    topic: String,
}
impl Parking {
    fn new(cfg: &KafkaCfg, group: &str, topic: &str) -> Result<Self, BoundaryError> {
        Ok(Self {
            producer: kafka::producer(cfg)?,
            group: group.into(),
            topic: format!("{}{}", topic, cfg.dlq_suffix),
        })
    }
    async fn park(&self, record: &BrokerRecord, message: &str) -> Result<(), BoundaryError> {
        let body = kafka::poison_body(&self.group, record, message, "IllegalArgumentException");
        let key = record
            .key
            .clone()
            .unwrap_or_else(|| format!("{}:{}", record.partition, record.offset));
        self.producer
            .send(
                FutureRecord::to(&self.topic).key(&key).payload(&body),
                Duration::from_secs(30),
            )
            .await
            .map_err(|(e, _)| BoundaryError::Broker(e))?;
        Ok(())
    }
    async fn intake(
        &self,
        result: Result<(), IntakeError>,
        record: &BrokerRecord,
    ) -> Result<(), BoundaryError> {
        match result {
            Ok(()) => Ok(()),
            Err(IntakeError::Invariant(_)) => {
                Err(BoundaryError::Invariant("ingestion evidence conflict"))
            }
            Err(error) if error.is_retryable() => {
                Err(BoundaryError::Retryable("ingestion storage unavailable"))
            }
            Err(error) => self.park(record, &error.to_string()).await,
        }
    }
    async fn load(
        &self,
        result: Result<(), LoadError>,
        record: &BrokerRecord,
    ) -> Result<(), BoundaryError> {
        match result {
            Ok(()) => Ok(()),
            Err(error) if error.is_invariant() => {
                Err(BoundaryError::Invariant("load/result evidence conflict"))
            }
            Err(error) if error.is_retryable() => {
                Err(BoundaryError::Retryable("load/result storage unavailable"))
            }
            Err(error) => self.park(record, &error.to_string()).await,
        }
    }
}

#[derive(Clone)]
struct ScanHandler {
    store: IngestionStore,
    outbox: PathBuf,
    projection_only: bool,
    parking: Parking,
    backpressure: Backpressure,
}
impl BatchHandler<ScanRequestRecord> for ScanHandler {
    fn process(
        &self,
        records: Vec<LockedRecord<ScanRequestRecord>>,
    ) -> BoxFuture<'_, Result<(), BoundaryError>> {
        Box::pin(async move {
            if records.is_empty() {
                return Ok(());
            }
            self.backpressure.await_permit().await?;
            for locked in records {
                if !should_ingest(locked.decoded.stream_name(), self.projection_only) {
                    continue;
                }
                let source = locked.decoded;
                let outbox = self.outbox.clone();
                let resolved = tokio::task::spawn_blocking(move || {
                    let payload =
                        crate::load::resolve_local_payload(source.payload_ref(), &outbox)?;
                    ResolvedScanRequestRecord::from(source, payload)
                        .map_err(|_| LoadError::Invalid("resolved payload is invalid"))
                })
                .await
                .map_err(|_| BoundaryError::Task)?;
                match resolved {
                    Ok(record) => {
                        self.parking
                            .intake(
                                self.store
                                    .record_scan_request_with_evidence(&record, &locked.metadata)
                                    .await
                                    .map(|_| ()),
                                &locked.record,
                            )
                            .await?
                    }
                    Err(error) => self.parking.load(Err(error), &locked.record).await?,
                }
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
struct HeartbeatHandler {
    store: IngestionStore,
    parking: Parking,
}
impl BatchHandler<ResolvedScanRequestRecord> for HeartbeatHandler {
    fn process(
        &self,
        records: Vec<LockedRecord<ResolvedScanRequestRecord>>,
    ) -> BoxFuture<'_, Result<(), BoundaryError>> {
        Box::pin(async move {
            for locked in records {
                self.parking
                    .intake(
                        self.store
                            .record_scan_request_with_evidence(&locked.decoded, &locked.metadata)
                            .await
                            .map(|_| ()),
                        &locked.record,
                    )
                    .await?;
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
struct LoadHandler {
    store: Arc<LoadStore>,
    parking: Parking,
}
impl BatchHandler<SyncLoad> for LoadHandler {
    fn process(
        &self,
        records: Vec<LockedRecord<SyncLoad>>,
    ) -> BoxFuture<'_, Result<(), BoundaryError>> {
        Box::pin(async move {
            for locked in records {
                match self.store.handle(&locked.decoded).await {
                    Ok(result) => {
                        self.parking
                            .load(
                                self.store
                                    .record_load_result_with_evidence(
                                        &locked.decoded,
                                        &result,
                                        &locked.metadata,
                                    )
                                    .await,
                                &locked.record,
                            )
                            .await?
                    }
                    Err(error) => self.parking.load(Err(error), &locked.record).await?,
                }
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
struct ResultHandler {
    store: Arc<LoadStore>,
    parking: Parking,
}
impl BatchHandler<PostgresResult> for ResultHandler {
    fn process(
        &self,
        records: Vec<LockedRecord<PostgresResult>>,
    ) -> BoxFuture<'_, Result<(), BoundaryError>> {
        Box::pin(async move {
            for locked in records {
                self.parking
                    .load(
                        self.store
                            .record_result_with_evidence(&locked.decoded, &locked.metadata)
                            .await,
                        &locked.record,
                    )
                    .await?;
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
struct WirelessHandler {
    handler: Arc<dyn WirelessProjectionHandler>,
    parking: Parking,
    backpressure: Backpressure,
}
impl BatchHandler<Value> for WirelessHandler {
    fn process(
        &self,
        records: Vec<LockedRecord<Value>>,
    ) -> BoxFuture<'_, Result<(), BoundaryError>> {
        Box::pin(async move {
            if records.is_empty() {
                return Ok(());
            }
            self.backpressure.await_permit().await?;
            for locked in records {
                match self.handler.project(locked.decoded, locked.metadata).await {
                    Ok(()) => {}
                    Err(RuntimeError::Permanent(message)) => {
                        self.parking.park(&locked.record, &message).await?
                    }
                    Err(error) => return Err(error.boundary()),
                }
            }
            Ok(())
        })
    }
}

pub fn should_ingest(stream: &str, projection_only: bool) -> bool {
    !(projection_only && stream == "wireless.audit")
}

pub fn decode_heartbeat(raw: &str) -> Result<ResolvedScanRequestRecord, Poison> {
    let mut value: Value =
        serde_json::from_str(raw).map_err(|_| Poison::invalid("invalid heartbeat JSON"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| Poison::invalid("heartbeat payload must be a JSON object"))?;
    let observed = object
        .get("observed_at")
        .and_then(Value::as_str)
        .ok_or_else(|| Poison::invalid("heartbeat observed_at must be a string"))?
        .to_string();
    let sensor = object
        .get("sensor_id")
        .and_then(Value::as_str)
        .ok_or_else(|| Poison::invalid("heartbeat sensor_id must be a string"))?
        .to_string();
    if java_is_blank(&sensor) || utf16_length(&sensor) > 64 {
        return Err(Poison::invalid(
            "heartbeat sensor_id must contain 1 to 64 characters",
        ));
    }
    let produced = match object.get("produced_at") {
        None | Some(Value::Null) => observed.clone(),
        Some(Value::String(s)) => s.clone(),
        _ => return Err(Poison::invalid("heartbeat produced_at must be a string")),
    };
    let version = match object.get("schema_version") {
        None | Some(Value::Null) => 1,
        Some(v) => crate::dq::int(&serde_json::json!({"version":v}), "version")
            .map_err(|_| Poison::invalid("heartbeat schema_version must be an integer"))?,
    };
    if version <= 0 {
        return Err(Poison::invalid("heartbeat schema_version must be positive"));
    }
    let hash = sha256_hex(raw);
    let event = match object.get("event_id") {
        None | Some(Value::Null) => hash,
        Some(Value::String(s)) => s.clone(),
        _ => return Err(Poison::invalid("heartbeat event_id must be a string")),
    };
    if java_is_blank(&event) || utf16_length(&event) > 255 {
        return Err(Poison::invalid(
            "heartbeat event_id must contain 1 to 255 characters",
        ));
    }
    let source = ScanRequestRecord::from_parts(
        raw.into(),
        HEARTBEAT_TOPIC.into(),
        event.clone(),
        observed,
        format!("inline://heartbeat/{event}"),
    )
    .map_err(Poison::invalid)?;
    // Use the same accepted date grammar as scan requests for produced_at too.
    ScanRequestRecord::from_parts(
        raw.into(),
        HEARTBEAT_TOPIC.into(),
        event.clone(),
        produced.clone(),
        format!("inline://heartbeat/{event}"),
    )
    .map_err(Poison::invalid)?;
    object.insert("event_id".into(), Value::String(event.clone()));
    object.insert("schema_version".into(), Value::from(version));
    object.insert("produced_at".into(), Value::String(produced));
    object
        .entry("source_identity")
        .or_insert(Value::String(sensor));
    object
        .entry("correlation_id")
        .or_insert(Value::String(event.clone()));
    object.entry("causation_id").or_insert(Value::String(event));
    ResolvedScanRequestRecord::from(source, value.to_string()).map_err(Poison::invalid)
}

/// Broker preflight is a startup action, so readiness cannot turn green before
/// every selected consumer topic and DLQ has available partitions.
async fn topic_preflight(cfg: KafkaCfg, group: String, topic: String) -> Result<(), WorkloadError> {
    tokio::task::spawn_blocking(move || {
        let consumer: BaseConsumer = kafka::consumer_settings(&cfg, &group)
            .map_err(boundary_workload)?
            .create()
            .map_err(|e| WorkloadError::Retryable(crate::errors::sanitize(&e.to_string())))?;
        for name in [&topic, &format!("{}{}", topic, cfg.dlq_suffix)] {
            let metadata = consumer
                .fetch_metadata(Some(name), Duration::from_secs(30))
                .map_err(|e| WorkloadError::Retryable(crate::errors::sanitize(&e.to_string())))?;
            if !metadata
                .topics()
                .iter()
                .any(|t| t.name() == name && t.error().is_none() && !t.partitions().is_empty())
            {
                return Err(WorkloadError::Retryable(
                    "required consumer topic is unavailable".into(),
                ));
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| WorkloadError::Retryable("broker preflight task failed".into()))?
}
fn boundary_workload(error: BoundaryError) -> WorkloadError {
    match error {
        BoundaryError::Configuration(message) => WorkloadError::Terminal(message),
        other => WorkloadError::Retryable(crate::errors::sanitize(&other.to_string())),
    }
}
struct LaneObserver {
    assigned: std::sync::atomic::AtomicBool,
    delegate: Option<Arc<dyn kafka::CommitObserver>>,
}
impl kafka::CommitObserver for LaneObserver {
    fn committed(&self, group: &str, topic: &str, partition: i32, next_offset: i64, records: u64) {
        if let Some(delegate) = &self.delegate {
            delegate.committed(group, topic, partition, next_offset, records);
        }
    }
    fn assignment(&self, group: &str, topic: &str, assigned: bool) {
        self.assigned
            .store(assigned, std::sync::atomic::Ordering::Release);
        if let Some(delegate) = &self.delegate {
            delegate.assignment(group, topic, assigned);
        }
    }
}
#[allow(clippy::too_many_arguments)]
fn consumer_workload<
    A: Send + 'static,
    H: BatchHandler<A> + Clone,
    D: Fn(&str) -> Result<A, Poison> + Send + Sync + Clone + 'static,
>(
    id: ProcessorId,
    cfg: KafkaCfg,
    group: String,
    topic: String,
    concurrency: usize,
    decode: D,
    handler: H,
    observer: Option<Arc<dyn kafka::CommitObserver>>,
) -> Workload {
    let startup_cfg = cfg.clone();
    let startup_group = group.clone();
    let startup_topic = topic.clone();
    let observer = Arc::new(LaneObserver {
        assigned: std::sync::atomic::AtomicBool::new(false),
        delegate: observer,
    });
    let readiness = observer.clone();
    Workload::new(id, move |stop| {
        let cfg = cfg.clone();
        let group = group.clone();
        let topic = topic.clone();
        let handler = handler.clone();
        let decode = decode.clone();
        let observer = observer.clone();
        Box::pin(async move {
            let consumer = LockedConsumer::new(cfg, group, topic).map_err(boundary_workload)?;
            let consumer = consumer.with_commit_observer(observer);
            consumer
                .run(concurrency, decode, handler, stop)
                .await
                .map_err(boundary_workload)
        })
    })
    .with_startup(move || {
        let cfg = startup_cfg.clone();
        let group = startup_group.clone();
        let topic = startup_topic.clone();
        Box::pin(topic_preflight(cfg, group, topic))
    })
    .with_readiness(move || {
        readiness
            .assigned
            .load(std::sync::atomic::Ordering::Acquire)
    })
}

pub fn consumer_workloads(
    cfg: &AppConfig,
    ingestion: IngestionStore,
    load: Arc<LoadStore>,
    wireless: Arc<dyn WirelessProjectionHandler>,
    backpressure: Backpressure,
) -> Result<Vec<Workload>, BoundaryError> {
    consumer_workloads_observed(cfg, ingestion, load, wireless, backpressure, None)
}

pub fn consumer_workloads_observed(
    cfg: &AppConfig,
    ingestion: IngestionStore,
    load: Arc<LoadStore>,
    wireless: Arc<dyn WirelessProjectionHandler>,
    backpressure: Backpressure,
    observer: Option<Arc<dyn kafka::CommitObserver>>,
) -> Result<Vec<Workload>, BoundaryError> {
    let kafka = &cfg.kafka;
    let mut workloads = Vec::new();
    let scan = ScanHandler {
        store: ingestion
            .clone()
            .with_load_streams(&cfg.ingest.load_stream_names),
        outbox: cfg.sync.outbox_dir.clone().into(),
        projection_only: cfg.wireless.projection.mode == "projected",
        parking: Parking::new(kafka, &kafka.scan_consumer, &kafka.scan_topic)?,
        backpressure: backpressure.clone(),
    };
    workloads.push(consumer_workload(
        ProcessorId::SyncScanIngestion,
        kafka.clone(),
        kafka.scan_consumer.clone(),
        kafka.scan_topic.clone(),
        kafka.scan_consumers_count as usize,
        |raw: &str| ScanRequestRecord::decode_wire(raw).map_err(Poison::invalid),
        scan,
        observer.clone(),
    ));
    workloads.push(consumer_workload(
        ProcessorId::SyncLoadConsumer,
        kafka.clone(),
        kafka.load_consumer.clone(),
        kafka.load_topic.clone(),
        kafka.load_consumers_count as usize,
        |raw: &str| {
            serde_json::from_str::<SyncLoad>(raw)
                .map_err(|_| Poison::invalid("invalid sync load record"))
        },
        LoadHandler {
            store: load.clone(),
            parking: Parking::new(kafka, &kafka.load_consumer, &kafka.load_topic)?,
        },
        observer.clone(),
    ));
    workloads.push(consumer_workload(
        ProcessorId::SyncResultConsumer,
        kafka.clone(),
        kafka.result_consumer.clone(),
        kafka.result_topic.clone(),
        kafka.result_consumers_count as usize,
        |raw: &str| {
            serde_json::from_str::<PostgresResult>(raw)
                .map_err(|_| Poison::invalid("invalid sync result record"))
        },
        ResultHandler {
            store: load,
            parking: Parking::new(kafka, &kafka.result_consumer, &kafka.result_topic)?,
        },
        observer.clone(),
    ));
    workloads.push(consumer_workload(
        ProcessorId::WirelessHeartbeatIngestion,
        kafka.clone(),
        kafka.wireless_heartbeat_consumer.clone(),
        HEARTBEAT_TOPIC.into(),
        1,
        decode_heartbeat,
        HeartbeatHandler {
            store: ingestion,
            parking: Parking::new(kafka, &kafka.wireless_heartbeat_consumer, HEARTBEAT_TOPIC)?,
        },
        observer.clone(),
    ));
    // In legacy mode the baseline's wireless workload waits indefinitely and
    // never subscribes: companion scan requests own the legacy intake path.
    if cfg.wireless.projection.enabled() {
        let decoder = wireless.clone();
        workloads.push(consumer_workload(
            ProcessorId::WirelessAuditProjection,
            kafka.clone(),
            kafka.wireless_audit_consumer.clone(),
            kafka.wireless_audit_topic.clone(),
            kafka.wireless_audit_consumers_count as usize,
            move |raw: &str| decoder.decode(raw),
            WirelessHandler {
                handler: wireless,
                parking: Parking::new(
                    kafka,
                    &kafka.wireless_audit_consumer,
                    &kafka.wireless_audit_topic,
                )?,
                backpressure,
            },
            observer,
        ));
    } else {
        workloads.push(Workload::new(
            ProcessorId::WirelessAuditProjection,
            |stop| {
                Box::pin(async move {
                    stop.cancelled().await;
                    Ok(())
                })
            },
        ));
    }
    Ok(workloads)
}

pub async fn schema_refresher(
    runtime: Arc<PgRuntime>,
    manifest: String,
    interval: Duration,
    retry: Duration,
    stop: CancellationToken,
) -> Result<(), WorkloadError> {
    loop {
        tokio::select! {_=stop.cancelled()=>return Ok(()),_=tokio::time::sleep(interval)=>{}}
        loop {
            let result = tokio::select! {_=stop.cancelled()=>return Ok(()),result=runtime.validate_schema(&manifest)=>result};
            match result {
                Ok(()) => break,
                Err(error)
                    if matches!(
                        error,
                        crate::postgres::PgError::Acquisition | crate::postgres::PgError::Deadline
                    ) || crate::postgres::PostgresErrorClass::classify(&error)
                        == crate::postgres::PostgresErrorClass::Retryable =>
                {
                    tokio::select! {_=stop.cancelled()=>return Ok(()),_=tokio::time::sleep(retry)=>{}}
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchOutcome {
    NoWork,
    Dispatched,
    ContinueDraining,
    StopDraining,
}

/// Stable outbox keys allow an acknowledgement gap to replay safely. The
/// database acknowledgement remains fenced and follows the broker receipt.
#[derive(Clone)]
pub struct OutboxPublisher {
    store: DispatchStore,
    producer: FutureProducer,
    owner: String,
    topics: Vec<String>,
    lease_seconds: i32,
    retry_base_seconds: i32,
    retry_max_seconds: i32,
}
impl OutboxPublisher {
    pub fn new(
        store: DispatchStore,
        cfg: &KafkaCfg,
        owner: String,
        lease_seconds: i32,
        retry_base_seconds: i32,
        retry_max_seconds: i32,
    ) -> Result<Self, BoundaryError> {
        if owner.trim().is_empty()
            || lease_seconds <= 0
            || retry_base_seconds <= 0
            || retry_max_seconds < retry_base_seconds
        {
            return Err(BoundaryError::Configuration(
                "invalid outbox owner, lease or retry bounds".into(),
            ));
        }
        Ok(Self {
            store,
            producer: kafka::producer(cfg)?,
            owner,
            topics: vec![cfg.load_topic.clone(), cfg.result_topic.clone()],
            lease_seconds,
            retry_base_seconds,
            retry_max_seconds,
        })
    }
    #[tracing::instrument(name="kafka.publish.outbox",skip_all,fields(messaging.system="kafka"))]
    pub async fn dispatch_next(&self) -> Result<DispatchOutcome, WorkloadError> {
        let Some(record) = self
            .store
            .claim_outbox(&self.owner, &self.topics, self.lease_seconds)
            .await
            .map_err(load_workload)?
        else {
            return Ok(DispatchOutcome::NoWork);
        };
        let batch = match record.load_batch_id() {
            Ok(batch) => batch,
            Err(error) => {
                self.store
                    .park_malformed(&record, &error.to_string())
                    .await
                    .map_err(load_workload)?;
                return Ok(DispatchOutcome::ContinueDraining);
            }
        };
        let mut fields = std::collections::HashMap::new();
        opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.inject_context(&tracing::Span::current().context(), &mut fields)
        });
        let headers = fields
            .iter()
            .fold(OwnedHeaders::new(), |headers, (key, value)| {
                headers.insert(Header {
                    key,
                    value: Some(value.as_str()),
                })
            });
        let timeout =
            Duration::from_millis((u64::try_from(self.lease_seconds).unwrap_or(1) * 900).max(1));
        let publish = self.producer.send(
            FutureRecord::to(&record.destination_topic)
                .key(&record.message_key)
                .payload(&record.payload)
                .headers(headers),
            timeout,
        );
        match tokio::time::timeout(timeout, publish).await {
            Ok(Ok(_)) => {
                // False means a newer fence owns the row or the batch already
                // progressed; publication remains at-least-once either way.
                if self
                    .store
                    .acknowledge(&record, batch.as_deref())
                    .await
                    .map_err(load_workload)?
                {
                    Ok(DispatchOutcome::Dispatched)
                } else {
                    Ok(DispatchOutcome::ContinueDraining)
                }
            }
            Ok(Err((error, _))) => {
                let message = crate::errors::sanitize(&error.to_string());
                let exponent = (record.attempt_count.max(1) - 1).min(30) as u32;
                let delay = i64::from(self.retry_base_seconds)
                    .saturating_mul(1_i64 << exponent)
                    .min(i64::from(self.retry_max_seconds));
                self.store
                    .fail(&record, &message, delay)
                    .await
                    .map_err(load_workload)?;
                Ok(DispatchOutcome::StopDraining)
            }
            Err(_) => Ok(DispatchOutcome::StopDraining),
        }
    }
    pub fn workload(&self, interval: Duration, drain_limit: usize) -> Workload {
        let publisher = self.clone();
        crate::supervision::periodic_workload(
            ProcessorId::SyncOutboxPublisher,
            interval,
            move || {
                let publisher = publisher.clone();
                Box::pin(async move {
                    for _ in 0..drain_limit.max(1) {
                        match publisher.dispatch_next().await? {
                            DispatchOutcome::NoWork | DispatchOutcome::StopDraining => break,
                            _ => {}
                        }
                    }
                    Ok(())
                })
            },
        )
    }
}
pub fn load_workload(error: LoadError) -> WorkloadError {
    if error.is_invariant() || error.is_retryable() {
        WorkloadError::Retryable(crate::errors::sanitize(&error.to_string()))
    } else {
        WorkloadError::Terminal(crate::errors::sanitize(&error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projection_only_suppresses_only_companion_wireless_discovery() {
        assert!(!should_ingest("wireless.audit", true));
        assert!(should_ingest("wireless.audit", false));
        assert!(should_ingest("unknown", true));
    }
    #[test]
    fn heartbeat_preserves_original_broker_hash_and_enriches_payload() {
        let raw = r#"{"observed_at":"2026-11-18T10:00:00Z","sensor_id":"sensor"}"#;
        let record = decode_heartbeat(raw).unwrap();
        assert_eq!(record.source().source_record_sha256(), sha256_hex(raw));
        assert_eq!(record.source().request_json(), raw);
        assert_eq!(record.source().dedupe_key(), sha256_hex(raw));
        let payload: Value = serde_json::from_str(record.payload_json()).unwrap();
        assert_eq!(payload["source_identity"], "sensor");
        assert_eq!(payload["schema_version"], 1);
        assert_eq!(payload["correlation_id"], record.source().dedupe_key());
    }
    #[test]
    fn heartbeat_checks_types_lengths_dates_and_integer_semantics() {
        for raw in [
            r#"[]"#,
            r#"{"observed_at":"invalid","sensor_id":"s"}"#,
            r#"{"observed_at":"2026-11-18T10:00:00Z","sensor_id":" "}"#,
            r#"{"observed_at":"2026-11-18T10:00:00Z","sensor_id":"s","schema_version":0}"#,
            r#"{"observed_at":"2026-11-18T10:00:00Z","sensor_id":"s","schema_version":1.2}"#,
            r#"{"observed_at":"2026-11-18T10:00:00Z","sensor_id":"s","produced_at":"invalid"}"#,
        ] {
            assert!(decode_heartbeat(raw).is_err(), "{raw}");
        }
        assert!(decode_heartbeat(
            r#"{"observed_at":"2026-11-18T10:00Z","sensor_id":"s","schema_version":1.0}"#
        )
        .is_ok());
    }
}
