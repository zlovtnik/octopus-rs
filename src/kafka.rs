//! Partition-ordered broker handling. Offsets follow durable effects and DLQ acks.

use crate::{
    config::KafkaCfg,
    domain::{BrokerConsumerContract, BrokerRecordMetadata},
    util::sha256_hex,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::{future::BoxFuture, FutureExt};
use opentelemetry::trace::TraceContextExt;
use rdkafka::{
    consumer::{
        stream_consumer::StreamPartitionQueue, CommitMode, Consumer, ConsumerContext, Rebalance,
        StreamConsumer,
    },
    error::KafkaError,
    message::Headers,
    producer::{FutureProducer, FutureRecord},
    ClientConfig, ClientContext, Message, Offset, TopicPartitionList,
};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tokio::{
    sync::{watch, Semaphore},
    task::JoinSet,
    time::{timeout_at, Instant},
};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[derive(Debug, thiserror::Error)]
pub enum BoundaryError {
    #[error("invalid Kafka configuration: {0}")]
    Configuration(String),
    #[error("broker invariant violated: {0}")]
    Invariant(&'static str),
    #[error("retryable durable handling failure: {0}")]
    Retryable(&'static str),
    #[error("consumer assignment changed before offset commit")]
    AssignmentChanged,
    #[error("consumer cancelled before durable batch completion")]
    Cancelled,
    #[error("Kafka operation failed")]
    Broker(#[from] KafkaError),
    #[error("partition task failed")]
    Task,
}

/// Decoder messages are sanitized at the broker publication boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poison {
    pub message: String,
    pub error_class: String,
}

impl Poison {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            error_class: "IllegalArgumentException".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerRecord {
    pub topic: String,
    pub partition: i32,
    pub offset: i64,
    pub key: Option<String>,
    pub payload: Option<Vec<u8>>,
    pub headers: BTreeMap<String, String>,
}

impl BrokerRecord {
    fn from_message(message: &impl Message) -> Self {
        Self {
            topic: message.topic().into(),
            partition: message.partition(),
            offset: message.offset(),
            key: message
                .key()
                .map(|value| String::from_utf8_lossy(value).into_owned()),
            payload: message.payload().map(<[u8]>::to_vec),
            headers: message
                .headers()
                .map(|headers| {
                    headers
                        .iter()
                        .filter_map(|header| {
                            Some((
                                header.key.to_owned(),
                                std::str::from_utf8(header.value?).ok()?.to_owned(),
                            ))
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    fn weight(&self) -> usize {
        self.payload.as_ref().map_or(0, Vec::len)
    }
}

pub(crate) fn poison_body(
    group: &str,
    record: &BrokerRecord,
    message: &str,
    class: &str,
) -> String {
    let mut body = serde_json::json!({
        "consumer_group": group,
        "error": crate::errors::sanitize(message),
        "error_class": crate::errors::sanitize(class),
        "offset": record.offset,
        "original": null,
        "partition": record.partition,
        "topic": record.topic
    });
    if let Some(raw) = &record.payload {
        match std::str::from_utf8(raw) {
            Ok(text) => body["original"] = text.into(),
            Err(_) => {
                body["original"] = STANDARD.encode(raw).into();
                body["original_encoding"] = "base64".into();
            }
        }
    }
    body.to_string()
}

#[derive(Clone, Debug)]
pub struct LockedRecord<A> {
    pub record: BrokerRecord,
    pub decoded: A,
    pub metadata: BrokerRecordMetadata,
}

/// Implementations must return only after committing all accepted durable
/// effects. Per-record permanent failures may complete only after an awaited
/// DLQ publish; retryable errors and evidence conflicts must return Err.
pub trait BatchHandler<A>: Send + Sync + 'static {
    fn process(&self, records: Vec<LockedRecord<A>>) -> BoxFuture<'_, Result<(), BoundaryError>>;
}

pub trait DurableBoundary: Send + Sync {
    fn park<'a>(
        &'a self,
        record: &'a BrokerRecord,
        reason: &'a Poison,
    ) -> BoxFuture<'a, Result<(), BoundaryError>>;
    /// Commit the *next* offset only after the whole ordered partition batch.
    fn commit<'a>(
        &'a self,
        topic: &'a str,
        partition: i32,
        next_offset: i64,
    ) -> BoxFuture<'a, Result<(), BoundaryError>>;
    /// Called only after commit returned successfully, with the number of
    /// records in that committed batch (including acknowledged poison).
    fn committed(&self, _topic: &str, _partition: i32, _next_offset: i64, _records: u64) {}
}

pub trait CommitObserver: Send + Sync + 'static {
    fn committed(&self, group: &str, topic: &str, partition: i32, next_offset: i64, records: u64);
    fn assignment(&self, _group: &str, _topic: &str, _assigned: bool) {}
}

struct HeaderExtractor<'a>(&'a BTreeMap<String, String>);
impl opentelemetry::propagation::Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(String::as_str).collect()
    }
}
fn batch_span<A>(records: &[LockedRecord<A>]) -> tracing::Span {
    let span = tracing::info_span!(
        "kafka.consume.batch",
        messaging.system = "kafka",
        messaging.batch.message_count = records.len()
    );
    if let Some(first) = records.first() {
        let parent = opentelemetry::global::get_text_map_propagator(|p| {
            p.extract(&HeaderExtractor(&first.record.headers))
        });
        let _ = span.set_parent(parent);
    }
    for record in records.iter().skip(1) {
        let context = opentelemetry::global::get_text_map_propagator(|p| {
            p.extract(&HeaderExtractor(&record.record.headers))
        });
        let linked = context.span().span_context().clone();
        if linked.is_valid() {
            span.add_link(linked);
        }
    }
    span
}

#[derive(Debug)]
pub enum DurableFailure {
    Permanent(Poison),
    Retryable,
    Invariant,
}

/// Only permanent non-invariant errors may authorize poison parking.
pub async fn finish_durable(
    result: Result<(), DurableFailure>,
    record: &BrokerRecord,
    boundary: &impl DurableBoundary,
) -> Result<(), BoundaryError> {
    match result {
        Ok(()) => Ok(()),
        Err(DurableFailure::Permanent(reason)) => boundary.park(record, &reason).await,
        Err(DurableFailure::Retryable) => {
            Err(BoundaryError::Retryable("durable storage unavailable"))
        }
        Err(DurableFailure::Invariant) => {
            Err(BoundaryError::Invariant("durable evidence conflict"))
        }
    }
}

pub fn consumer_settings(cfg: &KafkaCfg, group: &str) -> Result<ClientConfig, BoundaryError> {
    if cfg.locked_batch_max_bytes <= 0
        || cfg.max_poll_records <= 0
        || cfg.locked_batch_size <= 0
        || cfg.locked_batch_window_ms <= 0
    {
        return Err(BoundaryError::Configuration(
            "batch and polling bounds must be positive".into(),
        ));
    }
    let mut settings = ClientConfig::new();
    settings
        .set("bootstrap.servers", &cfg.bootstrap_servers)
        .set("group.id", group)
        .set("auto.offset.reset", "earliest")
        .set("enable.auto.commit", "false")
        .set("enable.auto.offset.store", "false")
        .set("isolation.level", "read_committed")
        .set("allow.auto.create.topics", "false")
        .set("fetch.max.bytes", cfg.locked_batch_max_bytes.to_string())
        .set(
            "max.partition.fetch.bytes",
            (1024 * 1024).min(cfg.locked_batch_max_bytes).to_string(),
        )
        .set("queued.min.messages", cfg.max_poll_records.to_string())
        .set(
            "queued.max.messages.kbytes",
            ((i64::from(cfg.locked_batch_max_bytes) + 1023) / 1024)
                .max(1)
                .to_string(),
        )
        .set("session.timeout.ms", "30000")
        .set("heartbeat.interval.ms", "3000");
    Ok(settings)
}

pub fn producer(cfg: &KafkaCfg) -> Result<FutureProducer, BoundaryError> {
    Ok(ClientConfig::new()
        .set("bootstrap.servers", &cfg.bootstrap_servers)
        .set("enable.idempotence", "true")
        .set("acks", "all")
        .set("retries", "3")
        .create()?)
}

pub fn provisioned_topic_partitions(cfg: &KafkaCfg, topic: &str) -> i32 {
    let topic = if cfg.dlq_suffix.is_empty() {
        topic
    } else {
        topic.strip_suffix(&cfg.dlq_suffix).unwrap_or(topic)
    };
    if [
        cfg.scan_topic.as_str(),
        cfg.load_topic.as_str(),
        cfg.result_topic.as_str(),
    ]
    .contains(&topic)
    {
        cfg.topic_partitions
    } else {
        3
    }
}

/// Count/byte splitting preserves order and emits oversized records alone so
/// they can be parked by the same durable path.
pub fn split_bounded<T>(
    records: Vec<T>,
    count: usize,
    bytes: usize,
    weight: impl Fn(&T) -> usize,
) -> Result<Vec<Vec<T>>, BoundaryError> {
    if count == 0 || bytes == 0 {
        return Err(BoundaryError::Configuration(
            "batch bounds must be positive".into(),
        ));
    }
    let mut result = Vec::new();
    let mut batch = Vec::new();
    let mut size = 0usize;
    for record in records {
        let next = weight(&record);
        if !batch.is_empty() && (batch.len() == count || size.saturating_add(next) > bytes) {
            result.push(std::mem::take(&mut batch));
            size = 0;
        }
        batch.push(record);
        size = size.saturating_add(next);
        if batch.len() == count || size >= bytes {
            result.push(std::mem::take(&mut batch));
            size = 0;
        }
    }
    if !batch.is_empty() {
        result.push(batch);
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub async fn process_batch<A: Send + 'static>(
    records: Vec<BrokerRecord>,
    group: &str,
    topic: &str,
    max_bytes: usize,
    decode: &(impl Fn(&str) -> Result<A, Poison> + Send + Sync),
    handler: &impl BatchHandler<A>,
    boundary: &impl DurableBoundary,
    cancelled: &CancellationToken,
) -> Result<(), BoundaryError> {
    if max_bytes == 0 {
        return Err(BoundaryError::Configuration(
            "batch bytes must be positive".into(),
        ));
    }
    let contract =
        BrokerConsumerContract::from(group, topic).map_err(BoundaryError::Configuration)?;
    let Some(first) = records.first() else {
        return Ok(());
    };
    let partition = first.partition;
    let mut previous = None;
    for record in &records {
        if record.topic != topic
            || record.partition != partition
            || record.offset < 0
            || previous.is_some_and(|offset| offset >= record.offset)
        {
            return Err(BoundaryError::Invariant(
                "unexpected topic, partition or offset ordering",
            ));
        }
        previous = Some(record.offset);
    }
    for batch in split_bounded(records, usize::MAX, max_bytes, BrokerRecord::weight)? {
        let committed_records = batch.len() as u64;
        let next_offset = batch
            .last()
            .expect("split emits nonempty batches")
            .offset
            .checked_add(1)
            .ok_or(BoundaryError::Invariant("offset overflow"))?;
        let mut prepared = Vec::new();
        for record in batch {
            let decoded = match &record.payload {
                None => Err(Poison::invalid(
                    "tombstone is not valid for a locked consumer",
                )),
                Some(raw) if raw.len() > max_bytes => Err(Poison::invalid(
                    "record exceeds kafka.locked-batch-max-bytes",
                )),
                Some(raw) => std::str::from_utf8(raw)
                    .map_err(|_| Poison::invalid("broker payload is not valid UTF-8"))
                    .and_then(&decode),
            };
            match decoded {
                Ok(decoded) => {
                    let raw = record.payload.as_ref().expect("decoded payload exists");
                    let metadata = BrokerRecordMetadata {
                        topic: record.topic.clone(),
                        partition,
                        offset: record.offset,
                        consumer_group: group.into(),
                        group_version: contract.group_version,
                        artifact_sha256: contract.contract_sha256.clone(),
                        message_key: record.key.clone(),
                        payload_sha256: sha256_hex(raw),
                    };
                    prepared.push(LockedRecord {
                        record,
                        decoded,
                        metadata,
                    });
                }
                Err(reason) => tokio::select! { biased;
                    _ = cancelled.cancelled() => return Err(BoundaryError::Cancelled),
                    result = boundary.park(&record, &reason) => result?,
                },
            }
        }
        let span = batch_span(&prepared);
        tokio::select! { biased;
            _ = cancelled.cancelled() => return Err(BoundaryError::Cancelled),
            result = handler.process(prepared).instrument(span.clone()) => result?,
        }
        tokio::select! { biased;
            _ = cancelled.cancelled() => return Err(BoundaryError::Cancelled),
            result = boundary.commit(topic, partition, next_offset).instrument(span) => result?,
        }
        boundary.committed(topic, partition, next_offset, committed_records);
    }
    Ok(())
}

struct AssignmentContext {
    revision: Arc<Mutex<u64>>,
    changed: watch::Sender<u64>,
    observer: Arc<RwLock<Option<Arc<dyn CommitObserver>>>>,
    group: String,
    topic: String,
}
impl ClientContext for AssignmentContext {}
impl ConsumerContext for AssignmentContext {
    fn pre_rebalance(&self, _: &Rebalance<'_>) {
        let mut revision = self
            .revision
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *revision = revision.wrapping_add(1);
        if let Some(observer) = &*self.observer.read().unwrap_or_else(|e| e.into_inner()) {
            observer.assignment(&self.group, &self.topic, false);
        }
    }
    fn post_rebalance(&self, _: &Rebalance<'_>) {
        self.changed.send_replace(
            *self
                .revision
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
    }
}

type NativeConsumer = StreamConsumer<AssignmentContext>;
struct NativeBoundary {
    consumer: Arc<NativeConsumer>,
    producer: FutureProducer,
    revision: Arc<Mutex<u64>>,
    epoch: u64,
    group: String,
    dlq_topic: String,
    observer: Option<Arc<dyn CommitObserver>>,
}
impl DurableBoundary for NativeBoundary {
    fn park<'a>(
        &'a self,
        record: &'a BrokerRecord,
        reason: &'a Poison,
    ) -> BoxFuture<'a, Result<(), BoundaryError>> {
        Box::pin(async move {
            let body = poison_body(&self.group, record, &reason.message, &reason.error_class);
            let key = record
                .key
                .clone()
                .unwrap_or_else(|| format!("{}:{}", record.partition, record.offset));
            self.producer
                .send(
                    FutureRecord::to(&self.dlq_topic).key(&key).payload(&body),
                    Duration::from_secs(30),
                )
                .await
                .map_err(|(error, _)| BoundaryError::Broker(error))?;
            Ok(())
        })
    }
    fn commit<'a>(
        &'a self,
        topic: &'a str,
        partition: i32,
        next_offset: i64,
    ) -> BoxFuture<'a, Result<(), BoundaryError>> {
        let consumer = self.consumer.clone();
        let revision = self.revision.clone();
        let epoch = self.epoch;
        let topic = topic.to_string();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                // Rebalance callbacks take this same lock before revocation.
                // A completed old worker can never commit under a new epoch.
                let current = revision
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if *current != epoch {
                    return Err(BoundaryError::AssignmentChanged);
                }
                let mut offsets = TopicPartitionList::new();
                offsets.add_partition_offset(&topic, partition, Offset::Offset(next_offset))?;
                consumer.commit(&offsets, CommitMode::Sync)?;
                Ok(())
            })
            .await
            .map_err(|_| BoundaryError::Task)?
        })
    }
    fn committed(&self, topic: &str, partition: i32, next_offset: i64, records: u64) {
        if let Some(observer) = &self.observer {
            observer.committed(&self.group, topic, partition, next_offset, records);
        }
    }
}

/// A resource per locked topic/group. Separate queues keep a slow partition
/// from blocking polling for the remaining assigned partitions.
pub struct LockedConsumer {
    consumer: Arc<NativeConsumer>,
    producer: FutureProducer,
    cfg: KafkaCfg,
    group: String,
    topic: String,
    revision: Arc<Mutex<u64>>,
    changed: watch::Receiver<u64>,
    observer: Arc<RwLock<Option<Arc<dyn CommitObserver>>>>,
}
impl Drop for LockedConsumer {
    fn drop(&mut self) {
        if let Some(observer) = &*self.observer.read().unwrap_or_else(|e| e.into_inner()) {
            observer.assignment(&self.group, &self.topic, false);
        }
    }
}

impl LockedConsumer {
    pub fn new(cfg: KafkaCfg, group: String, topic: String) -> Result<Self, BoundaryError> {
        BrokerConsumerContract::from(&group, &topic).map_err(BoundaryError::Configuration)?;
        let revision = Arc::new(Mutex::new(0));
        let (changed, receiver) = watch::channel(0);
        let observer = Arc::new(RwLock::new(None));
        let consumer = consumer_settings(&cfg, &group)?.create_with_context(AssignmentContext {
            revision: revision.clone(),
            changed,
            observer: observer.clone(),
            group: group.clone(),
            topic: topic.clone(),
        })?;
        let producer = producer(&cfg)?;
        Ok(Self {
            consumer: Arc::new(consumer),
            producer,
            cfg,
            group,
            topic,
            revision,
            changed: receiver,
            observer,
        })
    }

    pub fn with_commit_observer(self, observer: Arc<dyn CommitObserver>) -> Self {
        *self.observer.write().unwrap_or_else(|e| e.into_inner()) = Some(observer);
        self
    }

    pub async fn run<A, D, H>(
        mut self,
        partition_concurrency: usize,
        decode: D,
        handler: H,
        cancelled: CancellationToken,
    ) -> Result<(), BoundaryError>
    where
        A: Send + 'static,
        D: Fn(&str) -> Result<A, Poison> + Send + Sync + 'static,
        H: BatchHandler<A>,
    {
        if partition_concurrency == 0 {
            return Err(BoundaryError::Configuration(
                "partition concurrency must be positive".into(),
            ));
        }
        let metadata_consumer = self.consumer.clone();
        let topic = self.topic.clone();
        let metadata = tokio::task::spawn_blocking(move || {
            metadata_consumer.fetch_metadata(Some(&topic), Duration::from_secs(30))
        })
        .await
        .map_err(|_| BoundaryError::Task)??;
        if !metadata.topics().iter().any(|found| {
            found.name() == self.topic && found.error().is_none() && !found.partitions().is_empty()
        }) {
            return Err(BoundaryError::Invariant(
                "locked topic has no broker partitions",
            ));
        }
        self.consumer.subscribe(&[&self.topic])?;
        let decode = Arc::new(decode);
        let handler = Arc::new(handler);
        let permits = Arc::new(Semaphore::new(partition_concurrency));
        let mut workers = JoinSet::new();
        let mut epoch = u64::MAX;
        let mut bootstrap = Vec::new();
        let stop = cancelled.child_token();
        let result = async { loop {
            let current = *self.changed.borrow_and_update();
            if current != epoch {
                workers.abort_all();
                while workers.join_next().await.is_some() {}
                epoch = current;
                let assignment = self.consumer.assignment()?;
                if assignment.elements().iter().any(|part| part.topic() != self.topic) { break Err(BoundaryError::Invariant("unexpected assigned topic")); }
                let mut queues = BTreeMap::new();
                for part in assignment.elements() {
                    let queue = self.consumer.split_partition_queue(&self.topic, part.partition()).ok_or(BoundaryError::Invariant("partition queue unavailable"))?;
                    queues.insert(part.partition(), queue);
                }
                // Messages fetched before queue splitting remain on the main
                // queue. Drain that finite prefix before starting any worker;
                // otherwise newer queue records could commit past that prefix.
                while let Some(message) = self.consumer.recv().now_or_never() {
                    bootstrap.push((*self.changed.borrow(), BrokerRecord::from_message(&message?)));
                    if *self.changed.borrow() != epoch { break; }
                }
                if *self.changed.borrow() != epoch { continue; }
                let mut prefixes = BTreeMap::<i32, VecDeque<BrokerRecord>>::new();
                for (_, record) in bootstrap.drain(..).filter(|(generation, _)| *generation == epoch) {
                    if record.topic != self.topic || !queues.contains_key(&record.partition) { return Err(BoundaryError::Invariant("unexpected buffered topic or partition")); }
                    prefixes.entry(record.partition).or_default().push_back(record);
                }
                for (partition, queue) in queues {
                    let boundary = NativeBoundary { consumer:self.consumer.clone(), producer:self.producer.clone(), revision:self.revision.clone(), epoch, group:self.group.clone(), dlq_topic:format!("{}{}",self.topic,self.cfg.dlq_suffix), observer:self.observer.read().unwrap_or_else(|e|e.into_inner()).clone() };
                    workers.spawn(partition_worker(queue, prefixes.remove(&partition).unwrap_or_default(), self.cfg.clone(), self.group.clone(), self.topic.clone(), decode.clone(), handler.clone(), boundary, permits.clone(), stop.clone()));
                }
                if let Some(observer)=&*self.observer.read().unwrap_or_else(|e|e.into_inner()){observer.assignment(&self.group,&self.topic,!workers.is_empty());}
            }
            tokio::select! { biased;
                _ = cancelled.cancelled() => break Ok(()),
                result = workers.join_next(), if !workers.is_empty() => break match result { Some(Ok(result)) => result, _ => Err(BoundaryError::Task) },
                changed = self.changed.changed() => { if changed.is_err() { break Err(BoundaryError::Task); } },
                message = self.consumer.recv() => {
                    let message = message?;
                    let record = BrokerRecord::from_message(&message);
                    drop(message);
                    // A rebalance may run inside recv. Reinstall queues first;
                    // discarded old-generation messages remain uncommitted.
                    let generation = *self.changed.borrow();
                    if generation != epoch { bootstrap.push((generation, record)); continue; }
                    break Err(BoundaryError::Invariant("main queue received record after partition queue installation"));
                }
            }
        }}.await;
        if let Some(observer) = &*self.observer.read().unwrap_or_else(|e| e.into_inner()) {
            observer.assignment(&self.group, &self.topic, false);
        }
        stop.cancel();
        workers.abort_all();
        while workers.join_next().await.is_some() {}
        self.consumer.unsubscribe();
        result
    }
}

#[allow(clippy::too_many_arguments)]
async fn partition_worker<A, D, H>(
    queue: StreamPartitionQueue<AssignmentContext>,
    mut prefix: VecDeque<BrokerRecord>,
    cfg: KafkaCfg,
    group: String,
    topic: String,
    decode: Arc<D>,
    handler: Arc<H>,
    boundary: NativeBoundary,
    permits: Arc<Semaphore>,
    cancelled: CancellationToken,
) -> Result<(), BoundaryError>
where
    A: Send + 'static,
    D: Fn(&str) -> Result<A, Poison> + Send + Sync + 'static,
    H: BatchHandler<A>,
{
    let mut pending = None;
    loop {
        let first = match pending.take().or_else(|| prefix.pop_front()) {
            Some(record) => record,
            None => tokio::select! { biased;
                _ = cancelled.cancelled() => return Ok(()),
                record = queue.recv() => BrokerRecord::from_message(&record?),
            },
        };
        let deadline = Instant::now() + Duration::from_millis(cfg.locked_batch_window_ms as u64);
        let mut size = first.weight();
        let mut batch = vec![first];
        while batch.len() < cfg.locked_batch_size as usize
            && size < cfg.locked_batch_max_bytes as usize
        {
            let next = timeout_at(deadline, async {
                if let Some(record) = prefix.pop_front() {
                    return Ok(record);
                }
                tokio::select! { biased;
                    _ = cancelled.cancelled() => Err(BoundaryError::Cancelled),
                    record = queue.recv() => Ok(BrokerRecord::from_message(&record?)),
                }
            })
            .await;
            match next {
                Err(_) => break,
                Ok(Err(error)) => return Err(error),
                Ok(Ok(record)) => {
                    if size.saturating_add(record.weight()) > cfg.locked_batch_max_bytes as usize {
                        pending = Some(record);
                        break;
                    }
                    size += record.weight();
                    batch.push(record);
                }
            }
        }
        let _permit = tokio::select! { biased;
            _ = cancelled.cancelled() => return Ok(()),
            permit = permits.acquire() => permit.map_err(|_| BoundaryError::Task)?,
        };
        process_batch(
            batch,
            &group,
            &topic,
            cfg.locked_batch_max_bytes as usize,
            &*decode,
            &*handler,
            &boundary,
            &cancelled,
        )
        .await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Default)]
    struct Journal {
        events: Mutex<Vec<String>>,
        fail_park: AtomicBool,
        fail_handle: AtomicBool,
    }
    impl Journal {
        fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }
        fn record(&self, event: String) {
            self.events.lock().unwrap().push(event);
        }
    }
    impl BatchHandler<String> for Journal {
        fn process(
            &self,
            records: Vec<LockedRecord<String>>,
        ) -> BoxFuture<'_, Result<(), BoundaryError>> {
            Box::pin(async move {
                self.record(format!(
                    "handle:{:?}",
                    records
                        .iter()
                        .map(|record| record.record.offset)
                        .collect::<Vec<_>>()
                ));
                if self.fail_handle.load(Ordering::SeqCst) {
                    Err(BoundaryError::Retryable("test failure"))
                } else {
                    Ok(())
                }
            })
        }
    }
    impl DurableBoundary for Journal {
        fn park<'a>(
            &'a self,
            record: &'a BrokerRecord,
            _: &'a Poison,
        ) -> BoxFuture<'a, Result<(), BoundaryError>> {
            Box::pin(async move {
                self.record(format!("park:{}", record.offset));
                if self.fail_park.load(Ordering::SeqCst) {
                    Err(BoundaryError::Retryable("test DLQ failure"))
                } else {
                    Ok(())
                }
            })
        }
        fn commit<'a>(
            &'a self,
            _: &'a str,
            partition: i32,
            next_offset: i64,
        ) -> BoxFuture<'a, Result<(), BoundaryError>> {
            Box::pin(async move {
                self.record(format!("commit:{partition}:{next_offset}"));
                Ok(())
            })
        }
    }
    fn record(offset: i64, payload: Option<&str>) -> BrokerRecord {
        BrokerRecord {
            topic: "sync.scan.request".into(),
            partition: 0,
            offset,
            key: None,
            payload: payload.map(|value| value.as_bytes().to_vec()),
            headers: BTreeMap::new(),
        }
    }
    fn decode(raw: &str) -> Result<String, Poison> {
        if raw == "poison" {
            Err(Poison::invalid("invalid scan request"))
        } else {
            Ok(raw.into())
        }
    }
    async fn process(
        records: Vec<BrokerRecord>,
        journal: &Journal,
        cancel: &CancellationToken,
    ) -> Result<(), BoundaryError> {
        process_batch(
            records,
            "octopus-scan-v1",
            "sync.scan.request",
            1024,
            &decode,
            journal,
            journal,
            cancel,
        )
        .await
    }

    #[test]
    fn settings_preserve_replay_and_explicit_commit_contract() {
        let cfg = KafkaCfg::default();
        let settings = consumer_settings(&cfg, "octopus-scan-v1").unwrap();
        for (name, value) in [
            ("auto.offset.reset", "earliest"),
            ("enable.auto.commit", "false"),
            ("enable.auto.offset.store", "false"),
            ("isolation.level", "read_committed"),
            ("allow.auto.create.topics", "false"),
        ] {
            assert_eq!(settings.get(name), Some(value));
        }
        assert_eq!(settings.get("group.id"), Some("octopus-scan-v1"));
        assert_eq!(
            provisioned_topic_partitions(&cfg, &cfg.scan_topic),
            cfg.topic_partitions
        );
        assert_eq!(
            provisioned_topic_partitions(&cfg, &(cfg.load_topic.clone() + &cfg.dlq_suffix)),
            cfg.topic_partitions
        );
        assert_eq!(provisioned_topic_partitions(&cfg, "wireless.audit"), 3);
        assert!(consumer_settings(
            &KafkaCfg {
                locked_batch_size: 0,
                ..cfg
            },
            "x-v1"
        )
        .is_err());
    }

    #[test]
    fn byte_and_count_bounds_preserve_oversize_records_and_order() {
        let values = vec![3, 4, 5, 11, 1, 1, 1, 1];
        let batches = split_bounded(values.clone(), 3, 10, |v| *v).unwrap();
        assert_eq!(
            batches,
            vec![vec![3, 4], vec![5], vec![11], vec![1, 1, 1], vec![1]]
        );
        assert_eq!(batches.into_iter().flatten().collect::<Vec<_>>(), values);
        assert!(split_bounded(vec![1], 0, 1, |v| *v).is_err());
    }

    #[tokio::test]
    async fn poison_ack_precedes_durable_handler_and_commit() {
        let journal = Journal::default();
        process(
            vec![
                record(0, Some("ok")),
                record(1, Some("poison")),
                record(2, None),
            ],
            &journal,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            journal.events(),
            ["park:1", "park:2", "handle:[0]", "commit:0:3"]
        );
    }

    #[tokio::test]
    async fn failed_dlq_or_durable_handler_never_commits() {
        let journal = Journal::default();
        journal.fail_park.store(true, Ordering::SeqCst);
        assert!(process(
            vec![record(0, Some("poison"))],
            &journal,
            &CancellationToken::new()
        )
        .await
        .is_err());
        assert_eq!(journal.events(), ["park:0"]);
        let journal = Journal::default();
        journal.fail_handle.store(true, Ordering::SeqCst);
        assert!(process(
            vec![record(0, Some("ok"))],
            &journal,
            &CancellationToken::new()
        )
        .await
        .is_err());
        assert_eq!(journal.events(), ["handle:[0]"]);
    }

    #[tokio::test]
    async fn invariants_and_cancellation_do_not_park_or_commit() {
        let journal = Journal::default();
        for records in [
            vec![record(1, Some("ok")), record(0, Some("ok"))],
            vec![BrokerRecord {
                topic: "other".into(),
                ..record(0, Some("ok"))
            }],
            vec![record(i64::MAX, Some("ok"))],
        ] {
            assert!(matches!(
                process(records, &journal, &CancellationToken::new()).await,
                Err(BoundaryError::Invariant(_))
            ));
        }
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(matches!(
            process(vec![record(0, Some("ok"))], &journal, &cancelled).await,
            Err(BoundaryError::Cancelled)
        ));
        assert!(journal.events().is_empty());
    }

    #[tokio::test]
    async fn permanent_errors_only_park_and_await_acknowledgement() {
        let journal = Journal::default();
        let record = record(0, Some("ok"));
        for failure in [DurableFailure::Retryable, DurableFailure::Invariant] {
            assert!(finish_durable(Err(failure), &record, &journal)
                .await
                .is_err());
        }
        assert!(journal.events().is_empty());
        finish_durable(
            Err(DurableFailure::Permanent(Poison::invalid("invalid"))),
            &record,
            &journal,
        )
        .await
        .unwrap();
        assert_eq!(journal.events(), ["park:0"]);
        journal.fail_park.store(true, Ordering::SeqCst);
        assert!(finish_durable(
            Err(DurableFailure::Permanent(Poison::invalid("invalid"))),
            &record,
            &journal
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn oversized_record_parks_alone_and_preserves_safe_prior_commits() {
        let journal = Journal::default();
        process_batch(
            vec![
                record(0, Some("a")),
                record(1, Some("12345")),
                record(2, Some("b")),
            ],
            "octopus-scan-v1",
            "sync.scan.request",
            4,
            &decode,
            &journal,
            &journal,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            journal.events(),
            [
                "handle:[0]",
                "commit:0:1",
                "park:1",
                "handle:[]",
                "commit:0:2",
                "handle:[2]",
                "commit:0:3"
            ]
        );
    }
}
