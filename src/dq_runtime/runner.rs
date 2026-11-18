use super::*;
use crate::{
    config::{DqConfig, KafkaCfg},
    kafka,
};
use rdkafka::{
    admin::{AdminClient, AdminOptions, OwnedResourceSpecifier, ResourceSpecifier},
    client::{ClientContext, DefaultClientContext},
    config::ClientConfig,
    consumer::{BaseConsumer, CommitMode, Consumer, ConsumerContext, Rebalance, StreamConsumer},
    message::Message,
    producer::{FutureProducer, FutureRecord},
    Offset, TopicPartitionList,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
pub const REPORT_GROUP: &str = "octopus-dq-worker-reports-v1";
pub const TOPICS: [(&str, &str, i64); 6] = [
    ("dq.commands.v1", "delete", 7),
    ("dq.worker-reports.v1", "delete", 7),
    ("dq.events.v1", "delete", 30),
    ("dq.dlq.v1", "delete", 30),
    ("dq.registry.v1", "compact", 0),
    ("dq.audit.v1", "delete", 180),
];

pub async fn broker_preflight(config: &KafkaCfg) -> Result<()> {
    let bootstrap = config.bootstrap_servers.clone();
    let replicas = config.topic_replication_factor;
    tokio::task::spawn_blocking(move || {
        let consumer: BaseConsumer = ClientConfig::new()
            .set("bootstrap.servers", &bootstrap)
            .set("allow.auto.create.topics", "false")
            .create()
            .map_err(|_| error(503, "dq_topic_unavailable"))?;
        let metadata = consumer
            .fetch_metadata(None, Duration::from_secs(10))
            .map_err(|_| error(503, "dq_topic_unavailable"))?;
        for (name, _, _) in TOPICS {
            let topic = metadata
                .topics()
                .iter()
                .find(|t| t.name() == name && t.error().is_none())
                .ok_or_else(|| error(503, "dq_topic_unavailable"))?;
            if topic.partitions().is_empty()
                || topic
                    .partitions()
                    .iter()
                    .any(|p| p.error().is_some() || p.replicas().len() < (replicas as usize))
            {
                return Err(error(503, "dq_topic_replication_inadequate"));
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| error(503, "dq_topic_unavailable"))??;
    let admin: AdminClient<DefaultClientContext> = ClientConfig::new()
        .set("bootstrap.servers", &config.bootstrap_servers)
        .create()
        .map_err(|_| error(503, "dq_topic_unavailable"))?;
    let resources = TOPICS
        .iter()
        .map(|(name, _, _)| ResourceSpecifier::Topic(name))
        .collect::<Vec<_>>();
    let values = admin
        .describe_configs(
            &resources,
            &AdminOptions::new().request_timeout(Some(Duration::from_secs(10))),
        )
        .await
        .map_err(|_| error(503, "dq_topic_unavailable"))?;
    for value in values {
        let value = value.map_err(|_| error(503, "dq_topic_unavailable"))?;
        let name = match &value.specifier {
            OwnedResourceSpecifier::Topic(name) => name,
            _ => return Err(error(503, "dq_topic_unavailable")),
        };
        let (_, cleanup, days) = TOPICS
            .iter()
            .find(|(n, _, _)| *n == name)
            .ok_or_else(|| error(503, "dq_topic_unavailable"))?;
        if value.get("cleanup.policy").and_then(|v| v.value.as_deref()) != Some(cleanup)
            || (days > &0
                && value
                    .get("retention.ms")
                    .and_then(|v| v.value.as_ref())
                    .and_then(|v| v.parse::<i64>().ok())
                    != Some(days * 86_400_000))
        {
            return Err(error(503, "dq_topic_retention_mismatch"));
        }
    }
    Ok(())
}
pub fn receipt(
    config: &DqConfig,
    group: &str,
    topic: &str,
    partition: i32,
    offset: i64,
    key: &str,
    raw: &[u8],
) -> Value {
    let hash = crate::util::sha256_hex(raw);
    let parsed = std::str::from_utf8(raw)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(s).ok());
    let envelope = parsed.filter(|e| {
        raw.len() <= 65_536
            && e.is_object()
            && e["installation_id"] == config.installation_id
            && e["namespace"] == config.namespace
            && e["run_id"].as_str().is_some_and(|r| {
                key == format!("{}/{}/{}", config.installation_id, config.namespace, r)
            })
    });
    let event = envelope
        .as_ref()
        .and_then(|e| e["event_id"].as_str())
        .filter(|v| !v.is_empty() && crate::util::utf16_length(v) <= 256)
        .unwrap_or(&hash);
    let mut value = json!({"installation_id":config.installation_id,"namespace":config.namespace,"consumer_group":group,"topic":topic,"partition":partition,"offset":offset,"event_id":event,"payload_sha256":hash});
    if let Some(e) = envelope {
        value["envelope"] = e;
    } else {
        value["quarantine_reason"] = json!("invalid_record");
    }
    value
}
#[derive(Clone)]
struct ReportContext {
    epoch: Arc<Mutex<u64>>,
    assigned: Arc<AtomicBool>,
}
impl ClientContext for ReportContext {}
impl ConsumerContext for ReportContext {
    fn pre_rebalance(&self, rebalance: &Rebalance<'_>) {
        let mut epoch = self.epoch.lock().unwrap_or_else(|e| e.into_inner());
        *epoch = epoch.wrapping_add(1);
        self.assigned.store(
            matches!(rebalance,Rebalance::Assign(p)if p.count()>0),
            Ordering::Release,
        );
    }
}
#[derive(Clone)]
pub struct DqRuntime {
    store: DqStore,
    config: DqConfig,
    kafka: KafkaCfg,
    artifacts: artifacts::DqArtifacts,
    producer: FutureProducer,
    owner: String,
    minimum_similarity: f64,
    maintenance: Arc<AtomicBool>,
    reports: Arc<AtomicBool>,
    assigned: Arc<AtomicBool>,
}
impl DqRuntime {
    pub fn new(
        store: DqStore,
        config: DqConfig,
        kafka: KafkaCfg,
        artifacts: artifacts::DqArtifacts,
        minimum_similarity: f64,
    ) -> Result<Self> {
        let producer = kafka::producer(&kafka).map_err(|_| error(503, "dq_broker_unavailable"))?;
        Ok(Self {
            store,
            config,
            kafka,
            artifacts,
            producer,
            owner: id(),
            minimum_similarity,
            maintenance: Arc::new(AtomicBool::new(false)),
            reports: Arc::new(AtomicBool::new(false)),
            assigned: Arc::new(AtomicBool::new(false)),
        })
    }
    pub async fn initialize(&self) -> Result<()> {
        self.artifacts.initialize().await?;
        broker_preflight(&self.kafka).await
    }
    pub fn ready(&self) -> bool {
        self.maintenance.load(Ordering::Acquire)
            && self.reports.load(Ordering::Acquire)
            && self.assigned.load(Ordering::Acquire)
    }
    pub async fn tick(&self) -> Result<()> {
        self.artifacts.initialize().await?;
        self.store.expire_attempts().await?;
        let mut first = None;
        for stage in 0..3 {
            for _ in 0..self.config.batch_size {
                let result = match stage {
                    0 => match self
                        .store
                        .claim_preparation(&self.owner, self.config.lease_seconds, 1)
                        .await
                    {
                        Ok(runs) => match runs.into_iter().next() {
                            None => break,
                            Some(run) => self.prepare(&run).await,
                        },
                        Err(e) => Err(e),
                    },
                    1 => match self
                        .store
                        .claim_output(&self.owner, self.config.lease_seconds, 1)
                        .await
                    {
                        Ok(runs) => match runs.into_iter().next() {
                            None => break,
                            Some(run) => self.apply(&run).await,
                        },
                        Err(e) => Err(e),
                    },
                    _ => match self
                        .store
                        .claim_outbox(&self.owner, self.config.lease_seconds, 1)
                        .await
                    {
                        Ok(items) => match items.into_iter().next() {
                            None => break,
                            Some(item) => self.publish(&item).await,
                        },
                        Err(e) => Err(e),
                    },
                };
                if let Err(e) = result {
                    if first.is_none() {
                        first = Some(e);
                    }
                    break;
                }
            }
        }
        if let Err(e) = self.discover().await {
            if first.is_none() {
                first = Some(e);
            }
        }
        if let Some(e) = first {
            Err(e)
        } else {
            Ok(())
        }
    }
    async fn prepare(&self, run: &Value) -> Result<()> {
        let run_id = dq::text(run, "run_id")?;
        let work: Result<()> = async {
            let snapshot = self
                .store
                .prepare_snapshot(run, self.minimum_similarity)
                .await?;
            let reference = self.artifacts.put_snapshot(run, &snapshot).await?;
            self.store
                .complete_preparation(
                    run_id,
                    &self.owner,
                    &json!([reference]),
                    dq::text(&snapshot, "source_revision_digest")?,
                )
                .await?;
            Ok(())
        }
        .await;
        if let Err(e) = &work {
            let permanent = e.status < 500;
            let code = if e.code == "source_revision_changed" {
                e.code.as_str()
            } else if permanent {
                e.code.as_str()
            } else {
                "preparation_dependency_failure"
            };
            self.store
                .fail_work(run_id, &self.owner, code, permanent, true)
                .await?;
            if permanent {
                return Ok(());
            }
        }
        work
    }
    async fn apply(&self, run: &Value) -> Result<()> {
        let run_id = dq::text(run, "run_id")?;
        let work: Result<()> = async {
            let single = |key: &str| {
                run[key]
                    .as_array()
                    .filter(|a| a.len() == 1)
                    .map(|a| &a[0])
                    .ok_or_else(|| error(400, &format!("invalid_{key}")))
            };
            let snapshot = self
                .artifacts
                .read(single("input_refs")?, run, false)
                .await?;
            let proposal = self
                .artifacts
                .read(single("output_refs")?, run, true)
                .await?;
            self.store
                .apply_output(
                    &self.owner,
                    run,
                    &snapshot,
                    &proposal,
                    self.minimum_similarity,
                )
                .await?;
            Ok(())
        }
        .await;
        if let Err(e) = &work {
            let fresh = e.code == "source_revision_changed";
            let permanent = e.status < 500 && !fresh;
            let code = if fresh || permanent {
                e.code.as_str()
            } else {
                "application_dependency_failure"
            };
            self.store
                .fail_work(run_id, &self.owner, code, permanent, fresh)
                .await?;
            if fresh || permanent {
                return Ok(());
            }
        }
        work
    }
    async fn publish(&self, item: &DqOutbox) -> Result<()> {
        dq::bounded(&item.payload)?;
        let raw = dq::canonical(&item.payload)?;
        let result = self
            .producer
            .send(
                FutureRecord::to(&item.topic).key(&item.key).payload(&raw),
                Duration::from_secs(10),
            )
            .await;
        match result {
            Ok(_) => {
                self.store.acknowledge_outbox(item).await?;
                Ok(())
            }
            Err(_) => {
                self.store.fail_outbox(item).await?;
                Err(error(503, "dq_broker_unavailable"))
            }
        }
    }
    fn admission(&self, scope: &str, operation: &str, key: &str, candidate: Option<&str>) -> Value {
        let mut parameters = json!({"authorized_scope":scope,"policy_version":self.config.policy_version,"max_candidates":1000});
        if let Some(candidate) = candidate {
            parameters["candidate_id"] = json!(candidate);
        }
        json!({"installation_id":self.config.installation_id,"namespace":self.config.namespace,"processor_id":"atheros.dedup","processor_version":"0.1.0","operation":operation,"parameters":parameters,"idempotency_key":key})
    }
    async fn discover(&self) -> Result<()> {
        self.store
            .manifest(&DqPrincipal::internal(), "atheros.dedup", "0.1.0")
            .await?;
        let p = DqPrincipal {
            actor: "octopus-dq-discovery".into(),
            roles: ["automation".into()].into(),
            scopes: self.store.settings.scope_modes.keys().cloned().collect(),
        };
        for (scope, mode) in &self.store.settings.scope_modes {
            let mut request = self.admission(scope, "prepare_candidates", "discovery", None);
            request["policy_version"] = json!(self.config.policy_version);
            let snapshot = self
                .store
                .prepare_snapshot(&request, self.minimum_similarity)
                .await?;
            if snapshot["pairs"].as_array().is_some_and(|a| !a.is_empty()) {
                let key = dq::sha256(&json!([
                    "candidate-preparation",
                    scope,
                    mode,
                    self.config.policy_version,
                    snapshot["source_revision_digest"]
                ]))?;
                match self
                    .store
                    .admit(&p, &self.admission(scope, "prepare_candidates", &key, None))
                    .await
                {
                    Err(e) if e.status == 429 => {}
                    r => {
                        r?;
                    }
                }
            }
        }
        let mut tx = self.store.transaction().await?;
        let rows=tx.query("SELECT decision.candidate_id,decision.decision,policy.authorized_scope FROM atheros_search.merge_decisions decision JOIN atheros_search.merge_candidates candidate USING(candidate_id) JOIN atheros_search.devices l ON l.mac=candidate.mac_a JOIN atheros_search.devices r ON r.mac=candidate.mac_b JOIN octopus_core.dq_scope_policies policy ON policy.installation_id=$1 AND policy.namespace=$2 AND policy.mode IN ('shadow','enabled') AND(policy.authorized_scope='*' OR(l.location_id=policy.authorized_scope AND r.location_id=policy.authorized_scope)) WHERE NOT EXISTS(SELECT 1 FROM octopus_core.dq_decision_sources source WHERE source.candidate_id=decision.candidate_id AND source.decision_revision=encode(sha256(convert_to(jsonb_build_array($1::text,$2::text,policy.authorized_scope::text,policy.policy_version::text,policy.mode::text,decision.candidate_id,decision.decision)::text,'UTF8')),'hex')) ORDER BY decision.candidate_id,policy.authorized_scope LIMIT $3",&[&self.config.installation_id,&self.config.namespace,&i64::from(self.config.batch_size)]).await.map_err(database)?;
        tx.commit().await.map_err(database)?;
        for row in rows {
            let candidate: String = row.get(0);
            let decision: String = row.get(1);
            let scope: String = row.get(2);
            let mode = self
                .store
                .settings
                .scope_modes
                .get(&scope)
                .map(String::as_str)
                .unwrap_or("disabled");
            let key = dq::sha256(&json!([
                "decision-reconciliation",
                candidate,
                decision,
                scope,
                self.config.policy_version,
                mode
            ]))?;
            match self
                .store
                .admit(
                    &p,
                    &self.admission(&scope, "reconcile_decision", &key, Some(&candidate)),
                )
                .await
            {
                Err(e) if e.status == 429 => {}
                r => {
                    r?;
                }
            }
        }
        Ok(())
    }
    async fn reports(&self, stop: CancellationToken) -> Result<()> {
        let epoch = Arc::new(Mutex::new(0u64));
        let mut cfg = ClientConfig::new();
        cfg.set("bootstrap.servers", &self.kafka.bootstrap_servers)
            .set("group.id", REPORT_GROUP)
            .set("auto.offset.reset", "earliest")
            .set("enable.auto.commit", "false")
            .set("enable.auto.offset.store", "false")
            .set("isolation.level", "read_committed")
            .set("allow.auto.create.topics", "false")
            .set("max.partition.fetch.bytes", "131072");
        let consumer: StreamConsumer<ReportContext> = cfg
            .create_with_context(ReportContext {
                epoch: epoch.clone(),
                assigned: self.assigned.clone(),
            })
            .map_err(|_| error(503, "dq_reports_unavailable"))?;
        consumer
            .subscribe(&["dq.worker-reports.v1"])
            .map_err(|_| error(503, "dq_reports_unavailable"))?;
        loop {
            let message = tokio::select! {biased;_=stop.cancelled()=>return Ok(()),message=consumer.recv()=>message.map_err(|_|error(503,"dq_reports_unavailable"))?};
            let generation = *epoch.lock().unwrap_or_else(|e| e.into_inner());
            let topic = message.topic().to_owned();
            let partition = message.partition();
            let offset = message.offset();
            let key = message
                .key()
                .and_then(|k| std::str::from_utf8(k).ok())
                .unwrap_or("");
            let receipt = receipt(
                &self.config,
                REPORT_GROUP,
                &topic,
                partition,
                offset,
                key,
                message.payload().unwrap_or_default(),
            );
            drop(message);
            let mut retry = 0u32;
            loop {
                let result = tokio::select! {biased;_=stop.cancelled()=>return Ok(()),r=self.store.receive_receipt(&receipt)=>r};
                match result {
                    Ok(_) => break,
                    Err(_) => {
                        self.reports.store(false, Ordering::Release);
                        tokio::select! {_=stop.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(1<<retry.min(5)))=>{}}
                        retry = retry.saturating_add(1);
                    }
                }
            }
            let current = epoch.lock().unwrap_or_else(|e| e.into_inner());
            if *current != generation {
                continue;
            }
            let mut offsets = TopicPartitionList::new();
            offsets
                .add_partition_offset(
                    &topic,
                    partition,
                    Offset::Offset(
                        offset
                            .checked_add(1)
                            .ok_or_else(|| error(503, "dq_offset_overflow"))?,
                    ),
                )
                .map_err(|_| error(503, "dq_reports_unavailable"))?;
            consumer
                .commit(&offsets, CommitMode::Sync)
                .map_err(|_| error(503, "dq_reports_unavailable"))?;
            self.reports.store(true, Ordering::Release);
        }
    }
    pub async fn run(&self, stop: CancellationToken) -> Result<()> {
        let reports = async {
            loop {
                let result = self.reports(stop.child_token()).await;
                self.reports.store(false, Ordering::Release);
                self.assigned.store(false, Ordering::Release);
                if stop.is_cancelled() {
                    return Ok(());
                }
                if let Err(e) = result {
                    tracing::warn!(error_code=%e.code,"DQ reports retry");
                }
                tokio::select! {_=stop.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(1))=>{}}
            }
        };
        let maintenance = async {
            loop {
                let result = tokio::select! {biased;_=stop.cancelled()=>break,r=self.tick()=>r};
                self.maintenance.store(result.is_ok(), Ordering::Release);
                if let Err(e) = result {
                    tracing::warn!(error_code=%e.code,"DQ maintenance retry");
                }
                tokio::select! {_=stop.cancelled()=>break,_=tokio::time::sleep(Duration::from_millis(self.config.poll_interval_ms as u64))=>{}}
            }
            Ok::<_, DqError>(())
        };
        let result = tokio::try_join!(reports, maintenance).map(|_| ());
        self.maintenance.store(false, Ordering::Release);
        self.reports.store(false, Ordering::Release);
        self.assigned.store(false, Ordering::Release);
        result
    }
}
