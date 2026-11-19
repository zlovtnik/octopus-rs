use super::Result;
use futures_util::future::BoxFuture;
use octopus::{
    config::AppConfig,
    dispatch::DispatchStore,
    domain::BrokerRecordMetadata,
    ingestion::IngestionStore,
    kafka::{CommitObserver, Poison},
    load::LoadStore,
    observability::Metrics,
    postgres::PgRuntime,
    processor::ProcessorId,
    projections::{ProjectionError, ProjectionStore, WirelessObservation},
    runtime::{
        consumer_workloads_observed, Backpressure, OutboxPublisher, Planner, RuntimeError,
        WirelessProjectionHandler,
    },
    supervision::{LeaseStore, Workload},
};
use serde_json::Value;
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use uuid::Uuid;

// Only advertise processors with concrete native runtime wiring.
const PERIODIC: [ProcessorId; 4] = [
    ProcessorId::SyncJobPlanner,
    ProcessorId::SyncBacklogRecovery,
    ProcessorId::SyncLoadDispatch,
    ProcessorId::SyncOutboxPublisher,
];

pub fn validate(enabled: &BTreeSet<ProcessorId>) -> Result {
    let available: Vec<_> = ProcessorId::KAFKA_CONSUMERS
        .into_iter()
        .chain(PERIODIC)
        .collect();
    octopus::processor::select_workloads(enabled, &available)?;
    Ok(())
}

struct Wireless(ProjectionStore);

impl WirelessProjectionHandler for Wireless {
    fn decode(&self, raw: &str) -> std::result::Result<Value, Poison> {
        let value =
            serde_json::from_str(raw).map_err(|_| Poison::invalid("invalid wireless JSON"))?;
        WirelessObservation::from_value(&value).map_err(|e| Poison::invalid(e.to_string()))?;
        Ok(value)
    }

    fn project(
        &self,
        value: Value,
        metadata: BrokerRecordMetadata,
    ) -> BoxFuture<'_, std::result::Result<(), RuntimeError>> {
        Box::pin(async move {
            self.0
                .project_wireless_record(value, &metadata)
                .await
                .map(|_| ())
                .map_err(|e| match e {
                    ProjectionError::Invalid(message) => RuntimeError::Permanent(message.into()),
                    ProjectionError::CoordinateConflict => RuntimeError::Invariant(e.to_string()),
                    // Database or schema failures must keep the broker offset uncommitted.
                    ProjectionError::Database(_) => RuntimeError::Retryable(e.to_string()),
                })
        })
    }
}

struct Commits(Metrics);

impl CommitObserver for Commits {
    fn committed(&self, _: &str, _: &str, _: i32, _: i64, records: u64) {
        self.0.broker_committed(records);
    }
}

pub fn build(
    config: &AppConfig,
    enabled: &BTreeSet<ProcessorId>,
    db: Arc<PgRuntime>,
    backpressure: Backpressure,
    metrics: &Metrics,
) -> Result<Vec<Workload>> {
    let mut workloads = Vec::new();
    if ProcessorId::KAFKA_CONSUMERS
        .iter()
        .any(|id| enabled.contains(id))
    {
        let load = LoadStore::new(
            db.clone(),
            config.sync.outbox_dir.clone().into(),
            500,
            config.postgres.load_chunk_max_bytes as usize,
        );
        let wireless =
            ProjectionStore::with_wireless(db.clone(), config.wireless.projection.clone());
        workloads.extend(
            consumer_workloads_observed(
                config,
                IngestionStore::new(db.clone()),
                Arc::new(load),
                Arc::new(Wireless(wireless)),
                backpressure,
                Some(Arc::new(Commits(metrics.clone()))),
            )?
            .into_iter()
            .filter(|w| enabled.contains(&w.id)),
        );
    }
    let interval = Duration::from_millis(config.cron.idle_sleep_ms as u64);
    let owner = Uuid::new_v4().to_string();
    let dispatch = DispatchStore::new(db.clone());
    for id in PERIODIC.into_iter().filter(|id| enabled.contains(id)) {
        if id == ProcessorId::SyncOutboxPublisher {
            let publisher = OutboxPublisher::new(
                dispatch.clone(),
                &config.kafka,
                owner.clone(),
                config.cron.batch_dispatch_lease_seconds,
                config.cron.scan_retry_backoff_seconds,
                config.cron.batch_dispatch_retry_max_seconds,
            )?;
            workloads.push(publisher.workload(interval, config.cron.dispatch_batch_size as usize));
            continue;
        }
        let planner = Planner::new(db.clone(), config);
        let leases = LeaseStore::new(db.clone());
        let dispatch = dispatch.clone();
        let streams = config.ingest.load_stream_names.clone();
        let limit = i64::from(config.cron.ingest_batch_size);
        let attempts = config.cron.batch_max_attempts;
        let owner = owner.clone();
        let ttl = (interval * 2).as_secs().max(30) as i32;
        workloads.push(Workload::new(id, move |stop| {
            let (planner, leases, dispatch, streams, owner) = (
                planner.clone(),
                leases.clone(),
                dispatch.clone(),
                streams.clone(),
                owner.clone(),
            );
            Box::pin(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = stop.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(interval) => {}
                    }
                    let planner = planner.clone();
                    let dispatch = dispatch.clone();
                    let streams = streams.clone();
                    let result = leases
                        .run_fenced(id, &owner, ttl, stop.clone(), move |_| {
                            Box::pin(async move {
                                match id {
                                    ProcessorId::SyncJobPlanner => {
                                        planner.process_ingest().await?;
                                    }
                                    ProcessorId::SyncBacklogRecovery => {
                                        planner
                                            .recover_stale_batches()
                                            .await
                                            .map_err(octopus::runtime::load_workload)?;
                                    }
                                    ProcessorId::SyncLoadDispatch => {
                                        dispatch
                                            .enqueue_pending_streams(&streams, limit, attempts)
                                            .await
                                            .map_err(octopus::runtime::load_workload)?;
                                    }
                                    _ => unreachable!("scheduled sync processor"),
                                }
                                Ok(())
                            })
                        })
                        .await;
                    if stop.is_cancelled() {
                        return Ok(());
                    }
                    result?;
                }
            })
        }));
    }
    Ok(workloads)
}
