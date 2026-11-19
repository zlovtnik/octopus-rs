//! Restartable processor lifetimes and database-backed fenced work ownership.

use crate::{
    config::ProcessorConfig,
    errors::sanitize,
    postgres::{PgError, PgRuntime, PgTransaction},
    processor::{select_workloads, ProcessorId, ProcessorOwner, RetryPolicy},
};
use chrono::{DateTime, Utc};
use futures_util::future::BoxFuture;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{task::JoinSet, time::Instant};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessorLifecycle {
    Disabled,
    Starting,
    Ready,
    BackingOff,
    FailedTerminal,
}

impl ProcessorLifecycle {
    fn database_value(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Starting => "running",
            Self::Ready => "idle",
            Self::BackingOff => "degraded",
            Self::FailedTerminal => "failed",
        }
    }
    fn from_database(value: &str) -> Option<Self> {
        Some(match value {
            "disabled" => Self::Disabled,
            "running" => Self::Starting,
            "idle" => Self::Ready,
            "degraded" => Self::BackingOff,
            "failed" => Self::FailedTerminal,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProcessorStatus {
    pub lifecycle: ProcessorLifecycle,
    pub restart_count: i32,
    pub last_error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum WorkloadError {
    #[error("retryable processor failure: {0}")]
    Retryable(String),
    #[error("terminal processor failure: {0}")]
    Terminal(String),
}
impl From<PgError> for WorkloadError {
    fn from(value: PgError) -> Self {
        if matches!(value,PgError::Acquisition|PgError::Deadline) || crate::postgres::PostgresErrorClass::classify(&value)
            == crate::postgres::PostgresErrorClass::Retryable
        {
            Self::Retryable(sanitize(&value.to_string()))
        } else {
            Self::Terminal(sanitize(&value.to_string()))
        }
    }
}

type Operation =
    Arc<dyn Fn(CancellationToken) -> BoxFuture<'static, Result<(), WorkloadError>> + Send + Sync>;
type Startup = Arc<dyn Fn() -> BoxFuture<'static, Result<(), WorkloadError>> + Send + Sync>;
type Readiness = Arc<dyn Fn() -> bool + Send + Sync>;
#[derive(Clone)]
pub struct Workload {
    pub id: ProcessorId,
    run: Operation,
    startup: Startup,
    readiness: Readiness,
}
impl Workload {
    pub fn new(
        id: ProcessorId,
        run: impl Fn(CancellationToken) -> BoxFuture<'static, Result<(), WorkloadError>>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        Self {
            id,
            run: Arc::new(run),
            startup: Arc::new(|| Box::pin(async { Ok(()) })),
            readiness: Arc::new(|| true),
        }
    }
    pub fn with_startup(
        mut self,
        startup: impl Fn() -> BoxFuture<'static, Result<(), WorkloadError>> + Send + Sync + 'static,
    ) -> Self {
        self.startup = Arc::new(startup);
        self
    }
    pub fn with_readiness(mut self, ready: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        self.readiness = Arc::new(ready);
        self
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SupervisionError {
    #[error("invalid processor workloads: {0}")]
    Configuration(String),
    #[error("processor task panicked")]
    Task,
}

#[derive(Clone)]
pub struct Supervisor {
    runtime: Arc<PgRuntime>,
    config: ProcessorConfig,
    enabled: BTreeSet<ProcessorId>,
    statuses: Arc<RwLock<BTreeMap<ProcessorId, ProcessorStatus>>>,
    ready_checks: Arc<RwLock<BTreeMap<ProcessorId, Readiness>>>,
}
impl Supervisor {
    pub async fn create(
        config: ProcessorConfig,
        enabled: BTreeSet<ProcessorId>,
        runtime: Arc<PgRuntime>,
    ) -> Result<Self, PgError> {
        let mut tx = runtime.begin_worker().await?;
        let previous = tx
            .query(
                "SELECT processor_name,status,consecutive_failures,last_error FROM processor_state",
                &[],
            )
            .await?
            .into_iter()
            .filter_map(|row| {
                let id = ProcessorId::from_string(row.get::<_, String>(0).as_str()).ok()?;
                Some((
                    id,
                    ProcessorStatus {
                        lifecycle: ProcessorLifecycle::from_database(row.get::<_, &str>(1))?,
                        restart_count: row.get(2),
                        last_error: row.get(3),
                    },
                ))
            })
            .collect::<BTreeMap<_, _>>();
        tx.commit().await?;
        let statuses = ProcessorId::ALL
            .into_iter()
            .filter(|id| id.owner() == ProcessorOwner::Octopus || enabled.contains(id))
            .map(|id| {
                let old = previous.get(&id);
                (
                    id,
                    ProcessorStatus {
                        lifecycle: if enabled.contains(&id) {
                            ProcessorLifecycle::Starting
                        } else {
                            ProcessorLifecycle::Disabled
                        },
                        restart_count: old.map_or(0, |s| s.restart_count),
                        last_error: old.and_then(|s| s.last_error.clone()),
                    },
                )
            })
            .collect();
        let supervisor = Self {
            runtime,
            config,
            enabled,
            statuses: Arc::new(RwLock::new(statuses)),
            ready_checks: Arc::new(RwLock::new(BTreeMap::new())),
        };
        for (id, status) in supervisor.statuses() {
            supervisor.persist_status(id, status).await?;
        }
        Ok(supervisor)
    }
    pub fn statuses(&self) -> BTreeMap<ProcessorId, ProcessorStatus> {
        self.statuses
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn ready(&self) -> bool {
        self.statuses
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .all(|s| {
                matches!(
                    s.lifecycle,
                    ProcessorLifecycle::Ready | ProcessorLifecycle::Disabled
                )
            })
            && self
                .ready_checks
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .all(|ready| ready())
    }

    async fn persist_status(
        &self,
        id: ProcessorId,
        status: ProcessorStatus,
    ) -> Result<(), PgError> {
        let mut tx = self.runtime.begin_worker().await?;
        let now = Utc::now();
        let started = (status.lifecycle == ProcessorLifecycle::Starting).then_some(now);
        let succeeded = (status.lifecycle == ProcessorLifecycle::Ready).then_some(now);
        let failed = matches!(
            status.lifecycle,
            ProcessorLifecycle::BackingOff | ProcessorLifecycle::FailedTerminal
        )
        .then_some(now);
        let failures = if failed.is_some() {
            status.restart_count.max(1)
        } else {
            0
        };
        tx.execute("INSERT INTO processor_state(processor_name,shard_id,status,last_started_at,last_succeeded_at,last_failed_at,consecutive_failures,last_error,updated_at) VALUES($1,'default',$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(processor_name,shard_id) DO UPDATE SET status=EXCLUDED.status,last_started_at=COALESCE(EXCLUDED.last_started_at,processor_state.last_started_at),last_succeeded_at=COALESCE(EXCLUDED.last_succeeded_at,processor_state.last_succeeded_at),last_failed_at=COALESCE(EXCLUDED.last_failed_at,processor_state.last_failed_at),consecutive_failures=EXCLUDED.consecutive_failures,last_error=EXCLUDED.last_error,updated_at=EXCLUDED.updated_at",&[&id.as_str(),&status.lifecycle.database_value(),&started,&succeeded,&failed,&failures,&status.last_error,&now]).await?;
        tx.commit().await?;
        self.statuses
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, status);
        Ok(())
    }
    async fn start_run(&self, id: ProcessorId, run_id: &str) -> Result<(), PgError> {
        let mut tx = self.runtime.begin_worker().await?;
        tx.execute("INSERT INTO processor_runs(run_id,processor_name,shard_id,status,started_at) VALUES(CAST($1 AS text)::uuid,$2,'default','running',CURRENT_TIMESTAMP)",&[&run_id,&id.as_str()]).await?;
        tx.commit().await
    }
    async fn finish_run(
        &self,
        run_id: &str,
        status: &str,
        error: Option<&WorkloadError>,
    ) -> Result<(), PgError> {
        let message = error.map(|e| sanitize(&e.to_string()));
        let class = error.map(|e| match e {
            WorkloadError::Terminal(_) => "TerminalProcessorError",
            WorkloadError::Retryable(_) => "RetryableDependencyException",
        });
        let mut tx = self.runtime.begin_worker().await?;
        let count=tx.execute("UPDATE processor_runs SET status=$2,finished_at=CURRENT_TIMESTAMP,error_class=$3,error_text=$4 WHERE run_id::text=$1 AND status='running'",&[&run_id,&status,&class,&message]).await?;
        if count != 1 {
            let rows = tx
                .query(
                    "SELECT status FROM processor_runs WHERE run_id::text=$1",
                    &[&run_id],
                )
                .await?;
            if rows.first().map(|r| r.get::<_, String>(0)).as_deref() != Some(status) {
                return Err(PgError::Configuration("processor run is not running"));
            }
        }
        tx.commit().await
    }
    pub async fn run(
        &self,
        workloads: Vec<Workload>,
        stop: CancellationToken,
    ) -> Result<(), SupervisionError> {
        let ids = workloads.iter().map(|w| w.id).collect::<Vec<_>>();
        select_workloads(&self.enabled, &ids).map_err(SupervisionError::Configuration)?;
        *self.ready_checks.write().unwrap_or_else(|e| e.into_inner()) = workloads
            .iter()
            .filter(|w| self.enabled.contains(&w.id))
            .map(|w| (w.id, w.readiness.clone()))
            .collect();
        let child = stop.child_token();
        let mut tasks = JoinSet::new();
        for workload in workloads
            .into_iter()
            .filter(|w| self.enabled.contains(&w.id))
        {
            let supervisor = self.clone();
            let cancelled = child.clone();
            tasks.spawn(async move { supervisor.supervise(workload, cancelled).await });
        }
        let mut result = Ok(());
        tokio::select! {
            _=stop.cancelled()=>{},
            finished=tasks.join_next(),if !tasks.is_empty()=>{if finished.is_some_and(|r|r.is_err()){result=Err(SupervisionError::Task);}},
        }
        child.cancel();
        while let Some(finished) = tasks.join_next().await {
            if finished.is_err() {
                result = Err(SupervisionError::Task);
            }
        }
        result
    }
    async fn supervise(&self, workload: Workload, stop: CancellationToken) {
        let retry = RetryPolicy::new(
            self.config.restart_base_delay_ms,
            self.config.restart_max_delay_ms,
            None,
        )
        .expect("validated processor retry policy");
        let mut restarts = 0_i32;
        loop {
            if stop.is_cancelled() {
                return;
            }
            let run_id = uuid::Uuid::new_v4().to_string();
            let started = Instant::now();
            let cycle = async {
                self.start_run(workload.id, &run_id)
                    .await
                    .map_err(|e| WorkloadError::Retryable(sanitize(&e.to_string())))?;
                self.persist_status(
                    workload.id,
                    ProcessorStatus {
                        lifecycle: ProcessorLifecycle::Starting,
                        restart_count: restarts,
                        last_error: None,
                    },
                )
                .await
                .map_err(|e| WorkloadError::Retryable(sanitize(&e.to_string())))?;
                (workload.startup)().await?;
                self.persist_status(
                    workload.id,
                    ProcessorStatus {
                        lifecycle: ProcessorLifecycle::Ready,
                        restart_count: restarts,
                        last_error: None,
                    },
                )
                .await
                .map_err(|e| WorkloadError::Retryable(sanitize(&e.to_string())))?;
                (workload.run)(stop.clone()).await?;
                Err::<(), WorkloadError>(WorkloadError::Retryable(
                    "processor stream completed unexpectedly".into(),
                ))
            };
            let outcome =
                tokio::select! {biased;_=stop.cancelled()=>None,result=cycle=>Some(result)};
            let Some(Err(error)) = outcome else {
                let _ = self.finish_run(&run_id, "cancelled", None).await;
                return;
            };
            if matches!(error, WorkloadError::Terminal(_)) {
                // A failed status write must not leave in-memory readiness green.
                let status = ProcessorStatus {
                    lifecycle: ProcessorLifecycle::FailedTerminal,
                    restart_count: restarts,
                    last_error: Some(sanitize(&error.to_string())),
                };
                self.statuses
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(workload.id, status.clone());
                let _ = self.finish_run(&run_id, "failed_terminal", Some(&error)).await;
                let _ = self.persist_status(workload.id, status).await;
                stop.cancelled().await;
                return;
            }
            if started.elapsed() >= Duration::from_millis(self.config.restart_max_delay_ms as u64) {
                restarts = 0;
            }
            restarts = restarts.saturating_add(1);
            let status = ProcessorStatus {
                lifecycle: ProcessorLifecycle::BackingOff,
                restart_count: restarts,
                last_error: Some(sanitize(&error.to_string())),
            };
            self.statuses
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .insert(workload.id, status.clone());
            let _ = self.finish_run(&run_id, "retrying", Some(&error)).await;
            let _ = self.persist_status(workload.id, status).await;
            tokio::select! {_=stop.cancelled()=>return,_=tokio::time::sleep(retry.delay(workload.id,restarts))=>{}}
        }
    }
}

/// The callback is one real tick; cancellation drops it before another tick.
pub fn periodic_workload(
    id: ProcessorId,
    interval: Duration,
    action: impl Fn() -> BoxFuture<'static, Result<(), WorkloadError>> + Send + Sync + 'static,
) -> Workload {
    let action = Arc::new(action);
    Workload::new(id, move |stop| {
        let action = action.clone();
        Box::pin(async move {
            loop {
                tokio::select! {biased;_=stop.cancelled()=>return Ok(()),result=action()=>result?}
                tokio::select! {_=stop.cancelled()=>return Ok(()),_=tokio::time::sleep(interval)=>{}}
            }
        })
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub scope: String,
    pub owner_id: String,
    pub token: String,
    pub fence: i64,
    pub expires_at: DateTime<Utc>,
}
#[derive(Clone)]
pub struct LeaseStore {
    runtime: Arc<PgRuntime>,
}
impl LeaseStore {
    pub fn new(runtime: Arc<PgRuntime>) -> Self {
        Self { runtime }
    }
    pub async fn acquire(
        &self,
        resource_type: &str,
        resource_id: &str,
        owner: &str,
        ttl: i32,
    ) -> Result<Option<Lease>, PgError> {
        let token = uuid::Uuid::new_v4().to_string();
        let mut tx = self.runtime.begin_worker().await?;
        tx.execute("INSERT INTO work_leases(resource_type,resource_id) VALUES($1,$2) ON CONFLICT(resource_type,resource_id) DO UPDATE SET resource_id=EXCLUDED.resource_id",&[&resource_type,&resource_id]).await?;
        let rows=tx.query("WITH sampled AS MATERIALIZED (SELECT clock_timestamp() AS now) UPDATE work_leases SET owner_id=$3,lease_token=$4,fence=fence+1,attempt_count=attempt_count+1,lease_expires_at=sampled.now+$5*INTERVAL '1 second',last_error=NULL,updated_at=sampled.now FROM sampled WHERE resource_type=$1 AND resource_id=$2 AND (next_attempt_at IS NULL OR next_attempt_at<=sampled.now) AND (lease_expires_at IS NULL OR lease_expires_at<=sampled.now) RETURNING fence,lease_expires_at",&[&resource_type,&resource_id,&owner,&token,&f64::from(ttl.max(1))]).await?;
        let lease = rows.first().map(|r| Lease {
            scope: format!("{resource_type}/{resource_id}"),
            owner_id: owner.into(),
            token,
            fence: r.get(0),
            expires_at: r.get(1),
        });
        tx.commit().await?;
        Ok(lease)
    }
    pub async fn renew(
        &self,
        resource_type: &str,
        resource_id: &str,
        lease: &Lease,
        ttl: i32,
    ) -> Result<bool, PgError> {
        let mut tx = self.runtime.begin_worker().await?;
        let count=tx.execute("UPDATE work_leases SET lease_expires_at=CURRENT_TIMESTAMP+$6*INTERVAL '1 second',updated_at=CURRENT_TIMESTAMP WHERE resource_type=$1 AND resource_id=$2 AND owner_id=$3 AND lease_token=$4 AND fence=$5 AND lease_expires_at>CURRENT_TIMESTAMP",&[&resource_type,&resource_id,&lease.owner_id,&lease.token,&lease.fence,&f64::from(ttl.max(1))]).await?;
        tx.commit().await?;
        Ok(count == 1)
    }
    pub async fn release(
        &self,
        resource_type: &str,
        resource_id: &str,
        lease: &Lease,
    ) -> Result<bool, PgError> {
        let mut tx = self.runtime.begin_worker().await?;
        let count=tx.execute("UPDATE work_leases SET owner_id=NULL,lease_token=NULL,lease_expires_at=NULL,next_attempt_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE resource_type=$1 AND resource_id=$2 AND owner_id=$3 AND lease_token=$4 AND fence=$5",&[&resource_type,&resource_id,&lease.owner_id,&lease.token,&lease.fence]).await?;
        tx.commit().await?;
        Ok(count == 1)
    }
    /// Lock the fence in the same transaction as the protected mutation.
    pub async fn guard(
        tx: &mut PgTransaction,
        resource_type: &str,
        resource_id: &str,
        lease: &Lease,
    ) -> Result<bool, PgError> {
        Ok(!tx.query("WITH fenced AS MATERIALIZED (SELECT lease_expires_at FROM work_leases WHERE resource_type=$1 AND resource_id=$2 AND owner_id=$3 AND lease_token=$4 AND fence=$5 FOR UPDATE) SELECT 1 FROM fenced WHERE lease_expires_at>clock_timestamp()",&[&resource_type,&resource_id,&lease.owner_id,&lease.token,&lease.fence]).await?.is_empty())
    }
    pub async fn run_fenced<T: Send>(
        &self,
        id: ProcessorId,
        owner: &str,
        ttl: i32,
        stop: CancellationToken,
        operation: impl FnOnce(Lease) -> BoxFuture<'static, Result<T, WorkloadError>>,
    ) -> Result<Option<T>, WorkloadError> {
        let Some(lease) = self.acquire("processor", id.as_str(), owner, ttl).await? else {
            return Ok(None);
        };
        let renew = async {
            loop {
                tokio::time::sleep(Duration::from_secs(ttl.max(1) as u64) / 3).await;
                if !self.renew("processor", id.as_str(), &lease, ttl).await? {
                    return Err(WorkloadError::Retryable("processor lease was lost".into()));
                }
            }
        };
        let result = tokio::select! {biased;_=stop.cancelled()=>Err(WorkloadError::Retryable("processor cancelled".into())),result=operation(lease.clone())=>result,result=renew=>result};
        let release = self.release("processor", id.as_str(), &lease).await;
        match result {
            Err(error) => Err(error),
            Ok(value) => {
                release?;
                Ok(Some(value))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lifecycle_database_contract() {
        for value in [
            ProcessorLifecycle::Disabled,
            ProcessorLifecycle::Starting,
            ProcessorLifecycle::Ready,
            ProcessorLifecycle::BackingOff,
            ProcessorLifecycle::FailedTerminal,
        ] {
            assert_eq!(
                ProcessorLifecycle::from_database(value.database_value()),
                Some(value)
            );
        }
        assert_eq!(ProcessorLifecycle::from_database("ready"), None);
    }
    #[tokio::test]
    async fn periodic_tick_cancellation_is_joined() {
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = count.clone();
        let w = periodic_workload(
            ProcessorId::SyncJobPlanner,
            Duration::from_secs(100),
            move || {
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            },
        );
        let stop = CancellationToken::new();
        let future = (w.run)(stop.clone());
        tokio::pin!(future);
        tokio::select! {_=tokio::task::yield_now()=>{},result=&mut future=>panic!("unexpected completion {result:?}")};
        stop.cancel();
        future.await.unwrap();
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
