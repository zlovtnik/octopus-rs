mod support;

use octopus::{
    config::{AppConfig, ProcessorConfig},
    processor::ProcessorId,
    runtime::Planner,
    supervision::{LeaseStore, ProcessorLifecycle, Supervisor, Workload, WorkloadError},
};
use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;

async fn wait_for(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("runtime state did not converge");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_planning_is_atomic_and_completion_repair_resumes_from_checkpoint() {
    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let mut cfg = AppConfig::default();
    cfg.ingest.stream_names = vec!["proxy.events".into(), "wireless.audit".into()];
    cfg.cron.ingest_batch_size = 1;
    fixture.admin("INSERT INTO octopus_core.sync_events(stream_name,dedupe_key,observed_at,payload_ref,status,attempt_count) VALUES('proxy.events','first','2026-11-18T00:00:00Z','inline://json/e30','pending',0),('wireless.audit','second','2026-11-18T00:00:01Z','inline://json/e30','pending',0),('ignored','third','2026-11-18T00:00:02Z','inline://json/e30','pending',0)");
    let planner = Planner::new(fixture.runtime.clone(), &cfg);
    assert_eq!(planner.process_ingest().await.unwrap(), 1);
    assert_eq!(planner.process_ingest().await.unwrap(), 1);
    assert_eq!(planner.process_ingest().await.unwrap(), 0);
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let rows=tx.query("SELECT e.stream_name,e.status,e.attempt_count,b.cursor_start,b.cursor_end FROM sync_events e LEFT JOIN sync_batches b ON b.stream_name=e.stream_name AND b.dedupe_key=e.dedupe_key ORDER BY e.observed_at",&[]).await.unwrap();
    assert_eq!(rows[0].get::<_, String>(1), "batched");
    assert_eq!(rows[0].get::<_, i32>(2), 1);
    assert_eq!(rows[0].get::<_, String>(3), "0");
    assert_eq!(rows[0].get::<_, String>(4), "first");
    assert_eq!(rows[1].get::<_, String>(4), "1794960001");
    assert_eq!(rows[2].get::<_, String>(1), "pending");
    tx.commit().await.unwrap();
    fixture.admin("UPDATE octopus_core.sync_batches SET status='completed';UPDATE octopus_core.sync_jobs SET status='completed'");
    assert_eq!(planner.reconcile_completed_events().await.unwrap(), 1);
    assert_eq!(planner.reconcile_completed_events().await.unwrap(), 1);
    assert_eq!(planner.reconcile_completed_events().await.unwrap(), 0);
    assert_eq!(planner.reconcile_completed_events().await.unwrap(), 0);
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let count: i64 = tx
        .query(
            "SELECT count(*) FROM sync_events WHERE status='completed'",
            &[],
        )
        .await
        .unwrap()[0]
        .get(0);
    assert_eq!(count, 2);
    let rows=tx.query("SELECT status,rows_processed FROM processor_checkpoints WHERE processor_name='sync-backlog-recovery' AND shard_id='event-completion-v1'",&[]).await.unwrap();
    assert_eq!(rows[0].get::<_, String>(0), "healthy");
    assert_eq!(rows[0].get::<_, i64>(1), 2);
    tx.commit().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canonical_runtime_restarts_records_cancellation_and_rejects_stale_fences() {
    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let runtime = fixture.runtime.clone();
    let id = ProcessorId::SyncJobPlanner;
    let config = ProcessorConfig {
        restart_base_delay_ms: 5,
        restart_max_delay_ms: 20,
        ..ProcessorConfig::default()
    };
    let supervisor = Supervisor::create(config.clone(), BTreeSet::from([id]), runtime.clone())
        .await
        .unwrap();
    assert!(!supervisor.ready());
    let attempts = Arc::new(AtomicUsize::new(0));
    let started = attempts.clone();
    let workload = Workload::new(id, |stop| {
        Box::pin(async move {
            stop.cancelled().await;
            Ok(())
        })
    })
    .with_startup(move || {
        let attempt = started.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if attempt == 0 {
                Err(WorkloadError::Retryable(
                    "temporary dependency failure".into(),
                ))
            } else {
                Ok(())
            }
        })
    });
    let stop = CancellationToken::new();
    let runner = supervisor.clone();
    let cancelled = stop.clone();
    let task = tokio::spawn(async move { runner.run(vec![workload], cancelled).await });
    wait_for(|| supervisor.ready()).await;
    assert!(attempts.load(Ordering::SeqCst) >= 2);
    assert_eq!(
        supervisor.statuses()[&id].lifecycle,
        ProcessorLifecycle::Ready
    );
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut tx = runtime.begin_worker().await.unwrap();
    let statuses = tx
        .query(
            "SELECT status FROM processor_runs WHERE processor_name=$1 ORDER BY started_at",
            &[&id.as_str()],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();
    assert!(statuses.contains(&"retrying".into()));
    assert!(statuses.contains(&"cancelled".into()));
    assert!(!statuses.contains(&"running".into()));
    tx.commit().await.unwrap();

    let supervisor = Supervisor::create(config, BTreeSet::from([id]), runtime.clone())
        .await
        .unwrap();
    let workload = Workload::new(id, |_| {
        Box::pin(async { Err(WorkloadError::Terminal("password=do-not-retain".into())) })
    });
    let stop = CancellationToken::new();
    let runner = supervisor.clone();
    let cancelled = stop.clone();
    let task = tokio::spawn(async move { runner.run(vec![workload], cancelled).await });
    wait_for(|| supervisor.statuses()[&id].lifecycle == ProcessorLifecycle::FailedTerminal).await;
    assert!(!supervisor.ready());
    assert!(!supervisor.statuses()[&id]
        .last_error
        .as_ref()
        .unwrap()
        .contains("do-not-retain"));
    stop.cancel();
    task.await.unwrap().unwrap();

    let leases = LeaseStore::new(runtime.clone());
    let first = leases
        .acquire("processor", id.as_str(), "owner-a", 60)
        .await
        .unwrap()
        .unwrap();
    assert!(leases
        .acquire("processor", id.as_str(), "owner-b", 60)
        .await
        .unwrap()
        .is_none());
    assert!(leases
        .renew("processor", id.as_str(), &first, 60)
        .await
        .unwrap());
    let mut forged = first.clone();
    forged.token = "wrong-token".into();
    assert!(!leases
        .release("processor", id.as_str(), &forged)
        .await
        .unwrap());
    let mut tx = runtime.begin_worker().await.unwrap();
    assert!(
        !LeaseStore::guard(&mut tx, "processor", id.as_str(), &forged)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    fixture.admin("UPDATE octopus_core.work_leases SET lease_expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second'");
    let next = leases
        .acquire("processor", id.as_str(), "owner-b", 60)
        .await
        .unwrap()
        .unwrap();
    assert!(next.fence > first.fence);
    assert!(!leases
        .renew("processor", id.as_str(), &first, 60)
        .await
        .unwrap());
    assert!(!leases
        .release("processor", id.as_str(), &first)
        .await
        .unwrap());
    let mut tx = runtime.begin_worker().await.unwrap();
    assert!(LeaseStore::guard(&mut tx, "processor", id.as_str(), &next)
        .await
        .unwrap());
    tx.commit().await.unwrap();
    assert!(leases
        .release("processor", id.as_str(), &next)
        .await
        .unwrap());

    let stop = CancellationToken::new();
    let token = stop.clone();
    let runner = leases.clone();
    let task = tokio::spawn(async move {
        runner
            .run_fenced(id, "owner-c", 3, token, |_| {
                Box::pin(std::future::pending::<Result<(), WorkloadError>>())
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut tx = runtime.begin_worker().await.unwrap();
            let active: bool = tx
                .query(
                    "SELECT EXISTS(SELECT 1 FROM work_leases WHERE owner_id='owner-c')",
                    &[],
                )
                .await
                .unwrap()[0]
                .get(0);
            tx.commit().await.unwrap();
            if active {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    stop.cancel();
    assert!(task.await.unwrap().is_err());
    assert!(leases
        .acquire("processor", id.as_str(), "owner-d", 60)
        .await
        .unwrap()
        .is_some());
}
