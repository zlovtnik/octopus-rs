use super::{ArchiveError, PayloadArchiver};
use crate::{
    config::ArchiveConfig,
    postgres::{PgRuntime, PgTransaction},
    supervision::{Lease, LeaseStore},
};
use chrono::{Duration as ChronoDuration, Utc};
use futures_util::future::BoxFuture;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

pub type MaintenanceLease = Lease;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetentionCounts {
    pub selected: i64,
    pub archived: i64,
    pub deleted: i64,
}

#[derive(Clone)]
pub struct RetentionStore {
    runtime: Arc<PgRuntime>,
    leases: LeaseStore,
}

impl RetentionStore {
    pub fn new(runtime: Arc<PgRuntime>) -> Self {
        Self {
            leases: LeaseStore::new(runtime.clone()),
            runtime,
        }
    }

    pub async fn run_events(
        &self,
        owner: &str,
        config: ArchiveConfig,
        archiver: PayloadArchiver,
        lease_ttl_seconds: i32,
        stop: CancellationToken,
    ) -> Result<Option<RetentionCounts>, ArchiveError> {
        let store = self.clone();
        let days = config.event_retention_days;
        self.run_retention(
            owner,
            "event-retention",
            "wireless-event-retention",
            "sync_events",
            days,
            lease_ttl_seconds,
            stop,
            move |lease, progress| {
                Box::pin(async move {
                    let archived = archiver.archive_candidates(Some(&lease), || {
                        progress.lock().unwrap_or_else(|error| error.into_inner()).archived += 1;
                    }).await?;
                    let mut counts = store.retain_events(&config, &lease).await?;
                    counts.archived = archived as i64;
                    *progress.lock().unwrap_or_else(|error| error.into_inner()) = counts;
                    store.prune_tombstones_fenced(config.batch_size, Some(&lease)).await?;
                    Ok(counts)
                })
            },
        )
        .await
    }

    pub async fn run_search(
        &self,
        owner: &str,
        config: ArchiveConfig,
        lease_ttl_seconds: i32,
        stop: CancellationToken,
    ) -> Result<Option<RetentionCounts>, ArchiveError> {
        let store = self.clone();
        let days = config.search_retention_days;
        self.run_retention(
            owner,
            "search-retention",
            "search-document-retention",
            "atheros_search.search_documents",
            days,
            lease_ttl_seconds,
            stop,
            move |lease, _| Box::pin(async move { store.retain_search(&config, &lease).await }),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_retention(
        &self,
        owner: &str,
        resource_id: &str,
        policy: &str,
        table: &str,
        days: i32,
        ttl: i32,
        stop: CancellationToken,
        operation: impl FnOnce(Lease, Arc<std::sync::Mutex<RetentionCounts>>) -> BoxFuture<'static, Result<RetentionCounts, ArchiveError>>,
    ) -> Result<Option<RetentionCounts>, ArchiveError> {
        if stop.is_cancelled() {
            return Err(ArchiveError::Cancelled);
        }
        let Some(lease) = self
            .leases
            .acquire("maintenance", resource_id, owner, ttl)
            .await?
        else {
            return Ok(None);
        };
        let run = uuid::Uuid::new_v4().to_string();
        let progress = Arc::new(std::sync::Mutex::new(RetentionCounts::default()));
        let cutoff = Utc::now() - ChronoDuration::days(i64::from(days.max(1)));
        let result=async {
            let mut tx=self.runtime.begin_worker().await?;
            if !LeaseStore::guard(&mut tx,"maintenance",resource_id,&lease).await? {return Err(ArchiveError::LeaseLost);}
            let inserted=tx.execute("INSERT INTO retention_runs(run_id,policy_name,target_table,cutoff_at,status,lease_owner_id,lease_fence,started_at) VALUES($1,$2,$3,$4,'running',$5,$6,CURRENT_TIMESTAMP)",&[&run,&policy,&table,&cutoff,&lease.owner_id,&lease.fence]).await?;
            if inserted!=1 {return Err(ArchiveError::CandidateChanged);}
            tx.commit().await?;
            let renew=async {loop {
                tokio::time::sleep(Duration::from_secs(ttl.max(1) as u64)/3).await;
                if !self.leases.renew("maintenance",resource_id,&lease,ttl).await? {return Err(ArchiveError::LeaseLost);}
            }};
            tokio::select! {biased;
                _=stop.cancelled()=>Err(ArchiveError::Cancelled),
                result=operation(lease.clone(), progress.clone())=>result,
                result=renew=>result,
            }
        }.await;
        let committed = *progress.lock().unwrap_or_else(|error| error.into_inner());
        let (status, counts, error) = match &result {
            Ok(counts) => ("completed", *counts, None),
            Err(ArchiveError::Cancelled) => (
                "cancelled",
                committed,
                Some("retention processor cancelled".to_owned()),
            ),
            Err(error) => (
                "failed",
                committed,
                Some(crate::errors::sanitize(&error.to_string())),
            ),
        };
        let finished = self
            .finish_run(&run, status, counts, error.as_deref())
            .await;
        let released = self
            .leases
            .release("maintenance", resource_id, &lease)
            .await;
        match result {
            Err(error) => Err(error),
            Ok(counts) => {
                finished?;
                if !released? {
                    return Err(ArchiveError::LeaseLost);
                }
                Ok(Some(counts))
            }
        }
    }

    async fn finish_run(
        &self,
        run: &str,
        status: &str,
        counts: RetentionCounts,
        error: Option<&str>,
    ) -> Result<(), ArchiveError> {
        let mut tx = self.runtime.begin_worker().await?;
        let updated=tx.execute("UPDATE retention_runs SET status=$2,rows_selected=$3,rows_archived=$4,rows_deleted=$5,error_text=$6,finished_at=CURRENT_TIMESTAMP WHERE run_id=$1 AND status='running'",&[&run,&status,&counts.selected,&counts.archived,&counts.deleted,&error]).await?;
        if updated != 1 {
            return Err(ArchiveError::CandidateChanged);
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn retain_events(
        &self,
        config: &ArchiveConfig,
        lease: &MaintenanceLease,
    ) -> Result<RetentionCounts, ArchiveError> {
        let mut tx = self.runtime.begin_worker().await?;
        guard(&mut tx, "event-retention", lease).await?;
        let days = config.event_retention_days.max(1);
        let limit = i64::from(config.batch_size.max(1));
        let candidates = tx.query(EVENT_CANDIDATES, &[&days, &limit]).await?;
        let mut counts = RetentionCounts {
            selected: candidates.len() as i64,
            ..RetentionCounts::default()
        };
        for candidate in candidates {
            guard(&mut tx, "event-retention", lease).await?;
            let key: String = candidate.get(0);
            let stream: String = candidate.get(1);
            let sha: String = candidate.get(2);
            let observed_at: chrono::DateTime<Utc> = candidate.get(3);
            let tombstone_days = config.tombstone_retention_days.max(1);
            tx.execute("INSERT INTO sync_event_tombstones(dedupe_key,stream_name,payload_sha256,observed_at,expires_at) VALUES($1,$2,$3,$4,CURRENT_TIMESTAMP+($5::int*INTERVAL '1 day')) ON CONFLICT(dedupe_key,stream_name) DO UPDATE SET expires_at=GREATEST(sync_event_tombstones.expires_at,EXCLUDED.expires_at),updated_at=CURRENT_TIMESTAMP",&[&key,&stream,&sha,&observed_at,&tombstone_days]).await?;
            for sql in EVENT_CHILD_DELETES {
                tx.execute(sql, &[&key, &stream]).await?;
            }
            let deleted=tx.execute("DELETE FROM sync_events WHERE dedupe_key=$1 AND stream_name=$2 AND status='completed' AND payload_archived=true AND payload IS NULL AND payload_sha256=$3",&[&key,&stream,&sha]).await?;
            if deleted != 1 {
                return Err(ArchiveError::CandidateChanged);
            }
            counts.deleted += 1;
        }
        tx.commit().await?;
        Ok(counts)
    }

    pub async fn retain_search(
        &self,
        config: &ArchiveConfig,
        lease: &MaintenanceLease,
    ) -> Result<RetentionCounts, ArchiveError> {
        let mut tx = self.runtime.begin_worker().await?;
        guard(&mut tx, "search-retention", lease).await?;
        let days = config.search_retention_days.max(1);
        let limit = i64::from(config.batch_size.max(1));
        let candidates = tx.query(SEARCH_CANDIDATES, &[&days, &limit]).await?;
        let mut counts = RetentionCounts {
            selected: candidates.len() as i64,
            ..RetentionCounts::default()
        };
        for candidate in candidates {
            guard(&mut tx, "search-retention", lease).await?;
            let id: String = candidate.get(0);
            for sql in SEARCH_CHILD_DELETES {
                tx.execute(sql, &[&id]).await?;
            }
            let deleted=tx.execute("DELETE FROM atheros_search.search_documents WHERE document_id=$1::text::uuid AND status IN ('superseded','deleted','failed')",&[&id]).await?;
            if deleted != 1 {
                return Err(ArchiveError::CandidateChanged);
            }
            counts.deleted += 1;
        }
        tx.commit().await?;
        Ok(counts)
    }

    pub async fn prune_tombstones(&self, limit: i32) -> Result<u64, ArchiveError> {
        self.prune_tombstones_fenced(limit, None).await
    }

    async fn prune_tombstones_fenced(&self, limit: i32, lease: Option<&MaintenanceLease>) -> Result<u64, ArchiveError> {
        let mut tx = self.runtime.begin_worker().await?;
        if let Some(lease) = lease {
            guard(&mut tx, "event-retention", lease).await?;
        }
        let limit = i64::from(limit.max(1));
        let count=tx.execute("DELETE FROM sync_event_tombstones WHERE expires_at<clock_timestamp() AND (dedupe_key,stream_name) IN (SELECT dedupe_key,stream_name FROM sync_event_tombstones WHERE expires_at<CURRENT_TIMESTAMP ORDER BY expires_at,stream_name,dedupe_key LIMIT $1 FOR UPDATE SKIP LOCKED)",&[&limit]).await?;
        tx.commit().await?;
        Ok(count)
    }

    pub async fn cleanup_stale_workers(&self, limit: i32) -> Result<u64, ArchiveError> {
        let mut tx = self.runtime.begin_worker().await?;
        let limit = i64::from(limit.max(1));
        let mut count = 0;
        for sql in STALE_WORKER_UPDATES {
            count += tx.execute(sql, &[&limit]).await?;
        }
        tx.commit().await?;
        Ok(count)
    }
}

pub(super) async fn guard(
    tx: &mut PgTransaction,
    resource_id: &str,
    lease: &MaintenanceLease,
) -> Result<(), ArchiveError> {
    if LeaseStore::guard(tx, "maintenance", resource_id, lease).await? {
        Ok(())
    } else {
        Err(ArchiveError::LeaseLost)
    }
}

const EVENT_CANDIDATES: &str = r#"
SELECT e.dedupe_key,e.stream_name,e.payload_sha256,e.observed_at
FROM sync_events e
WHERE e.stream_name='wireless.audit' AND e.status='completed'
AND e.payload_archived=true AND e.payload IS NULL AND e.payload_sha256 IS NOT NULL
AND e.observed_at<CURRENT_TIMESTAMP-($1::int*INTERVAL '1 day')
AND EXISTS(SELECT 1 FROM sync_event_payload_archives a WHERE a.dedupe_key=e.dedupe_key AND a.stream_name=e.stream_name AND a.payload_sha256=e.payload_sha256)
AND NOT EXISTS(SELECT 1 FROM sync_jobs j WHERE j.dedupe_key=e.dedupe_key AND j.stream_name=e.stream_name AND j.status NOT IN ('completed','failed','cancelled'))
AND NOT EXISTS(SELECT 1 FROM sync_batches b WHERE b.dedupe_key=e.dedupe_key AND b.stream_name=e.stream_name AND b.status NOT IN ('completed','failed','cancelled'))
AND NOT EXISTS(SELECT 1 FROM sync_batches b JOIN outbox_events o ON split_part(o.source_id,':',1)=b.batch_id::text WHERE b.dedupe_key=e.dedupe_key AND b.stream_name=e.stream_name AND o.status NOT IN ('published','failed','cancelled'))
ORDER BY e.observed_at,e.dedupe_key LIMIT $2 FOR UPDATE OF e SKIP LOCKED
"#;

// Both parameters are bound in every statement, including frame children whose
// stream is implicit in their schema. No identifier comes from wire input.
const EVENT_CHILD_DELETES:&[&str]=&[
    "DELETE FROM wireless_frame_security WHERE dedupe_key=$1 AND $2::text='wireless.audit'",
    "DELETE FROM wireless_frame_identity WHERE dedupe_key=$1 AND $2::text='wireless.audit'",
    "DELETE FROM wireless_frame_app_signals WHERE dedupe_key=$1 AND $2::text='wireless.audit'",
    "DELETE FROM wireless_frame_network WHERE dedupe_key=$1 AND $2::text='wireless.audit'",
    "DELETE FROM wireless_frame_qos WHERE dedupe_key=$1 AND $2::text='wireless.audit'",
    "DELETE FROM wireless_frame_radio WHERE dedupe_key=$1 AND $2::text='wireless.audit'",
    "DELETE FROM wireless_frames WHERE dedupe_key=$1 AND $2::text='wireless.audit'",
    "DELETE FROM outbox_publish_attempts a USING outbox_events o,sync_batches b WHERE o.outbox_id=a.outbox_id AND b.batch_id::text=split_part(o.source_id,':',1) AND b.dedupe_key=$1 AND b.stream_name=$2 AND o.status IN ('published','failed','cancelled')",
    "DELETE FROM outbox_events o USING sync_batches b WHERE b.batch_id::text=split_part(o.source_id,':',1) AND b.dedupe_key=$1 AND b.stream_name=$2 AND o.status IN ('published','failed','cancelled')",
    "DELETE FROM sync_errors e WHERE EXISTS(SELECT 1 FROM sync_jobs j WHERE j.job_id=e.job_id AND j.dedupe_key=$1 AND j.stream_name=$2) OR EXISTS(SELECT 1 FROM sync_batches b WHERE b.batch_id=e.batch_id AND b.dedupe_key=$1 AND b.stream_name=$2)",
    "DELETE FROM sync_batches WHERE dedupe_key=$1 AND stream_name=$2 AND status IN ('completed','failed','cancelled')",
    "DELETE FROM sync_jobs WHERE dedupe_key=$1 AND stream_name=$2 AND status IN ('completed','failed','cancelled')",
    "DELETE FROM sync_backlog WHERE dedupe_key=$1 AND stream_name=$2 AND status IN ('synced','failed')",
];

const SEARCH_CANDIDATES: &str = r#"
SELECT d.document_id::text FROM atheros_search.search_documents d
WHERE d.status IN ('superseded','deleted','failed')
AND d.updated_at<CURRENT_TIMESTAMP-($1::int*INTERVAL '1 day')
AND NOT EXISTS(SELECT 1 FROM atheros_search.embedding_jobs j WHERE j.document_id=d.document_id AND j.status NOT IN ('completed','failed','cancelled'))
ORDER BY d.updated_at,d.document_id LIMIT $2 FOR UPDATE OF d SKIP LOCKED
"#;

const SEARCH_CHILD_DELETES:&[&str]=&[
    "DELETE FROM atheros_search.similarity_scan_state s WHERE (s.embedding_kind,s.vector_id) IN (SELECT 'event',vector_id FROM atheros_search.search_vectors_event WHERE document_id=$1::text::uuid UNION ALL SELECT 'device',vector_id FROM atheros_search.search_vectors_device WHERE document_id=$1::text::uuid UNION ALL SELECT 'behaviour',vector_id FROM atheros_search.search_vectors_behaviour WHERE document_id=$1::text::uuid UNION ALL SELECT 'sequence',vector_id FROM atheros_search.search_vectors_sequence WHERE document_id=$1::text::uuid)",
    "DELETE FROM atheros_search.similarity_pairs WHERE left_document_id=$1::text::uuid OR right_document_id=$1::text::uuid",
    "DELETE FROM atheros_search.embeddings WHERE document_id=$1::text::uuid",
    "DELETE FROM atheros_search.search_vectors_event WHERE document_id=$1::text::uuid",
    "DELETE FROM atheros_search.search_vectors_device WHERE document_id=$1::text::uuid",
    "DELETE FROM atheros_search.search_vectors_behaviour WHERE document_id=$1::text::uuid",
    "DELETE FROM atheros_search.search_vectors_sequence WHERE document_id=$1::text::uuid",
    "DELETE FROM atheros_search.embedding_jobs WHERE document_id=$1::text::uuid AND status IN ('completed','failed','cancelled')",
    "DELETE FROM atheros_search.search_document_tokens WHERE document_id=$1::text::uuid",
    "DELETE FROM atheros_search.search_document_tags WHERE document_id=$1::text::uuid",
];

const STALE_WORKER_UPDATES:&[&str]=&[
    "UPDATE sync_jobs SET status=CASE WHEN attempt_count>=max_attempts THEN 'failed' ELSE 'pending' END,owner_id=NULL,lease_token=NULL,lease_expires_at=NULL,next_attempt_at=CURRENT_TIMESTAMP,last_error=CASE WHEN attempt_count>=max_attempts THEN 'worker lease expired; retries exhausted' ELSE 'worker lease expired; returned to pending' END,updated_at=CURRENT_TIMESTAMP WHERE job_id IN (SELECT job_id FROM sync_jobs WHERE status IN ('leased','running') AND lease_expires_at<=CURRENT_TIMESTAMP ORDER BY lease_expires_at,job_id LIMIT $1 FOR UPDATE SKIP LOCKED)",
    "UPDATE sync_batches SET status=CASE WHEN attempt_count>=max_attempts THEN 'failed' ELSE 'pending' END,owner_id=NULL,lease_token=NULL,lease_expires_at=NULL,next_attempt_at=CURRENT_TIMESTAMP,last_error=CASE WHEN attempt_count>=max_attempts THEN 'worker lease expired; retries exhausted' ELSE 'worker lease expired; returned to pending' END,updated_at=CURRENT_TIMESTAMP WHERE batch_id IN (SELECT batch_id FROM sync_batches WHERE status IN ('leased','processing') AND lease_expires_at<=CURRENT_TIMESTAMP ORDER BY lease_expires_at,batch_id LIMIT $1 FOR UPDATE SKIP LOCKED)",
    "UPDATE work_leases SET owner_id=NULL,lease_token=NULL,lease_expires_at=NULL,next_attempt_at=CURRENT_TIMESTAMP,last_error='worker lease expired; released by cleanup',updated_at=CURRENT_TIMESTAMP WHERE (resource_type,resource_id) IN (SELECT resource_type,resource_id FROM work_leases WHERE lease_expires_at<=CURRENT_TIMESTAMP ORDER BY lease_expires_at,resource_type,resource_id LIMIT $1 FOR UPDATE SKIP LOCKED)",
];
