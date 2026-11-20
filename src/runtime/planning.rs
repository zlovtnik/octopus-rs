//! Durable legacy-ledger planning and checkpointed completion recovery.

use crate::{
    config::{AppConfig, CronConfig},
    dispatch::DispatchStore,
    load::LoadError,
    postgres::{PgError, PgRuntime},
    util::java_trim,
};
use std::{collections::BTreeSet, sync::Arc};

#[derive(Clone)]
pub struct Planner {
    runtime: Arc<PgRuntime>,
    cron: CronConfig,
    streams: Vec<String>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoveryCounts {
    pub outbox: u64,
    pub events: u64,
}

impl Planner {
    pub fn new(runtime: Arc<PgRuntime>, cfg: &AppConfig) -> Self {
        let streams = cfg
            .ingest
            .load_stream_names
            .iter()
            .map(|s| java_trim(s))
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Self {
            runtime,
            cron: cfg.cron.clone(),
            streams,
        }
    }
    /// A full source batch is locked and planned atomically. Backpressure pauses
    /// producers, while this method continues draining already admitted events.
    pub async fn process_ingest(&self) -> Result<u64, PgError> {
        if self.streams.is_empty() {
            return Ok(0);
        }
        let mut tx = self.runtime.begin_worker().await?;
        let candidates=tx.query("SELECT e.stream_name,e.dedupe_key FROM sync_events e WHERE e.stream_name=ANY($1) AND e.status IN ('pending','failed') AND e.attempt_count<$2 AND (e.status='pending' OR e.updated_at<=CURRENT_TIMESTAMP-CAST($3 AS integer)*INTERVAL '1 second') ORDER BY e.observed_at,e.stream_name,e.dedupe_key LIMIT $4 FOR UPDATE",&[&self.streams,&self.cron.scan_max_attempts.max(1),&self.cron.scan_retry_backoff_seconds.max(1),&i64::from(self.cron.ingest_batch_size.max(1))]).await?;
        let mut processed = 0;
        for row in candidates {
            let stream: String = row.get(0);
            let key: String = row.get(1);
            tx.execute("INSERT INTO sync_jobs(job_id,stream_name,dedupe_key,status,attempt_count,created_at) SELECT gen_random_uuid(),e.stream_name,e.dedupe_key,'pending',0,CURRENT_TIMESTAMP FROM sync_events e WHERE e.stream_name=$1 AND e.dedupe_key=$2 ON CONFLICT(dedupe_key,stream_name) DO UPDATE SET job_id=sync_jobs.job_id",&[&stream,&key]).await?;
            let created = tx.execute("INSERT INTO sync_batches(batch_id,job_id,batch_no,payload_ref,status,row_count,attempt_count,dedupe_key,stream_name,cursor_start,cursor_end,created_at,updated_at) SELECT gen_random_uuid(),j.job_id,0,e.payload_ref,'pending',1,0,e.dedupe_key,e.stream_name,COALESCE(c.cursor_value,'0'),CASE WHEN e.stream_name='wireless.audit' THEN floor(extract(epoch FROM e.observed_at))::text ELSE e.dedupe_key END,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP FROM sync_events e JOIN sync_jobs j ON j.stream_name=e.stream_name AND j.dedupe_key=e.dedupe_key LEFT JOIN sync_cursors c ON c.stream_name=e.stream_name WHERE e.stream_name=$1 AND e.dedupe_key=$2 ON CONFLICT(dedupe_key,stream_name) DO NOTHING",&[&stream,&key]).await?;
            processed+=tx.execute("UPDATE sync_events e SET status='batched',attempt_count=e.attempt_count+1,last_error=NULL,updated_at=CURRENT_TIMESTAMP WHERE e.stream_name=$1 AND e.dedupe_key=$2 AND e.status IN ('pending','failed') AND ($3 OR EXISTS(SELECT 1 FROM sync_batches b WHERE b.stream_name=e.stream_name AND b.dedupe_key=e.dedupe_key AND b.status='pending' AND b.created_at>=e.updated_at))",&[&stream,&key,&(created==1)]).await?;
        }
        tx.commit().await?;
        Ok(processed)
    }
    pub async fn recover_stale_batches(&self) -> Result<RecoveryCounts, LoadError> {
        let outbox = DispatchStore::new(self.runtime.clone())
            .recover_expired()
            .await?;
        let events = self.reconcile_completed_events().await?;
        Ok(RecoveryCounts { outbox, events })
    }
    /// Resume the bounded one-time upgrade repair from its persisted job key.
    pub async fn reconcile_completed_events(&self) -> Result<u64, PgError> {
        let mut tx = self.runtime.begin_worker().await?;
        tx.execute("INSERT INTO processor_checkpoints(processor_name,shard_id) VALUES('sync-backlog-recovery','event-completion-v1') ON CONFLICT(processor_name,shard_id) DO NOTHING",&[]).await?;
        let rows=tx.query("SELECT checkpoint_value,status FROM processor_checkpoints WHERE processor_name='sync-backlog-recovery' AND shard_id='event-completion-v1' FOR UPDATE",&[]).await?;
        let cursor: Option<String> = rows[0].get(0);
        let status: String = rows[0].get(1);
        if status == "healthy" {
            tx.commit().await?;
            return Ok(0);
        }
        let limit = self.cron.ingest_batch_size.clamp(1, 1000);
        let ids = tx
            .query(
                "SELECT job_id FROM sync_jobs WHERE job_id>$1 ORDER BY job_id LIMIT $2",
                &[&cursor.as_deref().unwrap_or(""), &i64::from(limit)],
            )
            .await?
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>();
        let changed = if ids.is_empty() {
            0
        } else {
            tx.execute("UPDATE sync_events event SET status='completed',last_error=NULL,updated_at=CURRENT_TIMESTAMP FROM sync_jobs job WHERE job.job_id=ANY($1) AND job.status='completed' AND event.stream_name=job.stream_name AND event.dedupe_key=job.dedupe_key AND event.status='batched' AND EXISTS(SELECT 1 FROM sync_batches batch WHERE batch.job_id=job.job_id AND batch.stream_name=job.stream_name AND batch.dedupe_key=job.dedupe_key AND batch.status='completed') AND NOT EXISTS(SELECT 1 FROM sync_batches batch WHERE batch.job_id=job.job_id AND batch.status<>'completed')",&[&ids]).await?
        };
        let next = ids.last().cloned().or(cursor);
        let status = if ids.len() < limit as usize {
            "healthy"
        } else {
            "running"
        };
        tx.execute("UPDATE processor_checkpoints SET checkpoint_value=$1,status=$2,last_started_at=COALESCE(last_started_at,CURRENT_TIMESTAMP),last_succeeded_at=CURRENT_TIMESTAMP,rows_processed=rows_processed+$3,updated_at=CURRENT_TIMESTAMP WHERE processor_name='sync-backlog-recovery' AND shard_id='event-completion-v1'",&[&next,&status,&(ids.len() as i64)]).await?;
        tx.commit().await?;
        Ok(changed)
    }
}
