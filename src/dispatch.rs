//! Durable dispatch and fenced outbox publication. Broker offsets stay outside this module.
use crate::{
    load::LoadError,
    postgres::{PgRuntime, PgTransaction},
};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseIdentity {
    pub owner_id: String,
    pub token: String,
    pub fence: i64,
}

#[derive(Clone, Debug)]
pub struct OutboxRecord {
    pub outbox_id: String,
    pub destination_topic: String,
    pub message_key: String,
    pub payload: String,
    pub attempt_count: i32,
    pub max_attempts: i32,
    pub lease: LeaseIdentity,
}

impl OutboxRecord {
    pub fn load_batch_id(&self) -> Result<Option<String>, LoadError> {
        if self.destination_topic != "sync.oracle.load" {
            return Ok(None);
        }
        let payload: serde_json::Value = serde_json::from_str(&self.payload)
            .map_err(|_| LoadError::Invalid("malformed load outbox payload"))?;
        let batch = payload
            .get("batch_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(LoadError::Invalid(
                "load outbox must contain string batch_id",
            ))?;
        let parsed = uuid::Uuid::parse_str(batch)
            .map_err(|_| LoadError::Invalid("load outbox batch_id must be UUID"))?
            .to_string();
        if !parsed.eq_ignore_ascii_case(batch) {
            return Err(LoadError::Invalid(
                "load outbox batch_id must use canonical UUID",
            ));
        }
        Ok(Some(parsed))
    }
}

#[derive(Clone)]
pub struct DispatchStore {
    runtime: Arc<PgRuntime>,
}
impl DispatchStore {
    pub fn new(runtime: Arc<PgRuntime>) -> Self {
        Self { runtime }
    }

    pub async fn ensure_cursors(&self, streams: &[String]) -> Result<(), LoadError> {
        let mut tx = self.runtime.begin_worker().await?;
        for stream in streams {
            if !crate::util::java_trim(stream).is_empty() {
                tx.execute("INSERT INTO sync_cursors(stream_name,cursor_value,updated_at) VALUES($1,'0',CURRENT_TIMESTAMP) ON CONFLICT(stream_name) DO NOTHING",&[stream]).await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn process_ingest_ledger(
        &self,
        streams: &[String],
        max_attempts: i32,
        backoff_seconds: i32,
        limit: i64,
    ) -> Result<u64, LoadError> {
        let streams = streams
            .iter()
            .map(|s| crate::util::java_trim(s))
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if streams.is_empty() {
            return Ok(0);
        }
        let mut tx = self.runtime.begin_worker().await?;
        let candidates=tx.query("SELECT stream_name,dedupe_key,payload_ref FROM sync_events WHERE stream_name=ANY($1) AND status IN ('pending','failed') AND attempt_count<$2 AND (status='pending' OR updated_at<=CURRENT_TIMESTAMP-CAST($3 AS integer)*INTERVAL '1 second') ORDER BY observed_at,stream_name,dedupe_key LIMIT $4 FOR UPDATE",&[&streams,&max_attempts.max(1),&backoff_seconds.max(1),&limit.max(1)]).await?;
        let mut count = 0;
        for candidate in candidates {
            let stream: String = candidate.get(0);
            let key: String = candidate.get(1);
            let reference: String = candidate.get(2);
            tx.execute("INSERT INTO sync_jobs(job_id,stream_name,dedupe_key,status,attempt_count,created_at) VALUES(gen_random_uuid(),$1,$2,'pending',0,CURRENT_TIMESTAMP) ON CONFLICT(dedupe_key,stream_name) DO UPDATE SET job_id=sync_jobs.job_id",&[&stream,&key]).await?;
            tx.execute("INSERT INTO sync_batches(batch_id,job_id,batch_no,payload_ref,status,row_count,attempt_count,dedupe_key,stream_name,cursor_start,cursor_end,created_at,updated_at) SELECT gen_random_uuid(),j.job_id,0,$3,'pending',1,0,e.dedupe_key,e.stream_name,COALESCE(c.cursor_value,'0'),CASE WHEN e.stream_name='wireless.audit' THEN floor(extract(epoch FROM e.observed_at))::text ELSE e.dedupe_key END,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP FROM sync_events e JOIN sync_jobs j ON j.stream_name=e.stream_name AND j.dedupe_key=e.dedupe_key LEFT JOIN sync_cursors c ON c.stream_name=e.stream_name WHERE e.stream_name=$1 AND e.dedupe_key=$2 ON CONFLICT(dedupe_key,stream_name) DO UPDATE SET batch_id=sync_batches.batch_id,updated_at=CURRENT_TIMESTAMP",&[&stream,&key,&reference]).await?;
            count+=tx.execute("UPDATE sync_events e SET status='batched',attempt_count=e.attempt_count+1,last_error=NULL,updated_at=CURRENT_TIMESTAMP WHERE e.stream_name=$1 AND e.dedupe_key=$2 AND e.status IN ('pending','failed') AND EXISTS(SELECT 1 FROM sync_batches b WHERE b.stream_name=e.stream_name AND b.dedupe_key=e.dedupe_key AND b.status='pending' AND b.created_at>=e.updated_at)",&[&stream,&key]).await?;
        }
        tx.commit().await?;
        Ok(count)
    }

    /// A durable checkpoint bounds this historical repair and resumes after restart.
    pub async fn reconcile_completed_events(&self, limit: i64) -> Result<u64, LoadError> {
        let limit = limit.clamp(1, 1000);
        let mut tx = self.runtime.begin_worker().await?;
        tx.execute("INSERT INTO processor_checkpoints(processor_name,shard_id) VALUES('sync-backlog-recovery','event-completion-v1') ON CONFLICT(processor_name,shard_id) DO NOTHING",&[]).await?;
        let checkpoint=tx.query("SELECT checkpoint_value,status FROM processor_checkpoints WHERE processor_name='sync-backlog-recovery' AND shard_id='event-completion-v1' FOR UPDATE",&[]).await?;
        if checkpoint[0].get::<_, String>(1) == "healthy" {
            tx.commit().await?;
            return Ok(0);
        }
        let prior: Option<String> = checkpoint[0].get(0);
        let ids = tx
            .query(
                "SELECT job_id FROM sync_jobs WHERE job_id>$1 ORDER BY job_id LIMIT $2",
                &[&prior.as_deref().unwrap_or(""), &limit],
            )
            .await?
            .iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>();
        let changed=tx.execute("UPDATE sync_events e SET status='completed',last_error=NULL,updated_at=CURRENT_TIMESTAMP FROM sync_jobs j WHERE j.job_id=ANY($1) AND j.status='completed' AND e.stream_name=j.stream_name AND e.dedupe_key=j.dedupe_key AND e.status='batched' AND EXISTS(SELECT 1 FROM sync_batches b WHERE b.job_id=j.job_id AND b.stream_name=j.stream_name AND b.dedupe_key=j.dedupe_key AND b.status='completed') AND NOT EXISTS(SELECT 1 FROM sync_batches b WHERE b.job_id=j.job_id AND b.status<>'completed')",&[&ids]).await?;
        let next = ids.last().cloned().or(prior);
        let status = if ids.len() < (limit as usize) {
            "healthy"
        } else {
            "running"
        };
        tx.execute("UPDATE processor_checkpoints SET checkpoint_value=$1,status=$2,last_started_at=COALESCE(last_started_at,CURRENT_TIMESTAMP),last_succeeded_at=CURRENT_TIMESTAMP,rows_processed=rows_processed+$3,updated_at=CURRENT_TIMESTAMP WHERE processor_name='sync-backlog-recovery' AND shard_id='event-completion-v1'",&[&next,&status,&(ids.len() as i64)]).await?;
        tx.commit().await?;
        Ok(changed)
    }

    pub async fn enqueue_pending(&self, limit: i64, max_attempts: i32) -> Result<u64, LoadError> {
        let streams = crate::load::SinkTarget::STREAMS
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>();
        self.enqueue_pending_streams(&streams, limit, max_attempts)
            .await
    }

    /// Explicit stream selection is a sink policy; an empty list disables dispatch.
    pub async fn enqueue_pending_streams(
        &self,
        streams: &[String],
        limit: i64,
        max_attempts: i32,
    ) -> Result<u64, LoadError> {
        let streams: Vec<String> = streams
            .iter()
            .map(|s| crate::util::java_trim(s))
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        if streams.is_empty() {
            return Ok(0);
        }
        let mut tx = self.runtime.begin_worker().await?;
        let count = tx.execute("INSERT INTO outbox_events(outbox_id,source_type,source_id,event_type,destination_topic,message_key,payload,status,attempt_count,max_attempts,next_attempt_at,created_at,updated_at) SELECT gen_random_uuid(),'sync_batch',b.batch_id,'sync.load.requested','sync.oracle.load',concat(b.batch_id,':',b.attempt_count+1),jsonb_build_object('job_id',b.job_id,'batch_id',b.batch_id,'batch_no',b.batch_no,'stream_name',b.stream_name,'payload_ref',b.payload_ref,'cursor_start',b.cursor_start,'cursor_end',b.cursor_end,'attempt',b.attempt_count+1),'pending',0,$1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP FROM sync_batches b WHERE b.status='pending' AND b.stream_name=ANY($2) AND NOT EXISTS(SELECT 1 FROM outbox_events retry WHERE retry.source_type='sync_batch_retry' AND retry.source_id=concat(b.batch_id,':',b.attempt_count+1) AND retry.event_type='sync.load.requested') ORDER BY b.created_at,b.batch_id LIMIT $3 ON CONFLICT ON CONSTRAINT outbox_events_source_event_uq DO UPDATE SET message_key=EXCLUDED.message_key,payload=EXCLUDED.payload,attempt_count=0,max_attempts=EXCLUDED.max_attempts,next_attempt_at=CURRENT_TIMESTAMP,status='pending',owner_id=NULL,lease_token=NULL,lease_expires_at=NULL,published_at=NULL,last_error=NULL,updated_at=CURRENT_TIMESTAMP WHERE outbox_events.status IN ('failed','cancelled') OR (outbox_events.status='published' AND outbox_events.message_key<>EXCLUDED.message_key)", &[&max_attempts.max(1), &streams, &limit.max(1)]).await?;
        tx.commit().await?;
        Ok(count)
    }

    pub async fn claim_outbox(
        &self,
        owner: &str,
        topics: &[String],
        lease_seconds: i32,
    ) -> Result<Option<OutboxRecord>, LoadError> {
        let topics: Vec<String> = topics
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        if owner.trim().is_empty() || topics.is_empty() {
            return Ok(None);
        }
        let token = uuid::Uuid::new_v4().to_string();
        let mut tx = self.runtime.begin_worker().await?;
        let rows = tx.query("WITH candidate AS (SELECT outbox_id FROM outbox_events WHERE destination_topic=ANY($1) AND status='pending' AND (next_attempt_at<=CURRENT_TIMESTAMP OR (lease_expires_at IS NOT NULL AND lease_expires_at<=CURRENT_TIMESTAMP)) AND attempt_count<max_attempts ORDER BY created_at,outbox_id FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE outbox_events o SET status='leased',owner_id=$2,lease_token=CAST($3 AS text)::uuid,fence=fence+1,attempt_count=attempt_count+1,lease_expires_at=CURRENT_TIMESTAMP+CAST($4 AS integer)*INTERVAL '1 second',updated_at=CURRENT_TIMESTAMP FROM candidate c WHERE o.outbox_id=c.outbox_id RETURNING o.outbox_id::text,o.destination_topic,o.message_key,o.payload::text,o.attempt_count,o.max_attempts,o.owner_id,o.lease_token::text,o.fence", &[&topics,&owner,&token,&lease_seconds.max(1)]).await?;
        let record = rows.first().map(|row| OutboxRecord {
            outbox_id: row.get(0),
            destination_topic: row.get(1),
            message_key: row.get(2),
            payload: row.get(3),
            attempt_count: row.get(4),
            max_attempts: row.get(5),
            lease: LeaseIdentity {
                owner_id: row.get(6),
                token: row.get(7),
                fence: row.get(8),
            },
        });
        tx.commit().await?;
        Ok(record)
    }

    pub async fn acknowledge(
        &self,
        record: &OutboxRecord,
        load_batch_id: Option<&str>,
    ) -> Result<bool, LoadError> {
        let expected = record.load_batch_id()?;
        if expected.as_deref() != load_batch_id {
            return Err(LoadError::Invalid(
                "outbox load destination/identity mismatch",
            ));
        }
        let mut tx = self.runtime.begin_worker().await?;
        let updated = tx.execute("UPDATE outbox_events SET status='published',published_at=CURRENT_TIMESTAMP,owner_id=NULL,lease_token=NULL,lease_expires_at=NULL,last_error=NULL,updated_at=CURRENT_TIMESTAMP WHERE outbox_id::text=$1 AND destination_topic=$5 AND message_key=$6 AND status='leased' AND owner_id=$2 AND lease_token=CAST($3 AS text)::uuid AND fence=$4 AND lease_expires_at>CURRENT_TIMESTAMP", &[&record.outbox_id,&record.lease.owner_id,&record.lease.token,&record.lease.fence,&record.destination_topic,&record.message_key]).await?;
        let mut batch_updated = true;
        if updated == 1 {
            if let Some(batch) = load_batch_id {
                let attempt = record
                    .message_key
                    .strip_prefix(&format!("{batch}:"))
                    .and_then(|n| n.parse::<i32>().ok())
                    .filter(|n| *n > 0)
                    .ok_or(LoadError::Invalid("invalid load message key"))?;
                batch_updated = tx.execute("UPDATE sync_batches SET status='dispatched',attempt_count=$2,outbox_id=CAST($3 AS text)::uuid,last_error=NULL,updated_at=CURRENT_TIMESTAMP WHERE batch_id=$1 AND status='pending' AND attempt_count=$4", &[&batch,&attempt,&record.outbox_id,&(attempt-1)]).await?==1;
                if batch_updated {
                    tx.execute("UPDATE sync_jobs j SET status='running',started_at=COALESCE(j.started_at,CURRENT_TIMESTAMP) FROM sync_batches b WHERE b.job_id=j.job_id AND b.batch_id=$1 AND b.status='dispatched' AND j.status IN ('pending','running')", &[&batch]).await?;
                }
            }
            publish_attempt(&mut tx, record, "published", None).await?;
        }
        tx.commit().await?;
        Ok(updated == 1 && batch_updated)
    }

    pub async fn fail(
        &self,
        record: &OutboxRecord,
        error: &str,
        delay_secs: i64,
    ) -> Result<(), LoadError> {
        let status = if record.attempt_count >= record.max_attempts {
            "failed"
        } else {
            "pending"
        };
        self.finish_failure(record, status, error, delay_secs, false)
            .await
    }

    pub async fn park_malformed(
        &self,
        record: &OutboxRecord,
        error: &str,
    ) -> Result<(), LoadError> {
        self.finish_failure(record, "failed", error, 0, true).await
    }

    async fn finish_failure(
        &self,
        record: &OutboxRecord,
        status: &str,
        error: &str,
        delay_secs: i64,
        published: bool,
    ) -> Result<(), LoadError> {
        let error = crate::errors::sanitize(error);
        let mut tx = self.runtime.begin_worker().await?;
        let count=tx.execute("UPDATE outbox_events SET status=$5,owner_id=NULL,lease_token=NULL,lease_expires_at=NULL,next_attempt_at=CURRENT_TIMESTAMP+CAST($6 AS bigint)*INTERVAL '1 second',last_error=$7,published_at=CASE WHEN $10 THEN CURRENT_TIMESTAMP ELSE published_at END,updated_at=CURRENT_TIMESTAMP WHERE outbox_id::text=$1 AND status='leased' AND owner_id=$2 AND lease_token=CAST($3 AS text)::uuid AND fence=$4 AND lease_expires_at>CURRENT_TIMESTAMP AND destination_topic=$8 AND message_key=$9",&[&record.outbox_id,&record.lease.owner_id,&record.lease.token,&record.lease.fence,&status,&delay_secs.max(0),&error,&record.destination_topic,&record.message_key,&published]).await?;
        if count != 1 {
            return Err(LoadError::Invariant("lost outbox lease"));
        }
        publish_attempt(&mut tx, record, status, Some(&error)).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn recover_expired(&self) -> Result<u64, LoadError> {
        let mut tx = self.runtime.begin_worker().await?;
        let count=tx.execute("UPDATE outbox_events SET status=CASE WHEN attempt_count>=max_attempts THEN 'failed' ELSE 'pending' END,owner_id=NULL,lease_token=NULL,lease_expires_at=NULL,next_attempt_at=CURRENT_TIMESTAMP,last_error=CASE WHEN attempt_count>=max_attempts THEN 'publish lease expired; max attempts reached' ELSE 'publish lease expired; retrying' END,updated_at=CURRENT_TIMESTAMP WHERE status='leased' AND lease_expires_at<=CURRENT_TIMESTAMP",&[]).await?;
        tx.commit().await?;
        Ok(count)
    }
}

async fn publish_attempt(
    tx: &mut PgTransaction,
    record: &OutboxRecord,
    status: &str,
    error: Option<&str>,
) -> Result<(), LoadError> {
    tx.execute("INSERT INTO outbox_publish_attempts(outbox_id,attempt_no,status,error_text,attempted_at) VALUES(CAST($1 AS text)::uuid,$2,$3,$4,CURRENT_TIMESTAMP) ON CONFLICT(outbox_id,attempt_no) DO UPDATE SET status=EXCLUDED.status,error_text=EXCLUDED.error_text,attempted_at=CURRENT_TIMESTAMP",&[&record.outbox_id,&record.attempt_count,&status,&error]).await?;
    Ok(())
}
