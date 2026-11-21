//! Authorized, atomic typed loads and durable result transitions.
use crate::{
    domain::{BrokerRecordMetadata, IngestionDisposition, PostgresResult, SyncLoad},
    postgres::{
        retry_broker_transaction, BrokerEvidenceError, PgError, PgRuntime, PgTransaction,
        PostgresErrorClass,
    },
    util::{java_is_blank, stable_uuid},
};
use base64::{
    alphabet,
    engine::{
        general_purpose::{GeneralPurpose, GeneralPurposeConfig},
        DecodePaddingMode,
    },
    Engine,
};
use chrono::Utc;
use serde_json::Value;
use std::{path::PathBuf, sync::Arc, time::Duration};

mod rows;
mod sink;
pub use rows::{checksum, transform, PayloadRows, SinkTarget, TransformedRow};

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("invalid load: {0}")]
    Invalid(&'static str),
    #[error("unauthorized coordinator {0}")]
    Unauthorized(&'static str),
    #[error("ingestion invariant violated: {0}")]
    Invariant(&'static str),
    #[error("payload read failed")]
    PayloadRead,
    #[error("payload file is missing")]
    MissingPayload,
    #[error(transparent)]
    Database(#[from] PgError),
}

impl From<BrokerEvidenceError> for LoadError {
    fn from(error: BrokerEvidenceError) -> Self {
        match error {
            BrokerEvidenceError::Database(error) => Self::Database(error),
            BrokerEvidenceError::Conflict => {
                Self::Invariant("broker coordinate changed after ingestion")
            }
            BrokerEvidenceError::Missing => Self::Invariant("evidence disappeared after upsert"),
        }
    }
}
impl LoadError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::PayloadRead | Self::Database(PgError::Deadline | PgError::Acquisition)
        ) || matches!(
            self,
            Self::Database(PgError::Query {
                class: PostgresErrorClass::Retryable,
                ..
            })
        )
    }
    pub fn is_invariant(&self) -> bool {
        matches!(self, Self::Invariant(_))
    }
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Unauthorized(_))
    }
}

#[derive(Clone)]
pub struct LoadStore {
    runtime: Arc<PgRuntime>,
    outbox_dir: PathBuf,
    chunk_rows: usize,
    chunk_bytes: usize,
}
impl LoadStore {
    pub fn new(
        runtime: Arc<PgRuntime>,
        outbox_dir: PathBuf,
        chunk_rows: usize,
        chunk_bytes: usize,
    ) -> Self {
        Self {
            runtime,
            outbox_dir,
            chunk_rows,
            chunk_bytes,
        }
    }

    pub async fn authorize(&self, load: &SyncLoad) -> Result<(), LoadError> {
        let mut tx = self.runtime.begin_worker().await?;
        authorize_load(&mut tx, load).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Authorization is deliberately outside the error-to-result boundary.
    pub async fn handle(&self, load: &SyncLoad) -> Result<PostgresResult, LoadError> {
        let mut tx = self.runtime.begin_worker().await?;
        authorize_load(&mut tx, load).await?;
        let recorded = lock_attempt(&mut tx, load).await?;
        tx.commit().await?;
        if let Some(result) = recorded {
            return Ok(result);
        }
        let outcome = self.handle_authorized(load).await;
        Ok(match outcome {
            Ok(result) => result,
            Err(error) if error.is_unauthorized() => return Err(error),
            Err(error) => PostgresResult::failure(
                load.job_id.clone(),
                load.batch_id.clone(),
                if error.is_retryable() {
                    "retryable"
                } else {
                    "permanent"
                }
                .into(),
                crate::errors::message(&error),
                Utc::now().to_rfc3339(),
            ),
        })
    }

    async fn handle_authorized(&self, load: &SyncLoad) -> Result<PostgresResult, LoadError> {
        if self.chunk_rows == 0 || self.chunk_bytes == 0 {
            return Err(LoadError::Invalid("chunk bounds must be positive"));
        }
        if java_is_blank(&load.job_id)
            || java_is_blank(&load.batch_id)
            || java_is_blank(&load.stream_name)
            || java_is_blank(&load.payload_ref)
        {
            return Err(LoadError::Invalid("blank load metadata"));
        }
        let target = SinkTarget::from_stream(&load.stream_name)
            .ok_or(LoadError::Invalid("unsupported stream_name"))?;
        let payload = self
            .resolve_payload(&load.payload_ref)
            .await
            .map_err(|error| {
                if matches!(error, LoadError::MissingPayload) {
                    LoadError::PayloadRead
                } else {
                    error
                }
            })?;
        for delay in [Duration::from_millis(200), Duration::from_millis(400)] {
            let result = self.insert_payload(load, target, &payload).await;
            if !result.as_ref().err().is_some_and(LoadError::is_retryable) {
                return result;
            }
            tokio::time::sleep(delay).await;
        }
        self.insert_payload(load, target, &payload).await
    }

    async fn insert_payload(
        &self,
        load: &SyncLoad,
        target: SinkTarget,
        payload: &str,
    ) -> Result<PostgresResult, LoadError> {
        let mut rows = PayloadRows::new(target, payload, self.chunk_bytes)?;
        let mut tx = self.runtime.begin_worker().await?;
        if let Some(result) = lock_attempt(&mut tx, load).await? {
            tx.commit().await?;
            return Ok(result);
        }
        let mut count = 0i64;
        loop {
            let mut chunk = Vec::new();
            let mut bytes = 0usize;
            while chunk.len() < self.chunk_rows {
                let Some(raw) = rows.peek()? else { break };
                let row: Value = serde_json::from_str(raw)
                    .map_err(|_| LoadError::Invalid("invalid payload row"))?;
                let row = rows.with_parents(row)?;
                let row_bytes = row.to_string().len();
                if row_bytes > self.chunk_bytes {
                    return Err(LoadError::Invalid(
                        "single PostgreSQL row exceeds byte limit",
                    ));
                }
                if !chunk.is_empty() && bytes + row_bytes > self.chunk_bytes {
                    break;
                }
                bytes += row_bytes;
                rows.advance();
                chunk.push(transform(target, &row, count + chunk.len() as i64)?);
            }
            if chunk.is_empty() {
                break;
            }
            sink::insert_chunk(&mut tx, &load.batch_id, target, &chunk).await?;
            count = count
                .checked_add(chunk.len() as i64)
                .ok_or(LoadError::Invalid("row count overflow"))?;
            if count > i32::MAX as i64 {
                return Err(LoadError::Invalid("inserted row count exceeds i32 limit"));
            }
        }
        let result = PostgresResult::success(
            load.job_id.clone(),
            load.batch_id.clone(),
            count as i32,
            checksum(target, payload),
            Utc::now().to_rfc3339(),
        );
        enqueue_result(&mut tx, &result, load.attempt).await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn resolve_payload(&self, reference: &str) -> Result<String, LoadError> {
        if let Some(hash) = reference.strip_prefix("sha256://") {
            let mut tx = self.runtime.begin_worker().await?;
            let rows=tx.query("SELECT payload::text FROM sync_events WHERE payload_sha256=$1 AND payload IS NOT NULL ORDER BY created_at LIMIT 1",&[&hash]).await?;
            let payload = rows
                .first()
                .map(|r| r.get::<_, String>(0))
                .ok_or(LoadError::Invalid("payload hash lookup returned no result"))?;
            tx.commit().await?;
            return Ok(payload);
        }
        let base = self.outbox_dir.clone();
        let reference = reference.to_owned();
        tokio::task::spawn_blocking(move || resolve_local_payload(&reference, &base))
            .await
            .map_err(|_| LoadError::PayloadRead)?
    }

    pub async fn record_load_result_with_evidence(
        &self,
        load: &SyncLoad,
        result: &PostgresResult,
        metadata: &BrokerRecordMetadata,
    ) -> Result<(), LoadError> {
        self.record_load_results_with_evidence(&[(load, result, metadata)])
            .await
    }
    pub async fn record_load_results_with_evidence(
        &self,
        records: &[(&SyncLoad, &PostgresResult, &BrokerRecordMetadata)],
    ) -> Result<(), LoadError> {
        retry_broker_transaction(
            || self.record_load_results_once(records),
            LoadError::is_retryable,
        )
        .await
    }

    async fn record_load_results_once(
        &self,
        records: &[(&SyncLoad, &PostgresResult, &BrokerRecordMetadata)],
    ) -> Result<(), LoadError> {
        if records.is_empty() {
            return Ok(());
        }
        let mut tx = self.runtime.begin_worker().await?;
        for (load, result, metadata) in records {
            validate_metadata(metadata)?;
            authorize_load(&mut tx, load).await?;
            if result.job_id != load.job_id || result.batch_id != load.batch_id {
                return Err(LoadError::Invalid("load/result identity mismatch"));
            }
            let key = format!("load:{}:{}", load.batch_id, load.attempt.max(1));
            if !tx.check_broker_evidence(metadata, &key).await? {
                enqueue_result(&mut tx, result, load.attempt).await?;
                tx.record_broker_evidence(metadata, &key, IngestionDisposition::Processed)
                    .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn record_result_with_evidence(
        &self,
        result: &PostgresResult,
        metadata: &BrokerRecordMetadata,
    ) -> Result<(), LoadError> {
        self.record_results_with_evidence(&[(result, metadata)])
            .await
    }
    pub async fn record_results_with_evidence(
        &self,
        records: &[(&PostgresResult, &BrokerRecordMetadata)],
    ) -> Result<(), LoadError> {
        retry_broker_transaction(
            || self.record_results_once(records),
            LoadError::is_retryable,
        )
        .await
    }

    async fn record_results_once(
        &self,
        records: &[(&PostgresResult, &BrokerRecordMetadata)],
    ) -> Result<(), LoadError> {
        if records.is_empty() {
            return Ok(());
        }
        let mut tx = self.runtime.begin_worker().await?;
        for (result, metadata) in records {
            validate_metadata(metadata)?;
            if java_is_blank(&result.job_id)
                || java_is_blank(&result.batch_id)
                || !matches!(result.status.as_str(), "success" | "failed")
                || result.row_count < 0
            {
                return Err(LoadError::Invalid("invalid result metadata"));
            }
            authorize_result(&mut tx, result, metadata.message_key.as_deref()).await?;
            let attempt = metadata
                .message_key
                .as_deref()
                .and_then(|k| k.rsplit_once(':'))
                .and_then(|(_, n)| n.parse::<i32>().ok())
                .filter(|n| *n > 0)
                .unwrap_or(1);
            let key = format!("result:{}:{attempt}", result.batch_id);
            if !tx.check_broker_evidence(metadata, &key).await? {
                apply_result(&mut tx, result, attempt).await?;
                tx.record_broker_evidence(metadata, &key, IngestionDisposition::Processed)
                    .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }
}

pub fn resolve_local_payload(
    reference: &str,
    outbox_dir: &std::path::Path,
) -> Result<String, LoadError> {
    if let Some(encoded) = reference.strip_prefix("inline://json/") {
        const INLINE_BASE64: GeneralPurpose = GeneralPurpose::new(
            &alphabet::URL_SAFE,
            GeneralPurposeConfig::new()
                .with_decode_allow_trailing_bits(true)
                .with_decode_padding_mode(DecodePaddingMode::RequireNone),
        );
        let unpadded = encoded.trim_end_matches('=');
        // Accept missing or partial padding up to the next complete quartet.
        let required_padding = (4 - unpadded.len() % 4) % 4;
        if encoded.len() - unpadded.len() > required_padding {
            return Err(LoadError::Invalid("invalid inline payload encoding"));
        }
        let decoded = INLINE_BASE64
            .decode(unpadded)
            .map_err(|_| LoadError::Invalid("invalid inline payload encoding"))?;
        return Ok(String::from_utf8_lossy(&decoded).into_owned());
    }
    if let Some(relative) = reference.strip_prefix("outbox://") {
        if java_is_blank(relative)
            || relative.contains('\0')
            || std::path::Path::new(relative).is_absolute()
        {
            return Err(LoadError::Invalid("invalid outbox path"));
        }
        let mut normalized = PathBuf::new();
        for part in std::path::Path::new(relative).components() {
            match part {
                std::path::Component::ParentDir => {
                    if !normalized.pop() {
                        return Err(LoadError::Invalid("outbox path escapes base"));
                    }
                }
                std::path::Component::Normal(value) => normalized.push(value),
                _ => {}
            }
        }
        let io_error = |e: std::io::Error| {
            if e.kind() == std::io::ErrorKind::NotFound {
                LoadError::MissingPayload
            } else {
                LoadError::PayloadRead
            }
        };
        use rustix::fs::{open, openat, Mode, OFlags};
        use std::io::Read;

        let directory = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let mut parent =
            open(outbox_dir, directory, Mode::empty()).map_err(|e| io_error(e.into()))?;
        let mut components = normalized.iter().peekable();
        while let Some(component) = components.next() {
            if components.peek().is_some() {
                parent = openat(
                    &parent,
                    component,
                    directory | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|e| io_error(e.into()))?;
            } else {
                let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
                let fd = openat(&parent, component, flags, Mode::empty())
                    .map_err(|e| io_error(e.into()))?;
                let mut file = std::fs::File::from(fd);
                if !file.metadata().map_err(io_error)?.is_file() {
                    return Err(LoadError::Invalid("outbox payload must be a regular file"));
                }
                let mut payload = String::new();
                file.read_to_string(&mut payload).map_err(io_error)?;
                return Ok(payload);
            }
        }
        return Err(LoadError::Invalid("outbox payload must be a regular file"));
    }
    Err(LoadError::Invalid("unsupported payload_ref scheme"))
}

pub(crate) async fn authorize_load(
    tx: &mut PgTransaction,
    load: &SyncLoad,
) -> Result<(), LoadError> {
    let key = format!("{}:{}", load.batch_id, load.attempt);
    let rows=tx.query("SELECT o.payload::text FROM outbox_events o JOIN sync_batches b ON b.batch_id=split_part(o.source_id,':',1) WHERE o.source_type IN ('sync_batch','sync_batch_retry') AND split_part(o.source_id,':',1)=$1 AND o.event_type='sync.load.requested' AND o.destination_topic='sync.oracle.load' AND o.message_key=$2 AND o.status IN ('pending','leased','published') AND b.job_id=$3 AND b.stream_name=$4 AND b.payload_ref=$5 AND b.cursor_start=$6 AND b.cursor_end=$7",&[&load.batch_id,&key,&load.job_id,&load.stream_name,&load.payload_ref,&load.cursor_start,&load.cursor_end]).await?;
    if rows.len() != 1
        || serde_json::from_str::<SyncLoad>(&rows[0].get::<_, String>(0))
            .ok()
            .as_ref()
            != Some(load)
    {
        return Err(LoadError::Unauthorized("load"));
    }
    Ok(())
}

async fn lock_attempt(
    tx: &mut PgTransaction,
    load: &SyncLoad,
) -> Result<Option<PostgresResult>, LoadError> {
    let batch = tx.query(
        "SELECT status,attempt_count FROM sync_batches WHERE batch_id=$1 AND job_id=$2 FOR UPDATE",
        &[&load.batch_id, &load.job_id],
    ).await?;
    let batch = batch.first().ok_or(LoadError::Unauthorized("load"))?;
    let key = format!("{}:{}", load.batch_id, load.attempt);
    let results = tx.query(
        "SELECT payload::text FROM outbox_events WHERE destination_topic='sync.oracle.result' AND event_type='sync.load.result' AND message_key=$1",
        &[&key],
    ).await?;
    if let Some(result) = results.first() {
        let result: PostgresResult = serde_json::from_str(&result.get::<_, String>(0))
            .map_err(|_| LoadError::Invariant("malformed stored load result"))?;
        if result.job_id != load.job_id || result.batch_id != load.batch_id || results.len() != 1 {
            return Err(LoadError::Invariant("stored load result identity mismatch"));
        }
        return Ok(Some(result));
    }
    let status: String = batch.get(0);
    let attempt: i32 = batch.get(1);
    if !matches!(status.as_str(), "pending" | "dispatched" | "running")
        || load.attempt != attempt.saturating_add(i32::from(status == "pending"))
    {
        return Err(LoadError::Unauthorized("load"));
    }
    Ok(None)
}
async fn authorize_result(
    tx: &mut PgTransaction,
    result: &PostgresResult,
    key: Option<&str>,
) -> Result<(), LoadError> {
    let rows=tx.query("SELECT o.payload::text FROM outbox_events o JOIN sync_batches b ON b.batch_id=split_part(o.source_id,':',1) JOIN outbox_events dispatch ON split_part(dispatch.source_id,':',1)=b.batch_id::text AND dispatch.source_type IN ('sync_batch','sync_batch_retry') AND dispatch.event_type='sync.load.requested' AND dispatch.destination_topic='sync.oracle.load' AND dispatch.message_key=o.message_key WHERE o.source_type IN ('sync_batch','sync_batch_result') AND split_part(o.source_id,':',1)=$1 AND o.event_type='sync.load.result' AND o.destination_topic='sync.oracle.result' AND o.message_key=$2 AND b.job_id=$3 AND o.status IN ('pending','leased','published')",&[&result.batch_id,&key.unwrap_or(""),&result.job_id]).await?;
    if rows.len() != 1
        || serde_json::from_str::<PostgresResult>(&rows[0].get::<_, String>(0))
            .ok()
            .as_ref()
            != Some(result)
    {
        return Err(LoadError::Unauthorized("result"));
    }
    Ok(())
}
fn validate_metadata(m: &BrokerRecordMetadata) -> Result<(), LoadError> {
    let hash = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if java_is_blank(&m.topic)
        || m.partition < 0
        || m.offset < 0
        || java_is_blank(&m.consumer_group)
        || m.group_version <= 0
        || !hash(&m.artifact_sha256)
        || !hash(&m.payload_sha256)
    {
        Err(LoadError::Invalid("invalid broker metadata"))
    } else {
        Ok(())
    }
}
async fn enqueue_result(
    tx: &mut PgTransaction,
    result: &PostgresResult,
    attempt: i32,
) -> Result<(), LoadError> {
    let attempt = attempt.max(1);
    let key = format!("{}:{attempt}", result.batch_id);
    let source = if attempt == 1 {
        result.batch_id.clone()
    } else {
        key.clone()
    };
    let kind = if attempt == 1 {
        "sync_batch"
    } else {
        "sync_batch_result"
    };
    let id = stable_uuid(
        "outbox:sync.oracle.result",
        &[&result.batch_id, &attempt.to_string()],
    );
    let payload = serde_json::to_value(result).map_err(|_| LoadError::Invalid("invalid result"))?;
    tx.execute("INSERT INTO outbox_events(outbox_id,source_type,source_id,event_type,destination_topic,message_key,payload,status,attempt_count,max_attempts,next_attempt_at,created_at,updated_at) VALUES(CAST($1 AS text)::uuid,$2,$3,'sync.load.result','sync.oracle.result',$4,$5,'pending',0,5,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT DO NOTHING",&[&id,&kind,&source,&key,&payload]).await?;
    tx.execute("UPDATE outbox_events SET payload=$1,attempt_count=0,max_attempts=5,next_attempt_at=CURRENT_TIMESTAMP,status='pending',owner_id=NULL,lease_token=NULL,lease_expires_at=NULL,published_at=NULL,last_error=NULL,updated_at=CURRENT_TIMESTAMP WHERE destination_topic='sync.oracle.result' AND message_key=$2 AND status IN ('failed','cancelled')",&[&payload,&key]).await?;
    Ok(())
}
async fn apply_result(
    tx: &mut PgTransaction,
    r: &PostgresResult,
    attempt: i32,
) -> Result<(), LoadError> {
    let rows=tx.query("SELECT job_id,stream_name,payload_ref,cursor_start,cursor_end,batch_no,status,attempt_count,max_attempts FROM sync_batches WHERE batch_id=$1 FOR UPDATE",&[&r.batch_id]).await?;
    let b = rows
        .first()
        .ok_or(LoadError::Invariant("unknown result batch"))?;
    if b.get::<_, String>(0) != r.job_id {
        return Err(LoadError::Invariant("result job does not own batch"));
    }
    let status: String = b.get(6);
    let prior: i32 = b.get(7);
    let max: i32 = b.get(8);
    let expected = prior + if status == "pending" { 1 } else { 0 };
    if matches!(status.as_str(), "completed" | "failed" | "cancelled") || attempt < expected {
        return Ok(());
    }
    if attempt > expected {
        return Err(LoadError::Invariant("result attempt is ahead of batch"));
    }
    if r.status == "success" {
        let changed = tx.execute(
            "UPDATE sync_batches SET status='completed',attempt_count=$5,row_count=$3,checksum=$4,last_error=NULL,updated_at=CURRENT_TIMESTAMP WHERE batch_id=$1 AND job_id=$2 AND status IN ('pending','dispatched','running')",
            &[&r.batch_id, &r.job_id, &r.row_count, &r.checksum, &attempt],
        ).await?;
        if changed != 1 {
            return Err(LoadError::Invariant("cannot complete batch"));
        }
        tx.execute("UPDATE sync_jobs SET status='completed',finished_at=COALESCE(finished_at,CURRENT_TIMESTAMP) WHERE job_id=$1 AND NOT EXISTS(SELECT 1 FROM sync_batches WHERE job_id=$1 AND status<>'completed')",&[&r.job_id]).await?;
        tx.execute("UPDATE sync_events e SET status='completed',last_error=NULL,updated_at=CURRENT_TIMESTAMP FROM sync_jobs j WHERE j.job_id=$1 AND j.status='completed' AND e.stream_name=j.stream_name AND e.dedupe_key=j.dedupe_key AND e.status='batched' AND EXISTS(SELECT 1 FROM sync_batches b WHERE b.job_id=j.job_id AND b.stream_name=j.stream_name AND b.dedupe_key=j.dedupe_key AND b.status='completed') AND NOT EXISTS(SELECT 1 FROM sync_batches b WHERE b.job_id=j.job_id AND b.status<>'completed')",&[&r.job_id]).await?;
        let stream: String = b.get(1);
        let end: String = b.get(4);
        let current = tx
            .query(
                "SELECT cursor_value FROM sync_cursors WHERE stream_name=$1 FOR UPDATE",
                &[&stream],
            )
            .await?;
        let numeric = |s: &str| {
            let digits = s.strip_prefix('-').unwrap_or(s);
            !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
        };
        let epoch = stream == "wireless.audit";
        if epoch
            && (!numeric(&end)
                || current
                    .first()
                    .is_some_and(|r| !numeric(&r.get::<_, String>(0))))
        {
            return Err(LoadError::Invalid("cursor format mismatch"));
        }
        tx.execute("INSERT INTO sync_cursors(stream_name,cursor_value,updated_at) VALUES($1,$2,CURRENT_TIMESTAMP) ON CONFLICT(stream_name) DO UPDATE SET cursor_value=CASE WHEN $3::boolean AND EXCLUDED.cursor_value::numeric>sync_cursors.cursor_value::numeric THEN EXCLUDED.cursor_value WHEN NOT($3::boolean) AND (sync_cursors.cursor_value='0' OR EXCLUDED.cursor_value>sync_cursors.cursor_value) THEN EXCLUDED.cursor_value ELSE sync_cursors.cursor_value END,updated_at=CURRENT_TIMESTAMP",&[&stream,&end,&epoch]).await?;
    } else if r.retryable && attempt < max {
        let changed=tx.execute("UPDATE sync_batches SET status='pending',attempt_count=attempt_count+CASE WHEN status='pending' THEN 1 ELSE 0 END,last_error=$3,updated_at=CURRENT_TIMESTAMP WHERE batch_id=$1 AND job_id=$2 AND status IN ('pending','dispatched','running')",&[&r.batch_id,&r.job_id,&r.error_text]).await?;
        if changed != 1 {
            return Err(LoadError::Invariant("cannot retry batch"));
        }
        let next = prior + if status == "pending" { 2 } else { 1 };
        let key = format!("{}:{next}", r.batch_id);
        let payload = serde_json::json!({"job_id":r.job_id,"batch_id":r.batch_id,"batch_no":b.get::<_,i32>(5),"stream_name":b.get::<_,String>(1),"payload_ref":b.get::<_,String>(2),"cursor_start":b.get::<_,String>(3),"cursor_end":b.get::<_,String>(4),"attempt":next});
        tx.execute("INSERT INTO outbox_events(outbox_id,source_type,source_id,event_type,destination_topic,message_key,payload,status,attempt_count,max_attempts,next_attempt_at,created_at,updated_at) VALUES(gen_random_uuid(),'sync_batch_retry',$1,'sync.load.requested','sync.oracle.load',$1,$2,'pending',0,$3,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT ON CONSTRAINT outbox_events_source_event_uq DO NOTHING",&[&key,&payload,&max]).await?;
    } else {
        let changed=tx.execute("UPDATE sync_batches SET status='failed',last_error=$3,updated_at=CURRENT_TIMESTAMP WHERE batch_id=$1 AND job_id=$2 AND status IN ('pending','dispatched','running')",&[&r.batch_id,&r.job_id,&r.error_text]).await?;
        if changed != 1 {
            return Err(LoadError::Invariant("cannot fail batch"));
        }
        tx.execute("UPDATE sync_jobs SET status='failed',finished_at=COALESCE(finished_at,CURRENT_TIMESTAMP) WHERE job_id=$1 AND status<>'completed'",&[&r.job_id]).await?;
        tx.execute(
            "INSERT INTO sync_errors(job_id,batch_id,error_class,error_text) VALUES($1,$2,$3,$4)",
            &[&r.job_id, &r.batch_id, &r.error_class, &r.error_text],
        )
        .await?;
    }
    Ok(())
}
