//! Atomic raw intake, broker evidence, and coordinator-owned initial work state.
//!
//! Kafka remains responsible for restart offsets. These transactions independently
//! record replay evidence and never apply schema DDL or commit broker offsets.

use crate::{
    domain::{
        BrokerRecordMetadata, IngestionDecision, IngestionDisposition, ResolvedScanRequestRecord,
    },
    postgres::{
        retry_broker_transaction, BrokerEvidenceError, PgError, PgRuntime, PgTransaction,
        PostgresErrorClass,
    },
    util::{java_is_blank, java_trim, stable_uuid, utf16_length},
};
use std::{collections::HashSet, sync::Arc};

#[path = "ingestion/wireless.rs"]
mod wireless;

#[derive(Debug, thiserror::Error)]
pub enum IntakeError {
    #[error("invalid scan record: {0}")]
    InvalidRecord(&'static str),
    #[error("ingestion invariant violated: {0}")]
    Invariant(&'static str),
    #[error(transparent)]
    Database(#[from] PgError),
}

impl From<BrokerEvidenceError> for IntakeError {
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

impl IntakeError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Database(PgError::Deadline | PgError::Acquisition)
        ) || matches!(
            self,
            Self::Database(PgError::Query {
                class: PostgresErrorClass::Retryable,
                ..
            })
        )
    }
}

#[derive(Clone)]
pub struct IngestionStore {
    runtime: Arc<PgRuntime>,
    load_streams: Option<Arc<HashSet<String>>>,
}

impl IngestionStore {
    pub fn new(runtime: Arc<PgRuntime>) -> Self {
        Self {
            runtime,
            load_streams: None,
        }
    }

    /// Limit batch creation to the streams configured for load dispatch.
    pub fn with_load_streams(mut self, streams: &[String]) -> Self {
        self.load_streams = Some(Arc::new(
            streams
                .iter()
                .map(|stream| java_trim(stream).to_owned())
                .collect(),
        ));
        self
    }

    pub async fn record_scan_request_with_evidence(
        &self,
        record: &ResolvedScanRequestRecord,
        metadata: &BrokerRecordMetadata,
    ) -> Result<IngestionDecision, IntakeError> {
        self.record_scan_requests_with_evidence(&[(record, metadata)])
            .await
            .map(|mut values| values.remove(0))
    }

    /// Preserve record order and commit the entire batch, including evidence,
    /// atomically. Each retry drops its old transaction and worker permit before
    /// sleeping, then obtains a new transaction and permit.
    pub async fn record_scan_requests_with_evidence(
        &self,
        records: &[(&ResolvedScanRequestRecord, &BrokerRecordMetadata)],
    ) -> Result<Vec<IngestionDecision>, IntakeError> {
        if records.is_empty() {
            return Ok(Vec::new());
        }
        let records = records
            .iter()
            .map(|(r, m)| (*r, Some(*m)))
            .collect::<Vec<_>>();
        self.record_batch(&records).await
    }

    /// Compatibility intake without broker evidence uses first occurrence per
    /// stream/key, matching Scala distinctBy rather than rejecting duplicates.
    pub async fn record_scan_requests(
        &self,
        records: &[ResolvedScanRequestRecord],
    ) -> Result<usize, IntakeError> {
        let mut seen = HashSet::new();
        let unique = records
            .iter()
            .filter(|r| seen.insert((r.source().stream_name(), r.source().dedupe_key())))
            .map(|r| (r, None))
            .collect::<Vec<_>>();
        if unique.is_empty() {
            return Ok(0);
        }
        Ok(self
            .record_batch(&unique)
            .await?
            .iter()
            .filter(|decision| decision.disposition == IngestionDisposition::Processed)
            .count())
    }

    async fn record_batch(
        &self,
        records: &[(&ResolvedScanRequestRecord, Option<&BrokerRecordMetadata>)],
    ) -> Result<Vec<IngestionDecision>, IntakeError> {
        retry_broker_transaction(
            || self.record_batch_once(records),
            IntakeError::is_retryable,
        )
        .await
    }

    async fn record_batch_once(
        &self,
        records: &[(&ResolvedScanRequestRecord, Option<&BrokerRecordMetadata>)],
    ) -> Result<Vec<IngestionDecision>, IntakeError> {
        let mut transaction = self.runtime.begin_worker().await?;
        let mut decisions = Vec::with_capacity(records.len());
        for (record, metadata) in records {
            let stream = record.source().stream_name();
            let create_batch = load_eligible(stream)
                && self
                    .load_streams
                    .as_ref()
                    .is_none_or(|streams| streams.contains(stream));
            decisions.push(ingest(&mut transaction, record, *metadata, create_batch).await?);
        }
        transaction.commit().await?;
        Ok(decisions)
    }
}

pub fn load_eligible(stream: &str) -> bool {
    matches!(
        stream,
        "proxy.events"
            | "proxy.payload_audit"
            | "wireless.audit"
            | "audit.wireless.bandwidth"
            | "wireless.rogue_ap"
            | "wireless.alert.rogue_ap"
            | "wireless.deauth_flood"
            | "wireless.alert.deauth_flood"
            | "wireless.signal_anomaly"
            | "wireless.alert.signal_anomaly"
            | "wireless.pmf_attack"
            | "wireless.alert.pmf_attack"
            | "wireless.client_inventory"
            | "wireless.client.inventory"
            | "wireless.probe_requests"
            | "wireless.probe.flush"
            | "wireless.attack_sequence"
            | "wireless.alert.attack_sequence"
            | "wireless.sequence"
            | "wireless.alert.sequence"
            | "wireless.sequence_alert"
            | "wifi.alert.handshake"
            | "wireless.alert.handshake"
            | "wireless.handshake"
    )
}

fn validate(
    record: &ResolvedScanRequestRecord,
    metadata: Option<&BrokerRecordMetadata>,
) -> Result<(), IntakeError> {
    if metadata.is_some_and(|m| m.payload_sha256 != record.source().source_record_sha256()) {
        return Err(IntakeError::InvalidRecord(
            "raw record hash does not match decoded payload hash",
        ));
    }
    if record.source().stream_name() == "wireless.audit"
        && record.source().dedupe_key() != record.event_payload_sha256()
    {
        return Err(IntakeError::InvalidRecord(
            "wireless.audit dedupe_key must match resolved payload hash",
        ));
    }
    Ok(())
}

async fn ingest(
    tx: &mut PgTransaction,
    record: &ResolvedScanRequestRecord,
    metadata: Option<&BrokerRecordMetadata>,
    create_batch: bool,
) -> Result<IngestionDecision, IntakeError> {
    validate(record, metadata)?;
    let source = record.source();
    let stream = source.stream_name();
    let key = source.dedupe_key();
    let job_id = stable_uuid("job", &[stream, key]);
    let batch_id = stable_uuid("batch", &[stream, key]);
    let event_kind = record
        .inspection()
        .event_kind
        .as_deref()
        .filter(|kind| utf16_length(kind) <= 64);
    if let Some(m) = metadata {
        if tx.check_broker_evidence(m, key).await? {
            let hydrated = hydrate(tx, record, event_kind).await?;
            if create_batch && hydrated {
                // A replay can admit work for a newly enabled stream. Hydration
                // has locked the live event and checked its business payload.
                let waiting_for_admission = !tx
                    .query(
                        "SELECT 1 FROM sync_events e
                         WHERE e.stream_name=$1 AND e.dedupe_key=$2 AND e.status='completed'
                           AND NOT EXISTS (SELECT 1 FROM sync_jobs j
                             WHERE j.stream_name=e.stream_name AND j.dedupe_key=e.dedupe_key)",
                        &[&stream, &key],
                    )
                    .await?
                    .is_empty();
                if waiting_for_admission {
                    ensure_batch(tx, record, &job_id, &batch_id).await?;
                }
            }
            return persisted_decision(
                tx,
                stream,
                key,
                job_id,
                batch_id,
                IngestionDisposition::Deduplicated,
            )
            .await;
        }
    }
    let tombstoned: bool = tx.query("SELECT EXISTS(SELECT 1 FROM sync_event_tombstones WHERE stream_name=$1 AND dedupe_key=$2 AND expires_at>CURRENT_TIMESTAMP)", &[&stream, &key]).await?[0].get(0);
    let decision = if tombstoned {
        IngestionDecision {
            disposition: IngestionDisposition::Deduplicated,
            dedupe_key: key.into(),
            job_id,
            batch_id,
        }
    } else {
        let existed: bool = tx
            .query(
                "SELECT EXISTS(SELECT 1 FROM sync_events WHERE stream_name=$1 AND dedupe_key=$2)",
                &[&stream, &key],
            )
            .await?[0]
            .get(0);
        let status = if create_batch { "batched" } else { "completed" };
        tx.execute("INSERT INTO sync_events (dedupe_key,stream_name,observed_at,payload_ref,payload,payload_sha256,status,attempt_count,last_error,producer,event_kind,created_at,updated_at) VALUES ($1,$2,CAST($3 AS text)::timestamptz,$4,CAST($5 AS text)::jsonb,$6,$7,1,NULL,'ssl-proxy',$8,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT(dedupe_key,stream_name) DO UPDATE SET dedupe_key=sync_events.dedupe_key",
            &[&key,&stream,&source.observed_at(),&source.payload_ref(),&record.payload_json(),&record.event_payload_sha256(),&status,&event_kind]).await?;
        let stored_hash: Option<String> = tx.query("SELECT payload_sha256 FROM sync_events WHERE stream_name=$1 AND dedupe_key=$2 FOR UPDATE", &[&stream,&key]).await?[0].get(0);
        if stored_hash
            .as_deref()
            .is_some_and(|hash| hash != record.event_payload_sha256())
        {
            return Err(IntakeError::Invariant(
                "event identity changed payload hash after ingestion",
            ));
        }
        hydrate(tx, record, event_kind).await?;
        if stream == "wireless.sensor.heartbeat" {
            upsert_heartbeat(tx, record).await?;
        }
        if create_batch {
            ensure_batch(tx, record, &job_id, &batch_id).await?;
        }
        let disposition = if existed {
            IngestionDisposition::Deduplicated
        } else {
            IngestionDisposition::Processed
        };
        persisted_decision(tx, stream, key, job_id, batch_id, disposition).await?
    };
    if let Some(m) = metadata {
        tx.record_broker_evidence(m, key, decision.disposition)
            .await?;
    }
    Ok(decision)
}

async fn ensure_batch(
    tx: &mut PgTransaction,
    record: &ResolvedScanRequestRecord,
    job_id: &str,
    batch_id: &str,
) -> Result<(), IntakeError> {
    let source = record.source();
    let stream = source.stream_name();
    let key = source.dedupe_key();
    tx.execute("INSERT INTO sync_jobs(job_id,stream_name,dedupe_key,status,attempt_count,created_at) VALUES ($1,$2,$3,'pending',0,CURRENT_TIMESTAMP) ON CONFLICT(dedupe_key,stream_name) DO UPDATE SET job_id=sync_jobs.job_id", &[&job_id,&stream,&key]).await?;
    let persisted_job: String = tx
        .query(
            "SELECT job_id FROM sync_jobs WHERE stream_name=$1 AND dedupe_key=$2",
            &[&stream, &key],
        )
        .await?[0]
        .get(0);
    let cursors = tx
        .query(
            "SELECT cursor_value FROM sync_cursors WHERE stream_name=$1",
            &[&stream],
        )
        .await?;
    let cursor: String = cursors
        .first()
        .map(|row| row.get(0))
        .unwrap_or_else(|| "0".into());
    let cursor_end = if stream == "wireless.audit" {
        tx.query(
            "SELECT floor(extract(epoch FROM CAST($1 AS text)::timestamptz))::text",
            &[&source.observed_at()],
        )
        .await?[0]
            .get::<_, String>(0)
    } else {
        key.into()
    };
    tx.execute("WITH new_batch AS (
        INSERT INTO sync_batches(batch_id,job_id,batch_no,payload_ref,status,row_count,attempt_count,dedupe_key,stream_name,cursor_start,cursor_end,created_at,updated_at)
        VALUES ($1,$2,0,$3,'pending',1,0,$4,$5,$6,$7,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
        ON CONFLICT(dedupe_key,stream_name) DO NOTHING
        RETURNING 1
    )
    UPDATE sync_events SET status='batched',updated_at=CURRENT_TIMESTAMP
    WHERE dedupe_key=$4 AND stream_name=$5 AND status<>'batched' AND EXISTS (SELECT 1 FROM new_batch)",
        &[&batch_id,&persisted_job,&source.payload_ref(),&key,&stream,&cursor,&cursor_end]).await?;
    Ok(())
}

async fn persisted_decision(
    tx: &mut PgTransaction,
    stream: &str,
    key: &str,
    job_id: String,
    batch_id: String,
    disposition: IngestionDisposition,
) -> Result<IngestionDecision, IntakeError> {
    let rows = tx.query("SELECT job.job_id,batch.batch_id FROM sync_jobs job JOIN sync_batches batch ON batch.job_id=job.job_id WHERE job.stream_name=$1 AND job.dedupe_key=$2 AND batch.stream_name=$1 AND batch.dedupe_key=$2", &[&stream,&key]).await?;
    let (job_id, batch_id) = rows
        .first()
        .map(|row| (row.get(0), row.get(1)))
        .unwrap_or((job_id, batch_id));
    Ok(IngestionDecision {
        disposition,
        dedupe_key: key.into(),
        job_id,
        batch_id,
    })
}

async fn hydrate(
    tx: &mut PgTransaction,
    record: &ResolvedScanRequestRecord,
    event_kind: Option<&str>,
) -> Result<bool, IntakeError> {
    let source = record.source();
    let updated = tx.execute("UPDATE sync_events SET payload=CAST($1 AS text)::jsonb,payload_sha256=$2,event_kind=COALESCE($3,event_kind),updated_at=CURRENT_TIMESTAMP WHERE dedupe_key=$4 AND stream_name=$5 AND payload_archived=false AND (payload IS NULL OR payload_sha256=$2) AND NOT EXISTS(SELECT 1 FROM sync_event_tombstones tombstone WHERE tombstone.dedupe_key=sync_events.dedupe_key AND tombstone.stream_name=sync_events.stream_name AND tombstone.expires_at>CURRENT_TIMESTAMP)",
        &[&record.payload_json(),&record.event_payload_sha256(),&event_kind,&source.dedupe_key(),&source.stream_name()]).await?;
    if updated > 0 && source.stream_name() == "wireless.audit" {
        wireless::hydrate(tx, source.dedupe_key(), record.payload_json()).await?;
    }
    Ok(updated > 0)
}

async fn upsert_heartbeat(
    tx: &mut PgTransaction,
    record: &ResolvedScanRequestRecord,
) -> Result<(), IntakeError> {
    let payload: serde_json::Value = serde_json::from_str(record.payload_json())
        .map_err(|_| IntakeError::InvalidRecord("heartbeat payload must be JSON"))?;
    let sensor = payload
        .get("sensor_id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !java_is_blank(id) && utf16_length(id) <= 64)
        .ok_or(IntakeError::InvalidRecord(
            "sensor_id must contain 1 to 64 characters",
        ))?;
    let location = payload
        .get("location_id")
        .and_then(serde_json::Value::as_str);
    let empty = serde_json::json!({});
    let capabilities = payload
        .get("capabilities")
        .filter(|v| v.is_object())
        .unwrap_or(&empty)
        .to_string();
    tx.execute("INSERT INTO sensors(sensor_id,location_id,capabilities,metadata,first_seen_at,last_seen_at,last_heartbeat_at,status,updated_at) VALUES ($1,$2,CAST($3 AS text)::jsonb,'{}'::jsonb,CAST($4 AS text)::timestamptz,CAST($4 AS text)::timestamptz,CAST($4 AS text)::timestamptz,'online',CURRENT_TIMESTAMP) ON CONFLICT(sensor_id) DO UPDATE SET location_id=CASE WHEN EXCLUDED.last_seen_at>=sensors.last_seen_at THEN COALESCE(EXCLUDED.location_id,sensors.location_id) ELSE sensors.location_id END,capabilities=CASE WHEN EXCLUDED.last_seen_at>=sensors.last_seen_at AND EXCLUDED.capabilities<>'{}'::jsonb THEN EXCLUDED.capabilities ELSE sensors.capabilities END,first_seen_at=LEAST(sensors.first_seen_at,EXCLUDED.first_seen_at),last_seen_at=GREATEST(sensors.last_seen_at,EXCLUDED.last_seen_at),last_heartbeat_at=GREATEST(sensors.last_heartbeat_at,EXCLUDED.last_heartbeat_at),status=CASE WHEN sensors.status='disabled' THEN 'disabled' ELSE 'online' END,updated_at=CURRENT_TIMESTAMP",
        &[&sensor,&location,&capabilities,&record.source().observed_at()]).await?;
    Ok(())
}
