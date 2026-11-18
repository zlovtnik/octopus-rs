//! Verified object storage and fenced archive-before-delete maintenance.

mod minio;
mod retention;

pub use minio::{MinioStore, ObjectVersion, ObjectVersions, StoredObject};
pub use retention::{MaintenanceLease, RetentionCounts, RetentionStore};

use crate::{config::ArchiveConfig, postgres::PgError, postgres::PgRuntime, util::sha256_hex};
use chrono::{DateTime, Datelike, Utc};
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("invalid archive candidate: {0}")]
    InvalidCandidate(&'static str),
    #[error("archive object integrity check failed")]
    Integrity,
    #[error("object storage configuration invalid")]
    Configuration,
    #[error("object storage request failed (retryable={retryable}, status={status:?})")]
    Storage {
        retryable: bool,
        status: Option<u16>,
    },
    #[error("object storage response invalid: {0}")]
    Response(&'static str),
    #[error("maintenance lease lost")]
    LeaseLost,
    #[error("maintenance candidate changed")]
    CandidateChanged,
    #[error("maintenance operation cancelled")]
    Cancelled,
    #[error(transparent)]
    Database(#[from] PgError),
}

impl ArchiveError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Storage {
                retryable: true,
                ..
            } | Self::LeaseLost
        ) || matches!(
            self,
            Self::Database(PgError::Deadline | PgError::Acquisition)
        ) || matches!(
            self,
            Self::Database(PgError::Query {
                class: crate::postgres::PostgresErrorClass::Retryable,
                ..
            })
        )
    }
}

#[derive(Clone, Debug)]
pub struct ArchiveCandidate {
    pub dedupe_key: String,
    pub stream_name: String,
    pub observed_at: DateTime<Utc>,
    pub payload: String,
    pub payload_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveReceipt {
    pub uri: String,
    pub payload_bytes: i64,
    pub payload_sha256: String,
}

pub fn lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub fn object_key(candidate: &ArchiveCandidate) -> Result<String, ArchiveError> {
    if !lowercase_sha256(&candidate.dedupe_key) {
        return Err(ArchiveError::InvalidCandidate(
            "dedupe key must be a lowercase SHA-256 value",
        ));
    }
    Ok(format!(
        "wireless/{:04}/{:02}/{:02}/{}.json",
        candidate.observed_at.year(),
        candidate.observed_at.month(),
        candidate.observed_at.day(),
        candidate.dedupe_key
    ))
}

impl MinioStore {
    pub async fn archive(
        &self,
        candidate: &ArchiveCandidate,
    ) -> Result<ArchiveReceipt, ArchiveError> {
        let key = object_key(candidate)?;
        let actual = sha256_hex(&candidate.payload);
        if actual != candidate.payload_sha256 {
            return Err(ArchiveError::InvalidCandidate("payload hash mismatch"));
        }
        self.put_verified(&key, candidate.payload.as_bytes(), &actual)
            .await?;
        Ok(ArchiveReceipt {
            uri: format!("s3://{}/{}", self.bucket(), key),
            payload_bytes: candidate.payload.len() as i64,
            payload_sha256: actual,
        })
    }
}

#[derive(Clone)]
pub struct PayloadArchiver {
    runtime: Arc<PgRuntime>,
    objects: MinioStore,
    config: ArchiveConfig,
}

impl PayloadArchiver {
    pub fn new(runtime: Arc<PgRuntime>, objects: MinioStore, config: ArchiveConfig) -> Self {
        Self {
            runtime,
            objects,
            config,
        }
    }

    pub async fn initialize(&self) -> Result<(), ArchiveError> {
        self.objects.initialize().await
    }

    pub async fn archive_once(&self) -> Result<u64, ArchiveError> {
        let mut tx = self.runtime.begin_worker().await?;
        let days = self.config.hot_days.max(1);
        let limit = i64::from(self.config.batch_size.max(1));
        let rows = tx.query("SELECT dedupe_key,stream_name,observed_at,CAST(payload AS TEXT),payload_sha256 FROM sync_events WHERE stream_name='wireless.audit' AND payload_archived=false AND status<>'failed' AND payload IS NOT NULL AND payload_sha256 IS NOT NULL AND observed_at<CURRENT_TIMESTAMP-($1::int*INTERVAL '1 day') ORDER BY observed_at,dedupe_key LIMIT $2", &[&days, &limit]).await?;
        let candidates = rows
            .iter()
            .map(|r| ArchiveCandidate {
                dedupe_key: r.get(0),
                stream_name: r.get(1),
                observed_at: r.get(2),
                payload: r.get(3),
                payload_sha256: r.get(4),
            })
            .collect::<Vec<_>>();
        tx.commit().await?;
        let mut archived = 0;
        for candidate in candidates {
            match self.objects.archive(&candidate).await {
                Ok(receipt) => {
                    self.record_archive(&candidate, &receipt).await?;
                    archived += 1;
                }
                Err(error @ ArchiveError::InvalidCandidate(_)) => {
                    let mut tx = self.runtime.begin_worker().await?;
                    tx.execute("UPDATE sync_events SET status='failed',attempt_count=attempt_count+1,last_error=$3,updated_at=CURRENT_TIMESTAMP WHERE dedupe_key=$1 AND stream_name=$2 AND payload_archived=false AND status<>'failed'", &[&candidate.dedupe_key,&candidate.stream_name,&error.to_string()]).await?;
                    tx.commit().await?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(archived)
    }

    pub async fn record_archive(
        &self,
        candidate: &ArchiveCandidate,
        receipt: &ArchiveReceipt,
    ) -> Result<(), ArchiveError> {
        if receipt.payload_sha256 != candidate.payload_sha256
            || receipt.payload_bytes != candidate.payload.len() as i64
            || receipt.payload_sha256 != sha256_hex(&candidate.payload)
        {
            return Err(ArchiveError::Integrity);
        }
        let expected = format!("s3://{}/{}", self.objects.bucket(), object_key(candidate)?);
        if receipt.uri != expected {
            return Err(ArchiveError::Integrity);
        }
        let mut tx = self.runtime.begin_worker().await?;
        tx.execute("INSERT INTO sync_event_payload_archives(dedupe_key,stream_name,observed_at,payload_sha256,archive_uri,payload_bytes,archived_at,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT(dedupe_key,stream_name) DO UPDATE SET archive_uri=EXCLUDED.archive_uri,payload_bytes=EXCLUDED.payload_bytes,updated_at=CURRENT_TIMESTAMP", &[&candidate.dedupe_key,&candidate.stream_name,&candidate.observed_at,&receipt.payload_sha256,&receipt.uri,&receipt.payload_bytes]).await?;
        let updated=tx.execute("UPDATE sync_events SET payload_archive_uri=$3,archived_payload_bytes=$4,payload_archived_at=CURRENT_TIMESTAMP,payload_archived=true,payload=NULL,updated_at=CURRENT_TIMESTAMP WHERE dedupe_key=$1 AND stream_name=$2 AND payload_archived=false AND payload_sha256=$5 AND payload IS NOT NULL", &[&candidate.dedupe_key,&candidate.stream_name,&receipt.uri,&receipt.payload_bytes,&receipt.payload_sha256]).await?;
        if updated != 1 {
            return Err(ArchiveError::CandidateChanged);
        }
        tx.commit().await?;
        Ok(())
    }
}
