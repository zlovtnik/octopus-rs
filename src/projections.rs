//! Coordinator-owned maintained projections. Every entry point commits its own
//! transaction; broker offsets remain the consumer boundary's responsibility.

use crate::{
    config::WirelessProjectionConfig,
    domain::BrokerRecordMetadata,
    postgres::{PgError, PgRuntime},
};
use serde_json::Value;
use std::sync::Arc;

pub mod identity;
pub mod intelligence;
mod maintained;
pub mod proxy;
mod queries;
pub mod search;
pub mod wireless;

pub use proxy::proxy_evidence;
pub use wireless::{decode_wireless, RadioSamples, WirelessObservation};

#[derive(Debug, thiserror::Error)]
pub enum ProjectionError {
    #[error("invalid projection input: {0}")]
    Invalid(&'static str),
    #[error("wireless broker coordinate payload hash conflict")]
    CoordinateConflict,
    #[error(transparent)]
    Database(#[from] PgError),
}

#[derive(Clone)]
pub struct ProjectionStore {
    runtime: Arc<PgRuntime>,
    wireless: WirelessProjectionConfig,
}

impl ProjectionStore {
    pub fn new(runtime: Arc<PgRuntime>) -> Self {
        Self::with_wireless(runtime, WirelessProjectionConfig::default())
    }

    pub fn with_wireless(runtime: Arc<PgRuntime>, wireless: WirelessProjectionConfig) -> Self {
        Self { runtime, wireless }
    }

    pub async fn project_wireless_record(
        &self,
        value: Value,
        metadata: &BrokerRecordMetadata,
    ) -> Result<bool, ProjectionError> {
        self.project_wireless_observation(WirelessObservation::from_value(&value)?, metadata)
            .await
    }

    pub async fn project_wireless_observation(
        &self,
        event: WirelessObservation,
        metadata: &BrokerRecordMetadata,
    ) -> Result<bool, ProjectionError> {
        let mut tx = self.runtime.begin_worker().await?;
        let projected = wireless::project(&mut tx, &event, metadata, &self.wireless).await?;
        tx.commit().await?;
        Ok(projected)
    }

    pub async fn expire_wireless_projections(&self, limit: i32) -> Result<i32, ProjectionError> {
        let mut tx = self.runtime.begin_worker().await?;
        let count = wireless::expire(&mut tx, limit).await?;
        tx.commit().await?;
        Ok(count)
    }
}
