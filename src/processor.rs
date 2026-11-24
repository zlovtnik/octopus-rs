//! Processor identities, catalog contracts and pure selection/retry policy.
use serde::Serialize;
use std::collections::BTreeSet;
use std::time::Duration;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum ProcessorOwner {
    #[serde(rename = "octopus")]
    Octopus,
    #[serde(rename = "atheros-search")]
    AtherosSearch,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum ProcessorFamily {
    #[serde(rename = "sync")]
    Sync,
    #[serde(rename = "wireless")]
    Wireless,
    #[serde(rename = "embedding")]
    Embedding,
    #[serde(rename = "search_projection")]
    SearchProjection,
    #[serde(rename = "maintenance")]
    Maintenance,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum ProcessorMode {
    #[serde(rename = "continuous")]
    Continuous,
    #[serde(rename = "periodic")]
    Periodic,
}
// Keep declaration order (and thus Ord and serde variant indices) stable.
macro_rules! processor_ids {
    ($($id:ident => $name:literal),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        pub enum ProcessorId {
            $(#[serde(rename = $name)] $id,)+
        }

        impl ProcessorId {
            const COUNT: usize = [$(Self::$id),+].len();

            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$id => $name,)+
                }
            }
        }
    };
}

processor_ids! {
    SyncScanIngestion => "sync-scan-ingestion",
    SyncJobPlanner => "sync-job-planner",
    SyncBacklogRecovery => "sync-backlog-recovery",
    SyncLoadDispatch => "sync-load-dispatch",
    SyncLoadConsumer => "sync-load-consumer",
    SyncResultConsumer => "sync-result-consumer",
    SyncOutboxPublisher => "sync-outbox-publisher",
    WirelessHeartbeatIngestion => "wireless-heartbeat-ingestion",
    WirelessAuditProjection => "wireless-audit-projection",
    WirelessFrameNormalizer => "wireless-frame-normalizer",
    WirelessInventoryProjector => "wireless-inventory-projector",
    WirelessIdentityProjector => "wireless-identity-projector",
    WirelessBehaviorProjector => "wireless-behavior-projector",
    WirelessTimingProjector => "wireless-timing-projector",
    WirelessSequenceProjector => "wireless-sequence-projector",
    WirelessBaselineProjector => "wireless-baseline-projector",
    WirelessSimilarityProjector => "wireless-similarity-projector",
    ThreatRiskProjector => "threat-risk-projector",
    EmbeddingPreparer => "embedding-preparer",
    EmbeddingCompleter => "embedding-completer",
    EmbeddingLeaseRecovery => "embedding-lease-recovery",
    EmbeddingTextBuilder => "embedding-text-builder",
    ProxySearchPreparer => "proxy-search-preparer",
    RfAlertProjector => "rf-alert-projector",
    EventRetention => "event-retention",
    SearchRetention => "search-retention",
    StaleWorkerCleanup => "stale-worker-cleanup",
    ScheduledReconciliation => "scheduled-reconciliation",
}

impl ProcessorId {
    // The catalog order differs from the enum's declaration order.
    pub const ALL: [Self; Self::COUNT] = {
        let mut ids = [Self::SyncScanIngestion; Self::COUNT];
        let mut index = 0;
        while index < ids.len() {
            ids[index] = CONTRACTS[index].id;
            index += 1;
        }
        ids
    };

    pub const KAFKA_CONSUMERS: [Self; 5] = [
        Self::WirelessAuditProjection,
        Self::SyncScanIngestion,
        Self::SyncLoadConsumer,
        Self::SyncResultConsumer,
        Self::WirelessHeartbeatIngestion,
    ];
    pub fn owner(self) -> ProcessorOwner {
        ProcessorCatalog::by_id(self).owner
    }

    pub fn family(self) -> ProcessorFamily {
        ProcessorCatalog::by_id(self).family
    }

    pub fn from_string(value: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|id| id.as_str() == value)
            .ok_or_else(|| format!("unknown or retired processor id: {value}"))
    }
    pub fn octopus_owned() -> impl Iterator<Item = Self> {
        ProcessorCatalog::contracts()
            .iter()
            .filter(|contract| contract.owner == ProcessorOwner::Octopus)
            .map(|contract| contract.id)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessorContract {
    pub id: ProcessorId,
    pub owner: ProcessorOwner,
    pub family: ProcessorFamily,
    pub mode: ProcessorMode,
    pub inputs: &'static [&'static str],
    pub outputs: &'static [&'static str],
    pub dependencies: &'static [ProcessorId],
    pub dedupe_key: &'static str,
    pub lease_scope: &'static str,
    pub terminal_behavior: &'static str,
    pub reconciliation_policy: &'static str,
    pub default_enabled: bool,
}
pub struct ProcessorCatalog;
impl ProcessorCatalog {
    pub fn contracts() -> &'static [ProcessorContract] {
        &CONTRACTS
    }
    pub fn by_id(id: ProcessorId) -> &'static ProcessorContract {
        CONTRACTS
            .iter()
            .find(|contract| contract.id == id)
            .expect("all IDs have contracts")
    }
}
static CONTRACTS: [ProcessorContract; ProcessorId::COUNT] = [
    ProcessorContract {
        id: ProcessorId::WirelessAuditProjection,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Wireless,
        mode: ProcessorMode::Continuous,
        inputs: &["wireless.audit"],
        outputs: &[
            "wireless_observation_summaries",
            "wireless_topology_nodes",
            "wireless_topology_edges",
        ],
        dependencies: &[],
        dedupe_key: "topic/partition/offset and payload hash",
        lease_scope: "kafka partition",
        terminal_behavior: "park invalid and permanent records; retry retryable storage errors",
        reconciliation_policy: "seven-day projection comparison",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::SyncScanIngestion,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Sync,
        mode: ProcessorMode::Continuous,
        inputs: &["sync.scan.request"],
        outputs: &["sync_events", "ingestion_evidence"],
        dependencies: &[],
        dedupe_key: "group/topic/partition/offset",
        lease_scope: "kafka partition",
        terminal_behavior: "park/DLQ invalid records",
        reconciliation_policy: "bounded offset audit",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::SyncJobPlanner,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Sync,
        mode: ProcessorMode::Periodic,
        inputs: &["sync_events"],
        outputs: &["sync_jobs", "sync_batches"],
        dependencies: &[ProcessorId::SyncScanIngestion],
        dedupe_key: "stream_name/dedupe_key",
        lease_scope: "stream",
        terminal_behavior: "park exhausted work",
        reconciliation_policy: "orphan event scan",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::SyncBacklogRecovery,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Sync,
        mode: ProcessorMode::Periodic,
        inputs: &["expired sync leases"],
        outputs: &["sync_jobs", "sync_batches"],
        dependencies: &[ProcessorId::SyncJobPlanner],
        dedupe_key: "job_id/batch_id",
        lease_scope: "batch",
        terminal_behavior: "fail exhausted batch",
        reconciliation_policy: "lease expiry scan",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::SyncLoadDispatch,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Sync,
        mode: ProcessorMode::Periodic,
        inputs: &["sync_batches"],
        outputs: &["outbox_events"],
        dependencies: &[ProcessorId::SyncJobPlanner],
        dedupe_key: "batch_id/attempt",
        lease_scope: "batch",
        terminal_behavior: "park exhausted dispatch",
        reconciliation_policy: "batch/outbox audit",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::SyncLoadConsumer,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Sync,
        mode: ProcessorMode::Continuous,
        inputs: &["sync.oracle.load"],
        outputs: &["domain tables", "sync.oracle.result"],
        dependencies: &[ProcessorId::SyncOutboxPublisher],
        dedupe_key: "batch_id/attempt",
        lease_scope: "kafka partition",
        terminal_behavior: "sync result failure",
        reconciliation_policy: "batch checksum",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::SyncResultConsumer,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Sync,
        mode: ProcessorMode::Continuous,
        inputs: &["sync.oracle.result"],
        outputs: &["sync_jobs", "sync_batches", "sync_cursors"],
        dependencies: &[ProcessorId::SyncLoadConsumer],
        dedupe_key: "batch_id/attempt",
        lease_scope: "kafka partition",
        terminal_behavior: "terminal job failure",
        reconciliation_policy: "batch/cursor scan",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::SyncOutboxPublisher,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Sync,
        mode: ProcessorMode::Continuous,
        inputs: &["outbox_events"],
        outputs: &["Redpanda"],
        dependencies: &[ProcessorId::SyncLoadDispatch],
        dedupe_key: "destination_topic/message_key",
        lease_scope: "outbox row",
        terminal_behavior: "park exhausted publication",
        reconciliation_policy: "publish-attempt audit",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::WirelessHeartbeatIngestion,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Wireless,
        mode: ProcessorMode::Continuous,
        inputs: &["wireless.sensor.heartbeat"],
        outputs: &["ingestion_receipts", "sensors"],
        dependencies: &[],
        dedupe_key: "consumer-group/topic/partition/offset and event-id",
        lease_scope: "kafka partition",
        terminal_behavior: "sanitize and park malformed records",
        reconciliation_policy: "monotonic sensor heartbeat audit",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::WirelessFrameNormalizer,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Wireless,
        mode: ProcessorMode::Continuous,
        inputs: &["wireless.audit"],
        outputs: &["wireless normalized tables"],
        dependencies: &[ProcessorId::SyncLoadConsumer],
        dedupe_key: "event_id",
        lease_scope: "wireless event",
        terminal_behavior: "park invalid frame",
        reconciliation_policy: "source/frame checksum",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::WirelessInventoryProjector,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Wireless,
        mode: ProcessorMode::Periodic,
        inputs: &["wireless normalized tables"],
        outputs: &["device/client/sensor inventory"],
        dependencies: &[ProcessorId::WirelessFrameNormalizer],
        dedupe_key: "device/window",
        lease_scope: "inventory key",
        terminal_behavior: "record reconciliation finding",
        reconciliation_policy: "inventory rebuild",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::WirelessIdentityProjector,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Wireless,
        mode: ProcessorMode::Periodic,
        inputs: &["inventory"],
        outputs: &["confirmed identity clusters and same_device edges"],
        dependencies: &[ProcessorId::WirelessInventoryProjector],
        dedupe_key: "identity/source",
        lease_scope: "identity key",
        terminal_behavior: "record reconciliation finding",
        reconciliation_policy: "identity rebuild",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::WirelessBehaviorProjector,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Wireless,
        mode: ProcessorMode::Periodic,
        inputs: &["wireless normalized tables"],
        outputs: &["behaviour_snapshots"],
        dependencies: &[ProcessorId::WirelessFrameNormalizer],
        dedupe_key: "mac/window",
        lease_scope: "behaviour window",
        terminal_behavior: "record reconciliation finding",
        reconciliation_policy: "behaviour rebuild",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::WirelessTimingProjector,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Wireless,
        mode: ProcessorMode::Periodic,
        inputs: &["wireless normalized tables"],
        outputs: &["timing_profiles"],
        dependencies: &[ProcessorId::WirelessFrameNormalizer],
        dedupe_key: "mac/session",
        lease_scope: "timing window",
        terminal_behavior: "record reconciliation finding",
        reconciliation_policy: "timing rebuild",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::WirelessSequenceProjector,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Wireless,
        mode: ProcessorMode::Periodic,
        inputs: &["wireless normalized tables"],
        outputs: &["frame_sequences", "sequence_transitions"],
        dependencies: &[ProcessorId::WirelessFrameNormalizer],
        dedupe_key: "session/token",
        lease_scope: "sequence session",
        terminal_behavior: "record reconciliation finding",
        reconciliation_policy: "sequence rebuild",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::WirelessBaselineProjector,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Wireless,
        mode: ProcessorMode::Periodic,
        inputs: &["wireless normalized tables"],
        outputs: &["baseline_profiles"],
        dependencies: &[ProcessorId::WirelessFrameNormalizer],
        dedupe_key: "bssid/window",
        lease_scope: "baseline window",
        terminal_behavior: "record reconciliation finding",
        reconciliation_policy: "baseline rebuild",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::WirelessSimilarityProjector,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Wireless,
        mode: ProcessorMode::Periodic,
        inputs: &["search_vectors"],
        outputs: &["similarity_pairs"],
        dependencies: &[ProcessorId::EmbeddingLeaseRecovery],
        dedupe_key: "kind/anchor/candidate",
        lease_scope: "similarity anchor",
        terminal_behavior: "record reconciliation finding",
        reconciliation_policy: "similarity rescan",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::ThreatRiskProjector,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::SearchProjection,
        mode: ProcessorMode::Periodic,
        inputs: &["wireless alerts", "similarity_pairs"],
        outputs: &["threat_signals", "ap_risk_scores"],
        dependencies: &[
            ProcessorId::WirelessSimilarityProjector,
            ProcessorId::RfAlertProjector,
        ],
        dedupe_key: "signal/subject/window",
        lease_scope: "risk subject",
        terminal_behavior: "record reconciliation finding",
        reconciliation_policy: "risk rescan",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::EmbeddingPreparer,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Embedding,
        mode: ProcessorMode::Periodic,
        inputs: &["search documents"],
        outputs: &["embedding_jobs"],
        dependencies: &[ProcessorId::EmbeddingTextBuilder],
        dedupe_key: "document/model/kind/checksum",
        lease_scope: "embedding job",
        terminal_behavior: "park invalid source",
        reconciliation_policy: "missing-job scan",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::EmbeddingCompleter,
        owner: ProcessorOwner::AtherosSearch,
        family: ProcessorFamily::Embedding,
        mode: ProcessorMode::Continuous,
        inputs: &["embedding_jobs"],
        outputs: &["search_vectors"],
        dependencies: &[ProcessorId::EmbeddingPreparer],
        dedupe_key: "job_id/model/fence",
        lease_scope: "embedding job",
        terminal_behavior: "bounded retry/DLQ",
        reconciliation_policy: "source/vector checksum",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::EmbeddingLeaseRecovery,
        owner: ProcessorOwner::AtherosSearch,
        family: ProcessorFamily::Embedding,
        mode: ProcessorMode::Continuous,
        inputs: &["expired embedding leases"],
        outputs: &["embedding_jobs"],
        dependencies: &[ProcessorId::EmbeddingCompleter],
        dedupe_key: "job_id/attempt/fence",
        lease_scope: "embedding job",
        terminal_behavior: "fail exhausted job",
        reconciliation_policy: "lease expiry scan",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::EmbeddingTextBuilder,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Embedding,
        mode: ProcessorMode::Periodic,
        inputs: &["normalized domain rows"],
        outputs: &["search_documents", "search_document_tokens"],
        dependencies: &[ProcessorId::WirelessInventoryProjector],
        dedupe_key: "source/checksum",
        lease_scope: "source row",
        terminal_behavior: "park malformed text input",
        reconciliation_policy: "document checksum",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::ProxySearchPreparer,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Embedding,
        mode: ProcessorMode::Periodic,
        inputs: &["proxy observations"],
        outputs: &["proxy_event_evidence", "search_documents", "embedding_jobs"],
        dependencies: &[],
        dedupe_key: "source/revision/input-revision",
        lease_scope: "proxy preparation",
        terminal_behavior: "retain terminal dispositions",
        reconciliation_policy: "bounded arrival and dirty-source scan",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::RfAlertProjector,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::SearchProjection,
        mode: ProcessorMode::Periodic,
        inputs: &["wireless events"],
        outputs: &["wireless alerts"],
        dependencies: &[],
        dedupe_key: "rule/subject/window",
        lease_scope: "alert key",
        terminal_behavior: "park invalid evidence",
        reconciliation_policy: "rule replay",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::EventRetention,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Maintenance,
        mode: ProcessorMode::Periodic,
        inputs: &["expired core events", "archive metadata"],
        outputs: &["retention_runs"],
        dependencies: &[ProcessorId::SyncResultConsumer],
        dedupe_key: "policy/cutoff",
        lease_scope: "retention policy",
        terminal_behavior: "record failed run",
        reconciliation_policy: "archive-before-delete audit",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::SearchRetention,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Maintenance,
        mode: ProcessorMode::Periodic,
        inputs: &["expired search rows"],
        outputs: &["retention_runs"],
        dependencies: &[ProcessorId::EmbeddingLeaseRecovery],
        dedupe_key: "policy/cutoff",
        lease_scope: "retention policy",
        terminal_behavior: "record failed run",
        reconciliation_policy: "search expiry scan",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::StaleWorkerCleanup,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Maintenance,
        mode: ProcessorMode::Periodic,
        inputs: &["expired worker leases"],
        outputs: &["jobs", "leases"],
        dependencies: &[ProcessorId::SyncBacklogRecovery],
        dedupe_key: "work_id/fence",
        lease_scope: "work item",
        terminal_behavior: "park exhausted work",
        reconciliation_policy: "lease scan",
        default_enabled: false,
    },
    ProcessorContract {
        id: ProcessorId::ScheduledReconciliation,
        owner: ProcessorOwner::Octopus,
        family: ProcessorFamily::Maintenance,
        mode: ProcessorMode::Periodic,
        inputs: &["domain/projection state"],
        outputs: &["reconciliation_findings"],
        dependencies: &[ProcessorId::StaleWorkerCleanup],
        dedupe_key: "processor/entity/version",
        lease_scope: "processor shard",
        terminal_behavior: "persist unresolved finding",
        reconciliation_policy: "deterministic diff/repair",
        default_enabled: false,
    },
];

/// The configured selection is checked for dependencies; implicit consumers are
/// deliberately not required to enable their upstream producer workloads.
/// Ownership validation belongs to AppConfig, matching the Scala supervisor.
pub fn selected_processors(
    configured: &[String],
    consumers_enabled: bool,
) -> Result<BTreeSet<ProcessorId>, String> {
    let configured = configured
        .iter()
        .map(|id| ProcessorId::from_string(id))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut enabled = configured.clone();
    if consumers_enabled {
        enabled.extend(ProcessorId::KAFKA_CONSUMERS);
    }
    let mut missing = configured
        .iter()
        .flat_map(|id| {
            ProcessorCatalog::by_id(*id)
                .dependencies
                .iter()
                .filter(|dependency| {
                    dependency.owner() == ProcessorOwner::Octopus && !enabled.contains(dependency)
                })
                .map(move |dependency| format!("{}->{}", id.as_str(), dependency.as_str()))
        })
        .collect::<Vec<_>>();
    missing.sort();
    if missing.is_empty() {
        Ok(enabled)
    } else {
        Err(format!(
            "enabled processors have disabled dependencies: {}",
            missing.join(",")
        ))
    }
}

/// Validate every supplied workload, including duplicates in disabled entries,
/// before selecting enabled IDs in supplied order.
pub fn select_workloads(
    enabled: &BTreeSet<ProcessorId>,
    workloads: &[ProcessorId],
) -> Result<Vec<ProcessorId>, String> {
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for id in workloads {
        if !seen.insert(*id) {
            duplicates.insert(id.as_str());
        }
    }
    if !duplicates.is_empty() {
        return Err(format!(
            "duplicate processor workloads: {}",
            duplicates.into_iter().collect::<Vec<_>>().join(",")
        ));
    }
    let mut missing = enabled
        .difference(&seen)
        .map(|id| id.as_str())
        .collect::<Vec<_>>();
    missing.sort();
    if !missing.is_empty() {
        return Err(format!(
            "enabled processors have no workload: {}",
            missing.join(",")
        ));
    }
    Ok(workloads
        .iter()
        .copied()
        .filter(|id| enabled.contains(id))
        .collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    base_delay_ms: i64,
    max_delay_ms: i64,
    max_attempts: Option<i32>,
}

impl RetryPolicy {
    pub fn new(
        base_delay_ms: i64,
        max_delay_ms: i64,
        max_attempts: Option<i32>,
    ) -> Result<Self, String> {
        if base_delay_ms <= 0 {
            return Err("base delay must be positive".into());
        }
        if max_delay_ms < base_delay_ms {
            return Err("max delay must be at least base delay".into());
        }
        if max_attempts.is_some_and(|attempts| attempts <= 0) {
            return Err("max attempts must be positive when configured".into());
        }
        Ok(Self {
            base_delay_ms,
            max_delay_ms,
            max_attempts,
        })
    }

    pub fn delay(self, id: ProcessorId, attempt: i32) -> Duration {
        let attempt = attempt.max(1);
        let bucket = java_string_hash(id.as_str())
            .wrapping_mul(31)
            .wrapping_add(attempt)
            .rem_euclid(401);
        let jitter = (f64::from(bucket) - 200.0) / 1000.0;
        retry_delay(self.base_delay_ms, self.max_delay_ms, attempt, jitter)
    }

    pub fn permits(self, attempt: i32) -> bool {
        self.max_attempts.is_none_or(|maximum| attempt <= maximum)
    }
}

/// Java String.hashCode uses UTF-16 code units and signed 32-bit wraparound.
pub fn java_string_hash(value: &str) -> i32 {
    value.encode_utf16().fold(0_i32, |hash, unit| {
        hash.wrapping_mul(31).wrapping_add(i32::from(unit))
    })
}

/// Pure supervisor delay. Keep this separate from RetryPolicy validation: the
/// Scala supervisor clamps its base/max and jitter even when called directly.
pub fn retry_delay(base_delay_ms: i64, max_delay_ms: i64, attempt: i32, jitter: f64) -> Duration {
    let exponent = (attempt.max(1) - 1).min(30) as u32;
    let uncapped = (base_delay_ms.max(1) as u128) << exponent;
    let capped = uncapped.min(max_delay_ms.max(base_delay_ms).max(0) as u128) as i64;
    let bounded = jitter.clamp(-0.2, 0.2);
    // Rust saturating float-to-integer conversion matches Java Math.round's
    // overflow/NaN handling; all non-NaN delays are nonnegative here.
    let rounded = ((capped as f64) * (1.0 + bounded)).round() as i64;
    Duration::from_millis(rounded.max(1) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_complete_and_has_stable_ownership() {
        let contracts = ProcessorCatalog::contracts();
        assert_eq!(contracts.len(), 28);
        assert_eq!(ProcessorId::octopus_owned().count(), 26);
        assert_eq!(
            ProcessorId::ALL
                .into_iter()
                .filter(|id| id.owner() == ProcessorOwner::AtherosSearch)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                ProcessorId::EmbeddingCompleter,
                ProcessorId::EmbeddingLeaseRecovery
            ])
        );
        let mut ids = BTreeSet::new();
        for id in ProcessorId::ALL {
            assert_eq!(ProcessorId::from_string(id.as_str()), Ok(id));
            assert!(ids.insert(id));
            let contract = ProcessorCatalog::by_id(id);
            assert_eq!(contract.id, id);
            assert_eq!(contract.owner, id.owner());
            assert_eq!(contract.family, id.family());
            assert!(!contract.default_enabled);
            assert!(!contract.inputs.is_empty());
            assert!(!contract.outputs.is_empty());
            assert!(!contract.dedupe_key.is_empty());
            assert!(!contract.lease_scope.is_empty());
            assert!(!contract.terminal_behavior.is_empty());
            assert!(!contract.reconciliation_policy.is_empty());
            assert!(!contract.dependencies.contains(&id));
        }
        assert!(ProcessorId::from_string("EVENT-RETENTION").is_err());
        assert!(ProcessorId::from_string(" event-retention").is_err());
        assert!(ProcessorId::from_string("retired").is_err());
    }

    #[test]
    fn catalog_matches_canonical_manifest() {
        let current = std::env::current_dir().unwrap();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .chain(current.ancestors())
            .find(|path| {
                path.join("sql/postgres/contracts/processors.json")
                    .is_file()
            });
        // Standalone source checkouts do not contain the umbrella schema tree.
        if let Some(root) = root {
            let manifest: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(root.join("sql/postgres/contracts/processors.json"))
                    .unwrap(),
            )
            .unwrap();
            let entries = manifest["processors"].as_array().unwrap();
            assert_eq!(entries.len(), 28);
            let mut canonical = std::collections::BTreeMap::new();
            for entry in entries {
                assert!(canonical
                    .insert(entry["id"].as_str().unwrap(), entry)
                    .is_none());
            }
            for contract in ProcessorCatalog::contracts() {
                assert_eq!(
                    canonical[contract.id.as_str()],
                    &serde_json::to_value(contract).unwrap()
                );
            }
        }
    }

    #[test]
    fn consumers_union_with_proxy_selection_without_producer_dependencies() {
        let selected = selected_processors(&["proxy-search-preparer".into()], true).unwrap();
        assert_eq!(selected.len(), 6);
        assert!(selected.contains(&ProcessorId::ProxySearchPreparer));
        assert!(ProcessorId::KAFKA_CONSUMERS
            .into_iter()
            .all(|id| selected.contains(&id)));
        assert_eq!(
            selected_processors(&[], true).unwrap(),
            ProcessorId::KAFKA_CONSUMERS.into_iter().collect()
        );
        assert!(selected_processors(&[], false).unwrap().is_empty());
        assert_eq!(
            selected_processors(&["proxy-search-preparer".into()], false).unwrap(),
            BTreeSet::from([ProcessorId::ProxySearchPreparer])
        );
    }

    #[test]
    fn dependencies_validate_configured_entries_and_skip_search_owned_dependencies() {
        assert_eq!(
            selected_processors(&["event-retention".into()], false).unwrap_err(),
            "enabled processors have disabled dependencies: event-retention->sync-result-consumer"
        );
        assert!(selected_processors(&["event-retention".into()], true).is_ok());
        assert!(selected_processors(&["wireless-similarity-projector".into()], false).is_ok());
        assert!(selected_processors(&["embedding-lease-recovery".into()], false).is_ok());
        assert!(selected_processors(&["unknown".into()], false).is_err());
    }

    #[test]
    fn workload_selection_rejects_duplicates_and_missing_then_preserves_order() {
        let enabled = BTreeSet::from([
            ProcessorId::EventRetention,
            ProcessorId::ProxySearchPreparer,
        ]);
        assert!(select_workloads(&enabled, &[ProcessorId::EventRetention])
            .unwrap_err()
            .contains("proxy-search-preparer"));
        assert!(select_workloads(
            &BTreeSet::new(),
            &[ProcessorId::EventRetention, ProcessorId::EventRetention]
        )
        .unwrap_err()
        .contains("duplicate processor workloads"));
        assert_eq!(
            select_workloads(
                &enabled,
                &[
                    ProcessorId::ProxySearchPreparer,
                    ProcessorId::SyncScanIngestion,
                    ProcessorId::EventRetention
                ]
            )
            .unwrap(),
            vec![
                ProcessorId::ProxySearchPreparer,
                ProcessorId::EventRetention
            ]
        );
    }

    #[test]
    fn retry_delays_are_deterministic_capped_and_attempt_limit_is_inclusive() {
        let policy = RetryPolicy::new(1000, 8000, Some(3)).unwrap();
        let delays = (1..=20)
            .map(|attempt| policy.delay(ProcessorId::EventRetention, attempt))
            .collect::<Vec<_>>();
        assert_eq!(
            delays[..4],
            [883, 1768, 3540, 7088].map(Duration::from_millis)
        );
        assert_eq!(
            policy.delay(ProcessorId::EventRetention, 20),
            Duration::from_millis(7216)
        );
        assert_eq!(
            policy.delay(ProcessorId::EventRetention, i32::MAX),
            Duration::from_millis(6464)
        );
        assert!(delays
            .iter()
            .all(|delay| *delay >= Duration::from_millis(800)
                && *delay <= Duration::from_millis(9600)));
        assert_eq!(
            delays,
            (1..=20)
                .map(|attempt| policy.delay(ProcessorId::EventRetention, attempt))
                .collect::<Vec<_>>()
        );
        assert!(policy.permits(3));
        assert!(!policy.permits(4));
        assert!(RetryPolicy::new(1, 1, None).unwrap().permits(i32::MAX));
        assert_eq!(
            policy.delay(ProcessorId::EventRetention, i32::MIN),
            policy.delay(ProcessorId::EventRetention, 1)
        );
        assert!(RetryPolicy::new(0, 1, None).is_err());
        assert!(RetryPolicy::new(2, 1, None).is_err());
        assert!(RetryPolicy::new(1, 1, Some(0)).is_err());
    }

    #[test]
    fn java_hash_and_retry_overflow_cases() {
        assert_eq!(java_string_hash(""), 0);
        assert_eq!(java_string_hash("hello"), 99162322);
        assert_eq!(java_string_hash("\u{1f600}"), 1772899);
        assert_eq!(java_string_hash("polygenelubricants"), i32::MIN);
        assert_eq!(retry_delay(1, 8, 1, -1.0), Duration::from_millis(1));
        assert_eq!(retry_delay(100, 800, 1, 1.0), Duration::from_millis(120));
        assert_eq!(
            retry_delay(100, 800, i32::MAX, 0.0),
            Duration::from_millis(800)
        );
        assert_eq!(
            retry_delay(i64::MAX, i64::MAX, i32::MAX, 0.2),
            Duration::from_millis(i64::MAX as u64)
        );
        assert_eq!(retry_delay(5, 5, 1, -0.1), Duration::from_millis(5));
    }
}
