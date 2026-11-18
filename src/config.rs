//! Typed coordinator defaults, environment and explicit HOCON overrides.
use crate::compatibility::hocon;
use crate::processor::{ProcessorId, ProcessorOwner};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(pub Vec<String>);
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid Octopus configuration: {}", self.0.join("; "))
    }
}
impl std::error::Error for ConfigError {}

fn trim(value: &str) -> &str {
    value.trim_matches(|c| c <= '\u{20}')
}
trait EnvValue: Sized {
    fn parse_env(value: &str) -> Result<Self, ()>;
    fn parse_config(value: &hocon::Value) -> Result<Self, ()> {
        match value {
            hocon::Value::Scalar(value) => Self::parse_env(value),
            _ => Err(()),
        }
    }
}
impl EnvValue for String {
    fn parse_env(value: &str) -> Result<Self, ()> {
        Ok(value.into())
    }
}
impl EnvValue for Vec<String> {
    fn parse_env(value: &str) -> Result<Self, ()> {
        Ok(value.split(',').map(|s| trim(s).into()).collect())
    }
    fn parse_config(value: &hocon::Value) -> Result<Self, ()> {
        match value {
            hocon::Value::Scalar(value) => Self::parse_env(value),
            hocon::Value::List(values) => Ok(values.iter().map(|s| trim(s).into()).collect()),
            _ => Err(()),
        }
    }
}
macro_rules! scalar { ($($t:ty),*) => {$ (impl EnvValue for $t { fn parse_env(value:&str)->Result<Self,()>{trim(value).parse().map_err(|_|())} })*}; }
scalar!(i32, i64, f64);
impl EnvValue for bool {
    fn parse_env(value: &str) -> Result<Self, ()> {
        match trim(value).to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" => Ok(true),
            "false" | "no" | "off" => Ok(false),
            _ => Err(()),
        }
    }
}
macro_rules! section {
 ($name:ident { $($field:ident : $ty:ty = $default:expr => [$($env:literal),*]),* $(,)? }) => {
  #[derive(Clone, PartialEq)]
  pub struct $name { $(pub $field:$ty),* }
  impl Default for $name { fn default()->Self {Self {$($field:$default),*}} }
  impl $name {
   fn bind(&mut self, env:&BTreeMap<String,String>, errors:&mut Vec<String>){$($(if let Some(value)=env.get($env){match <$ty as EnvValue>::parse_env(value){Ok(v)=>self.$field=v,Err(())=>errors.push(concat!("invalid value for ",$env).into())}})*)*}
   fn bind_config(&mut self, prefix:&str, values:&BTreeMap<String,hocon::Value>, errors:&mut Vec<String>){$(
    let field = if stringify!($field) == "manifest_sha256" { "manifest-sha-256".to_owned() } else { stringify!($field).replace('_',"-") };
    let path=format!("{prefix}.{field}");
    if let Some(value)=values.get(&path) {match <$ty as EnvValue>::parse_config(value){Ok(value)=>self.$field=value,Err(())=>errors.push(format!("invalid value for {path}"))}}
   )*}
   pub const ENVIRONMENT_KEYS: &'static [&'static str] = &[$($($env,)*)*];
  }
 };
}

section!(PostgresConfig {
 host: String = "127.0.0.1".into() => ["POSTGRES_HOST"],
 port: i32 = 5432 => ["POSTGRES_PORT"],
 database: String = "sync".into() => ["POSTGRES_DATABASE"],
 user: String = "octopus_runtime".into() => ["POSTGRES_USER"],
 password: String = "".into() => ["POSTGRES_PASSWORD"],
 pool_size: i32 = 20 => ["POSTGRES_POOL_SIZE"],
 healthcheck_reserve: i32 = 2 => ["POSTGRES_HEALTHCHECK_RESERVE"],
 connection_timeout_ms: i64 = 5000 => ["POSTGRES_CONNECTION_TIMEOUT_MS"],
 statement_timeout_secs: i32 = 30 => ["POSTGRES_STATEMENT_TIMEOUT_SECS"],
 network_timeout_secs: i32 = 60 => ["POSTGRES_NETWORK_TIMEOUT_SECS"],
 load_chunk_max_bytes: i32 = 4194304 => ["POSTGRES_LOAD_CHUNK_MAX_BYTES"],
 enabled: bool = false => ["POSTGRES_ENABLED"],
 warn_only: bool = false => ["POSTGRES_WARN_ONLY"],
 ssl_mode: String = "verify-full".into() => ["POSTGRES_SSL_MODE"],
 ssl_ca_path: String = "".into() => ["POSTGRES_SSL_CA_PATH"],
 ssl_server_name: String = "".into() => ["POSTGRES_SSL_SERVER_NAME"],
 ssl_client_key_store_path: String = "".into() => ["POSTGRES_SSL_CLIENT_KEYSTORE_PATH"],
 ssl_client_key_store_password: String = "".into() => ["POSTGRES_SSL_CLIENT_KEYSTORE_PASSWORD"],
 ssl_client_key_store_type: String = "PKCS12".into() => ["POSTGRES_SSL_CLIENT_KEYSTORE_TYPE"],
 local_dev_allow_public_key_retrieval: bool = false => ["POSTGRES_LOCAL_DEV_ALLOW_PUBLIC_KEY_RETRIEVAL"],
 manifest_sha256: String = "7f20b99662f8591cbb6e963e37c01a3c5d6e06a39eb0fb531a2f540f2e6419bb".into() => ["POSTGRES_SCHEMA_MANIFEST_SHA256"],
});

section!(KafkaCfg {
 bootstrap_servers: String = "localhost:9092".into() => ["SYNC_REDPANDA_BOOTSTRAP_SERVERS"],
 load_topic: String = "sync.oracle.load".into() => ["SYNC_LOAD_TOPIC"],
 result_topic: String = "sync.oracle.result".into() => ["SYNC_RESULT_TOPIC"],
 scan_topic: String = "sync.scan.request".into() => ["COORDINATOR_SCAN_TOPIC", "SYNC_SCAN_TOPIC"],
 payload_audit_topic: String = "proxy.payload_audit".into() => ["COORDINATOR_PAYLOAD_AUDIT_TOPIC", "SYNC_PAYLOAD_AUDIT_TOPIC"],
 dlq_suffix: String = ".dlq".into() => ["SYNC_DLQ_SUFFIX"],
 scan_consumer: String = "octopus-scan-postgres-v1".into() => ["COORDINATOR_SCAN_CONSUMER", "SYNC_SCAN_CONSUMER"],
 result_consumer: String = "octopus-result-postgres-v1".into() => ["COORDINATOR_RESULT_CONSUMER", "SYNC_RESULT_CONSUMER"],
 payload_audit_consumer: String = "octopus-payload-audit-postgres-v1".into() => ["COORDINATOR_PAYLOAD_AUDIT_CONSUMER", "SYNC_PAYLOAD_AUDIT_CONSUMER"],
 load_consumer: String = "octopus-load-postgres-v1".into() => ["COORDINATOR_LOAD_CONSUMER", "SYNC_LOAD_CONSUMER"],
 scan_consumers_count: i32 = 4 => ["SYNC_SCAN_CONSUMERS_COUNT"],
 load_consumers_count: i32 = 4 => ["SYNC_LOAD_CONSUMERS_COUNT"],
 result_consumers_count: i32 = 4 => ["SYNC_RESULT_CONSUMERS_COUNT"],
 wireless_audit_topic: String = "wireless.audit".into() => ["SYNC_WIRELESS_AUDIT_TOPIC"],
 wireless_audit_consumer: String = "wireless-audit-projection-v1".into() => ["WIRELESS_AUDIT_CONSUMER"],
 wireless_heartbeat_consumer: String = "wireless-sensor-heartbeat-postgres-v1".into() => ["WIRELESS_HEARTBEAT_CONSUMER"],
 wireless_audit_consumers_count: i32 = 1 => ["WIRELESS_AUDIT_CONSUMERS_COUNT"],
 max_poll_records: i32 = 500 => ["COORDINATOR_MAX_POLL_RECORDS"],
 poll_timeout_ms: i64 = 3000 => ["COORDINATOR_POLL_TIMEOUT_MS"],
 locked_batch_size: i32 = 500 => ["COORDINATOR_LOCKED_BATCH_SIZE"],
 locked_batch_window_ms: i64 = 250 => ["COORDINATOR_LOCKED_BATCH_WINDOW_MS"],
 locked_batch_max_bytes: i32 = 8388608 => ["COORDINATOR_LOCKED_BATCH_MAX_BYTES"],
 topic_partitions: i32 = 24 => ["SYNC_REDPANDA_TOPIC_PARTITIONS"],
 topic_replication_factor: i32 = 3 => ["SYNC_REDPANDA_TOPIC_REPLICATION_FACTOR"],
});

section!(CronConfig {
 idle_sleep_ms: i32 = 250 => ["COORDINATOR_IDLE_SLEEP_MS"],
 idle_sleep_backoff_ms: i32 = 1000 => ["COORDINATOR_IDLE_SLEEP_BACKOFF_MS"],
 dispatch_batch_size: i32 = 50 => ["COORDINATOR_DISPATCH_BATCH_SIZE"],
 ingest_batch_size: i32 = 1000 => ["COORDINATOR_INGEST_BATCH_SIZE"],
 scan_max_attempts: i32 = 5 => ["COORDINATOR_SCAN_MAX_ATTEMPTS"],
 scan_retry_backoff_seconds: i32 = 30 => ["COORDINATOR_SCAN_RETRY_BACKOFF_SECS"],
 batch_dispatch_lease_seconds: i32 = 300 => ["COORDINATOR_BATCH_LEASE_SECS"],
 batch_dispatch_retry_max_seconds: i32 = 300 => ["COORDINATOR_BATCH_RETRY_MAX_SECS"],
 batch_max_attempts: i32 = 5 => ["COORDINATOR_BATCH_MAX_ATTEMPTS"],
 heartbeat_log_interval_ms: i32 = 15000 => ["COORDINATOR_HEARTBEAT_INTERVAL_MS"],
 schema_refresh_interval_seconds: i32 = 300 => ["SCHEMA_REFRESH_INTERVAL_SECS"],
 scan_fetch_count: i32 = 500 => ["COORDINATOR_SCAN_FETCH_COUNT"],
 result_fetch_count: i32 = 200 => ["COORDINATOR_RESULT_FETCH_COUNT"],
});

section!(IngestConfig {
 stream_names: Vec<String> = vec!["proxy.events".into(), "wireless.audit".into(), "audit.wireless.bandwidth".into(), "wireless.alert.rogue_ap".into(), "wireless.alert.deauth_flood".into(), "wireless.alert.signal_anomaly".into(), "wireless.alert.pmf_attack".into(), "wireless.client.inventory".into(), "wireless.probe.flush".into(), "proxy.payload_audit".into()] => ["SYNC_STREAM_NAMES", "COORDINATOR_STREAM_NAMES"],
 load_stream_names: Vec<String> = vec!["proxy.events".into(), "wireless.audit".into(), "audit.wireless.bandwidth".into(), "wireless.alert.rogue_ap".into(), "wireless.alert.deauth_flood".into(), "wireless.alert.signal_anomaly".into(), "wireless.alert.pmf_attack".into(), "wireless.client.inventory".into(), "wireless.probe.flush".into(), "proxy.payload_audit".into()] => ["COORDINATOR_LOAD_STREAM_NAMES"],
});

section!(BackpressureConfig {
 budget_multiplier: i32 = 4 => ["COORDINATOR_BACKPRESSURE_BUDGET_MULTIPLIER"],
 adaptive_pull_change_threshold: i32 = 50 => ["COORDINATOR_ADAPTIVE_PULL_CHANGE_THRESHOLD"],
 adaptive_pull_min_restart_interval_ms: i32 = 10000 => ["COORDINATOR_ADAPTIVE_PULL_MIN_RESTART_INTERVAL_MS"],
});

section!(HttpConfig {
 port: i32 = 8081 => ["COORDINATOR_HTTP_PORT"],
});

section!(PublicStatsConfig {
 enabled: bool = false => ["OCTOPUS_PUBLIC_STATS_ENABLED"],
 allowed_origins: Vec<String> = vec![] => ["OCTOPUS_PUBLIC_STATS_ALLOWED_ORIGINS"],
 peaks_refresh_seconds: i32 = 300 => ["OCTOPUS_PUBLIC_STATS_PEAKS_REFRESH_SECONDS"],
 rate_window_seconds: i32 = 300 => ["OCTOPUS_PUBLIC_STATS_RATE_WINDOW_SECONDS"],
});

section!(SyncConfig {
 outbox_dir: String = "/var/lib/sync/outbox".into() => ["SYNC_OUTBOX_DIR"],
});

section!(WirelessProjectionConfig {
 mode: String = "legacy".into() => ["WIRELESS_PROJECTION_MODE"],
 ranges_enabled: bool = false => ["WIRELESS_RANGES_ENABLED"],
 calibrations_json: String = "[]".into() => ["WIRELESS_CALIBRATIONS_JSON"],
});

section!(WirelessConfig {
 projection: WirelessProjectionConfig = WirelessProjectionConfig::default() => [],
 backlog_save_topic: String = "wireless.backlog.save".into() => ["WIRELESS_BACKLOG_SAVE_TOPIC"],
 backlog_save_consumer: String = "wireless-backlog-save-postgres-v1".into() => ["WIRELESS_BACKLOG_SAVE_CONSUMER"],
 backlog_list_topic: String = "wireless.backlog.list".into() => ["WIRELESS_BACKLOG_LIST_TOPIC"],
 backlog_list_consumer: String = "wireless-backlog-list-postgres-v1".into() => ["WIRELESS_BACKLOG_LIST_CONSUMER"],
 backlog_list_reply_topic: String = "wireless.backlog.list.reply".into() => ["WIRELESS_BACKLOG_LIST_REPLY_TOPIC"],
 backlog_synced_topic: String = "wireless.backlog.synced".into() => ["WIRELESS_BACKLOG_SYNCED_TOPIC"],
 backlog_synced_consumer: String = "wireless-backlog-synced-postgres-v1".into() => ["WIRELESS_BACKLOG_SYNCED_CONSUMER"],
 backlog_prune_topic: String = "wireless.backlog.prune".into() => ["WIRELESS_BACKLOG_PRUNE_TOPIC"],
 backlog_prune_consumer: String = "wireless-backlog-prune-postgres-v1".into() => ["WIRELESS_BACKLOG_PRUNE_CONSUMER"],
 backlog_prune_reply_topic: String = "wireless.backlog.prune.reply".into() => ["WIRELESS_BACKLOG_PRUNE_REPLY_TOPIC"],
 mac_lookup_topic: String = "wireless.mac.lookup".into() => ["WIRELESS_MAC_LOOKUP_TOPIC"],
 mac_lookup_consumer: String = "wireless-mac-lookup-postgres-v1".into() => ["WIRELESS_MAC_LOOKUP_CONSUMER"],
 mac_lookup_reply_topic: String = "wireless.mac.lookup.reply".into() => ["WIRELESS_MAC_LOOKUP_REPLY_TOPIC"],
 networks_authorized_topic: String = "wireless.networks.authorized".into() => ["WIRELESS_NETWORKS_AUTHORIZED_TOPIC"],
 networks_authorized_consumer: String = "wireless-networks-authorized-postgres-v1".into() => ["WIRELESS_NETWORKS_AUTHORIZED_CONSUMER"],
 networks_authorized_reply_topic: String = "wireless.networks.authorized.reply".into() => ["WIRELESS_NETWORKS_AUTHORIZED_REPLY_TOPIC"],
 probe_flush_topic: String = "wireless.probe.flush".into() => ["WIRELESS_PROBE_FLUSH_TOPIC"],
 probe_flush_consumer: String = "wireless-probe-flush-postgres-v1".into() => ["WIRELESS_PROBE_FLUSH_CONSUMER"],
 consumers_count: i32 = 1 => ["WIRELESS_CONSUMERS_COUNT"],
 max_poll_records: i32 = 500 => ["WIRELESS_MAX_POLL_RECORDS"],
});

section!(RuntimeConfig {
 environment: String = "production".into() => ["OCTOPUS_ENVIRONMENT"],
 processors_enabled: bool = false => ["OCTOPUS_PROCESSORS_ENABLED"],
 consumers_enabled: bool = false => ["OCTOPUS_CONSUMERS_ENABLED"],
});

section!(ProcessorConfig {
 enabled: Vec<String> = vec![] => ["OCTOPUS_ENABLED_PROCESSORS"],
 restart_base_delay_ms: i64 = 1000 => ["OCTOPUS_PROCESSOR_RESTART_BASE_DELAY_MS"],
 restart_max_delay_ms: i64 = 30000 => ["OCTOPUS_PROCESSOR_RESTART_MAX_DELAY_MS"],
 batch_size: i32 = 250 => ["OCTOPUS_PROCESSOR_BATCH_SIZE"],
 interval_seconds: i32 = 10 => ["OCTOPUS_PROCESSOR_INTERVAL_SECONDS"],
 embedding_model: String = "nomic-embed-text-v2-moe".into() => ["OCTOPUS_EMBEDDING_MODEL"],
 embedding_pending_high_water: i32 = 1000000 => ["OCTOPUS_EMBEDDING_PENDING_HIGH_WATER"],
 proxy_input_revision: String = "legacy_unknown".into() => ["OCTOPUS_PROXY_INPUT_REVISION"],
 event_duplicate_distance: f64 = 0.05 => ["OCTOPUS_EVENT_DUPLICATE_DISTANCE"],
 behavior_similarity_threshold: f64 = 0.88 => ["OCTOPUS_BEHAVIOR_SIMILARITY_THRESHOLD"],
 sequence_distance_threshold: f64 = 0.10 => ["OCTOPUS_SEQUENCE_DISTANCE_THRESHOLD"],
});

section!(ArchiveConfig {
 enabled: bool = false => ["OCTOPUS_ARCHIVE_ENABLED"],
 endpoint: String = "http://minio:9000".into() => ["MINIO_ENDPOINT"],
 access_key: String = "".into() => ["MINIO_ACCESS_KEY_ID"],
 secret_key: String = "".into() => ["MINIO_SECRET_ACCESS_KEY"],
 bucket: String = "ssl-proxy-wireless-raw-archive".into() => ["WIRELESS_RAW_ARCHIVE_BUCKET"],
 region: String = "us-east-1".into() => ["MINIO_REGION"],
 hot_days: i32 = 7 => ["WIRELESS_RAW_PAYLOAD_HOT_DAYS"],
 event_retention_days: i32 = 30 => ["SYNC_EVENT_ROW_RETENTION_DAYS"],
 search_retention_days: i32 = 30 => ["SEARCH_RETENTION_DAYS"],
 tombstone_retention_days: i32 = 45 => ["SYNC_EVENT_TOMBSTONE_RETENTION_DAYS"],
 batch_size: i32 = 100 => ["WIRELESS_RAW_ARCHIVE_BATCH_SIZE"],
 interval_ms: i64 = 300000 => ["WIRELESS_RAW_ARCHIVE_INTERVAL_MS"],
 maintenance_interval_ms: i64 = 3600000 => ["RETENTION_MAINTENANCE_INTERVAL_MS"],
});

section!(DqConfig {
 enabled: bool = false => ["OCTOPUS_DQ_ENABLED"],
 installation_id: String = "".into() => ["OCTOPUS_DQ_INSTALLATION_ID"],
 namespace: String = "".into() => ["OCTOPUS_DQ_NAMESPACE"],
 scope_modes_json: String = "{}".into() => ["OCTOPUS_DQ_SCOPE_MODES_JSON"],
 policy_version: String = "".into() => ["OCTOPUS_DQ_POLICY_VERSION"],
 approved_digests_json: String = "[]".into() => ["OCTOPUS_DQ_APPROVED_DIGESTS_JSON"],
 control_token: String = "".into() => ["OCTOPUS_DQ_CONTROL_TOKEN"],
 artifact_bucket: String = "dq-artifacts".into() => ["OCTOPUS_DQ_ARTIFACT_BUCKET"],
 poll_interval_ms: i64 = 1000 => ["OCTOPUS_DQ_POLL_INTERVAL_MS"],
 batch_size: i32 = 8 => ["OCTOPUS_DQ_BATCH_SIZE"],
 lease_seconds: i32 = 60 => ["OCTOPUS_DQ_LEASE_SECONDS"],
 max_queued: i32 = 10000 => ["OCTOPUS_DQ_MAX_QUEUED"],
 max_artifact_bytes: i32 = 8388608 => ["OCTOPUS_DQ_MAX_ARTIFACT_BYTES"],
});

// Nested configuration is bound explicitly rather than interpreted as a scalar.
impl EnvValue for WirelessProjectionConfig {
    fn parse_env(_: &str) -> Result<Self, ()> {
        Err(())
    }
}

#[derive(Clone, PartialEq, Default)]
pub struct AppConfig {
    pub postgres: PostgresConfig,
    pub kafka: KafkaCfg,
    pub cron: CronConfig,
    pub ingest: IngestConfig,
    pub backpressure: BackpressureConfig,
    pub http: HttpConfig,
    pub public_stats: PublicStatsConfig,
    pub sync: SyncConfig,
    pub wireless: WirelessConfig,
    pub runtime: RuntimeConfig,
    pub processors: ProcessorConfig,
    pub archive: ArchiveConfig,
    pub dq: DqConfig,
}

impl RuntimeConfig {
    pub fn any_enabled(&self) -> bool {
        self.processors_enabled || self.consumers_enabled
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_args(std::iter::empty::<String>())
    }
    /// Native equivalents of `-Dconfig.file=...` and `-Dsection.field=value`.
    /// JVM execution flags and unsupported HOCON constructs fail closed.
    pub fn load_args(args: impl IntoIterator<Item = String>) -> Result<Self, ConfigError> {
        let mut properties = BTreeMap::new();
        for arg in args {
            let Some((key, value)) = arg.strip_prefix("-D").and_then(|arg| arg.split_once('='))
            else {
                return Err(ConfigError(vec!["unsupported coordinator argument".into()]));
            };
            if key.is_empty() {
                return Err(ConfigError(vec!["invalid configuration property".into()]));
            }
            properties.insert(key.to_owned(), value.to_owned());
        }
        let text = properties
            .remove("config.file")
            .map(|path| {
                std::fs::read_to_string(path)
                    .map_err(|_| ConfigError(vec!["cannot read config.file".into()]))
            })
            .transpose()?;
        for key in [
            "config.resource",
            "config.url",
            "config.override_with_env_vars",
        ] {
            if properties.contains_key(key) {
                return Err(ConfigError(vec![format!(
                    "unsupported configuration property {key}"
                )]));
            }
        }
        Self::from_sources(&std::env::vars().collect(), text.as_deref(), &properties)
    }
    /// Precedence is explicit properties, HOCON overrides, bundled environment
    /// bindings, then defaults. Optional HOCON references preserve prior values.
    pub fn from_sources(
        env: &BTreeMap<String, String>,
        text: Option<&str>,
        properties: &BTreeMap<String, String>,
    ) -> Result<Self, ConfigError> {
        let mut config = Self::from_env_unvalidated(env)?;
        if let Some(text) = text {
            let values = hocon::parse(text, env).map_err(|e| ConfigError(vec![e.to_string()]))?;
            config.bind_config(&values)?;
        }
        let values = properties
            .iter()
            .map(|(key, value)| (key.clone(), hocon::Value::Scalar(value.clone())))
            .collect();
        config.bind_config(&values)?;
        config.resolve_postgres_password(env, |path| std::fs::read_to_string(path))?;
        config.validate()?;
        Ok(config)
    }
    fn bind_config(&mut self, values: &BTreeMap<String, hocon::Value>) -> Result<(), ConfigError> {
        let mut errors = Vec::new();
        self.postgres.bind_config("postgres", values, &mut errors);
        self.kafka.bind_config("kafka", values, &mut errors);
        self.cron.bind_config("cron", values, &mut errors);
        self.ingest.bind_config("ingest", values, &mut errors);
        self.backpressure
            .bind_config("backpressure", values, &mut errors);
        self.http.bind_config("http", values, &mut errors);
        self.public_stats
            .bind_config("public-stats", values, &mut errors);
        self.sync.bind_config("sync", values, &mut errors);
        self.wireless.bind_config("wireless", values, &mut errors);
        self.wireless
            .projection
            .bind_config("wireless.projection", values, &mut errors);
        self.runtime.bind_config("runtime", values, &mut errors);
        self.processors
            .bind_config("processors", values, &mut errors);
        self.archive.bind_config("archive", values, &mut errors);
        self.dq.bind_config("dq", values, &mut errors);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ConfigError(errors))
        }
    }
    pub fn from_env(env: &BTreeMap<String, String>) -> Result<Self, ConfigError> {
        Self::from_env_with_reader(env, |path| std::fs::read_to_string(path))
    }
    pub fn from_env_with_reader<F>(
        env: &BTreeMap<String, String>,
        read: F,
    ) -> Result<Self, ConfigError>
    where
        F: FnOnce(&str) -> std::io::Result<String>,
    {
        let mut config = Self::from_env_unvalidated(env)?;
        config.resolve_postgres_password(env, read)?;
        config.validate()?;
        Ok(config)
    }
    fn from_env_unvalidated(env: &BTreeMap<String, String>) -> Result<Self, ConfigError> {
        let mut config = Self::default();
        let mut errors = Vec::new();
        config.postgres.bind(env, &mut errors);
        config.kafka.bind(env, &mut errors);
        config.cron.bind(env, &mut errors);
        config.ingest.bind(env, &mut errors);
        config.backpressure.bind(env, &mut errors);
        config.http.bind(env, &mut errors);
        config.public_stats.bind(env, &mut errors);
        config.sync.bind(env, &mut errors);
        config.wireless.bind(env, &mut errors);
        config.wireless.projection.bind(env, &mut errors);
        config.runtime.bind(env, &mut errors);
        config.processors.bind(env, &mut errors);
        config.archive.bind(env, &mut errors);
        config.dq.bind(env, &mut errors);
        if !errors.is_empty() {
            return Err(ConfigError(errors));
        }
        Ok(config)
    }
    pub fn environment_keys() -> Vec<&'static str> {
        [
            PostgresConfig::ENVIRONMENT_KEYS,
            KafkaCfg::ENVIRONMENT_KEYS,
            CronConfig::ENVIRONMENT_KEYS,
            IngestConfig::ENVIRONMENT_KEYS,
            BackpressureConfig::ENVIRONMENT_KEYS,
            HttpConfig::ENVIRONMENT_KEYS,
            PublicStatsConfig::ENVIRONMENT_KEYS,
            SyncConfig::ENVIRONMENT_KEYS,
            WirelessConfig::ENVIRONMENT_KEYS,
            WirelessProjectionConfig::ENVIRONMENT_KEYS,
            RuntimeConfig::ENVIRONMENT_KEYS,
            ProcessorConfig::ENVIRONMENT_KEYS,
            ArchiveConfig::ENVIRONMENT_KEYS,
            DqConfig::ENVIRONMENT_KEYS,
            &["POSTGRES_PASSWORD_FILE"],
        ]
        .concat()
    }
    pub fn resolve_postgres_password<F>(
        &mut self,
        env: &BTreeMap<String, String>,
        read: F,
    ) -> Result<(), ConfigError>
    where
        F: FnOnce(&str) -> std::io::Result<String>,
    {
        let Some(path) = env
            .get("POSTGRES_PASSWORD_FILE")
            .map(|s| trim(s))
            .filter(|s| !s.is_empty())
        else {
            return Ok(());
        };
        let fail = |message: &str| ConfigError(vec![message.into()]);
        if !self.postgres.password.is_empty() {
            return Err(fail(
                "POSTGRES_PASSWORD and POSTGRES_PASSWORD_FILE cannot both be configured",
            ));
        }
        let raw = read(path).map_err(|_| fail("cannot read POSTGRES_PASSWORD_FILE"))?;
        let password = raw.strip_suffix('\n').unwrap_or(&raw);
        let password = password.strip_suffix('\r').unwrap_or(password);
        if password.is_empty() || password.contains(['\n', '\r', '\0']) {
            return Err(fail(
                "POSTGRES_PASSWORD_FILE must contain one non-empty line",
            ));
        }
        self.postgres.password = password.into();
        Ok(())
    }
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errors = Vec::new();
        let mut check = |bad: bool, message: &str| {
            if bad {
                errors.push(message.to_owned());
            }
        };
        let p = &self.processors;
        check(
            p.enabled.iter().any(|s| trim(s).is_empty()),
            "processors.enabled must not contain blank processor IDs",
        );
        check(
            duplicates(&p.enabled),
            "processors.enabled must not contain duplicate processor IDs",
        );
        check(
            p.restart_base_delay_ms <= 0,
            "processors.restart-base-delay-ms must be positive",
        );
        check(
            p.restart_max_delay_ms < p.restart_base_delay_ms,
            "processors.restart-max-delay-ms must be at least processors.restart-base-delay-ms",
        );
        check(p.batch_size <= 0, "processors.batch-size must be positive");
        check(
            p.interval_seconds <= 0,
            "processors.interval-seconds must be positive",
        );
        check(
            p.embedding_model != "nomic-embed-text-v2-moe",
            "processors.embedding-model must be nomic-embed-text-v2-moe",
        );
        check(
            p.embedding_pending_high_water < 0,
            "processors.embedding-pending-high-water must not be negative",
        );
        check(
            p.enabled.iter().any(|s| s == "proxy-search-preparer")
                && p.embedding_pending_high_water <= 0,
            "proxy-search-preparer requires a positive embedding-pending-high-water",
        );
        check(p.proxy_input_revision!="legacy_unknown" && !p.proxy_input_revision.strip_prefix("nomic-prefix-v1:").is_some_and(sha256),"processors.proxy-input-revision must be legacy_unknown or nomic-prefix-v1:<artifact-sha256>");
        check(
            !p.event_duplicate_distance.is_finite()
                || !(0.0..=2.0).contains(&p.event_duplicate_distance),
            "processors.event-duplicate-distance must be between 0 and 2",
        );
        check(
            !p.behavior_similarity_threshold.is_finite()
                || !(-1.0..=1.0).contains(&p.behavior_similarity_threshold),
            "processors.behavior-similarity-threshold must be between -1 and 1",
        );
        check(
            !p.sequence_distance_threshold.is_finite()
                || !(0.0..=2.0).contains(&p.sequence_distance_threshold),
            "processors.sequence-distance-threshold must be between 0 and 2",
        );
        check(
            !p.enabled.is_empty() && !self.runtime.processors_enabled,
            "processors.enabled requires runtime.processors-enabled=true",
        );
        let ingest = &self.ingest;
        check(
            !ingest.stream_names.iter().any(|s| s == "proxy.events"),
            "ingest.stream-names must contain proxy.events",
        );
        check(!ingest.load_stream_names.iter().any(|s|s=="proxy.events"),"ingest.load-stream-names must contain proxy.events so proxy events are persisted to PostgreSQL");
        check(
            duplicates(&ingest.stream_names),
            "ingest.stream-names must not contain duplicates",
        );
        check(
            duplicates(&ingest.load_stream_names),
            "ingest.load-stream-names must not contain duplicates",
        );
        check(
            ingest
                .load_stream_names
                .iter()
                .any(|s| !ingest.stream_names.contains(s)),
            "ingest.load-stream-names must be a subset of ingest.stream-names",
        );
        let a = &self.archive;
        check(
            p.enabled.iter().any(|s| s == "event-retention") && !a.enabled,
            "event-retention requires archive.enabled=true",
        );
        for (field, value) in [
            ("endpoint", &a.endpoint),
            ("access-key", &a.access_key),
            ("secret-key", &a.secret_key),
            ("bucket", &a.bucket),
        ] {
            check(
                a.enabled && trim(value).is_empty(),
                &format!("archive.{field} must not be blank"),
            );
        }
        check(a.hot_days <= 0, "archive.hot-days must be positive");
        check(
            a.event_retention_days < a.hot_days,
            "archive.event-retention-days must be at least archive.hot-days",
        );
        check(
            a.search_retention_days <= 0,
            "archive.search-retention-days must be positive",
        );
        check(
            a.tombstone_retention_days < a.event_retention_days,
            "archive.tombstone-retention-days must be at least archive.event-retention-days",
        );
        check(a.batch_size <= 0, "archive.batch-size must be positive");
        check(a.interval_ms <= 0, "archive.interval-ms must be positive");
        check(
            a.maintenance_interval_ms <= 0,
            "archive.maintenance-interval-ms must be positive",
        );
        check(
            self.dq.enabled
                && [&a.endpoint, &a.access_key, &a.secret_key]
                    .iter()
                    .any(|s| trim(s).is_empty()),
            "enabled DQ requires MINIO_ENDPOINT, MINIO_ACCESS_KEY_ID and MINIO_SECRET_ACCESS_KEY",
        );
        let k = &self.kafka;
        check(
            k.dlq_suffix.is_empty(),
            "kafka.dlq-suffix must not be empty",
        );
        for (field, value) in [
            ("max-poll-records", i64::from(k.max_poll_records)),
            ("scan-consumers-count", i64::from(k.scan_consumers_count)),
            ("load-consumers-count", i64::from(k.load_consumers_count)),
            (
                "result-consumers-count",
                i64::from(k.result_consumers_count),
            ),
            ("poll-timeout-ms", k.poll_timeout_ms),
            ("topic-partitions", i64::from(k.topic_partitions)),
            ("locked-batch-size", i64::from(k.locked_batch_size)),
            ("locked-batch-window-ms", k.locked_batch_window_ms),
            (
                "locked-batch-max-bytes",
                i64::from(k.locked_batch_max_bytes),
            ),
        ] {
            check(value <= 0, &format!("kafka.{field} must be positive"));
        }
        check(
            k.locked_batch_size > k.max_poll_records,
            "kafka.locked-batch-size must not exceed kafka.max-poll-records",
        );
        check(
            !(1..=32767).contains(&k.topic_replication_factor),
            "kafka.topic-replication-factor must be between 1 and 32767",
        );
        check(
            !(1..=65535).contains(&self.http.port),
            "http.port must be between 1 and 65535",
        );
        check(
            self.public_stats.enabled && self.public_stats.allowed_origins.is_empty(),
            "public-stats.allowed-origins must not be empty when public-stats.enabled=true",
        );
        check(
            self.public_stats.peaks_refresh_seconds <= 0,
            "public-stats.peaks-refresh-seconds must be positive",
        );
        check(
            self.public_stats.rate_window_seconds <= 0,
            "public-stats.rate-window-seconds must be positive",
        );
        check(
            self.wireless.consumers_count <= 0,
            "wireless.consumers-count must be positive",
        );
        check(
            self.wireless.max_poll_records <= 0,
            "wireless.max-poll-records must be positive",
        );
        let b = &self.backpressure;
        for (field, value) in [
            ("budget-multiplier", b.budget_multiplier),
            (
                "adaptive-pull-change-threshold",
                b.adaptive_pull_change_threshold,
            ),
            (
                "adaptive-pull-min-restart-interval-ms",
                b.adaptive_pull_min_restart_interval_ms,
            ),
        ] {
            check(
                value <= 0,
                &format!("backpressure.{field} must be positive"),
            );
        }
        let c = &self.cron;
        for (field, value) in [
            ("idle-sleep-ms", c.idle_sleep_ms),
            ("idle-sleep-backoff-ms", c.idle_sleep_backoff_ms),
            ("dispatch-batch-size", c.dispatch_batch_size),
            ("ingest-batch-size", c.ingest_batch_size),
            ("scan-max-attempts", c.scan_max_attempts),
            ("scan-retry-backoff-seconds", c.scan_retry_backoff_seconds),
            (
                "batch-dispatch-lease-seconds",
                c.batch_dispatch_lease_seconds,
            ),
            (
                "batch-dispatch-retry-max-seconds",
                c.batch_dispatch_retry_max_seconds,
            ),
            ("batch-max-attempts", c.batch_max_attempts),
            ("heartbeat-log-interval-ms", c.heartbeat_log_interval_ms),
            (
                "schema-refresh-interval-seconds",
                c.schema_refresh_interval_seconds,
            ),
            ("scan-fetch-count", c.scan_fetch_count),
            ("result-fetch-count", c.result_fetch_count),
        ] {
            check(value <= 0, &format!("cron.{field} must be positive"));
        }
        check(c.batch_dispatch_retry_max_seconds<c.scan_retry_backoff_seconds,"cron.batch-dispatch-retry-max-seconds must be at least cron.scan-retry-backoff-seconds");
        let pg = &self.postgres;
        check(
            !(1..=65535).contains(&pg.port),
            "postgres.port must be between 1 and 65535",
        );
        check(pg.pool_size <= 0, "postgres.pool-size must be positive");
        check(
            pg.healthcheck_reserve < 0,
            "postgres.healthcheck-reserve must not be negative",
        );
        check(
            pg.healthcheck_reserve >= pg.pool_size,
            "postgres.healthcheck-reserve must be smaller than postgres.pool-size",
        );
        check(
            pg.connection_timeout_ms <= 0,
            "postgres.connection-timeout-ms must be positive",
        );
        check(!(1..=i32::MAX/1000).contains(&pg.statement_timeout_secs),"postgres.statement-timeout-secs must be positive and safely convertible to milliseconds");
        check(
            !(1..=i32::MAX / 1000).contains(&pg.network_timeout_secs),
            "postgres.network-timeout-secs must be positive and safely convertible to milliseconds",
        );
        check(
            pg.network_timeout_secs <= pg.statement_timeout_secs,
            "postgres.network-timeout-secs must exceed postgres.statement-timeout-secs",
        );
        check(
            pg.load_chunk_max_bytes <= 0,
            "postgres.load-chunk-max-bytes must be positive",
        );
        if pg.enabled {
            for (field, value) in [
                ("host", &pg.host),
                ("database", &pg.database),
                ("user", &pg.user),
                ("password", &pg.password),
            ] {
                check(
                    trim(value).is_empty(),
                    &format!("postgres.{field} must not be blank"),
                );
            }
            check(
                ["localhost", "127.0.0.1", "::1", "[::1]"]
                    .contains(&trim(&pg.host).to_ascii_lowercase().as_str()),
                "postgres.host must reference the external PostgreSQL cluster, not loopback",
            );
            check(
                ["root", "postgres"].contains(&trim(&pg.user).to_ascii_lowercase().as_str()),
                "postgres.user must be a least-privilege non-superuser account",
            );
            check(
                trim(&pg.database) != "sync",
                "postgres.database must select sync",
            );
            if pg.ssl_mode != "disable" {
                check(
                    trim(&pg.ssl_ca_path).is_empty(),
                    "postgres.ssl-ca-path is required when ssl-mode is not disable",
                );
                check(
                    trim(&pg.ssl_server_name).is_empty(),
                    "postgres.ssl-server-name is required when ssl-mode is not disable",
                );
                check(!trim(&pg.ssl_server_name).is_empty() && !trim(&pg.ssl_server_name).eq_ignore_ascii_case(trim(&pg.host)),"postgres.ssl-server-name must equal postgres.host because the PostgreSQL driver verifies the endpoint identity");
                check(trim(&pg.ssl_client_key_store_path).is_empty()!=trim(&pg.ssl_client_key_store_password).is_empty(),"postgres.ssl-client-key-store-path and postgres.ssl-client-key-store-password must be configured together");
                check(
                    !["JKS", "PKCS12"].contains(
                        &trim(&pg.ssl_client_key_store_type)
                            .to_ascii_uppercase()
                            .as_str(),
                    ),
                    "postgres.ssl-client-key-store-type must be JKS or PKCS12",
                );
            }
            check(
                pg.warn_only,
                "postgres.warn-only must be false when PostgreSQL readiness is enabled",
            );
            check(pg.local_dev_allow_public_key_retrieval && self.runtime.environment!="development","postgres.local-dev-allow-public-key-retrieval requires OCTOPUS_ENVIRONMENT=development");
            check(
                !sha256(&pg.manifest_sha256),
                "postgres.manifest-sha-256 must be 64 lowercase hexadecimal characters",
            );
        }
        if self.runtime.any_enabled() || !p.enabled.is_empty() || self.dq.enabled {
            check(
                !pg.enabled,
                "an enabled runtime requires postgres.enabled=true",
            );
            let consumers: Vec<_> = p
                .enabled
                .iter()
                .filter_map(|id| ProcessorId::from_string(id).ok())
                .filter(|id| ProcessorId::KAFKA_CONSUMERS.contains(id))
                .collect();
            check(
                !consumers.is_empty() && !self.runtime.consumers_enabled,
                &format!(
                    "consumer processors {} require runtime.consumers-enabled=true",
                    consumers
                        .iter()
                        .map(|id| id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
            let missing: Vec<_> = [
                "sync-load-consumer",
                "sync-result-consumer",
                "sync-scan-ingestion",
            ]
            .into_iter()
            .filter(|id| !p.enabled.iter().any(|s| s == id))
            .collect();
            check(self.runtime.consumers_enabled && !p.enabled.is_empty() && !missing.is_empty(),&format!("runtime.consumers-enabled=true with an explicit processor catalog requires locked-consumer processors: {}",missing.join(", ")));
            let w = &self.wireless;
            let groups = [
                &k.scan_consumer,
                &k.result_consumer,
                &k.payload_audit_consumer,
                &k.load_consumer,
                &k.wireless_audit_consumer,
                &k.wireless_heartbeat_consumer,
                &w.backlog_save_consumer,
                &w.backlog_list_consumer,
                &w.backlog_synced_consumer,
                &w.backlog_prune_consumer,
                &w.mac_lookup_consumer,
                &w.networks_authorized_consumer,
                &w.probe_flush_consumer,
            ];
            check(
                groups.iter().any(|s| !versioned_group(s)),
                "every configured consumer group must end in a non-zero version suffix such as -v1",
            );
            check(
                groups.iter().collect::<BTreeSet<_>>().len() != groups.len(),
                "configured consumer groups must not contain duplicates",
            );
        }
        for id in &p.enabled {
            match ProcessorId::from_string(id) {
                Err(message) => check(true, &message),
                Ok(id) if id.owner() != ProcessorOwner::Octopus => check(
                    true,
                    &format!(
                        "processor {} is owned by atheros-search, not octopus",
                        id.as_str()
                    ),
                ),
                _ => {}
            }
        }
        errors.extend(self.dq.errors());
        errors.extend(self.wireless.projection.errors());
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ConfigError(errors))
        }
    }
}

fn duplicates(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() != values.len()
}
fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn versioned_group(value: &str) -> bool {
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return false;
    }
    let Some((prefix, version)) = value.rsplit_once('v') else {
        return false;
    };
    prefix.len() > 1
        && prefix.ends_with(['-', '_', '.'])
        && !version.is_empty()
        && version.as_bytes()[0] != b'0'
        && version.bytes().all(|b| b.is_ascii_digit())
}

impl DqConfig {
    pub fn settings(&self) -> DqSettings {
        DqSettings {
            installation_id: self.installation_id.clone(),
            namespace: self.namespace.clone(),
            scope_modes: if self.enabled {
                self.scope_modes()
            } else {
                BTreeMap::new()
            },
            policy_version: self.policy_version.clone(),
            approved_digests: self.approved_digests(),
            max_queued: self.max_queued,
            lease_seconds: self.lease_seconds,
            artifact_bucket: self.artifact_bucket.clone(),
        }
    }
    pub fn scope_modes(&self) -> BTreeMap<String, String> {
        serde_json::from_str(&self.scope_modes_json).unwrap_or_default()
    }
    pub fn approved_digests(&self) -> BTreeSet<String> {
        serde_json::from_str(&self.approved_digests_json).unwrap_or_default()
    }
    pub fn errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let mut check = |bad: bool, msg: &str| {
            if bad {
                errors.push(msg.to_owned());
            }
        };
        let scopes = serde_json::from_str::<BTreeMap<String, String>>(&self.scope_modes_json).ok();
        let digests = serde_json::from_str::<Vec<String>>(&self.approved_digests_json).ok();
        check(
            self.enabled && !identifier(&self.installation_id),
            "dq.installation-id must be a safe non-empty identifier",
        );
        check(
            self.enabled && !identifier(&self.namespace),
            "dq.namespace must be a safe non-empty identifier",
        );
        check(
            self.enabled && trim(&self.policy_version).is_empty(),
            "dq.policy-version must not be blank",
        );
        check(
            self.enabled && self.control_token.encode_utf16().count() < 32,
            "dq.control-token must contain at least 32 characters",
        );
        let bucket = self.artifact_bucket.as_bytes();
        let valid_bucket = (3..=63).contains(&bucket.len())
            && bucket
                .first()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && bucket
                .last()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && bucket
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(b));
        check(
            !valid_bucket,
            "dq.artifact-bucket must be a valid bucket name",
        );
        check(
            scopes.is_none(),
            "dq.scope-modes-json must be a JSON object",
        );
        check(
            scopes.as_ref().is_some_and(|m| {
                m.iter().any(|(s, mode)| {
                    (s != "*" && !identifier(s)) || !["shadow", "enabled"].contains(&mode.as_str())
                })
            }),
            "dq.scope-modes-json contains an invalid scope or mode",
        );
        check(
            scopes
                .as_ref()
                .is_some_and(|m| m.contains_key("*") && m.len() > 1),
            "dq.scope-modes-json must not mix wildcard and location scopes",
        );
        check(
            self.enabled && scopes.as_ref().is_none_or(|m| m.is_empty()),
            "dq.scope-modes-json must authorize at least one scope when enabled",
        );
        check(
            digests.as_ref().is_none_or(|d| {
                d.iter()
                    .any(|s| !s.strip_prefix("sha256:").is_some_and(sha256))
            }),
            "dq.approved-digests-json must contain sha256 image digests",
        );
        check(
            self.enabled && digests.as_ref().is_none_or(|d| d.is_empty()),
            "dq.approved-digests-json must approve at least one image when enabled",
        );
        check(
            !(100..=60000).contains(&self.poll_interval_ms),
            "dq.poll-interval-ms must be between 100 and 60000",
        );
        check(
            !(1..=100).contains(&self.batch_size),
            "dq.batch-size must be between 1 and 100",
        );
        check(
            !(10..=3600).contains(&self.lease_seconds),
            "dq.lease-seconds must be between 10 and 3600",
        );
        check(
            !(1..=1000000).contains(&self.max_queued),
            "dq.max-queued must be between 1 and 1000000",
        );
        check(
            !(1024..=67108864).contains(&self.max_artifact_bytes),
            "dq.max-artifact-bytes must be between 1024 and 67108864",
        );
        errors
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DqSettings {
    pub installation_id: String,
    pub namespace: String,
    pub scope_modes: BTreeMap<String, String>,
    pub policy_version: String,
    pub approved_digests: BTreeSet<String>,
    pub max_queued: i32,
    pub lease_seconds: i32,
    pub artifact_bucket: String,
}
impl DqSettings {
    pub fn mode(&self, scope: &str) -> Option<&str> {
        self.scope_modes
            .get(scope)
            .map(String::as_str)
            .filter(|mode| matches!(*mode, "shadow" | "enabled"))
    }
}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SensorCalibration {
    pub sensor_id: String,
    pub location_id: String,
    pub version: String,
    pub reference_rssi: f64,
    pub reference_meters: f64,
    pub path_loss_exponent: f64,
    pub uncertainty_db: f64,
    pub frequencies_mhz: Vec<i32>,
    pub channels: Vec<i32>,
    pub minimum_samples: i32,
    pub maximum_stddev_db: f64,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub access_points: Vec<String>,
}
impl WirelessProjectionConfig {
    pub fn enabled(&self) -> bool {
        self.mode != "legacy"
    }
    pub fn projection_only(&self) -> bool {
        self.mode == "projected"
    }
    pub fn calibrations(&self) -> Result<Vec<SensorCalibration>, String> {
        let values: Vec<SensorCalibration> = serde_json::from_str(&self.calibrations_json)
            .map_err(|_| "invalid sensor calibration JSON".to_owned())?;
        let mut identities = BTreeSet::new();
        for c in &values {
            let valid_text = |s: &str, max| !s.is_empty() && s.encode_utf16().count() <= max;
            let mac = |s: &String| {
                s.len() == 17
                    && s.bytes().enumerate().all(|(i, b)| {
                        if i % 3 == 2 {
                            b == b':'
                        } else {
                            b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                        }
                    })
            };
            if !valid_text(&c.sensor_id, 64)
                || !valid_text(&c.location_id, 128)
                || !valid_text(&c.version, 64)
                || ![
                    c.reference_rssi,
                    c.reference_meters,
                    c.path_loss_exponent,
                    c.uncertainty_db,
                    c.maximum_stddev_db,
                ]
                .into_iter()
                .all(f64::is_finite)
                || !(-120.0..0.0).contains(&c.reference_rssi)
                || c.reference_meters <= 0.0
                || c.reference_meters > 100.0
                || !(1.0..=6.0).contains(&c.path_loss_exponent)
                || c.uncertainty_db <= 0.0
                || c.uncertainty_db > 30.0
                || c.minimum_samples < 2
                || c.maximum_stddev_db <= 0.0
                || c.maximum_stddev_db > 20.0
                || c.frequencies_mhz.is_empty()
                || c.frequencies_mhz.iter().any(|f| !(2300..=7200).contains(f))
                || c.channels.is_empty()
                || c.channels.iter().any(|ch| !(1..=233).contains(ch))
                || c.valid_from >= c.valid_until
                || !c.access_points.iter().all(mac)
                || !identities.insert((&c.sensor_id, &c.version, c.valid_from))
            {
                return Err("invalid or duplicate sensor calibration".into());
            }
        }
        Ok(values)
    }
    pub fn errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if !["legacy", "shadow", "projected"].contains(&self.mode.as_str()) {
            errors.push("wireless projection mode must be legacy, shadow or projected".into());
        }
        let calibrations = self.calibrations();
        if let Err(message) = &calibrations {
            errors.push(message.clone());
        }
        if self.ranges_enabled && calibrations.as_ref().map_or(true, |c| c.is_empty()) {
            errors.push("ranges require reviewed sensor calibration".into());
        }
        errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
    #[test]
    fn defaults_are_fail_closed() {
        let c = AppConfig::from_env(&BTreeMap::new()).unwrap_or_else(|e| panic!("{e}"));
        assert!(!c.postgres.enabled);
        assert!(!c.runtime.any_enabled());
        assert!(c.processors.enabled.is_empty());
        assert_eq!(c.postgres.pool_size, 20);
        assert_eq!(c.kafka.topic_partitions, 24);
        assert_eq!(c.kafka.locked_batch_size, 500);
        assert_eq!(
            c.postgres.manifest_sha256,
            "7f20b99662f8591cbb6e963e37c01a3c5d6e06a39eb0fb531a2f540f2e6419bb"
        );
    }
    #[test]
    fn aliases_preserve_precedence_and_csv_empty_entries() {
        let e = env(&[
            ("COORDINATOR_SCAN_TOPIC", "old"),
            ("SYNC_SCAN_TOPIC", "new"),
            ("SYNC_STREAM_NAMES", "ignored"),
            ("COORDINATOR_STREAM_NAMES", " proxy.events, "),
        ]);
        let c = AppConfig::from_env(&e).err().unwrap();
        assert!(c.0.iter().any(|s| s.contains("subset")));
        let mut c = AppConfig::default();
        let mut errors = vec![];
        c.kafka.bind(&e, &mut errors);
        c.ingest.bind(&e, &mut errors);
        assert_eq!(c.kafka.scan_topic, "new");
        assert_eq!(c.ingest.stream_names, vec!["proxy.events", ""]);
    }
    #[test]
    fn secrets_preserve_spaces_strip_one_line_ending_and_redact_failures() {
        let e = env(&[("POSTGRES_PASSWORD_FILE", " /secret ")]);
        for (raw, want) in [
            (" secret \r\n", " secret "),
            (" \n", " "),
            ("secret\r", "secret"),
        ] {
            let mut c = AppConfig::default();
            c.resolve_postgres_password(&e, |p| {
                assert_eq!(p, "/secret");
                Ok(raw.into())
            })
            .unwrap();
            assert_eq!(c.postgres.password, want);
        }
        for raw in ["", "\n", "secret\n\n", "a\rb", "a\0"] {
            assert!(AppConfig::default()
                .resolve_postgres_password(&e, |_| Ok(raw.into()))
                .is_err());
        }
        let mut c = AppConfig::default();
        c.postgres.password = "hidden-value".into();
        let err = c
            .resolve_postgres_password(&e, |_| panic!("must not read"))
            .unwrap_err();
        assert!(!err.to_string().contains("hidden-value"));
        assert!(AppConfig::default()
            .resolve_postgres_password(&e, |_| Err(std::io::Error::other("hidden-value")))
            .unwrap_err()
            .to_string()
            .contains("cannot read"));
    }
    #[test]
    fn invalid_scalar_never_exposes_input() {
        let e = env(&[("POSTGRES_PORT", "secret-number")]);
        let err = AppConfig::from_env(&e).err().unwrap();
        assert_eq!(err.0, vec!["invalid value for POSTGRES_PORT"]);
    }
    #[test]
    fn timeout_boundaries() {
        for (s, n) in [
            (0, 60),
            (-1, 60),
            (30, 0),
            (30, 30),
            (60, 30),
            (i32::MAX, i32::MAX),
            (30, i32::MAX),
        ] {
            let mut c = AppConfig::default();
            c.postgres.statement_timeout_secs = s;
            c.postgres.network_timeout_secs = n;
            assert!(c.validate().is_err());
        }
        let mut c = AppConfig::default();
        c.postgres.statement_timeout_secs = i32::MAX / 1000 - 1;
        c.postgres.network_timeout_secs = i32::MAX / 1000;
        assert!(c.validate().is_ok());
    }
    fn active() -> AppConfig {
        let mut c = AppConfig::default();
        c.postgres.enabled = true;
        c.postgres.host = "postgres.example.internal".into();
        c.postgres.ssl_server_name = c.postgres.host.clone();
        c.postgres.ssl_ca_path = "/ca".into();
        c.postgres.password = "secret".into();
        c.runtime.processors_enabled = true;
        c.runtime.consumers_enabled = true;
        c
    }
    #[test]
    fn active_runtime_and_groups() {
        let c = active();
        assert!(c.validate().is_ok());
        let mut c = c;
        c.postgres.enabled = false;
        assert!(c
            .validate()
            .unwrap_err()
            .to_string()
            .contains("requires postgres.enabled"));
        let mut c = active();
        c.kafka.wireless_heartbeat_consumer = "unversioned".into();
        assert!(c
            .validate()
            .unwrap_err()
            .to_string()
            .contains("version suffix"));
        let mut c = active();
        c.kafka.wireless_heartbeat_consumer = c.kafka.scan_consumer.clone();
        assert!(c.validate().unwrap_err().to_string().contains("duplicates"));
        for g in ["a-v1", "a_v99", "a.v2147483648"] {
            assert!(versioned_group(g));
        }
        for g in ["-v1", "a-v0", "a-v01", "a-v1 ", "a-v+1"] {
            assert!(!versioned_group(g));
        }
    }
    #[test]
    fn processor_catalog_and_lane_validation() {
        for ids in [
            vec![""],
            vec!["sync-job-planner", "sync-job-planner"],
            vec!["missing"],
            vec!["embedding-completer"],
        ] {
            let mut c = active();
            c.processors.enabled = ids.into_iter().map(String::from).collect();
            assert!(c.validate().is_err());
        }
        let mut c = active();
        c.runtime.consumers_enabled = false;
        c.processors.enabled = vec!["wireless-heartbeat-ingestion".into()];
        assert!(c
            .validate()
            .unwrap_err()
            .to_string()
            .contains("require runtime.consumers-enabled"));
        let mut c = active();
        c.processors.enabled = vec!["sync-job-planner".into()];
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("requires locked-consumer processors"));
    }
    #[test]
    fn all_hocon_environment_names_have_bindings() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../octopus/src/main/resources/application.conf");
        let source = match std::fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("Scala configuration comparison unavailable in standalone checkout");
                return;
            }
            Err(error) => panic!("cannot read {}: {error}", path.display()),
        };
        let mut names = BTreeSet::new();
        for chunk in source.split("${?").skip(1) {
            names.insert(chunk.split('}').next().unwrap());
        }
        let actual: BTreeSet<_> = AppConfig::environment_keys()
            .into_iter()
            .filter(|s| *s != "POSTGRES_PASSWORD_FILE")
            .collect();
        assert_eq!(names, actual);
    }
    #[test]
    fn production_ssl_disable_matches_scala_configuration_validation() {
        // Scala enabledPostgresErrors gates CA/name checks on sslMode, not on
        // isDevelopment. Preserve validation separately from TLS runtime setup.
        let mut config = active();
        config.runtime.environment = "production".into();
        config.postgres.ssl_mode = "disable".into();
        config.postgres.ssl_ca_path.clear();
        config.postgres.ssl_server_name.clear();
        assert!(config.validate().is_ok());
    }
    #[test]
    fn dq_inputs_fail_closed_even_disabled() {
        let mut d = DqConfig::default();
        assert!(d.errors().is_empty());
        d.scope_modes_json = "[]".into();
        assert!(d.errors().iter().any(|s| s.contains("JSON object")));
        d.scope_modes_json = r#"{"*":"shadow","site":"enabled"}"#.into();
        assert!(d.errors().iter().any(|s| s.contains("mix wildcard")));
        d.scope_modes_json = "{}".into();
        d.approved_digests_json = r#"["sha256:bad"]"#.into();
        assert!(d.errors().iter().any(|s| s.contains("sha256 image")));
        d.enabled = true;
        assert!(d.errors().iter().any(|s| s.contains("control-token")));
    }
    #[test]
    fn calibration_errors_and_ranges() {
        let mut c = WirelessProjectionConfig::default();
        assert!(c.errors().is_empty());
        c.ranges_enabled = true;
        assert_eq!(
            c.errors(),
            vec!["ranges require reviewed sensor calibration"]
        );
        c.calibrations_json = "not-json".into();
        assert!(c
            .errors()
            .iter()
            .any(|s| s == "invalid sensor calibration JSON"));
        c.mode = "unknown".into();
        assert!(c.errors().iter().any(|s| s.contains("mode must")));
    }

    #[test]
    fn numeric_bounds_are_enforced_when_lanes_are_disabled() {
        macro_rules! invalid {
            ($($section:ident.$field:ident = $value:expr => $message:literal),* $(,)?) => {
                $(let mut c = AppConfig::default(); c.$section.$field = $value;
                assert!(c.validate().unwrap_err().0.iter().any(|s|s.contains($message)), $message);)*
            };
        }
        invalid! {
            processors.restart_base_delay_ms = 0 => "restart-base-delay-ms",
            processors.restart_max_delay_ms = 0 => "restart-max-delay-ms",
            processors.batch_size = 0 => "processors.batch-size",
            processors.interval_seconds = 0 => "processors.interval-seconds",
            processors.embedding_pending_high_water = -1 => "embedding-pending-high-water",
            processors.event_duplicate_distance = f64::NAN => "event-duplicate-distance",
            processors.behavior_similarity_threshold = f64::INFINITY => "behavior-similarity-threshold",
            processors.sequence_distance_threshold = -0.1 => "sequence-distance-threshold",
            kafka.max_poll_records = 0 => "max-poll-records",
            kafka.scan_consumers_count = 0 => "scan-consumers-count",
            kafka.load_consumers_count = 0 => "load-consumers-count",
            kafka.result_consumers_count = 0 => "result-consumers-count",
            kafka.poll_timeout_ms = 0 => "poll-timeout-ms",
            kafka.topic_partitions = 0 => "topic-partitions",
            kafka.locked_batch_size = 0 => "locked-batch-size",
            kafka.locked_batch_window_ms = 0 => "locked-batch-window-ms",
            kafka.locked_batch_max_bytes = 0 => "locked-batch-max-bytes",
            kafka.topic_replication_factor = 32768 => "topic-replication-factor",
            http.port = 65536 => "http.port",
            public_stats.peaks_refresh_seconds = 0 => "peaks-refresh-seconds",
            public_stats.rate_window_seconds = 0 => "rate-window-seconds",
            wireless.consumers_count = 0 => "wireless.consumers-count",
            wireless.max_poll_records = 0 => "wireless.max-poll-records",
            backpressure.budget_multiplier = 0 => "budget-multiplier",
            backpressure.adaptive_pull_change_threshold = 0 => "adaptive-pull-change-threshold",
            backpressure.adaptive_pull_min_restart_interval_ms = 0 => "adaptive-pull-min-restart-interval-ms",
            cron.idle_sleep_ms = 0 => "idle-sleep-ms",
            cron.idle_sleep_backoff_ms = 0 => "idle-sleep-backoff-ms",
            cron.dispatch_batch_size = 0 => "dispatch-batch-size",
            cron.ingest_batch_size = 0 => "ingest-batch-size",
            cron.scan_max_attempts = 0 => "scan-max-attempts",
            cron.scan_retry_backoff_seconds = 0 => "scan-retry-backoff-seconds",
            cron.batch_dispatch_lease_seconds = 0 => "batch-dispatch-lease-seconds",
            cron.batch_dispatch_retry_max_seconds = 0 => "batch-dispatch-retry-max-seconds",
            cron.batch_max_attempts = 0 => "batch-max-attempts",
            cron.heartbeat_log_interval_ms = 0 => "heartbeat-log-interval-ms",
            cron.schema_refresh_interval_seconds = 0 => "schema-refresh-interval-seconds",
            cron.scan_fetch_count = 0 => "scan-fetch-count",
            cron.result_fetch_count = 0 => "result-fetch-count",
            postgres.port = 0 => "postgres.port",
            postgres.pool_size = 0 => "pool-size",
            postgres.healthcheck_reserve = -1 => "healthcheck-reserve",
            postgres.connection_timeout_ms = 0 => "connection-timeout-ms",
            postgres.load_chunk_max_bytes = 0 => "load-chunk-max-bytes",
            archive.hot_days = 0 => "hot-days",
            archive.event_retention_days = 0 => "event-retention-days",
            archive.search_retention_days = 0 => "search-retention-days",
            archive.tombstone_retention_days = 0 => "tombstone-retention-days",
            archive.batch_size = 0 => "archive.batch-size",
            archive.interval_ms = 0 => "archive.interval-ms",
            archive.maintenance_interval_ms = 0 => "maintenance-interval-ms",
        }
    }

    #[test]
    fn postgres_credentials_tls_and_development_restrictions() {
        let mut c = active();
        c.postgres.host = "localhost".into();
        c.postgres.user = "postgres".into();
        c.postgres.ssl_client_key_store_path = "/client.p12".into();
        c.postgres.ssl_client_key_store_type = "PEM".into();
        c.postgres.manifest_sha256 = "bad".into();
        c.postgres.warn_only = true;
        c.postgres.local_dev_allow_public_key_retrieval = true;
        let messages = c.validate().unwrap_err().to_string();
        for expected in [
            "external PostgreSQL",
            "least-privilege",
            "ssl-server-name must equal",
            "configured together",
            "JKS or PKCS12",
            "manifest-sha-256",
            "warn-only",
            "OCTOPUS_ENVIRONMENT=development",
        ] {
            assert!(messages.contains(expected), "{expected}");
        }
        let mut c = active();
        c.postgres.local_dev_allow_public_key_retrieval = true;
        c.runtime.environment = "development".into();
        assert!(c.validate().is_ok());
        c.postgres.ssl_mode = "disable".into();
        c.postgres.ssl_ca_path.clear();
        c.postgres.ssl_server_name.clear();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn ingest_catalog_archive_and_stats_gates() {
        let mut c = AppConfig::default();
        c.ingest.stream_names.clear();
        c.ingest.load_stream_names.clear();
        assert_eq!(c.validate().unwrap_err().0.len(), 2);
        let mut c = AppConfig::default();
        c.ingest.stream_names.push("proxy.events".into());
        c.ingest.load_stream_names.push("outside".into());
        let errors = c.validate().unwrap_err().to_string();
        assert!(errors.contains("duplicates") && errors.contains("subset"));
        let mut c = active();
        c.runtime.consumers_enabled = false;
        c.processors.enabled = vec!["event-retention".into()];
        assert!(c
            .validate()
            .unwrap_err()
            .to_string()
            .contains("event-retention requires"));
        c.archive.enabled = true;
        let errors = c.validate().unwrap_err().to_string();
        assert!(errors.contains("archive.access-key") && errors.contains("archive.secret-key"));
        let mut c = AppConfig::default();
        c.public_stats.enabled = true;
        assert!(c
            .validate()
            .unwrap_err()
            .to_string()
            .contains("allowed-origins"));
        c.public_stats.allowed_origins = vec!["https://example.org".into()];
        assert!(c.validate().is_ok());
    }

    #[test]
    fn enabled_dq_validates_exact_scopes_digests_and_ranges() {
        let mut d = DqConfig {
            enabled: true,
            installation_id: "lab".into(),
            namespace: "production".into(),
            policy_version: "reviewed-v1".into(),
            control_token: "s".repeat(32),
            scope_modes_json: r#"{"site":"shadow"}"#.into(),
            approved_digests_json: format!(r#"["sha256:{}"]"#, "a".repeat(64)),
            ..DqConfig::default()
        };
        assert!(d.errors().is_empty());
        assert_eq!(d.scope_modes().get("site").unwrap(), "shadow");
        assert_eq!(d.approved_digests().len(), 1);
        assert_eq!(d.settings().mode("site"), Some("shadow"));
        assert_eq!(d.settings().mode("unknown"), None);
        d.enabled = false;
        assert_eq!(d.settings().mode("site"), None);
        d.poll_interval_ms = 99;
        d.batch_size = 101;
        d.lease_seconds = 9;
        d.max_queued = 1000001;
        d.max_artifact_bytes = 1023;
        let errors = d.errors().join(";");
        for expected in [
            "poll-interval-ms",
            "batch-size",
            "lease-seconds",
            "max-queued",
            "max-artifact-bytes",
        ] {
            assert!(errors.contains(expected));
        }
    }

    #[test]
    fn calibration_identity_bounds_and_reviewed_ranges() {
        let calibration = serde_json::json!({"sensorId":"sensor-1","locationId":"lab","version":"v1","referenceRssi":-60.0,"referenceMeters":1.0,"pathLossExponent":2.0,"uncertaintyDb":4.0,"frequenciesMhz":[2412],"channels":[1],"minimumSamples":2,"maximumStddevDb":5.0,"validFrom":"2026-01-01T00:00:00Z","validUntil":"2027-01-01T00:00:00Z","accessPoints":["aa:bb:cc:dd:ee:ff"]});
        let mut c = WirelessProjectionConfig {
            mode: "projected".into(),
            ranges_enabled: true,
            calibrations_json: serde_json::json!([calibration.clone()]).to_string(),
        };
        assert!(c.enabled() && c.projection_only() && c.errors().is_empty());
        c.calibrations_json =
            serde_json::json!([calibration.clone(), calibration.clone()]).to_string();
        assert_eq!(
            c.calibrations().err().unwrap(),
            "invalid or duplicate sensor calibration"
        );
        for (key, value) in [
            ("sensorId", serde_json::json!("")),
            ("referenceRssi", serde_json::json!(0)),
            ("referenceMeters", serde_json::json!(101)),
            ("pathLossExponent", serde_json::json!(7)),
            ("uncertaintyDb", serde_json::json!(0)),
            ("minimumSamples", serde_json::json!(1)),
            ("maximumStddevDb", serde_json::json!(21)),
            ("frequenciesMhz", serde_json::json!([])),
            ("channels", serde_json::json!([234])),
            ("validUntil", serde_json::json!("2025-01-01T00:00:00Z")),
            ("accessPoints", serde_json::json!(["AA:BB:CC:DD:EE:FF"])),
        ] {
            let mut invalid = calibration.clone();
            invalid[key] = value;
            c.calibrations_json = serde_json::json!([invalid]).to_string();
            assert!(c.calibrations().is_err(), "{key}");
        }
    }
}
