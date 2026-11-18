//! PostgreSQL resource and transaction boundaries; this module never applies DDL.

use crate::config::PostgresConfig;
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use postgres_openssl::MakeTlsConnector;
use std::{collections::BTreeMap, error::Error, path::Path, sync::Arc, time::Duration};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};
use tokio_postgres::{config::SslMode, types::ToSql, Row};

pub const REQUIRED_TABLES: &[&str] = &[
    "sync_events",
    "sync_batches",
    "proxy_events",
    "proxy_blocked_host_rollups",
    "proxy_payload_audit",
    "wireless_sensors",
    "wireless_audit_frames",
    "wireless_bandwidth_windows",
    "wireless_alerts",
    "wireless_client_inventory",
    "wireless_probe_requests",
];
pub const REQUIRED_COLUMN_TYPES: &[(&str, &str, &str)] = &[
    ("sync_events", "payload_ref", "text"),
    ("sync_batches", "payload_ref", "text"),
    ("proxy_events", "source_conflicts", "jsonb"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostgresErrorClass {
    Retryable,
    Permanent,
}

impl PostgresErrorClass {
    pub fn wire_value(self) -> &'static str {
        match self {
            Self::Retryable => "retryable",
            Self::Permanent => "permanent",
        }
    }

    /// Structured states take precedence over unstructured timeout messages.
    pub fn classify_states_and_messages(
        states: &[&str],
        messages: &[&str],
        transient: bool,
    ) -> Self {
        if !states.is_empty() {
            return if states.iter().any(|s| is_retryable_sqlstate(s)) {
                Self::Retryable
            } else {
                Self::Permanent
            };
        }
        if transient
            || messages.iter().any(|message| {
                let message = message.to_lowercase();
                [
                    "timeout",
                    "temporarily unavailable",
                    "connection reset",
                    "deadlock",
                    "could not serialize",
                    "lock not available",
                ]
                .iter()
                .any(|part| message.contains(part))
            })
        {
            Self::Retryable
        } else {
            Self::Permanent
        }
    }

    pub fn classify(error: &(dyn Error + 'static)) -> Self {
        let mut current = Some(error);
        let mut states = Vec::new();
        let mut messages = Vec::new();
        let mut seen = Vec::new();
        let mut closed = false;
        while let Some(error) = current {
            let ptr = error as *const dyn Error as *const ();
            if seen.contains(&ptr) {
                break;
            }
            seen.push(ptr);
            messages.push(error.to_string());
            if let Some(pg) = error.downcast_ref::<tokio_postgres::Error>() {
                if let Some(code) = pg.code() {
                    states.push(code.code().to_string());
                }
                closed |= pg.is_closed();
            }
            current = error.source();
        }
        Self::classify_states_and_messages(
            &states.iter().map(String::as_str).collect::<Vec<_>>(),
            &messages.iter().map(String::as_str).collect::<Vec<_>>(),
            closed,
        )
    }
}

pub fn is_retryable_sqlstate(state: &str) -> bool {
    let state = state.to_ascii_uppercase();
    state.starts_with("08")
        || state.starts_with("40")
        || matches!(
            state.as_str(),
            "HYT00" | "HYT01" | "55P03" | "57014" | "57P03"
        )
}

#[derive(Debug, thiserror::Error)]
pub enum PgError {
    #[error("invalid PostgreSQL connection configuration: {0}")]
    Configuration(&'static str),
    #[error("PostgreSQL TLS initialization failed")]
    Tls,
    #[error("PostgreSQL connection acquisition failed")]
    Acquisition,
    #[error("PostgreSQL operation deadline exceeded; connection discarded")]
    Deadline,
    #[error("PostgreSQL transaction is already finished")]
    Finished,
    #[error("PostgreSQL transaction failed; rollback is required")]
    FailedTransaction,
    #[error("PostgreSQL operation failed ({class:?})")]
    Query {
        class: PostgresErrorClass,
        #[source]
        source: tokio_postgres::Error,
    },
    #[error("PostgreSQL schema preflight failed: {0}")]
    Preflight(String),
}

impl From<tokio_postgres::Error> for PgError {
    fn from(source: tokio_postgres::Error) -> Self {
        Self::Query {
            class: PostgresErrorClass::classify(&source),
            source,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaReadiness {
    pub required_version: String,
    pub applied_version: Option<String>,
    pub required_checksum: String,
    pub applied_checksum: Option<String>,
    pub ready: bool,
}

/// Pure contract checks shared by real preflight and fixture tests.
pub fn schema_problems(
    tables: &[String],
    columns: &BTreeMap<(String, String), String>,
    readiness: Option<&SchemaReadiness>,
    expected_checksum: &str,
) -> Vec<String> {
    let mut errors = Vec::new();
    for table in REQUIRED_TABLES {
        if !tables.iter().any(|found| found == table) {
            errors.push(format!("missing table {table}"));
        }
    }
    for (table, column, expected) in REQUIRED_COLUMN_TYPES {
        if !columns
            .get(&(table.to_string(), column.to_string()))
            .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
        {
            errors.push(format!(
                "invalid column {table}.{column}: expected {expected}"
            ));
        }
    }
    match readiness {
        None => errors.push("missing octopus_core schema_readiness row".into()),
        Some(row) => {
            if !row.ready {
                errors.push("schema_readiness.ready is false".into());
            }
            if row.applied_version.as_deref() != Some(&row.required_version) {
                errors.push("applied version does not match required version".into());
            }
            if !row
                .required_checksum
                .eq_ignore_ascii_case(expected_checksum)
            {
                errors.push("required checksum does not match configured checksum".into());
            }
            if !row
                .applied_checksum
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case(expected_checksum))
            {
                errors.push("applied checksum does not match configured checksum".into());
            }
        }
    }
    errors
}

fn connection_config(
    config: &PostgresConfig,
) -> Result<(tokio_postgres::Config, MakeTlsConnector), PgError> {
    if !config.enabled {
        return Err(PgError::Configuration("PostgreSQL is disabled"));
    }
    if !(1..=65535).contains(&config.port)
        || config.pool_size <= 0
        || config.healthcheck_reserve < 0
        || config.healthcheck_reserve >= config.pool_size
        || config.connection_timeout_ms <= 0
        || config.statement_timeout_secs <= 0
        || config.statement_timeout_secs > i32::MAX / 1000
        || config.network_timeout_secs <= config.statement_timeout_secs
    {
        return Err(PgError::Configuration(
            "invalid connection capacity or timeout bounds",
        ));
    }
    let mut pg = tokio_postgres::Config::new();
    pg.host(&config.host)
        .port(config.port as u16)
        .dbname(&config.database)
        .user(&config.user)
        .password(&config.password)
        .application_name("octopus")
        .connect_timeout(Duration::from_millis(config.connection_timeout_ms as u64))
        .options(format!(
            "-c timezone=UTC -c search_path=octopus_core,atheros_search -c statement_timeout={}",
            i64::from(config.statement_timeout_secs) * 1000
        ));
    let mut tls = SslConnector::builder(SslMethod::tls()).map_err(|_| PgError::Tls)?;
    if config.ssl_mode == "disable" {
        pg.ssl_mode(SslMode::Disable);
    } else {
        if config.ssl_server_name.is_empty()
            || !config
                .ssl_server_name
                .eq_ignore_ascii_case(config.host.trim())
        {
            return Err(PgError::Configuration("TLS server name must equal host"));
        }
        if !Path::new(&config.ssl_ca_path).is_file() {
            return Err(PgError::Configuration("CA bundle must be a regular file"));
        }
        tls.set_verify(SslVerifyMode::PEER);
        tls.set_ca_file(&config.ssl_ca_path)
            .map_err(|_| PgError::Tls)?;
        pg.ssl_mode(SslMode::Require);
        let path = &config.ssl_client_key_store_path;
        if path.is_empty() != config.ssl_client_key_store_password.is_empty() {
            return Err(PgError::Configuration(
                "client keystore path and password must be configured together",
            ));
        }
        if !path.is_empty() {
            let material = crate::compatibility::tls_identity::load(
                path,
                &config.ssl_client_key_store_password,
                &config.ssl_client_key_store_type,
            )
                .map_err(|_| PgError::Tls)?;
            tls.set_certificate(&material.certificate)
                .map_err(|_| PgError::Tls)?;
            tls.set_private_key(&material.private_key)
                .map_err(|_| PgError::Tls)?;
            for cert in material.chain {
                tls.add_extra_chain_cert(cert).map_err(|_| PgError::Tls)?;
            }
            tls.check_private_key().map_err(|_| PgError::Tls)?;
        }
    }
    Ok((pg, MakeTlsConnector::new(tls.build())))
}

#[derive(Clone)]
pub struct PgRuntime {
    pool: Pool,
    workers: Arc<Semaphore>,
    deadline: Duration,
    acquire_deadline: Duration,
    tls: MakeTlsConnector,
    statement_timeout_ms: i64,
}

impl PgRuntime {
    fn build(config: &PostgresConfig) -> Result<Self, PgError> {
        let (pg, tls) = connection_config(config)?;
        let manager = Manager::from_config(
            pg,
            tls.clone(),
            ManagerConfig {
                recycling_method: RecyclingMethod::Verified,
            },
        );
        let pool = Pool::builder(manager)
            .max_size(config.pool_size as usize)
            .build()
            .map_err(|_| PgError::Configuration("pool configuration"))?;
        Ok(Self {
            pool,
            workers: Arc::new(Semaphore::new(
                (config.pool_size - config.healthcheck_reserve) as usize,
            )),
            deadline: Duration::from_secs(config.network_timeout_secs as u64),
            acquire_deadline: Duration::from_millis(config.connection_timeout_ms as u64),
            tls,
            statement_timeout_ms: i64::from(config.statement_timeout_secs) * 1000,
        })
    }

    /// Connectivity and canonical schema proof are mandatory before returning.
    pub async fn connect(config: &PostgresConfig) -> Result<Self, PgError> {
        let runtime = Self::build(config)?;
        runtime.validate_schema(&config.manifest_sha256).await?;
        Ok(runtime)
    }

    async fn acquire(&self, worker: bool) -> Result<PgTransaction, PgError> {
        let permit = if worker {
            Some(
                timeout(self.acquire_deadline, self.workers.clone().acquire_owned())
                    .await
                    .map_err(|_| PgError::Acquisition)?
                    .map_err(|_| PgError::Acquisition)?,
            )
        } else {
            None
        };
        let client = timeout(self.acquire_deadline, self.pool.get())
            .await
            .map_err(|_| PgError::Acquisition)?
            .map_err(|_| PgError::Acquisition)?;
        let mut transaction = PgTransaction {
            client: Some(client),
            permit,
            deadline: self.deadline,
            tls: self.tls.clone(),
            finished: false,
            failed: false,
        };
        transaction
            .command(if worker { "BEGIN" } else { "BEGIN READ ONLY" })
            .await?;
        transaction.command(&format!("SET LOCAL search_path TO octopus_core, atheros_search; SET LOCAL TIME ZONE 'UTC'; SET LOCAL statement_timeout = {}", self.statement_timeout_ms)).await?;
        Ok(transaction)
    }

    pub async fn begin_worker(&self) -> Result<PgTransaction, PgError> {
        self.acquire(true).await
    }

    pub async fn health_check(&self) -> bool {
        match self.acquire(false).await {
            Ok(mut transaction) => {
                transaction.query("SELECT 1", &[]).await.is_ok()
                    && transaction.commit().await.is_ok()
            }
            Err(_) => false,
        }
    }

    pub async fn validate_schema(&self, manifest: &str) -> Result<(), PgError> {
        let mut transaction = self.begin_worker().await?;
        let tables = transaction.query("SELECT table_name FROM information_schema.tables WHERE table_schema = 'octopus_core' AND table_type = 'BASE TABLE'", &[]).await?.iter().map(|row| row.get(0)).collect::<Vec<String>>();
        let columns = transaction.query("SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = 'octopus_core'", &[]).await?.iter().map(|row| ((row.get::<_,String>(0), row.get::<_,String>(1)), row.get(2))).collect();
        let rows = transaction.query("SELECT required_version, applied_version, required_checksum, applied_checksum, ready FROM octopus_core.schema_readiness WHERE domain = $1", &[&"octopus_core"]).await?;
        let readiness = rows.first().map(|row| SchemaReadiness {
            required_version: row.get(0),
            applied_version: row.get(1),
            required_checksum: row.get(2),
            applied_checksum: row.get(3),
            ready: row.get(4),
        });
        let errors = schema_problems(&tables, &columns, readiness.as_ref(), manifest);
        transaction.commit().await?;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(PgError::Preflight(errors.join("; ")))
        }
    }

    pub fn close(&self) {
        self.pool.close();
    }
}

/// Owns its pooled connection. Unfinished/drop/cancellation always evicts it.
pub struct PgTransaction {
    client: Option<Object>,
    permit: Option<OwnedSemaphorePermit>,
    deadline: Duration,
    tls: MakeTlsConnector,
    finished: bool,
    failed: bool,
}

impl PgTransaction {
    fn client(&self) -> Result<&Object, PgError> {
        self.client.as_ref().ok_or(PgError::Finished)
    }

    fn active_client(&self) -> Result<&Object, PgError> {
        let client = self.client()?;
        if self.failed {
            Err(PgError::FailedTransaction)
        } else {
            Ok(client)
        }
    }

    async fn discard_after_deadline(&mut self) {
        if let Some(client) = self.client.as_ref() {
            // Cancellation is racy: even a successful request never makes this
            // connection eligible for reuse. Dropping ClientWrapper aborts I/O.
            let token = client.cancel_token();
            let _ = timeout(Duration::from_secs(1), token.cancel_query(self.tls.clone())).await;
        }
        self.evict();
    }

    fn evict(&mut self) {
        if let Some(client) = self.client.take() {
            drop(Object::take(client));
        }
        self.permit.take();
    }

    fn query_error(&mut self, error: tokio_postgres::Error) -> PgError {
        self.failed = true;
        // Server-side cancellation is also uncertain: never recycle it merely
        // because the command completed with SQLSTATE 57014.
        if error.code().is_some_and(|code| code.code() == "57014") || error.is_closed() {
            self.evict();
        }
        error.into()
    }

    async fn command(&mut self, sql: &str) -> Result<(), PgError> {
        match timeout(self.deadline, self.client()?.batch_execute(sql)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(self.query_error(error)),
            Err(_) => {
                self.discard_after_deadline().await;
                Err(PgError::Deadline)
            }
        }
    }

    pub async fn query(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, PgError> {
        self.active_client()?;
        self.failed = true;
        match timeout(self.deadline, self.client()?.query(sql, params)).await {
            Ok(Ok(rows)) => {
                self.failed = false;
                Ok(rows)
            }
            Ok(Err(error)) => Err(self.query_error(error)),
            Err(_) => {
                self.discard_after_deadline().await;
                Err(PgError::Deadline)
            }
        }
    }

    pub async fn execute(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, PgError> {
        self.active_client()?;
        self.failed = true;
        match timeout(self.deadline, self.client()?.execute(sql, params)).await {
            Ok(Ok(count)) => {
                self.failed = false;
                Ok(count)
            }
            Ok(Err(error)) => Err(self.query_error(error)),
            Err(_) => {
                self.discard_after_deadline().await;
                Err(PgError::Deadline)
            }
        }
    }

    pub async fn commit(mut self) -> Result<(), PgError> {
        self.active_client()?;
        self.command("COMMIT").await?;
        self.finished = true;
        Ok(())
    }
    pub async fn rollback(mut self) -> Result<(), PgError> {
        self.command("ROLLBACK").await?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for PgTransaction {
    fn drop(&mut self) {
        if !self.finished {
            self.evict();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_bounds_and_tls_fail_closed() {
        let mut config = PostgresConfig::default();
        assert!(connection_config(&config).is_err());
        config.enabled = true;
        config.ssl_mode = "disable".into();
        let (pg, _) = connection_config(&config).unwrap();
        assert_eq!(pg.get_ssl_mode(), SslMode::Disable);
        assert!(pg
            .get_options()
            .unwrap()
            .contains("statement_timeout=30000"));
        config.healthcheck_reserve = config.pool_size;
        assert!(connection_config(&config).is_err());
        config.healthcheck_reserve = 2;
        config.ssl_mode = "require".into();
        assert!(connection_config(&config).is_err());
    }

    // A real PostgreSQL is needed for transaction cancellation and pool reuse.
    // No DDL is necessary for these SELECT-only connection lifecycle checks.
    #[tokio::test]
    async fn docker_transaction_deadlines_and_drop_evict_connections() {
        use std::process::Command;
        let required = std::env::var("OCTOPUS_REQUIRE_DOCKER").as_deref() == Ok("true");
        if !Command::new("docker")
            .arg("info")
            .output()
            .is_ok_and(|out| out.status.success())
        {
            assert!(
                !required,
                "OCTOPUS_REQUIRE_DOCKER=true but Docker is unavailable"
            );
            eprintln!("Docker lifecycle test unavailable; no integration result claimed");
            return;
        }
        struct Container(String);
        impl Drop for Container {
            fn drop(&mut self) {
                let _ = Command::new("docker")
                    .args(["rm", "-f", "-v", &self.0])
                    .output();
            }
        }
        let name = format!("octopus-native-postgres-{}", uuid::Uuid::new_v4());
        let output = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &name,
                "-e",
                "POSTGRES_PASSWORD=integration-only",
                "-e",
                "POSTGRES_DB=sync",
                "-p",
                "127.0.0.1::5432",
                "postgres:16-bookworm",
            ])
            .output()
            .unwrap();
        let _container = Container(name.clone());
        assert!(
            output.status.success(),
            "Docker PostgreSQL startup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut ready = false;
        for _ in 0..60 {
            if Command::new("docker")
                .args([
                    "exec",
                    &name,
                    "pg_isready",
                    "-h",
                    "127.0.0.1",
                    "-U",
                    "postgres",
                    "-d",
                    "sync",
                ])
                .output()
                .is_ok_and(|out| out.status.success())
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert!(ready, "PostgreSQL did not become ready");
        let port = Command::new("docker")
            .args(["port", &name, "5432/tcp"])
            .output()
            .unwrap();
        let port = String::from_utf8(port.stdout)
            .unwrap()
            .trim()
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let config = PostgresConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            port,
            database: "sync".into(),
            user: "postgres".into(),
            password: "integration-only".into(),
            ssl_mode: "disable".into(),
            pool_size: 2,
            healthcheck_reserve: 1,
            statement_timeout_secs: 1,
            network_timeout_secs: 3,
            connection_timeout_ms: 250,
            ..PostgresConfig::default()
        };
        let runtime = PgRuntime::build(&config).unwrap();
        assert!(runtime.health_check().await);
        let mut abandoned = runtime.begin_worker().await.unwrap();
        assert!(timeout(Duration::from_millis(50), abandoned.query("SELECT pg_sleep(3)", &[])).await.is_err());
        assert!(matches!(abandoned.commit().await, Err(PgError::FailedTransaction)));
        assert!(
            runtime.validate_schema(&"a".repeat(64)).await.is_err(),
            "unprovisioned database must never pass preflight"
        );
        let mut transaction = runtime.begin_worker().await.unwrap();
        let old_pid: i32 = transaction
            .query("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()[0]
            .get(0);
        let error = transaction
            .query("SELECT pg_sleep(3)", &[])
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            PgError::Query {
                class: PostgresErrorClass::Retryable,
                ..
            }
        ));
        assert!(matches!(
            transaction.rollback().await,
            Err(PgError::Finished)
        ));
        let mut transaction = runtime.begin_worker().await.unwrap();
        assert_eq!(
            transaction.query("SELECT 1::int", &[]).await.unwrap()[0].get::<_, i32>(0),
            1
        );
        let deadline_pid: i32 = transaction
            .query("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()[0]
            .get(0);
        // Force the client deadline below the server's timeout to test eviction.
        transaction.deadline = Duration::from_millis(20);
        assert!(matches!(
            transaction.query("SELECT pg_sleep(3)", &[]).await,
            Err(PgError::Deadline)
        ));
        drop(transaction);
        let mut transaction = runtime.begin_worker().await.unwrap();
        let new_pid: i32 = transaction
            .query("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()[0]
            .get(0);
        assert_ne!(old_pid, new_pid);
        assert_ne!(deadline_pid, new_pid);
        assert!(transaction.query("SELECT 1/0", &[]).await.is_err());
        assert!(matches!(
            transaction.query("SELECT 1", &[]).await,
            Err(PgError::FailedTransaction)
        ));
        assert!(matches!(
            transaction.commit().await,
            Err(PgError::FailedTransaction)
        ));
        let mut transaction = runtime.begin_worker().await.unwrap();
        assert!(transaction.query("SELECT 1/0", &[]).await.is_err());
        transaction.rollback().await.unwrap();
        let mut transaction = runtime.begin_worker().await.unwrap();
        assert!(
            runtime.health_check().await,
            "reserved health capacity must remain available"
        );
        assert!(
            matches!(runtime.begin_worker().await, Err(PgError::Acquisition)),
            "worker permit acquisition must be bounded"
        );
        let active_pid: i32 = transaction
            .query("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()[0]
            .get(0);
        transaction
            .command("SET LOCAL statement_timeout = 10000")
            .await
            .unwrap();
        let task = tokio::spawn(async move { transaction.query("SELECT pg_sleep(10)", &[]).await });
        let inspect = format!("SELECT wait_event FROM pg_stat_activity WHERE pid = {active_pid}");
        let mut sleeping = false;
        for _ in 0..40 {
            let output = Command::new("docker")
                .args([
                    "exec", &name, "psql", "-U", "postgres", "-d", "sync", "-Atc", &inspect,
                ])
                .output()
                .unwrap();
            if String::from_utf8_lossy(&output.stdout).trim() == "PgSleep" {
                sleeping = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(sleeping, "query must be active before task cancellation");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let mut transaction = runtime.begin_worker().await.unwrap();
        let replacement_pid: i32 = transaction
            .query("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()[0]
            .get(0);
        assert_ne!(replacement_pid, active_pid);
        transaction.commit().await.unwrap();
        assert!(runtime.health_check().await);
        runtime.close();
    }
}
