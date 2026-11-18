mod support;

use chrono::Utc;
use octopus::{
    archive::{
        object_key, ArchiveCandidate, ArchiveError, MinioStore, PayloadArchiver, RetentionStore,
    },
    config::ArchiveConfig,
    postgres::PgRuntime,
    supervision::LeaseStore,
    util::sha256_hex,
};
use std::{process::Command, time::Duration};
use tokio_util::sync::CancellationToken;

const MINIO_IMAGE: &str =
    "elestio/minio@sha256:25348a257f1ece1b192f25f6cd9854618fa86422ac87b494b5d4e629c556d4bd";

struct Minio {
    container: Container,
    store: MinioStore,
}
struct Container(String);
impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", "-v", &self.0])
            .output();
    }
}
impl Minio {
    async fn start() -> Self {
        let name = format!("native-archive-{}", uuid::Uuid::new_v4());
        support::checked(Command::new("docker").args([
            "run",
            "-d",
            "--name",
            &name,
            "-p",
            "127.0.0.1::9000",
            "-e",
            "MINIO_ROOT_USER=archive-test",
            "-e",
            "MINIO_ROOT_PASSWORD=archive-test-password",
            MINIO_IMAGE,
            "server",
            "/data",
        ]));
        let container = Container(name);
        let store = Self::store(&container);
        let value = Self { container, store };
        let mut ready = false;
        for _ in 0..120 {
            if value.store.initialize().await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(ready, "scratch MinIO did not become ready");
        value
    }
    fn store(container: &Container) -> MinioStore {
        let output = support::checked(Command::new("docker").args(["port", &container.0, "9000/tcp"]));
        let endpoint = format!(
            "http://{}",
            String::from_utf8(output.stdout).unwrap().trim()
        );
        MinioStore::new(
            &endpoint,
            "archive-test",
            "archive-test-password",
            "us-east-1",
            "wireless-archive",
        )
        .unwrap()
    }
    fn stop(&self) {
        support::checked(Command::new("docker").args(["stop", "--time", "1", &self.container.0]));
    }
    async fn restart(&mut self) {
        support::checked(Command::new("docker").args(["start", &self.container.0]));
        self.store = Self::store(&self.container);
        for _ in 0..120 {
            if self.store.initialize().await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let logs=Command::new("docker").args(["logs",&self.container.0]).output().unwrap();
        panic!("MinIO restart failed: {}",String::from_utf8_lossy(&logs.stderr));
    }
}

fn candidate(key: &str, payload: &str) -> ArchiveCandidate {
    ArchiveCandidate {
        dedupe_key: sha256_hex(key),
        stream_name: "wireless.audit".into(),
        observed_at: "2020-01-02T03:04:05-08:00"
            .parse::<chrono::DateTime<chrono::FixedOffset>>()
            .unwrap()
            .with_timezone(&Utc),
        payload: payload.into(),
        payload_sha256: sha256_hex(payload),
    }
}

async fn seed(runtime: &PgRuntime, candidate: &ArchiveCandidate) {
    let mut tx = runtime.begin_worker().await.unwrap();
    tx.execute("INSERT INTO sync_events(dedupe_key,stream_name,observed_at,payload_ref,payload,payload_sha256,status) VALUES($1,$2,$3,'inline',$4::text::jsonb,$5,'completed')",&[&candidate.dedupe_key,&candidate.stream_name,&candidate.observed_at,&candidate.payload,&candidate.payload_sha256]).await.unwrap();
    tx.commit().await.unwrap();
}

async fn count(runtime: &PgRuntime, sql: &str) -> i64 {
    let mut tx = runtime.begin_worker().await.unwrap();
    let result = tx.query(sql, &[]).await.unwrap()[0].get(0);
    tx.commit().await.unwrap();
    result
}

#[test]
fn archive_key_is_utc_and_requires_safe_sha256() {
    let value = candidate("source", r#"{"v": 1}"#);
    assert!(object_key(&value)
        .unwrap()
        .starts_with("wireless/2020/01/02/"));
    let mut invalid = value.clone();
    invalid.dedupe_key = "../escape".into();
    assert!(object_key(&invalid).is_err());
    invalid.dedupe_key = "A".repeat(64);
    assert!(object_key(&invalid).is_err());
    let mut offset = value;
    offset.observed_at = "2020-01-02T00:04:05+10:00"
        .parse::<chrono::DateTime<chrono::FixedOffset>>()
        .unwrap()
        .with_timezone(&Utc);
    assert!(object_key(&offset)
        .unwrap()
        .starts_with("wireless/2020/01/01/"));
}

#[tokio::test(flavor = "multi_thread")]
async fn real_minio_archive_is_verified_restart_safe_and_retention_is_fenced() {
    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let mut objects = Minio::start().await;
    let config = ArchiveConfig {
        enabled: true,
        hot_days: 1,
        event_retention_days: 1,
        search_retention_days: 1,
        batch_size: 100,
        ..ArchiveConfig::default()
    };
    let archiver = PayloadArchiver::new(
        fixture.runtime.clone(),
        objects.store.clone(),
        config.clone(),
    );
    let retention = RetentionStore::new(fixture.runtime.clone());

    // A mismatching object may never be overwritten or acknowledged in SQL.
    let collision = candidate("collision", r#"{"v": 1}"#);
    seed(&fixture.runtime, &collision).await;
    let key = object_key(&collision).unwrap();
    objects
        .store
        .put_versioned(&key, b"different", &sha256_hex(b"different"))
        .await
        .unwrap();
    assert!(matches!(
        archiver.archive_once().await,
        Err(ArchiveError::Integrity)
    ));
    assert_eq!(
        count(
            &fixture.runtime,
            "SELECT count(*) FROM sync_events WHERE payload IS NOT NULL AND payload_archived=false"
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &fixture.runtime,
            "SELECT count(*) FROM sync_event_payload_archives"
        )
        .await,
        0
    );
    objects.store.delete(&key, None).await.unwrap();

    // Outage must preserve raw data. Retrying after restart verifies and records
    // the already-written object before clearing the PostgreSQL payload.
    objects.stop();
    assert!(archiver.archive_once().await.unwrap_err().is_retryable());
    assert_eq!(
        count(
            &fixture.runtime,
            "SELECT count(*) FROM sync_events WHERE payload IS NOT NULL"
        )
        .await,
        1
    );
    objects.restart().await;
    objects.store.archive(&collision).await.unwrap();
    let archiver = PayloadArchiver::new(
        fixture.runtime.clone(),
        objects.store.clone(),
        config.clone(),
    );
    assert_eq!(archiver.archive_once().await.unwrap(), 1);
    assert_eq!(archiver.archive_once().await.unwrap(), 0);
    assert_eq!(
        objects
            .store
            .get_verified(&key, &collision.payload_sha256, 1024)
            .await
            .unwrap(),
        collision.payload.as_bytes()
    );
    assert!(objects
        .store
        .get_verified(&key, &collision.payload_sha256, 1)
        .await
        .is_err());

    let leases = LeaseStore::new(fixture.runtime.clone());
    let lease = leases
        .acquire("maintenance", "event-retention", "owner", 30)
        .await
        .unwrap()
        .unwrap();
    let mut stale = lease.clone();
    stale.fence += 1;
    assert!(matches!(
        retention.retain_events(&config, &stale).await,
        Err(ArchiveError::LeaseLost)
    ));
    assert_eq!(
        count(&fixture.runtime, "SELECT count(*) FROM sync_events").await,
        1
    );

    // An active job blocks deletion even when its event has a valid archive.
    fixture.admin(&format!("INSERT INTO octopus_core.sync_jobs(job_id,dedupe_key,stream_name,status) VALUES('busy','{}','wireless.audit','pending')",collision.dedupe_key));
    assert_eq!(
        retention
            .retain_events(&config, &lease)
            .await
            .unwrap()
            .deleted,
        0
    );
    fixture.admin("UPDATE octopus_core.sync_jobs SET status='completed' WHERE job_id='busy'");
    assert_eq!(
        retention
            .retain_events(&config, &lease)
            .await
            .unwrap()
            .deleted,
        1
    );
    assert_eq!(
        count(&fixture.runtime, "SELECT count(*) FROM sync_events").await,
        0
    );
    assert_eq!(
        count(
            &fixture.runtime,
            "SELECT count(*) FROM sync_event_tombstones"
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &fixture.runtime,
            "SELECT count(*) FROM sync_event_payload_archives"
        )
        .await,
        1
    );
    assert!(leases
        .release("maintenance", "event-retention", &lease)
        .await
        .unwrap());

    // Invalid local candidates quarantine without object publication.
    let mut corrupt = candidate("corrupt", r#"{"v": 2}"#);
    corrupt.payload_sha256 = "f".repeat(64);
    seed(&fixture.runtime, &corrupt).await;
    assert_eq!(archiver.archive_once().await.unwrap(), 0);
    assert_eq!(
        count(
            &fixture.runtime,
            "SELECT count(*) FROM sync_events WHERE status='failed' AND payload IS NOT NULL"
        )
        .await,
        1
    );

    let result = retention
        .run_events(
            "owner",
            config.clone(),
            archiver.clone(),
            30,
            CancellationToken::new(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.deleted, 0);
    assert_eq!(
        count(
            &fixture.runtime,
            "SELECT count(*) FROM retention_runs WHERE status='completed'"
        )
        .await,
        1
    );

    // A wrong receipt cannot clear payloads, including a forged destination.
    let valid = candidate("valid", r#"{"v": 3}"#);
    seed(&fixture.runtime, &valid).await;
    let receipt = objects.store.archive(&candidate("other", &valid.payload)).await.unwrap();
    assert!(matches!(
        archiver.record_archive(&valid, &receipt).await,
        Err(ArchiveError::Integrity)
    ));

    // Search retention preserves active embedding work and deletes old terminal
    // documents together with vectors, token/tag children and terminal jobs.
    let document = "00000000-0000-0000-0000-000000000123";
    fixture.admin(&format!("INSERT INTO atheros_search.search_documents(document_id,source_kind,source_id,normalized_text,normalized_sha256,search_vector,status,updated_at) VALUES('{document}','event','old-doc','text',repeat('a',64),to_tsvector('text'),'superseded',CURRENT_TIMESTAMP-INTERVAL '3 days'); INSERT INTO atheros_search.embedding_jobs(job_id,document_id,embedding_kind,embedding_model,content_sha256,status) VALUES('00000000-0000-0000-0000-000000000124','{document}','event','model',repeat('a',64),'pending')"));
    let search_lease = leases
        .acquire("maintenance", "search-retention", "owner", 30)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        retention
            .retain_search(&config, &search_lease)
            .await
            .unwrap()
            .deleted,
        0
    );
    fixture.admin("UPDATE atheros_search.embedding_jobs SET status='completed'");
    assert_eq!(
        retention
            .retain_search(&config, &search_lease)
            .await
            .unwrap()
            .deleted,
        1
    );
    assert_eq!(
        count(
            &fixture.runtime,
            "SELECT count(*) FROM atheros_search.search_documents"
        )
        .await,
        0
    );
    leases
        .release("maintenance", "search-retention", &search_lease)
        .await
        .unwrap();
    assert_eq!(
        retention
            .run_search("owner", config.clone(), 30, CancellationToken::new())
            .await
            .unwrap()
            .unwrap()
            .deleted,
        0
    );

    // Cleanup enforces retry exhaustion and releases worker lease state.
    fixture.admin("INSERT INTO octopus_core.sync_jobs(job_id,dedupe_key,stream_name,status,attempt_count,max_attempts,owner_id,lease_token,lease_expires_at) VALUES('expired','expired','custom.raw','running',1,1,'owner','token',CURRENT_TIMESTAMP-INTERVAL '1 second')");
    assert_eq!(retention.cleanup_stale_workers(10).await.unwrap(), 1);
    assert_eq!(count(&fixture.runtime,"SELECT count(*) FROM sync_jobs WHERE job_id='expired' AND status='failed' AND owner_id IS NULL").await,1);
    fixture.admin("UPDATE octopus_core.sync_event_tombstones SET expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second'");
    assert_eq!(retention.prune_tombstones(10).await.unwrap(), 1);

    // Cancellation is recorded and releases the fenced maintenance lease.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_endpoint = format!("http://{}", listener.local_addr().unwrap());
    let accepted = std::sync::Arc::new(tokio::sync::Notify::new());
    let observed = accepted.clone();
    let app = axum::Router::new().fallback(move || {
        let observed = observed.clone();
        async move {
            observed.notify_one();
            std::future::pending::<axum::http::StatusCode>().await
        }
    });
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let slow = MinioStore::with_timeout(
        &slow_endpoint,
        "archive-test",
        "archive-test-password",
        "us-east-1",
        "wireless-archive",
        Duration::from_secs(10),
    )
    .unwrap();
    let slow_archiver = PayloadArchiver::new(fixture.runtime.clone(), slow, config.clone());
    let cancellation = CancellationToken::new();
    let running = retention.run_events("owner", config, slow_archiver, 30, cancellation.clone());
    tokio::pin!(running);
    tokio::select! {
        _=accepted.notified()=>{},
        result=&mut running=>panic!("retention completed before cancellation: {result:?}"),
        _=tokio::time::sleep(Duration::from_secs(10))=>panic!("retention did not reach object storage"),
    }
    cancellation.cancel();
    assert!(matches!(running.await, Err(ArchiveError::Cancelled)));
    server.abort();
    let _ = server.await;
    assert_eq!(
        count(
            &fixture.runtime,
            "SELECT count(*) FROM retention_runs WHERE status='cancelled'"
        )
        .await,
        1
    );
    assert_eq!(count(&fixture.runtime,"SELECT count(*) FROM work_leases WHERE resource_type='maintenance' AND owner_id IS NOT NULL").await,0);
}
