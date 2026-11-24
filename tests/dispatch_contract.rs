mod support;
use octopus::{dispatch::DispatchStore, domain::SyncLoad};

// The fixture's synchronous admin calls must allow the connection driver to
// close evicted transactions while PostgreSQL waits for their locks to clear.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claims_are_exclusive_fenced_and_recovered_without_losing_destination() {
    let Some(f) = support::Fixture::start().await else {
        return;
    };
    let store = DispatchStore::new(f.runtime.clone());
    let batch = uuid::Uuid::new_v4().to_string();
    let mut tx = f.runtime.begin_worker().await.unwrap();
    tx.execute(
        "INSERT INTO sync_jobs(job_id,dedupe_key,stream_name) VALUES(CAST($1 AS text),CAST($1 AS text),'proxy.events')",
        &[&batch],
    )
    .await
    .unwrap();
    tx.execute("INSERT INTO sync_batches(batch_id,job_id,dedupe_key,stream_name,payload_ref,cursor_start,cursor_end) VALUES(CAST($1 AS text),CAST($1 AS text),CAST($1 AS text),'proxy.events','inline://json/e30','0','1')",&[&batch]).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(store.enqueue_pending(10, 2).await.unwrap(), 1);
    assert_eq!(store.enqueue_pending(10, 2).await.unwrap(), 0);
    let topics = vec!["sync.oracle.load".to_string()];
    let (a, b) = tokio::join!(
        store.claim_outbox("owner-a", &topics, 30),
        store.claim_outbox("owner-b", &topics, 30)
    );
    let claimed: Vec<_> = [a.unwrap(), b.unwrap()].into_iter().flatten().collect();
    assert_eq!(claimed.len(), 1);
    let first = claimed[0].clone();
    assert_eq!(first.attempt_count, 1);
    assert_eq!(
        first.load_batch_id().unwrap().as_deref(),
        Some(batch.as_str())
    );
    let parsed: SyncLoad = serde_json::from_str(&first.payload).unwrap();
    assert_eq!(parsed.attempt, 1);
    let mut forged = first.clone();
    forged.lease.fence += 1;
    assert!(!store.acknowledge(&forged, Some(&batch)).await.unwrap());
    assert!(store
        .fail(&forged, "lost", 0)
        .await
        .unwrap_err()
        .is_invariant());
    forged = first.clone();
    forged.destination_topic = "other.topic".into();
    assert!(store.acknowledge(&forged, Some(&batch)).await.is_err());
    assert!(store
        .fail(&forged, "wrong destination", 0)
        .await
        .unwrap_err()
        .is_invariant());
    f.admin("UPDATE octopus_core.outbox_events SET lease_expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second' WHERE status='leased'");
    assert!(!store.acknowledge(&first, Some(&batch)).await.unwrap());
    assert_eq!(store.recover_expired().await.unwrap(), 1);
    let second = store
        .claim_outbox("owner-b", &topics, 30)
        .await
        .unwrap()
        .unwrap();
    assert!(second.lease.fence > first.lease.fence);
    assert_ne!(second.lease.token, first.lease.token);
    assert_eq!(second.attempt_count, 2);
    assert!(!store.acknowledge(&first, Some(&batch)).await.unwrap());
    assert!(store.acknowledge(&second, Some(&batch)).await.unwrap());
    assert!(!store.acknowledge(&second, Some(&batch)).await.unwrap());
    let mut tx = f.runtime.begin_worker().await.unwrap();
    let state=tx.query("SELECT b.status,b.attempt_count,j.status FROM sync_batches b JOIN sync_jobs j USING(job_id) WHERE b.batch_id=$1",&[&batch]).await.unwrap();
    assert_eq!(state[0].get::<_, String>(0), "dispatched");
    assert_eq!(state[0].get::<_, i32>(1), 1);
    assert_eq!(state[0].get::<_, String>(2), "running");
    let attempts: i64 = tx
        .query("SELECT count(*) FROM outbox_publish_attempts", &[])
        .await
        .unwrap()[0]
        .get(0);
    assert_eq!(attempts, 1);
    tx.commit().await.unwrap();
    let mut tx = f.runtime.begin_worker().await.unwrap();
    tx.execute("INSERT INTO outbox_events(outbox_id,source_type,source_id,event_type,destination_topic,message_key,payload,status,max_attempts) VALUES(gen_random_uuid(),'sync_batch_result','failed-test','sync.load.result','sync.oracle.result','key','{}','pending',1)",&[]).await.unwrap();
    tx.commit().await.unwrap();
    let results = vec!["sync.oracle.result".into()];
    let record = store
        .claim_outbox("owner", &results, 5)
        .await
        .unwrap()
        .unwrap();
    store
        .fail(&record, "password=secret failure", 0)
        .await
        .unwrap();
    let mut tx = f.runtime.begin_worker().await.unwrap();
    let state = tx
        .query(
            "SELECT status,last_error FROM outbox_events WHERE outbox_id::text=$1",
            &[&record.outbox_id],
        )
        .await
        .unwrap();
    assert_eq!(state[0].get::<_, String>(0), "failed");
    assert!(!state[0].get::<_, String>(1).contains("secret"));
    tx.commit().await.unwrap();
    let streams = vec!["proxy.events".into()];
    store.ensure_cursors(&streams).await.unwrap();
    f.admin("INSERT INTO octopus_core.sync_events(dedupe_key,stream_name,payload_ref,observed_at,status) VALUES('15','proxy.events','inline://json/e30',CURRENT_TIMESTAMP,'pending')");
    assert_eq!(
        store
            .process_ingest_ledger(&streams, 5, 30, 10)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .process_ingest_ledger(&streams, 5, 30, 10)
            .await
            .unwrap(),
        0
    );
    assert_eq!(store.enqueue_pending_streams(&[], 10, 5).await.unwrap(), 0);
    assert_eq!(
        store
            .enqueue_pending_streams(&streams, 10, 5)
            .await
            .unwrap(),
        1
    );
    f.admin("UPDATE octopus_core.sync_jobs SET status='completed' WHERE dedupe_key='15'; UPDATE octopus_core.sync_batches SET status='completed' WHERE dedupe_key='15'");
    let initial=store.reconcile_completed_events(1).await.unwrap();
    let changed = store.reconcile_completed_events(100).await.unwrap();
    assert_eq!(initial+changed,1);
    let mut tx = f.runtime.begin_worker().await.unwrap();
    let state: String = tx
        .query("SELECT status FROM sync_events WHERE dedupe_key='15'", &[])
        .await
        .unwrap()[0]
        .get(0);
    assert_eq!(state, "completed");
    tx.commit().await.unwrap();
    assert_eq!(store.reconcile_completed_events(100).await.unwrap(), 0);
}
