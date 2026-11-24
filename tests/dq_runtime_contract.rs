mod support;
use octopus::{
    config::{DqConfig, DqSettings},
    dq::{self, DqPrincipal},
    dq_runtime::{self, DqStore},
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn settings() -> DqSettings {
    DqSettings {
        installation_id: "dq-test".into(),
        namespace: "native".into(),
        scope_modes: BTreeMap::from([("north".into(), "shadow".into())]),
        policy_version: "p1".into(),
        approved_digests: BTreeSet::from([format!("sha256:{}", "a".repeat(64))]),
        max_queued: 100,
        lease_seconds: 60,
        artifact_bucket: "dq-artifacts".into(),
    }
}
fn config() -> DqConfig {
    DqConfig {
        installation_id: "dq-test".into(),
        namespace: "native".into(),
        ..DqConfig::default()
    }
}
fn actor() -> DqPrincipal {
    DqPrincipal {
        actor: "a".repeat(64),
        roles: ["admin".into(), "operator".into()].into(),
        scopes: ["north".into()].into(),
    }
}
fn manifest() -> Value {
    let schema = json!({"type":"object","additionalProperties":false,"required":["authorized_scope","policy_version","max_candidates"],"properties":{"authorized_scope":{"type":"string"},"policy_version":{"type":"string"},"max_candidates":{"type":"integer","minimum":1,"maximum":1000},"candidate_id":{"type":"string"}}});
    let mut value = json!({"installation_id":"dq-test","namespace":"native","processor_id":"atheros.dedup","version":"0.1.0","owner_team":"wireless","implementation_digest":format!("sha256:{}","a".repeat(64)),"worker_service":"dedup-worker:9090","protocol_version":"dq.v1","parameter_schema_sha256":dq::sha256(&schema).unwrap(),"parameter_schema":schema,"inputs":[],"outputs":[],"resources":{"concurrency":2,"timeout_seconds":60,"max_input_bytes":1000000,"max_output_bytes":1000000},"policy_version":"p1"});
    value["manifest_sha256"] = json!(dq::sha256(&value).unwrap());
    value
}
fn request(key: &str) -> Value {
    json!({"installation_id":"dq-test","namespace":"native","processor_id":"atheros.dedup","operation":"prepare_candidates","idempotency_key":key,"parameters":{"authorized_scope":"north","policy_version":"p1","max_candidates":10}})
}
fn reference(run: &str, attempt: Option<&str>) -> Value {
    let artifact = uuid::Uuid::new_v4().to_string();
    let uri = if let Some(a) = attempt {
        format!("s3://dq-artifacts/dq-test/native/runs/{run}/attempts/{a}/{artifact}")
    } else {
        format!(
            "s3://dq-artifacts/dq-test/native/inputs/{run}/{}",
            "c".repeat(64)
        )
    };
    let mut r = json!({"artifact_id":artifact,"installation_id":"dq-test","namespace":"native","uri":uri,"version_id":"version-1","etag":"etag","sha256":"c".repeat(64),"schema_id":if attempt.is_some(){"atheros.dedup.proposal.v1"}else{"atheros.dedup.snapshot.v1"},"media_type":"application/json","size_bytes":100});
    if let Some(a) = attempt {
        r["producer_run_id"] = json!(run);
        r["producer_attempt_id"] = json!(a);
    }
    r
}
fn envelope(run: &str, attempt: &Value, kind: &str, artifacts: Value) -> Value {
    json!({"schema_version":1,"event_id":uuid::Uuid::new_v4().to_string(),"event_type":kind,"installation_id":"dq-test","namespace":"native","run_id":run,"processor_id":"atheros.dedup","processor_version":"0.1.0","attempt_id":attempt["attempt_id"],"fence":attempt["fence"],"sequence":1,"occurred_at":chrono::Utc::now().to_rfc3339(),"correlation_id":run,"source_revision_digest":"b".repeat(64),"artifacts":artifacts})
}
fn receipt(envelope: &Value, offset: i64, hash: &str) -> Value {
    json!({"installation_id":"dq-test","namespace":"native","consumer_group":"octopus-dq","topic":"dq.worker-reports.v1","partition":0,"offset":offset,"event_id":envelope["event_id"],"payload_sha256":hash,"envelope":envelope})
}
fn code<T: std::fmt::Debug>(r: Result<T, dq::DqError>, expected: &str) {
    assert_eq!(r.unwrap_err().code, expected);
}

#[test]
fn raw_report_receipts_quarantine_before_parsing() {
    let c = config();
    let raw = b"\xff\xfe";
    let r = dq_runtime::runner::receipt(&c, "g", "dq.worker-reports.v1", 0, 1, "", raw);
    assert_eq!(r["payload_sha256"], octopus::util::sha256_hex(raw));
    assert_eq!(r["quarantine_reason"], "invalid_record");
    let value =
        json!({"installation_id":"dq-test","namespace":"native","run_id":"r","event_id":"e"});
    let raw = value.to_string();
    let r = dq_runtime::runner::receipt(
        &c,
        "g",
        "dq.worker-reports.v1",
        0,
        1,
        "dq-test/native/r",
        raw.as_bytes(),
    );
    assert_eq!(r["envelope"], value);
    assert_eq!(r["event_id"], "e");
    let rejected = dq_runtime::runner::receipt(
        &c,
        "g",
        "dq.worker-reports.v1",
        0,
        1,
        "wrong",
        raw.as_bytes(),
    );
    assert_eq!(rejected["quarantine_reason"], "invalid_record");
    let huge=json!({"installation_id":"dq-test","namespace":"native","run_id":"r","payload":"x".repeat(65536)}).to_string();
    assert_eq!(
        dq_runtime::runner::receipt(
            &c,
            "g",
            "dq.worker-reports.v1",
            0,
            1,
            "dq-test/native/r",
            huge.as_bytes()
        )["quarantine_reason"],
        "invalid_record"
    );
}
#[test]
fn artifacts_and_retention_reject_scope_traversal_and_unpinned_versions() {
    let c = config();
    let run = json!({"installation_id":"dq-test","namespace":"native","run_id":"r","current_attempt":{"attempt_id":"a"}});
    let r = reference("r", None);
    assert!(dq_runtime::artifacts::object_key(&r, &run, false, &c).is_ok());
    let mut legacy = r;
    let legacy_key = format!("dq-test/native/inputs/legacy-owner/{}", "c".repeat(64));
    legacy["uri"] = json!(format!("s3://{}/{legacy_key}", c.artifact_bucket));
    assert_eq!(
        dq_runtime::artifacts::object_key(&legacy, &run, false, &c).unwrap(),
        legacy_key
    );
    code(
        dq::validate_artifacts(&json!([legacy]), &c.settings(), "r", None, true),
        "forbidden_artifact_reference",
    );
    let out = reference("r", Some("a"));
    assert!(dq_runtime::artifacts::object_key(&out, &run, true, &c).is_ok());
    let mut invalid = out.clone();
    invalid["version_id"] = json!("null");
    assert!(dq_runtime::artifacts::object_key(&invalid, &run, true, &c).is_err());
    invalid = out;
    invalid["producer_attempt_id"] = json!("old");
    assert!(dq_runtime::artifacts::object_key(&invalid, &run, true, &c).is_err());
    for key in [
        "dq-test/native/inputs/r/h",
        "dq-test/native/runs/r/attempts/a/h",
    ] {
        assert!(dq_runtime::retention::allowed_key(key, &c));
    }
    for key in [
        "other/native/inputs/r/h",
        "dq-test/native/inputs/../h",
        "dq-test/native/inputs/r/h/extra",
        "dq-test/native/runs/r/attempts/a/",
    ] {
        assert!(!dq_runtime::retention::allowed_key(key, &c));
    }
}
fn proposal_fixture() -> (Value, Value, Value) {
    let mut snapshot = json!({"installation_id":"dq-test","namespace":"native","authorized_scope":"north","operation":"prepare_candidates","policy_version":"p1","pairs":[{"pair_id":"pair","mac_a":"00:00:00:00:00:01","mac_b":"00:00:00:00:00:02","confidence":0.9}],"devices":[{"mac":"00:00:00:00:00:01"},{"mac":"00:00:00:00:00:02"}],"candidates":[],"decisions":[]});
    let hash = dq::sha256(&snapshot).unwrap();
    snapshot["source_revision_digest"] = json!(hash);
    let run = json!({"run_id":"r","current_attempt":{"attempt_id":"a","fence":2},"operation":"prepare_candidates","policy_version":"p1","source_revision_digest":hash,"installation_id":"dq-test","namespace":"native","processor_id":"atheros.dedup","parameters":{"authorized_scope":"north","max_candidates":10}});
    let output = json!({"run_id":"r","attempt_id":"a","fence":2,"operation":"prepare_candidates","source_revision_digest":hash,"policy_version":"p1","candidates":[{"mac_a":"00:00:00:00:00:01","mac_b":"00:00:00:00:00:02","confidence":0.9,"pair_id":"pair"}],"reconciliations":[],"summary":{"candidate_count":1,"reconciliation_count":0}});
    (run, snapshot, output)
}
#[test]
fn proposal_validation_preserves_identity_scope_pairs_and_digest() {
    let (run, snapshot, output) = proposal_fixture();
    let p = dq_runtime::apply::validate(&run, &snapshot, &output).unwrap();
    assert_eq!(
        dq_runtime::apply::shadow_comparison(&snapshot, &p).unwrap()["missing_pairs"],
        0
    );
    for (field, value) in [
        ("run_id", json!("other")),
        ("fence", json!(1)),
        ("policy_version", json!("old")),
        ("unknown", json!(true)),
    ] {
        let mut invalid = output.clone();
        invalid[field] = value;
        assert!(dq_runtime::apply::validate(&run, &snapshot, &invalid).is_err());
    }
    let mut invalid = output.clone();
    invalid["candidates"][0]["confidence"] = json!(0.95);
    code(
        dq_runtime::apply::validate(&run, &snapshot, &invalid),
        "proposal_candidate_forbidden",
    );
    let mut corrupt = snapshot.clone();
    corrupt["devices"] = json!([]);
    code(
        dq_runtime::apply::validate(&run, &corrupt, &output),
        "proposal_identity_mismatch",
    );
    let mut duplicate = output.clone();
    duplicate["candidates"]
        .as_array_mut()
        .unwrap()
        .push(output["candidates"][0].clone());
    duplicate["summary"]["candidate_count"] = json!(2);
    code(
        dq_runtime::apply::validate(&run, &snapshot, &duplicate),
        "proposal_duplicate_pair",
    );
}

#[tokio::test]
async fn durable_control_scope_fences_receipts_and_rollback() {
    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let store = DqStore::new(fixture.runtime.clone(), settings());
    store.reconcile_policies().await.unwrap();
    let p = actor();
    let m = manifest();
    assert_eq!(store.register(&p, &m).await.unwrap(), m);
    assert_eq!(store.register(&p, &m).await.unwrap(), m);
    assert_eq!(
        store.catalog(&p).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let request = request("one");
    let run = store.admit(&p, &request).await.unwrap();
    let run_id = run["run_id"].as_str().unwrap();
    assert_eq!(store.admit(&p, &request).await.unwrap()["run_id"], run_id);
    let mut conflict = request.clone();
    conflict["parameters"]["max_candidates"] = json!(2);
    code(store.admit(&p, &conflict).await, "idempotency_conflict");
    let mut denied = p.clone();
    denied.scopes = ["south".into()].into();
    code(store.get_run(&denied, run_id).await, "forbidden_scope");
    let claims = store.claim_preparation("preparer", 60, 1).await.unwrap();
    assert_eq!(claims[0]["run_id"], run_id);
    assert!(!store
        .complete_preparation(
            run_id,
            "old",
            &json!([reference(run_id, None)]),
            &"b".repeat(64)
        )
        .await
        .unwrap());
    let refs = json!([reference(run_id, None)]);
    assert!(store
        .complete_preparation(run_id, "preparer", &refs, &"b".repeat(64))
        .await
        .unwrap());
    assert_eq!(
        store.dispatches(1).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let heartbeat = json!({"installation_id":"dq-test","namespace":"native","worker_instance_id":"worker-one","processor_id":"atheros.dedup","processor_version":"0.1.0","implementation_digest":format!("sha256:{}","a".repeat(64)),"address":"worker:9090","concurrency":2,"ready":true});
    store.heartbeat(&heartbeat).await.unwrap();
    let reservation = json!({"installation_id":"dq-test","namespace":"native","worker_instance_id":"worker-one","worker_slot":0});
    let reserved = store.reserve(run_id, &reservation).await.unwrap();
    assert_eq!(
        store.reserve(run_id, &reservation).await.unwrap()["attempt"],
        reserved["attempt"]
    );
    let a = &reserved["attempt"];
    assert!(store.get_run(&p, run_id).await.unwrap()["current_attempt"]
        .get("lease_token")
        .is_none());
    assert!(store
        .get_run(&DqPrincipal::internal(), run_id)
        .await
        .unwrap()["current_attempt"]
        .get("lease_token")
        .is_some());
    let lease = json!({"installation_id":"dq-test","namespace":"native","run_id":run_id,"worker_instance_id":"worker-one","lease_token":a["lease_token"],"fence":a["fence"]});
    store
        .accepted(a["attempt_id"].as_str().unwrap(), &lease)
        .await
        .unwrap();
    let mut stale = lease.clone();
    stale["fence"] = json!(0);
    code(
        store.renew(a["attempt_id"].as_str().unwrap(), &stale).await,
        "stale_lease",
    );
    let e = envelope(
        run_id,
        a,
        "output_ready",
        json!([reference(run_id, a["attempt_id"].as_str())]),
    );
    let r = receipt(&e, 1, &"d".repeat(64));
    assert_eq!(store.receive_receipt(&r).await.unwrap()["applied"], true);
    assert_eq!(store.receive_receipt(&r).await.unwrap()["duplicate"], true);
    let mut conflicting = r.clone();
    conflicting["offset"] = json!(2);
    conflicting["payload_sha256"] = json!("e".repeat(64));
    assert_eq!(
        store.receive_receipt(&conflicting).await.unwrap()["quarantined"],
        true
    );
    assert_eq!(
        store.claim_output("applier", 60, 1).await.unwrap()[0]["run_id"],
        run_id
    );
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    assert!(!store
        .guard_output_tx(
            &mut tx,
            run_id,
            a["attempt_id"].as_str().unwrap(),
            a["fence"].as_i64().unwrap(),
            "stale",
            "b".repeat(64).as_str()
        )
        .await
        .unwrap());
    tx.commit().await.unwrap();
    let items = store.claim_outbox("publisher", 60, 100).await.unwrap();
    assert!(!items.is_empty());
    let mut wrong = items[0].clone();
    wrong.fence += 1;
    assert!(!store.acknowledge_outbox(&wrong).await.unwrap());
    assert!(store.acknowledge_outbox(&items[0]).await.unwrap());
    assert!(!store.acknowledge_outbox(&items[0]).await.unwrap());
    let mut disabled = settings();
    disabled.scope_modes.clear();
    DqStore::new(fixture.runtime.clone(), disabled)
        .reconcile_policies()
        .await
        .unwrap();
    assert_eq!(
        store.get_run(&p, run_id).await.unwrap()["status"],
        "cancelled"
    );
    code(
        store.renew(a["attempt_id"].as_str().unwrap(), &lease).await,
        "policy_changed",
    );
    fixture.runtime.close();
}

#[tokio::test]
async fn artifact_admission_requires_an_unclaimed_run_owned_version() {
    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let store = DqStore::new(fixture.runtime.clone(), settings());
    store.reconcile_policies().await.unwrap();
    let principal = actor();
    store.register(&principal, &manifest()).await.unwrap();
    let first = store
        .admit(&principal, &request("artifact-owner"))
        .await
        .unwrap();
    let second = store
        .admit(&principal, &request("other-owner"))
        .await
        .unwrap();
    let owner = first["run_id"].as_str().unwrap();
    let other = second["run_id"].as_str().unwrap();
    assert_eq!(
        store.claim_preparation("prep", 60, 2).await.unwrap().len(),
        2
    );

    let owned = reference(owner, None);
    let artifact = owned["artifact_id"].as_str().unwrap();
    let mut alternate = owned.clone();
    alternate["artifact_id"] = json!("alternate");
    let mut reused_id = reference(other, None);
    reused_id["artifact_id"] = json!(artifact);
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    tx.execute(
        "INSERT INTO dq_artifacts (artifact_id,run_id,reference,installation_id,namespace,retained_until)
         VALUES ($1,$2,$3,'dq-test','native','-infinity')",
        &[&artifact, &owner, &owned],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let revision = "b".repeat(64);
    for (run, reference, expected) in [
        (owner, &owned, "artifact_identity_conflict"),
        (owner, &alternate, "artifact_identity_conflict"),
        (other, &owned, "forbidden_artifact_reference"),
        (other, &reused_id, "artifact_identity_conflict"),
    ] {
        code(
            store
                .complete_preparation(run, "prep", &json!([reference]), &revision)
                .await,
            expected,
        );
        assert_eq!(
            store.get_run(&principal, run).await.unwrap()["input_refs"],
            json!([])
        );
    }
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    tx.execute(
        "UPDATE dq_artifacts SET retained_until=NULL WHERE artifact_id=$1",
        &[&artifact],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(store
        .complete_preparation(owner, "prep", &json!([owned]), &revision)
        .await
        .unwrap());

    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    tx.execute(
        "UPDATE dq_runs SET status='applying', work_owner='applier',
            work_expires_at=CURRENT_TIMESTAMP + INTERVAL '1 minute' WHERE run_id=$1",
        &[&owner],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    store
        .fail_work(owner, "applier", "source_revision_changed", false, true)
        .await
        .unwrap();
    assert_eq!(
        store.get_run(&principal, owner).await.unwrap()["input_refs"],
        json!([])
    );
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    tx.execute(
        "UPDATE dq_runs SET next_attempt_at=CURRENT_TIMESTAMP WHERE run_id=$1",
        &[&owner],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        store.claim_preparation("retry", 60, 1).await.unwrap()[0]["run_id"],
        owner
    );

    let mut mismatched = alternate.clone();
    mismatched["etag"] = json!("different");
    code(
        store
            .complete_preparation(owner, "retry", &json!([mismatched]), &revision)
            .await,
        "artifact_identity_conflict",
    );
    let expected_refs = json!([alternate]);
    assert!(store
        .complete_preparation(owner, "retry", &expected_refs, &revision)
        .await
        .unwrap());
    assert_eq!(
        store.get_run(&principal, owner).await.unwrap()["input_refs"],
        expected_refs
    );
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let artifacts = tx
        .query(
            "SELECT reference FROM dq_artifacts WHERE run_id=$1",
            &[&owner],
        )
        .await
        .unwrap();
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0].get::<_, Value>(0), expected_refs[0]);
    let invokes = tx
        .query(
            "SELECT payload->'artifacts' FROM dq_outbox WHERE topic='dq.commands.v1'
               AND payload->>'run_id'=$1 AND payload->>'event_type'='invoke' ORDER BY created_at",
            &[&owner],
        )
        .await
        .unwrap();
    assert_eq!(invokes.len(), 2);
    assert_eq!(invokes[1].get::<_, Value>(0), expected_refs);
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn interrupted_retention_hides_and_retries_the_deleted_version() {
    use axum::{http::StatusCode, routing::delete, Router};
    use octopus::{config::ArchiveConfig, dq_runtime::DqArtifacts};
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let store = DqStore::new(fixture.runtime.clone(), settings());
    store.reconcile_policies().await.unwrap();
    let principal = actor();
    store.register(&principal, &manifest()).await.unwrap();
    let run = store
        .admit(&principal, &request("retention"))
        .await
        .unwrap();
    let run_id = run["run_id"].as_str().unwrap();
    let mut first = reference(run_id, None);
    let mut second = reference(run_id, None);
    let mut invalid = reference("different-run", None);
    let mut shared = reference(run_id, None);
    let invalid_id = "artifact-0-invalid";
    let shared_id = "artifact-0-shared";
    invalid["artifact_id"] = json!(invalid_id);
    shared["artifact_id"] = json!(shared_id);
    shared["version_id"] = json!("version-shared");
    let legacy = store
        .admit(&principal, &request("legacy-shared-artifact"))
        .await
        .unwrap();
    let legacy_run = legacy["run_id"].as_str().unwrap();
    let artifact = "artifact-first";
    let other = "artifact-second";
    first["artifact_id"] = json!(artifact);
    second["artifact_id"] = json!(other);
    second["version_id"] = json!("version-2");
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    tx.execute(
        "UPDATE dq_runs SET status='succeeded', completed_at=CURRENT_TIMESTAMP - INTERVAL '91 days',
             input_refs=$2 WHERE run_id=$1",
        &[&run_id, &json!([first, second, invalid, shared])],
    )
    .await
    .unwrap();
    tx.execute(
        "INSERT INTO dq_artifacts
           (artifact_id,run_id,reference,installation_id,namespace,closed_at,retained_until)
         SELECT artifact.id, run_id, artifact.ref, installation_id, namespace,
                completed_at, completed_at + INTERVAL '90 days'
         FROM dq_runs CROSS JOIN (VALUES ($1::text,$3::jsonb), ($4,$5), ($6,$7), ($8,$9)) artifact(id, ref)
         WHERE run_id=$2",
        &[
            &artifact,
            &run_id,
            &first,
            &other,
            &second,
            &invalid_id,
            &invalid,
            &shared_id,
            &shared,
        ],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE dq_runs SET input_refs=$2 WHERE run_id=$1",
        &[&legacy_run, &json!([shared])],
    )
    .await
    .unwrap();
    let shard = octopus::util::sha256_hex(json!(["dq-test", "native"]).to_string());
    tx.execute(
        "INSERT INTO processor_checkpoints (processor_name, shard_id, checkpoint_value)
         VALUES ('dq-artifact-retention', $1,
                 jsonb_build_array((CURRENT_TIMESTAMP + INTERVAL '2 days')::text, 'prior')::text)",
        &[&shard],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        store.artifact(&principal, artifact, false).await.unwrap(),
        first
    );

    let deleted = Arc::new(tokio::sync::Notify::new());
    let on_delete = deleted.clone();
    let app = Router::new().fallback_service(delete(move |uri: axum::http::Uri| {
        let deleted = on_delete.clone();
        async move {
            assert_eq!(uri.query(), Some("versionId=version-1"));
            deleted.notify_one();
            std::future::pending::<StatusCode>().await
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let config = DqConfig {
        artifact_bucket: "dq-artifacts".into(),
        ..config()
    };
    let storage = |addr| ArchiveConfig {
        endpoint: format!("http://{addr}"),
        access_key: "test-key".into(),
        secret_key: "test-secret".into(),
        ..ArchiveConfig::default()
    };
    let artifacts = DqArtifacts::new(config.clone(), &storage(addr)).unwrap();
    let worker = {
        let store = store.clone();
        let config = config.clone();
        tokio::spawn(async move { store.collect_retention(&artifacts, &config).await })
    };
    tokio::time::timeout(Duration::from_secs(10), deleted.notified())
        .await
        .unwrap();
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    server.abort();

    code(
        store.artifact(&principal, artifact, true).await,
        "artifact_not_found",
    );
    assert_eq!(
        store.get_run(&principal, run_id).await.unwrap()["input_refs"],
        json!([second, shared])
    );
    assert_eq!(
        store.artifact(&principal, other, false).await.unwrap(),
        second
    );
    assert_eq!(
        store.artifact(&principal, shared_id, false).await.unwrap(),
        shared
    );
    assert_eq!(
        store.get_run(&principal, legacy_run).await.unwrap()["input_refs"],
        json!([shared])
    );
    // A later reopening can still retain the unclaimed artifact.
    let later = store
        .admit(&principal, &request("retention-after-failure"))
        .await
        .unwrap();
    let later_run = later["run_id"].as_str().unwrap();
    let mut later = reference(later_run, None);
    later["version_id"] = json!("version-3");
    let later_id = later["artifact_id"].as_str().unwrap();
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    tx.execute(
        "UPDATE dq_runs SET projection_applied=true WHERE run_id=$1",
        &[&run_id],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE dq_runs SET status='succeeded', completed_at=CURRENT_TIMESTAMP - INTERVAL '90 days 1 hour',
             input_refs=$2 WHERE run_id=$1",
        &[&later_run, &json!([later])],
    )
    .await
    .unwrap();
    tx.execute(
        "INSERT INTO dq_artifacts (artifact_id,run_id,reference,installation_id,namespace)
         VALUES ($1,$2,$3,'dq-test','native')",
        &[&later_id, &later_run, &later],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE dq_outbox SET status='published', published_at=CURRENT_TIMESTAMP WHERE payload->>'run_id'=$1",
        &[&later_run],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let deleted = Arc::new(AtomicUsize::new(0));
    let calls = deleted.clone();
    let app = Router::new().fallback_service(delete(move |uri: axum::http::Uri| {
        let calls = calls.clone();
        async move {
            if uri.query() == Some("versionId=version-3") {
                return (StatusCode::NO_CONTENT, "");
            }
            assert_eq!(uri.query(), Some("versionId=version-1"));
            let body = match calls.fetch_add(1, Ordering::Relaxed) {
                0 => "",
                1 => "<Error><Code>NoSuchBucket</Code></Error>",
                2 => "<?xml version=\"1.0\"?><Error><Code>NoSuchVersion</Code><VersionId>version-1</VersionId></Error>",
                _ => panic!("unexpected deletion retry"),
            };
            (StatusCode::NOT_FOUND, body)
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let artifacts =
        DqArtifacts::new(config.clone(), &storage(listener.local_addr().unwrap())).unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let retry_id = octopus::util::sha256_hex(artifact);
    for calls in 1..=2 {
        code(
            store.collect_retention(&artifacts, &config).await,
            "retention_dependency_failure",
        );
        assert_eq!(deleted.load(Ordering::Relaxed), calls);
        let mut tx = fixture.runtime.begin_worker().await.unwrap();
        let row = &tx
            .query(
                "SELECT a.retained_until = '-infinity'::timestamptz,
                        retry.next_attempt_at > CURRENT_TIMESTAMP,
                        NOT EXISTS (SELECT 1 FROM dq_runs WHERE run_id = $3)
                 FROM dq_artifacts a CROSS JOIN work_leases retry
                 WHERE a.artifact_id = $1 AND retry.resource_type = 'dq-artifact-retention'
                   AND retry.resource_id = $2",
                &[&artifact, &retry_id, &later_run],
            )
            .await
            .unwrap()[0];
        assert!(row.get::<_, bool>(0), "failed claims stay durable");
        assert!(row.get::<_, bool>(1), "failed claims are deferred");
        assert!(
            row.get::<_, bool>(2),
            "later artifacts and metadata are collected"
        );
        tx.commit().await.unwrap();
        store.collect_retention(&artifacts, &config).await.unwrap();
        assert_eq!(deleted.load(Ordering::Relaxed), calls);
        let mut tx = fixture.runtime.begin_worker().await.unwrap();
        tx.execute(
            "UPDATE work_leases SET next_attempt_at = CURRENT_TIMESTAMP
             WHERE resource_type = 'dq-artifact-retention' AND resource_id = $1",
            &[&retry_id],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    store.collect_retention(&artifacts, &config).await.unwrap();
    server.abort();
    assert_eq!(deleted.load(Ordering::Relaxed), 3);
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    assert!(tx
        .query(
            "SELECT 1 FROM dq_artifacts WHERE artifact_id=$1",
            &[&artifact]
        )
        .await
        .unwrap()
        .is_empty());
    assert!(tx
        .query(
            "SELECT 1 FROM dq_artifacts WHERE artifact_id=$1",
            &[&invalid_id],
        )
        .await
        .unwrap()
        .is_empty());
    tx.commit().await.unwrap();
    assert_eq!(
        store.artifact(&principal, other, false).await.unwrap(),
        second
    );
}

#[tokio::test]
async fn retention_collects_valid_artifact_behind_a_full_page_of_invalid_claims() {
    use axum::{http::StatusCode, routing::delete, Router};
    use octopus::{config::ArchiveConfig, dq_runtime::DqArtifacts};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let store = DqStore::new(fixture.runtime.clone(), settings());
    store.reconcile_policies().await.unwrap();
    let principal = actor();
    store.register(&principal, &manifest()).await.unwrap();
    let run = store
        .admit(&principal, &request("retention-page"))
        .await
        .unwrap();
    let run_id = run["run_id"].as_str().unwrap();
    let valid = reference(run_id, None);
    let artifact = valid["artifact_id"].as_str().unwrap();
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    tx.execute(
        "UPDATE dq_runs SET status='succeeded', completed_at=CURRENT_TIMESTAMP - INTERVAL '91 days',
             input_refs=$2 WHERE run_id=$1",
        &[&run_id, &json!([valid])],
    )
    .await
    .unwrap();
    tx.execute(
        "INSERT INTO dq_artifacts
           (artifact_id,run_id,reference,installation_id,namespace,closed_at,retained_until)
         SELECT 'invalid-' || n,run_id,
                jsonb_build_object('uri','s3://dq-artifacts/dq-test/native/inputs/foreign/object-' || n,
                                   'version_id','version-1'),
                installation_id,namespace,completed_at,'-infinity'::timestamptz
         FROM dq_runs CROSS JOIN generate_series(1,100) n WHERE run_id=$1",
        &[&run_id],
    )
    .await
    .unwrap();
    tx.execute(
        "INSERT INTO dq_artifacts
           (artifact_id,run_id,reference,installation_id,namespace,closed_at,retained_until)
         SELECT $2,run_id,$3,installation_id,namespace,completed_at,completed_at + INTERVAL '90 days'
         FROM dq_runs WHERE run_id=$1",
        &[&run_id, &artifact, &valid],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let deleted = Arc::new(AtomicUsize::new(0));
    let calls = deleted.clone();
    let path = valid["uri"]
        .as_str()
        .unwrap()
        .strip_prefix("s3:/")
        .unwrap()
        .to_owned();
    let app = Router::new().fallback_service(delete(move |uri: axum::http::Uri| async move {
        assert_eq!(uri.path(), path);
        assert_eq!(uri.query(), Some("versionId=version-1"));
        calls.fetch_add(1, Ordering::Relaxed);
        StatusCode::NO_CONTENT
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let archive = ArchiveConfig {
        endpoint: format!("http://{}", listener.local_addr().unwrap()),
        access_key: "test-key".into(),
        secret_key: "test-secret".into(),
        ..ArchiveConfig::default()
    };
    let config = DqConfig {
        artifact_bucket: "dq-artifacts".into(),
        ..config()
    };
    let artifacts = DqArtifacts::new(config.clone(), &archive).unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    store.collect_retention(&artifacts, &config).await.unwrap();
    server.abort();
    assert_eq!(deleted.load(Ordering::Relaxed), 1);

    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let rows = tx
        .query(
            "SELECT count(*) AS total,
                    count(*) FILTER (WHERE retained_until='-infinity'::timestamptz) AS claimed
             FROM dq_artifacts WHERE run_id=$1",
            &[&run_id],
        )
        .await
        .unwrap();
    assert_eq!(rows[0].get::<_, i64>("total"), 100);
    assert_eq!(rows[0].get::<_, i64>("claimed"), 100);
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn retention_keeps_terminal_runs_that_share_open_review_evidence() {
    use octopus::{config::ArchiveConfig, dq_runtime::DqArtifacts};

    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let store = DqStore::new(fixture.runtime.clone(), settings());
    store.reconcile_policies().await.unwrap();
    let principal = actor();
    store.register(&principal, &manifest()).await.unwrap();
    let owner = store
        .admit(&principal, &request("shared-owner"))
        .await
        .unwrap();
    let holder = store
        .admit(&principal, &request("shared-review"))
        .await
        .unwrap();
    let owner = owner["run_id"].as_str().unwrap();
    let holder = holder["run_id"].as_str().unwrap();
    let input = reference(owner, None);
    let artifact = input["artifact_id"].as_str().unwrap();
    let mut alias = input.clone();
    alias["artifact_id"] = json!("legacy-shared-id");
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    tx.execute(
        "INSERT INTO merge_candidates (candidate_id, mac_a, mac_b, projection_run_id, status)
         VALUES ('shared-review', '00:11:22:33:44:55', '00:11:22:33:44:66', 'test', 'pending')",
        &[],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE dq_runs SET status='succeeded', completed_at=CURRENT_TIMESTAMP - INTERVAL '92 days'
         WHERE run_id IN ($1,$2)",
        &[&owner, &holder],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE dq_runs SET projection_applied=true,
            summary='{\"review_candidate_ids\":[\"shared-review\"]}', input_refs=$2 WHERE run_id=$1",
        &[&holder, &json!([alias])],
    )
    .await
    .unwrap();
    tx.execute(
        "INSERT INTO dq_artifacts
           (artifact_id,run_id,reference,installation_id,namespace,closed_at,retained_until)
         SELECT $2,run_id,$3,installation_id,namespace,completed_at,completed_at + INTERVAL '90 days'
         FROM dq_runs WHERE run_id=$1",
        &[&owner, &artifact, &input],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE dq_outbox SET status='published', published_at=CURRENT_TIMESTAMP WHERE payload->>'run_id'=$1",
        &[&holder],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let config = config();
    let archive = ArchiveConfig {
        endpoint: "http://127.0.0.1:0".into(),
        access_key: "test-key".into(),
        secret_key: "test-secret".into(),
        ..ArchiveConfig::default()
    };
    let artifacts = DqArtifacts::new(config.clone(), &archive).unwrap();
    assert_eq!(store.retention_batch(&artifacts, &config).await.unwrap(), 0);
    assert!(store.get_run(&principal, holder).await.is_ok());

    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    tx.execute(
        "UPDATE merge_candidates SET status='confirmed', updated_at=CURRENT_TIMESTAMP - INTERVAL '91 days'
         WHERE candidate_id='shared-review'",
        &[],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(store.retention_batch(&artifacts, &config).await.unwrap(), 1);
    code(store.get_run(&principal, holder).await, "run_not_found");
}

#[tokio::test]
async fn retention_rechecks_eligibility_after_a_concurrent_review_reopens() {
    use octopus::{config::ArchiveConfig, dq_runtime::DqArtifacts};
    use std::time::Duration;

    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let store = DqStore::new(fixture.runtime.clone(), settings());
    store.reconcile_policies().await.unwrap();
    let principal = actor();
    store.register(&principal, &manifest()).await.unwrap();
    let run = store
        .admit(&principal, &request("retention-concurrent-review"))
        .await
        .unwrap();
    let run_id = run["run_id"].as_str().unwrap();
    let input = reference(run_id, None);
    let artifact = input["artifact_id"].as_str().unwrap();
    let other = store
        .admit(&principal, &request("retention-unlocked"))
        .await
        .unwrap();
    let other = other["run_id"].as_str().unwrap();
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    tx.execute(
        "INSERT INTO merge_candidates (candidate_id, mac_a, mac_b, projection_run_id, status, updated_at)
         VALUES ('retention-review', '00:11:22:33:44:55', '00:11:22:33:44:66', 'test',
                 'confirmed', CURRENT_TIMESTAMP - INTERVAL '92 days')",
        &[],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE dq_runs SET status='succeeded', completed_at=CURRENT_TIMESTAMP - INTERVAL '91 days',
          projection_applied=true, summary='{\"review_candidate_ids\":[\"retention-review\"]}', input_refs=$2
         WHERE run_id=$1",
        &[&run_id, &json!([input])],
    )
    .await
    .unwrap();
    tx.execute(
        "INSERT INTO dq_artifacts
           (artifact_id, run_id, reference, installation_id, namespace, closed_at, retained_until)
         SELECT $2, run_id, $3, installation_id, namespace, completed_at, completed_at + INTERVAL '90 days'
         FROM dq_runs WHERE run_id=$1",
        &[&run_id, &artifact, &input],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE dq_runs SET status='succeeded', completed_at=CURRENT_TIMESTAMP - INTERVAL '91 days'
         WHERE run_id=$1",
        &[&other],
    )
    .await
    .unwrap();
    tx.execute(
        "INSERT INTO dq_artifacts
           (artifact_id,run_id,reference,installation_id,namespace,closed_at,retained_until)
         SELECT 'retention-unlocked',run_id,'{\"uri\":\"invalid\",\"version_id\":\"v1\"}',
                installation_id,namespace,completed_at,completed_at + INTERVAL '90 days'
         FROM dq_runs WHERE run_id=$1",
        &[&other],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let mut review = fixture.runtime.begin_worker().await.unwrap();
    let pid: i32 = review.query("SELECT pg_backend_pid()", &[]).await.unwrap()[0].get(0);
    review
        .execute(
            "UPDATE merge_candidates SET status='pending', updated_at=CURRENT_TIMESTAMP
             WHERE candidate_id='retention-review'",
            &[],
        )
        .await
        .unwrap();
    let config = DqConfig {
        artifact_bucket: "dq-artifacts".into(),
        ..config()
    };
    let archive = ArchiveConfig {
        endpoint: "http://127.0.0.1:0".into(),
        access_key: "test-key".into(),
        secret_key: "test-secret".into(),
        ..ArchiveConfig::default()
    };
    let artifacts = DqArtifacts::new(config.clone(), &archive).unwrap();
    // Keep the review lock held through a full page. The unrelated artifact
    // must still be processed, and the locked artifact remains unclaimed.
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(5),
            store.retention_batch(&artifacts, &config)
        )
        .await
        .expect("the review lock wait must be bounded")
        .unwrap(),
        1,
    );
    assert_eq!(
        store.artifact(&principal, artifact, false).await.unwrap(),
        input,
    );
    let collect = {
        let store = store.clone();
        tokio::spawn(async move { store.collect_retention(&artifacts, &config).await })
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut observer = fixture.runtime.begin_worker().await.unwrap();
            let blocked: bool = observer
                .query(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY (pg_blocking_pids(pid)))",
                    &[&pid],
                )
                .await
                .unwrap()[0]
                .get(0);
            observer.commit().await.unwrap();
            if blocked {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("collector must wait for the review before claiming the artifact");
    review.commit().await.unwrap();
    collect.await.unwrap().unwrap();
    assert_eq!(
        store.artifact(&principal, artifact, false).await.unwrap(),
        input,
    );
    assert_eq!(
        store.get_run(&principal, run_id).await.unwrap()["input_refs"],
        json!([input]),
    );
}
