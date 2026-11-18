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
