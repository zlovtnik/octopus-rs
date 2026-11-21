mod support;

use octopus::projections::{identity, intelligence::stable_id};

#[tokio::test]
async fn reversed_candidate_refresh_preserves_human_merge_below_automatic_threshold() {
    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let left = "aa:bb:cc:dd:ee:02";
    let right = "aa:bb:cc:dd:ee:04";
    let id = stable_id("merge-candidate", &[left, right]);
    fixture.admin(&format!(
        "INSERT INTO atheros_search.devices(mac,first_seen,last_seen)
         VALUES('{left}',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),
               ('{right}',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);
         INSERT INTO atheros_search.merge_candidates(
             candidate_id,mac_a,mac_b,confidence,status,projection_run_id,
             confirmation_source,confirmed_at)
         VALUES('{id}','{right}','{left}',0.4,'confirmed','legacy','human',CURRENT_TIMESTAMP);
         INSERT INTO atheros_search.merge_decisions(candidate_id,decision)
         VALUES('{id}','merge');"
    ));

    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let ids =
        identity::apply_identity_candidates(&mut tx, &[(right.into(), left.into(), 0.75)], &[])
            .await
            .unwrap();
    assert_eq!(ids, vec![id.clone()]);
    let row = tx
        .query(
            "SELECT candidate.confidence,candidate.status,candidate.confirmation_source,
                    decision.decision
             FROM atheros_search.merge_candidates candidate
             JOIN atheros_search.merge_decisions decision USING(candidate_id)
             WHERE candidate.candidate_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    assert_eq!(row[0].get::<_, f64>(0), 0.75);
    assert_eq!(row[0].get::<_, String>(1), "confirmed");
    assert_eq!(row[0].get::<_, String>(2), "human");
    assert_eq!(row[0].get::<_, String>(3), "merge");
    let members = tx
        .query(
            "SELECT member.mac,member.confidence FROM atheros_search.identity_cluster_members member
             JOIN atheros_search.identity_clusters cluster USING(cluster_id)
             WHERE cluster.status='active' ORDER BY member.mac",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].get::<_, String>(0), left);
    assert_eq!(members[1].get::<_, String>(0), right);
    assert!(members.iter().all(|row| row.get::<_, f64>(1) == 0.75));

    let other = "aa:bb:cc:dd:ee:06";
    let pending_id = identity::persist_merge_candidate(&mut tx, left, other, 0.8)
        .await
        .unwrap();
    identity::persist_merge_candidate(&mut tx, other, left, 0.6)
        .await
        .unwrap();
    let pending = tx
        .query(
            "SELECT confidence,status FROM atheros_search.merge_candidates WHERE candidate_id=$1",
            &[&pending_id],
        )
        .await
        .unwrap();
    assert_eq!(pending[0].get::<_, f64>(0), 0.8);
    assert_eq!(pending[0].get::<_, String>(1), "pending");
    tx.commit().await.unwrap();
}
