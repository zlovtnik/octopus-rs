mod support;

use octopus::projections::{identity, intelligence::stable_id, ProjectionStore};

#[tokio::test]
async fn reversed_candidate_refresh_preserves_human_merge_below_automatic_threshold() {
    reversed_candidate_refresh(None).await;
}

#[tokio::test]
async fn legacy_reversed_candidate_refresh_preserves_its_id_and_human_decision() {
    reversed_candidate_refresh(Some("00000000-0000-4000-8000-000000000001")).await;
}

async fn reversed_candidate_refresh(legacy_id: Option<&str>) {
    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let left = "aa:bb:cc:dd:ee:02";
    let right = "aa:bb:cc:dd:ee:04";
    let id = legacy_id
        .map(str::to_owned)
        .unwrap_or_else(|| stable_id("merge-candidate", &[left, right]));
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
        identity::apply_identity_candidates(&mut tx, &[(left.into(), right.into(), 0.75)], &[])
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

    fixture.admin(&format!(
        "INSERT INTO atheros_search.search_documents(
             document_id,source_kind,source_id,source_key,source_table,normalized_text,normalized_sha256)
         SELECT gen_random_uuid(),'device',mac,mac,'inventory_devices','text',repeat('a',64)
         FROM (VALUES ('{left}'),('{right}')) device(mac);
         INSERT INTO atheros_search.similarity_pairs(
             pair_id,pair_kind,embedding_model,embedding_kind,left_document_id,right_document_id,
             left_source_table,left_source_key,left_source_mac,right_source_table,right_source_key,
             right_source_mac,cosine_distance,cosine_similarity,evidence,computed_at,projection_run_id)
         SELECT gen_random_uuid(),'device_device',model,'device',a.document_id,b.document_id,
                a.source_table,a.source_key,a.source_key,b.source_table,b.source_key,b.source_key,
                1-similarity,similarity,'{{}}',computed_at,gen_random_uuid()
         FROM atheros_search.search_documents a CROSS JOIN atheros_search.search_documents b
         CROSS JOIN (VALUES ('lower',0.7,TIMESTAMPTZ '2020-01-01'),
                            ('higher',0.9,TIMESTAMPTZ '2020-01-02')) scores(model,similarity,computed_at)
         WHERE a.source_key='{left}' AND b.source_key='{right}';"
    ));
    let store = ProjectionStore::new(fixture.runtime.clone());
    // The limit would be consumed by the older, weaker pair without symmetric exclusion.
    assert_eq!(store.project_cluster_candidates(1, 0.5).await.unwrap(), 1);
    assert_eq!(store.project_cluster_candidates(1, 0.5).await.unwrap(), 0);
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let rows = tx
        .query(
            "SELECT candidate_id,confidence,status,confirmation_source FROM atheros_search.merge_candidates
             WHERE (mac_a=$1 AND mac_b=$2) OR (mac_a=$2 AND mac_b=$1)",
            &[&left, &right],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, String>(0), id);
    assert_eq!(rows[0].get::<_, f64>(1), 0.9);
    assert_eq!(rows[0].get::<_, String>(2), "confirmed");
    assert_eq!(rows[0].get::<_, String>(3), "human");
    tx.commit().await.unwrap();
}
