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

#[tokio::test]
async fn stronger_evidence_refreshes_reviewed_candidate_when_reverse_exists() {
    let Some(fixture) = support::Fixture::start_required().await else {
        return;
    };
    fixture.admin(
        "INSERT INTO atheros_search.merge_candidates(
             candidate_id,mac_a,mac_b,confidence,status,projection_run_id,
             confirmation_source,confirmed_at)
         VALUES('reviewed','aa:bb:cc:dd:ee:02','aa:bb:cc:dd:ee:04',0.60,'confirmed','legacy','human',CURRENT_TIMESTAMP),
               ('reverse','aa:bb:cc:dd:ee:04','aa:bb:cc:dd:ee:02',0.70,'pending','legacy',NULL,NULL);
         INSERT INTO atheros_search.merge_decisions(candidate_id,decision) VALUES('reviewed','merge');
         INSERT INTO atheros_search.search_documents(
             document_id,source_kind,source_id,source_key,source_table,normalized_text,normalized_sha256)
         SELECT gen_random_uuid(),'device',mac,mac,'inventory_devices','text',repeat('a',64)
         FROM (VALUES ('aa:bb:cc:dd:ee:02'),('aa:bb:cc:dd:ee:04')) device(mac);
         INSERT INTO atheros_search.similarity_pairs(
             pair_id,pair_kind,embedding_model,embedding_kind,left_document_id,right_document_id,
             left_source_table,left_source_key,left_source_mac,right_source_table,right_source_key,
             right_source_mac,cosine_distance,cosine_similarity,evidence,computed_at,projection_run_id)
         SELECT gen_random_uuid(),'device_device','test','device',a.document_id,b.document_id,
                a.source_table,a.source_key,a.source_key,b.source_table,b.source_key,b.source_key,
                0.01,0.99,'{}',CURRENT_TIMESTAMP,gen_random_uuid()
         FROM atheros_search.search_documents a CROSS JOIN atheros_search.search_documents b
         WHERE a.source_key='aa:bb:cc:dd:ee:04' AND b.source_key='aa:bb:cc:dd:ee:02';",
    );

    let store = ProjectionStore::new(fixture.runtime.clone());
    assert_eq!(store.project_cluster_candidates(1, 0.5).await.unwrap(), 1);
    assert_eq!(store.project_cluster_candidates(1, 0.5).await.unwrap(), 0);
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let rows = tx
        .query(
            "SELECT candidate_id,confidence,status,confirmation_source
             FROM atheros_search.merge_candidates ORDER BY candidate_id",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<_, String>(0), "reverse");
    assert_eq!(rows[0].get::<_, f64>(1), 0.70);
    assert_eq!(rows[0].get::<_, String>(2), "pending");
    assert_eq!(rows[1].get::<_, String>(0), "reviewed");
    assert_eq!(rows[1].get::<_, f64>(1), 0.99);
    assert_eq!(rows[1].get::<_, String>(2), "confirmed");
    assert_eq!(rows[1].get::<_, String>(3), "human");
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn fresh_similarity_reopens_an_expired_reverse_candidate_without_reusing_its_score() {
    let Some(fixture) = support::Fixture::start_required().await else {
        return;
    };
    fixture.admin(
        "INSERT INTO atheros_search.devices(mac,registered,registered_device_id,first_seen,last_seen)
         SELECT mac,true,'e20c112d-aba4-4c87-90c2-cb8f57aaead3',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
         FROM (VALUES ('aa:bb:cc:dd:ee:02'),('aa:bb:cc:dd:ee:04')) device(mac);
         INSERT INTO atheros_search.merge_candidates(
             candidate_id,mac_a,mac_b,confidence,projection_run_id,computed_at,expires_at)
         VALUES('expired','aa:bb:cc:dd:ee:04','aa:bb:cc:dd:ee:02',0.999,'legacy',
                CURRENT_TIMESTAMP-INTERVAL '31 days',CURRENT_TIMESTAMP-INTERVAL '1 day');
         INSERT INTO atheros_search.search_documents(
             document_id,source_kind,source_id,source_key,source_table,normalized_text,normalized_sha256)
         SELECT gen_random_uuid(),'device',mac,mac,'inventory_devices','text',repeat('a',64)
         FROM (VALUES ('aa:bb:cc:dd:ee:02'),('aa:bb:cc:dd:ee:04')) device(mac);
         INSERT INTO atheros_search.similarity_pairs(
             pair_id,pair_kind,embedding_model,embedding_kind,left_document_id,right_document_id,
             left_source_table,left_source_key,left_source_mac,right_source_table,right_source_key,
             right_source_mac,cosine_distance,cosine_similarity,evidence,computed_at,projection_run_id)
         SELECT gen_random_uuid(),'device_device','test','device',a.document_id,b.document_id,
                a.source_table,a.source_key,a.source_key,b.source_table,b.source_key,b.source_key,
                0.2,0.8,'{}',CURRENT_TIMESTAMP-INTERVAL '2 days',gen_random_uuid()
         FROM atheros_search.search_documents a CROSS JOIN atheros_search.search_documents b
         WHERE a.source_key='aa:bb:cc:dd:ee:02' AND b.source_key='aa:bb:cc:dd:ee:04';",
    );

    let store = ProjectionStore::new(fixture.runtime.clone());
    assert_eq!(store.project_cluster_candidates(1, 0.5).await.unwrap(), 1);
    assert_eq!(store.project_cluster_candidates(1, 0.5).await.unwrap(), 0);
    assert_eq!(store.project_approved_identities(1).await.unwrap(), 0);
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let rows = tx
        .query(
            "SELECT candidate_id,status,expires_at>CURRENT_TIMESTAMP,confidence
             FROM atheros_search.merge_candidates",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, String>(0), "expired");
    assert_eq!(rows[0].get::<_, String>(1), "pending");
    assert!(rows[0].get::<_, bool>(2));
    assert_eq!(rows[0].get::<_, f64>(3), 0.999);
    tx.commit().await.unwrap();

    fixture.admin(
        "UPDATE atheros_search.similarity_pairs
         SET cosine_similarity=0.99,cosine_distance=0.01,computed_at=computed_at+INTERVAL '1 day'",
    );
    assert_eq!(store.project_cluster_candidates(1, 0.5).await.unwrap(), 1);
    assert_eq!(store.project_cluster_candidates(1, 0.5).await.unwrap(), 0);
    assert!(store.project_approved_identities(1).await.unwrap() > 0);
}

#[tokio::test]
async fn similarity_paging_uses_latest_evidence_across_pair_orientations() {
    let Some(fixture) = support::Fixture::start_required().await else {
        return;
    };
    fixture.admin(
        "INSERT INTO atheros_search.search_documents(
             document_id,source_kind,source_id,source_key,source_table,normalized_text,normalized_sha256)
         SELECT gen_random_uuid(),'device',mac,mac,'inventory_devices','text',repeat('a',64)
         FROM (VALUES ('aa:bb:cc:dd:ee:02'),('aa:bb:cc:dd:ee:04'),('aa:bb:cc:dd:ee:06')) device(mac);
         INSERT INTO atheros_search.similarity_pairs(
             pair_id,pair_kind,embedding_model,embedding_kind,left_document_id,right_document_id,
             left_source_table,left_source_key,left_source_mac,right_source_table,right_source_key,
             right_source_mac,cosine_distance,cosine_similarity,evidence,computed_at,projection_run_id)
         SELECT gen_random_uuid(),'device_device',model,'device',a.document_id,b.document_id,
                a.source_table,a.source_key,a.source_key,b.source_table,b.source_key,b.source_key,
                1-similarity,similarity,'{}',CURRENT_TIMESTAMP-age,gen_random_uuid()
         FROM (VALUES ('older-low','02','04',0.80,INTERVAL '4 days'),
                      ('newer-high','04','02',0.99,INTERVAL '3 days'),
                      ('older-high','02','06',0.99,INTERVAL '4 days'),
                      ('newer-low','06','02',0.80,INTERVAL '3 days')) scores(model,left_mac,right_mac,similarity,age)
         JOIN atheros_search.search_documents a ON a.source_key='aa:bb:cc:dd:ee:' || left_mac
         JOIN atheros_search.search_documents b ON b.source_key='aa:bb:cc:dd:ee:' || right_mac",
    );
    let store = ProjectionStore::new(fixture.runtime.clone());
    assert_eq!(store.project_cluster_candidates(2, 0.5).await.unwrap(), 2);
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let rows = tx
        .query(
            "SELECT mac_a, mac_b, confidence FROM atheros_search.merge_candidates ORDER BY mac_b",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows[0].get::<_, String>(0), "aa:bb:cc:dd:ee:02");
    assert_eq!(rows[0].get::<_, String>(1), "aa:bb:cc:dd:ee:04");
    assert_eq!(rows[0].get::<_, f64>(2), 0.99);
    assert_eq!(rows[1].get::<_, String>(1), "aa:bb:cc:dd:ee:06");
    assert_eq!(rows[1].get::<_, f64>(2), 0.80);
    tx.commit().await.unwrap();

    fixture.admin("DELETE FROM atheros_search.similarity_pairs WHERE embedding_model='newer-low'");
    assert_eq!(store.project_cluster_candidates(2, 0.5).await.unwrap(), 0);
}

async fn reversed_candidate_refresh(legacy_id: Option<&str>) {
    let Some(fixture) = support::Fixture::start_required().await else {
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
    assert_eq!(
        identity::persist_merge_candidate(&mut tx, right, left, 0.2)
            .await
            .unwrap(),
        id
    );
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
    let refreshed_id = identity::persist_merge_candidate(&mut tx, other, left, 0.6)
        .await
        .unwrap();
    assert_eq!(refreshed_id, pending_id);
    let pending = tx
        .query(
            "SELECT candidate_id,confidence,status FROM atheros_search.merge_candidates
             WHERE (mac_a=$1 AND mac_b=$2) OR (mac_a=$2 AND mac_b=$1)",
            &[&left, &other],
        )
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].get::<_, String>(0), pending_id);
    assert_eq!(pending[0].get::<_, f64>(1), 0.8);
    assert_eq!(pending[0].get::<_, String>(2), "pending");
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
