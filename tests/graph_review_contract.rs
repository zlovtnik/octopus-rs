mod support;

use octopus::projections::{identity::persist_merge_candidate, ProjectionStore};
use std::time::Duration;
use support::Fixture;

async fn assert_query(fixture: &Fixture, sql: &str) {
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let rows = tx.query(sql, &[]).await.unwrap();
    assert_eq!(rows.len(), 1, "{sql}");
    assert_eq!(rows[0].get::<_, Option<bool>>(0), Some(true), "{sql}");
    tx.commit().await.unwrap();
}

async fn wait_for_blocked_backend(fixture: &Fixture, blocker: i32) -> i32 {
    let mut observer = fixture.runtime.begin_worker().await.unwrap();
    let pid = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let rows = observer
                .query(
                    "SELECT pid FROM pg_locks WHERE NOT granted
                       AND $1 = ANY(pg_blocking_pids(pid))",
                    &[&blocker],
                )
                .await
                .unwrap();
            if let Some(row) = rows.first() {
                return row.get(0);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("projection did not reach the expected lock");
    observer.commit().await.unwrap();
    pid
}

#[tokio::test]
async fn graph_limit_tracks_fresh_evidence_and_repairs_older_changes() {
    let Some(fixture) = Fixture::start().await else {
        return;
    };
    let store = ProjectionStore::new(fixture.runtime.clone());
    fixture.admin(
        "INSERT INTO octopus_core.devices(mac_id, mac_hint, display_name, last_seen) VALUES
           ('02:00:00:00:00:01', '02:00:00:00:00:01', 'newer', '2026-09-20 13:10:00+00'),
           ('02:00:00:00:00:02', '02:00:00:00:00:02', 'older', '2026-09-20 13:00:00+00');
         INSERT INTO octopus_core.wireless_frames(dedupe_key, source_mac, bssid, ssid, observed_at) VALUES
           ('newer', '02:00:00:00:00:01', '12:00:00:00:00:01', 'new-network', '2026-09-20 13:10:00+00'),
           ('older', '02:00:00:00:00:02', '12:00:00:00:00:02', 'old-network', '2026-09-20 13:00:00+00')",
    );

    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT coverage_status = 'partial'
               AND source_watermark_at = '2026-09-20 13:10:00+00'
               AND projection_watermark_at IS NULL
        FROM atheros_search.investigation_watermarks WHERE projection_name = 'graph_projection'",
    )
    .await;
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT coverage_status = 'complete' AND projection_watermark_at = source_watermark_at
        FROM atheros_search.investigation_watermarks WHERE projection_name = 'graph_projection'",
    )
    .await;

    // Both nodes are stale. The older last refresh gets the only slot.
    fixture.admin(
        "UPDATE atheros_search.graph_nodes SET updated_at = '2020-01-01'
         WHERE node_id IN ('device:02:00:00:00:00:02', 'ap:12:00:00:00:00:02');
         UPDATE octopus_core.devices SET last_seen = last_seen + INTERVAL '1 minute';
         UPDATE octopus_core.wireless_frames SET location_id = 'new-location', sensor_id = 'new-sensor'",
    );
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT
           (SELECT observed_at = '2026-09-20 13:01:00+00' FROM atheros_search.graph_nodes
             WHERE node_id = 'device:02:00:00:00:00:02')
           AND
           (SELECT location_id = 'new-location' AND sensor_id = 'new-sensor'
            FROM atheros_search.graph_nodes WHERE node_id = 'ap:12:00:00:00:00:02')",
    )
    .await;
    store.project_infrastructure_graph(1).await.unwrap();

    fixture.admin(
        "UPDATE octopus_core.devices SET os_hint = 'corrected' WHERE mac_id = '02:00:00:00:00:02';
         UPDATE atheros_search.graph_nodes SET is_threat = true, node_payload = '{}'::jsonb
           WHERE node_id = 'ap:12:00:00:00:00:02';
         UPDATE octopus_core.wireless_frames SET ssid = 'corrected-network' WHERE dedupe_key = 'older';
         INSERT INTO octopus_core.wireless_frames(dedupe_key, source_mac, bssid, observed_at)
           VALUES ('older-late', '02:00:00:00:00:02', '12:00:00:00:00:02', '2026-09-20 12:59:00+00')",
    );
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT node_payload->>'os_hint' = 'corrected'
        FROM atheros_search.graph_nodes WHERE node_id = 'device:02:00:00:00:00:02'",
    )
    .await;
    assert_query(
        &fixture,
        "SELECT normalized_ssid = 'corrected-network' AND label = normalized_ssid AND NOT is_threat
        FROM atheros_search.graph_nodes WHERE node_id = 'ap:12:00:00:00:00:02'",
    )
    .await;
    assert_query(&fixture, "SELECT evidence->>'frame_count' = '2'
        FROM atheros_search.graph_edges WHERE edge_id = 'observed:02:00:00:00:00:02:12:00:00:00:00:02'").await;

    // Both pairs have a new latest observation without a count change. Only the
    // newest pair fits this tick, so the old existing edge is still incomplete.
    fixture.admin(
        "UPDATE octopus_core.wireless_frames SET observed_at = observed_at + INTERVAL '1 minute',
           ssid = NULL WHERE dedupe_key IN ('newer', 'older');
         UPDATE atheros_search.graph_nodes SET node_payload = '{}'::jsonb
           WHERE node_id = 'ap:12:00:00:00:00:02'",
    );
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT coverage_status = 'partial' AND projection_watermark_at IS NULL
        FROM atheros_search.investigation_watermarks WHERE projection_name = 'graph_projection'",
    )
    .await;
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT coverage_status = 'complete' AND projection_watermark_at = '2026-09-20 13:11:00+00'
        FROM atheros_search.investigation_watermarks WHERE projection_name = 'graph_projection'",
    )
    .await;
    assert_query(
        &fixture,
        "SELECT normalized_ssid = 'corrected-network' AND label = normalized_ssid
        FROM atheros_search.graph_nodes WHERE node_id = 'ap:12:00:00:00:00:02'",
    )
    .await;

    // An unfinished pair can straddle a completed pair's latest observation.
    fixture.admin(
        "INSERT INTO octopus_core.wireless_frames(dedupe_key, source_mac, bssid, observed_at) VALUES
         ('new-pair', '02:00:00:00:00:01', '12:00:00:00:00:03', '2026-09-20 13:15:00+00'),
         ('older-fresh', '02:00:00:00:00:02', '12:00:00:00:00:02', '2026-09-20 13:20:00+00')",
    );
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT coverage_status = 'partial' AND projection_watermark_at IS NULL
        FROM atheros_search.investigation_watermarks WHERE projection_name = 'graph_projection'",
    )
    .await;

    fixture.admin("DELETE FROM octopus_core.wireless_frames WHERE source_mac='02:00:00:00:00:02'");
    store.project_infrastructure_graph(5).await.unwrap();
    assert_query(
        &fixture,
        "SELECT coverage_status = 'complete' AND NOT EXISTS (
           SELECT 1 FROM atheros_search.graph_edges
           WHERE edge_kind = 'observed_at' AND source_node_id = 'device:02:00:00:00:00:02')
         FROM atheros_search.investigation_watermarks WHERE projection_name = 'graph_projection'",
    )
    .await;
}

#[tokio::test]
async fn candidate_edges_prioritize_changes_and_share_confirmation_threshold() {
    let Some(fixture) = Fixture::start().await else {
        return;
    };
    let store = ProjectionStore::new(fixture.runtime.clone());
    fixture.admin(
        "INSERT INTO octopus_core.devices(mac_id, mac_hint)
           SELECT mac, mac FROM unnest(ARRAY['02:00:00:00:00:01','02:00:00:00:00:02',
           '04:00:00:00:00:01','04:00:00:00:00:02','06:00:00:00:00:01','06:00:00:00:00:02']) AS mac;
         INSERT INTO octopus_core.wireless_frames(dedupe_key, source_mac, bssid, bssid_oui, observed_at) VALUES
           ('a1', '02:00:00:00:00:01', '12:00:00:00:00:01', '120000', '2026-09-20 13:00:00+00'),
           ('a2', '02:00:00:00:00:02', '12:00:00:00:00:01', '120000', '2026-09-20 13:01:00+00'),
           ('b1', '04:00:00:00:00:01', '14:00:00:00:00:01', '140000', '2026-09-20 12:00:00+00'),
           ('b2', '04:00:00:00:00:02', '14:00:00:00:00:01', '140000', '2026-09-20 12:03:00+00'),
           ('c1', '06:00:00:00:00:01', '16:00:00:00:00:01', '160000', '2026-09-20 11:00:00+00'),
           ('c2', '06:00:00:00:00:02', '16:00:00:00:00:01', '160000', '2026-09-20 11:01:00+00');
         INSERT INTO octopus_core.wireless_frame_radio(dedupe_key, channel_number)
           SELECT dedupe_key, 1 FROM octopus_core.wireless_frames;
         INSERT INTO atheros_search.devices(mac, registered, registered_device_id, first_seen, last_seen)
           SELECT mac, true, 'e20c112d-aba4-4c87-90c2-cb8f57aaead3', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
           FROM unnest(ARRAY['04:00:00:00:00:01','04:00:00:00:00:02']) AS mac",
    );
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    persist_merge_candidate(&mut tx, "04:00:00:00:00:01", "04:00:00:00:00:02", 0.985)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(store.project_approved_identities(1).await.unwrap() > 0);
    store.project_infrastructure_graph(20).await.unwrap();
    assert_query(
        &fixture,
        "SELECT weight = 0.985 AND evidence->>'confirmation_source' = 'automatic'
        FROM atheros_search.graph_edges WHERE edge_kind = 'same_device'",
    )
    .await;

    fixture.admin(
        "UPDATE atheros_search.graph_edges SET evidence = '{}'::jsonb, weight = 0
           WHERE source_node_id = 'device:04:00:00:00:00:01' AND edge_kind IN ('roaming','same_channel','vendor_link');
         DELETE FROM atheros_search.graph_edges WHERE source_node_id = 'device:06:00:00:00:00:01'
           AND edge_kind IN ('roaming','same_channel','vendor_link')",
    );
    // A complete scan at one pair per page visits all 15 radio-device pairs.
    for _ in 0..15 {
        store.project_infrastructure_graph(1).await.unwrap();
    }
    assert_query(
        &fixture,
        "SELECT count(*) = 3 AND bool_and(weight = 1 AND observed_at = '2026-09-20 12:03:00+00')
        FROM atheros_search.graph_edges WHERE source_node_id = 'device:04:00:00:00:00:01'
        AND edge_kind IN ('roaming','same_channel','vendor_link')",
    )
    .await;
    assert_query(&fixture, "SELECT count(*) = 3 FROM atheros_search.graph_edges
        WHERE source_node_id = 'device:06:00:00:00:00:01' AND edge_kind IN ('roaming','same_channel','vendor_link')").await;
    assert_query(
        &fixture,
        "SELECT count(*) = 1 FROM atheros_search.graph_edges WHERE edge_kind = 'same_device'",
    )
    .await;

    // Hold the graph between its initial cleanup and the same-device upsert.
    let mut blocker = fixture.runtime.begin_worker().await.unwrap();
    let blocker_pid = blocker
        .query(
            "SELECT pg_backend_pid() FROM atheros_search.graph_nodes
             WHERE node_id = 'device:04:00:00:00:00:01' FOR UPDATE",
            &[],
        )
        .await
        .unwrap()[0]
        .get(0);
    let graph_run = {
        let store = store.clone();
        tokio::spawn(async move { store.project_infrastructure_graph(20).await })
    };
    wait_for_blocked_backend(&fixture, blocker_pid).await;
    fixture.admin(
        "INSERT INTO atheros_search.merge_candidates
           (candidate_id, mac_a, mac_b, status, projection_run_id)
         VALUES ('reverse', '04:00:00:00:00:02', '04:00:00:00:00:01', 'not_match', 'fixture');
         INSERT INTO atheros_search.merge_decisions (candidate_id, decision)
         VALUES ('reverse', 'not_match')",
    );
    blocker.commit().await.unwrap();
    graph_run.await.unwrap().unwrap();
    assert_query(
        &fixture,
        "SELECT count(*) = 0 FROM atheros_search.graph_edges WHERE edge_kind = 'same_device'",
    )
    .await;
    assert!(store.project_approved_identities(1).await.unwrap() > 0);
    assert_query(
        &fixture,
        "SELECT count(*) = 0 FROM atheros_search.identity_cluster_members member
         JOIN atheros_search.identity_clusters cluster USING (cluster_id)
         WHERE cluster.status = 'active'
           AND member.mac IN ('04:00:00:00:00:01', '04:00:00:00:00:02')",
    )
    .await;
}

#[tokio::test]
async fn cluster_refresh_cleans_referencing_edges_and_prioritizes_null_observation_times() {
    let Some(fixture) = Fixture::start().await else {
        return;
    };
    let store = ProjectionStore::new(fixture.runtime.clone());
    fixture.admin(
        "INSERT INTO atheros_search.identity_clusters
           (cluster_id, cluster_name, last_seen, projection_run_id)
         VALUES ('current','current','2020-01-01','fixture'),
                ('missing','missing','2020-01-01','fixture'),
                ('obsolete','obsolete','2020-01-01','fixture')",
    );
    store.project_infrastructure_graph(10).await.unwrap();
    fixture.admin(
        "ALTER TABLE atheros_search.graph_edges
           ADD FOREIGN KEY (source_node_id) REFERENCES atheros_search.graph_nodes,
           ADD FOREIGN KEY (target_node_id) REFERENCES atheros_search.graph_nodes;
         INSERT INTO atheros_search.graph_edges
           (edge_id, source_node_id, target_node_id, edge_kind, projection_run_id)
         VALUES ('legacy','identity:current','identity:obsolete','legacy_link','fixture');
         UPDATE atheros_search.identity_clusters SET status='inactive' WHERE cluster_id='obsolete';
         UPDATE atheros_search.graph_nodes SET observed_at = NULL WHERE node_id='identity:missing';
         UPDATE atheros_search.graph_nodes SET updated_at = '2020-01-01' WHERE node_id='identity:current'",
    );
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT NOT EXISTS (SELECT 1 FROM atheros_search.graph_edges WHERE edge_id='legacy')
            AND NOT EXISTS (SELECT 1 FROM atheros_search.graph_nodes WHERE node_id='identity:obsolete')
            AND (SELECT observed_at='2020-01-01' FROM atheros_search.graph_nodes
                 WHERE node_id='identity:missing')
            AND (SELECT updated_at='2020-01-01' FROM atheros_search.graph_nodes
                 WHERE node_id='identity:current')",
    )
    .await;
}

#[tokio::test]
async fn roaming_scan_advances_through_a_sparse_page_and_wraps_to_earlier_pairs() {
    let Some(fixture) = Fixture::start().await else {
        return;
    };
    let store = ProjectionStore::new(fixture.runtime.clone());
    fixture.admin(
        "INSERT INTO octopus_core.devices(mac_id,mac_hint)
         SELECT mac,mac FROM (
           SELECT '02:00:00:00:00:' || lpad(to_hex(n),2,'0') AS mac
           FROM generate_series(1,13) n
         ) devices",
    );
    store.project_infrastructure_graph(20).await.unwrap();
    fixture.admin(
        "INSERT INTO octopus_core.wireless_frames(dedupe_key,source_mac,bssid,observed_at)
         SELECT n::text, '02:00:00:00:00:' || lpad(to_hex(n),2,'0'),
                '12:00:00:00:00:01',
                '2026-09-20 13:00:00+00'::timestamptz + n * INTERVAL '1 hour'
         FROM generate_series(1,13) n;
         INSERT INTO octopus_core.wireless_frames(dedupe_key,source_mac,bssid,observed_at)
         VALUES ('late-match-a','02:00:00:00:00:0c','12:00:00:00:00:01','2026-09-20 13:00:00+00'),
                ('late-match-b','02:00:00:00:00:0d','12:00:00:00:00:01','2026-09-20 13:10:00+00'),
                ('other-ap-a','02:00:00:00:00:0c','12:00:00:00:00:02','2026-09-20 14:00:00+00'),
                ('other-ap-b','02:00:00:00:00:0d','12:00:00:00:00:02','2026-09-20 14:10:00+00')",
    );
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT coverage_status='partial' AND projection_watermark_at IS NULL
            AND NOT EXISTS (SELECT 1 FROM atheros_search.graph_edges WHERE edge_kind='roaming')
            AND (SELECT checkpoint_value IS NOT NULL FROM octopus_core.processor_checkpoints
                 WHERE processor_name='wireless-identity-projector' AND shard_id='graph-roaming')
         FROM atheros_search.investigation_watermarks WHERE projection_name='graph_projection'",
    )
    .await;

    let store = ProjectionStore::new(fixture.runtime.clone());
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT weight=2 AND observed_at='2026-09-20 14:10:00+00'
            AND (SELECT checkpoint_value IS NULL FROM octopus_core.processor_checkpoints
                 WHERE processor_name='wireless-identity-projector' AND shard_id='graph-roaming')
         FROM atheros_search.graph_edges
         WHERE edge_id='roaming:02:00:00:00:00:0c:02:00:00:00:00:0d'",
    )
    .await;

    fixture.admin(
        "INSERT INTO octopus_core.wireless_frames(dedupe_key,source_mac,bssid,observed_at)
         VALUES ('early-match','02:00:00:00:00:02','12:00:00:00:00:01','2026-09-20 14:05:00+00')",
    );
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT weight=1 AND observed_at='2026-09-20 14:05:00+00'
         FROM atheros_search.graph_edges
         WHERE edge_id='roaming:02:00:00:00:00:01:02:00:00:00:00:02'",
    )
    .await;
}

#[tokio::test]
async fn wireless_coverage_and_historical_signal_buckets_follow_retained_frames() {
    let Some(fixture) = Fixture::start().await else {
        return;
    };
    let store = ProjectionStore::new(fixture.runtime.clone());
    fixture.admin(
        "INSERT INTO octopus_core.wireless_frames(dedupe_key, source_mac, bssid, observed_at)
           VALUES ('self', '02:00:00:00:00:01', '02:00:00:00:00:01', CURRENT_TIMESTAMP)",
    );
    store.project_infrastructure_graph(10).await.unwrap();
    assert_query(
        &fixture,
        "SELECT source_watermark_at IS NULL AND coverage_status = 'unknown'
        FROM atheros_search.investigation_watermarks WHERE projection_name = 'wireless_evidence'",
    )
    .await;
    fixture.admin(
        "INSERT INTO octopus_core.wireless_frames(dedupe_key, source_mac, bssid, observed_at, updated_at)
           VALUES ('old-stalled', '02:00:00:00:00:01', '12:00:00:00:00:01',
                   '2020-01-02 13:01:00+00', '2020-01-02 13:01:00+00')",
    );
    store.project_infrastructure_graph(10).await.unwrap();
    assert_query(
        &fixture,
        "SELECT source_watermark_at = '2020-01-02 13:01:00+00'
               AND projection_watermark_at IS NULL AND coverage_status = 'stalled'
        FROM atheros_search.investigation_watermarks WHERE projection_name = 'wireless_evidence'",
    )
    .await;

    fixture.admin(
        "UPDATE octopus_core.wireless_frames SET updated_at = CURRENT_TIMESTAMP WHERE dedupe_key = 'old-stalled';
         INSERT INTO octopus_core.wireless_frames(dedupe_key, source_mac, bssid, observed_at)
           VALUES ('old-more', '02:00:00:00:00:01', '12:00:00:00:00:01', '2020-01-02 13:03:00+00')",
    );
    store.project_infrastructure_graph(10).await.unwrap();
    assert_query(
        &fixture,
        "SELECT frame_count = 2 FROM atheros_search.wireless_signal_summaries",
    )
    .await;
    fixture.admin(
        "DELETE FROM octopus_core.wireless_frames WHERE dedupe_key = 'old-more';
         UPDATE octopus_core.wireless_frames SET updated_at = observed_at WHERE dedupe_key = 'old-stalled'",
    );
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT frame_count = 1 AND last_observed_at = '2020-01-02 13:01:00+00'
        FROM atheros_search.wireless_signal_summaries",
    )
    .await;
    fixture.admin("DELETE FROM octopus_core.wireless_frames WHERE dedupe_key = 'old-stalled'");
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT count(*) = 0 FROM atheros_search.wireless_signal_summaries",
    )
    .await;

    fixture.admin(
        "INSERT INTO octopus_core.wireless_frames(dedupe_key, source_mac, bssid, observed_at, updated_at)
         VALUES ('old-gap','02:00:00:00:00:01','12:00:00:00:00:01','2020-01-02 13:01:00+00','2020-01-02 13:01:00+00'),
                ('recent','02:00:00:00:00:01','12:00:00:00:00:01',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
    );
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT coverage_status = 'partial' AND projection_watermark_at = source_watermark_at
         FROM atheros_search.investigation_watermarks WHERE projection_name = 'wireless_evidence'",
    )
    .await;
    fixture.admin("UPDATE octopus_core.wireless_frames SET updated_at=CURRENT_TIMESTAMP WHERE dedupe_key='old-gap'");
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT coverage_status = 'complete' AND projection_watermark_at = source_watermark_at
         FROM atheros_search.investigation_watermarks WHERE projection_name = 'wireless_evidence'",
    )
    .await;
}

#[tokio::test]
async fn channel_frequency_and_retained_support_control_observation_edges() {
    let Some(fixture) = Fixture::start().await else {
        return;
    };
    let store = ProjectionStore::new(fixture.runtime.clone());
    fixture.admin(
        "INSERT INTO octopus_core.devices(mac_id,mac_hint)
         SELECT mac,mac FROM unnest(ARRAY['02:00:00:00:00:01','02:00:00:00:00:02',
           '02:00:00:00:00:03','02:00:00:00:00:04']) mac;
         INSERT INTO octopus_core.wireless_frames(dedupe_key,source_mac,bssid,bssid_oui,observed_at) VALUES
           ('a-low','02:00:00:00:00:01','12:00:00:00:00:01','120000','2026-09-20 13:00:00+00'),
           ('b-low','02:00:00:00:00:02','12:00:00:00:00:01','120000','2026-09-20 13:10:00+00'),
           ('a-gap-high','02:00:00:00:00:01','12:00:00:00:00:02','120000','2026-09-20 12:30:00+00'),
           ('a-high','02:00:00:00:00:01','12:00:00:00:00:02','120000','2026-09-20 13:30:00+00'),
           ('b-high','02:00:00:00:00:02','12:00:00:00:00:02','120000','2026-09-20 13:35:00+00'),
           ('c-low','02:00:00:00:00:03','12:00:00:00:00:03','130000','2026-09-20 13:00:00+00'),
           ('d-high','02:00:00:00:00:04','12:00:00:00:00:04','140000','2026-09-20 13:00:00+00');
         INSERT INTO octopus_core.wireless_frame_radio(dedupe_key,channel_number,frequency_mhz)
         SELECT dedupe_key,CASE WHEN dedupe_key='b-high' THEN NULL ELSE 1 END,CASE WHEN dedupe_key LIKE '%high' THEN 5955 ELSE 2412 END
         FROM octopus_core.wireless_frames",
    );
    store.project_infrastructure_graph(20).await.unwrap();
    assert_query(
        &fixture,
        "SELECT weight=2 AND evidence->>'channels'='2412 MHz,5955 MHz'
         FROM atheros_search.graph_edges
         WHERE edge_id='same-channel:02:00:00:00:00:01:02:00:00:00:00:02'",
    )
    .await;
    assert_query(
        &fixture,
        "SELECT NOT EXISTS(SELECT 1 FROM atheros_search.graph_edges
         WHERE edge_id='same-channel:02:00:00:00:00:03:02:00:00:00:00:04')",
    )
    .await;
    // The two high-band observations straddle d-high with a thirty-minute gap.
    assert_query(
        &fixture,
        "SELECT NOT EXISTS(SELECT 1 FROM atheros_search.graph_edges
         WHERE edge_id='same-channel:02:00:00:00:00:01:02:00:00:00:00:04')",
    )
    .await;
    assert_query(
        &fixture,
        "SELECT weight=2 AND observed_at='2026-09-20 13:35:00+00'
         FROM atheros_search.graph_edges
         WHERE edge_id='roaming:02:00:00:00:00:01:02:00:00:00:00:02'",
    )
    .await;
    // Keep both device nodes and retained frames, but remove the shared evidence.
    fixture.admin(
        "DELETE FROM octopus_core.wireless_frames WHERE dedupe_key IN ('b-low','b-high');
         INSERT INTO octopus_core.wireless_frames(dedupe_key,source_mac,bssid,bssid_oui,observed_at)
         VALUES ('b-unrelated','02:00:00:00:00:02','18:00:00:00:00:01','180000','2026-09-20 14:00:00+00');
         INSERT INTO octopus_core.wireless_frame_radio(dedupe_key,channel_number,frequency_mhz)
         VALUES ('b-unrelated',36,5180)",
    );
    store.project_infrastructure_graph(20).await.unwrap();
    assert_query(
        &fixture,
        "SELECT count(*)=2 FROM atheros_search.graph_nodes
         WHERE node_id IN ('device:02:00:00:00:00:01','device:02:00:00:00:00:02')",
    )
    .await;
    assert_query(
        &fixture,
        "SELECT NOT EXISTS(SELECT 1 FROM atheros_search.graph_edges
         WHERE source_node_id='device:02:00:00:00:00:01'
           AND target_node_id='device:02:00:00:00:00:02'
           AND edge_kind IN ('roaming','same_channel','vendor_link'))",
    )
    .await;
}

#[tokio::test]
async fn signal_count_mismatches_remain_partial_until_each_bucket_is_repaired() {
    let Some(fixture) = Fixture::start().await else {
        return;
    };
    let store = ProjectionStore::new(fixture.runtime.clone());
    fixture.admin(
        "INSERT INTO octopus_core.wireless_frames(dedupe_key,source_mac,bssid,observed_at) VALUES
         ('a','02:00:00:00:00:01','12:00:00:00:00:01',CURRENT_TIMESTAMP),
         ('b','02:00:00:00:00:02','12:00:00:00:00:01',CURRENT_TIMESTAMP)",
    );
    store.project_infrastructure_graph(10).await.unwrap();
    fixture.admin("UPDATE atheros_search.wireless_signal_summaries SET frame_count=99");
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT coverage_status='partial' AND projection_watermark_at=source_watermark_at
         FROM atheros_search.investigation_watermarks WHERE projection_name='wireless_evidence'",
    )
    .await;
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT coverage_status='complete' AND projection_watermark_at=source_watermark_at
         FROM atheros_search.investigation_watermarks WHERE projection_name='wireless_evidence'",
    )
    .await;
}

#[tokio::test]
async fn channel_only_evidence_counts_separately_only_when_its_time_window_is_unresolved() {
    let Some(fixture) = Fixture::start().await else {
        return;
    };
    let store = ProjectionStore::new(fixture.runtime.clone());
    fixture.admin(
        "INSERT INTO octopus_core.devices(mac_id,mac_hint)
         SELECT mac,mac FROM unnest(ARRAY['02:00:00:00:00:01','02:00:00:00:00:02']) mac;
         INSERT INTO octopus_core.wireless_frames(dedupe_key,source_mac,observed_at)
         SELECT device || '-' || kind, '02:00:00:00:00:0' || device,
                CASE WHEN kind='unknown' THEN '2026-09-20 13:05:00+00'::timestamptz
                     ELSE '2026-09-20 13:00:00+00'::timestamptz END
         FROM unnest(ARRAY['1','2']) device CROSS JOIN unnest(ARRAY['low','high','unknown']) kind;
         INSERT INTO octopus_core.wireless_frame_radio(dedupe_key,channel_number,frequency_mhz)
         SELECT dedupe_key,1,CASE WHEN dedupe_key LIKE '%low' THEN 2412
                                WHEN dedupe_key LIKE '%high' THEN 5955 END
         FROM octopus_core.wireless_frames",
    );
    store.project_infrastructure_graph(10).await.unwrap();
    assert_query(
        &fixture,
        "SELECT weight=2 AND evidence->>'channels'='2412 MHz,5955 MHz'
                AND observed_at='2026-09-20 13:05:00+00'
         FROM atheros_search.graph_edges WHERE edge_kind='same_channel'",
    )
    .await;

    fixture.admin(
        "INSERT INTO octopus_core.wireless_frames(dedupe_key,source_mac,observed_at)
         SELECT device || '-unknown11','02:00:00:00:00:0' || device,'2026-09-20 13:05:00+00'
         FROM unnest(ARRAY['1','2']) device;
         INSERT INTO octopus_core.wireless_frame_radio(dedupe_key,channel_number)
         SELECT dedupe_key,11 FROM octopus_core.wireless_frames WHERE dedupe_key LIKE '%unknown11'",
    );
    store.project_infrastructure_graph(10).await.unwrap();
    assert_query(
        &fixture,
        "SELECT weight=3 AND evidence->>'channels'='2412 MHz,5955 MHz,channel 11'
         FROM atheros_search.graph_edges WHERE edge_kind='same_channel'",
    )
    .await;

    fixture.admin(
        "INSERT INTO octopus_core.wireless_frames(dedupe_key,source_mac,observed_at)
         SELECT device || '-unresolved','02:00:00:00:00:0' || device,'2026-09-20 14:00:00+00'
         FROM unnest(ARRAY['1','2']) device;
         INSERT INTO octopus_core.wireless_frame_radio(dedupe_key,channel_number)
         SELECT dedupe_key,1 FROM octopus_core.wireless_frames WHERE dedupe_key LIKE '%unresolved'",
    );
    store.project_infrastructure_graph(10).await.unwrap();
    assert_query(
        &fixture,
        "SELECT weight=4 AND evidence->>'channels'='2412 MHz,5955 MHz,channel 1,channel 11'
                AND observed_at='2026-09-20 14:00:00+00'
         FROM atheros_search.graph_edges WHERE edge_kind='same_channel'",
    )
    .await;
}

#[tokio::test]
async fn signal_timestamp_mismatches_remain_partial_until_each_bucket_is_repaired() {
    let Some(fixture) = Fixture::start().await else {
        return;
    };
    let store = ProjectionStore::new(fixture.runtime.clone());
    fixture.admin(
        "INSERT INTO octopus_core.wireless_frames(dedupe_key,source_mac,bssid,observed_at) VALUES
         ('a','02:00:00:00:00:01','12:00:00:00:00:01','2020-01-02 13:03:00+00'),
         ('b','02:00:00:00:00:02','12:00:00:00:00:01','2020-01-02 13:03:00+00')",
    );
    store.project_infrastructure_graph(10).await.unwrap();
    fixture.admin(
        "UPDATE octopus_core.wireless_frames SET updated_at=observed_at;
         UPDATE atheros_search.wireless_signal_summaries
         SET last_observed_at=last_observed_at-INTERVAL '1 minute'",
    );
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT coverage_status='partial' AND projection_watermark_at=source_watermark_at
         FROM atheros_search.investigation_watermarks WHERE projection_name='wireless_evidence'",
    )
    .await;
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT coverage_status='complete' AND projection_watermark_at=source_watermark_at
         FROM atheros_search.investigation_watermarks WHERE projection_name='wireless_evidence'",
    )
    .await;
}

#[tokio::test]
async fn radio_backfill_keeps_stale_summary_buckets_partial_until_rebuilt() {
    let Some(fixture) = Fixture::start().await else {
        return;
    };
    let store = ProjectionStore::new(fixture.runtime.clone());
    fixture.admin(
        "INSERT INTO octopus_core.wireless_frames(dedupe_key,source_mac,bssid,observed_at) VALUES
           ('a','02:00:00:00:00:01','12:00:00:00:00:01','2020-01-02 13:03:00+00'),
           ('b','02:00:00:00:00:02','12:00:00:00:00:01','2020-01-02 13:03:00+00')",
    );
    store.project_infrastructure_graph(10).await.unwrap();
    fixture.admin(
        "INSERT INTO octopus_core.sync_events
           (dedupe_key,stream_name,observed_at,payload_ref,payload,status,producer,signal_dbm)
         SELECT dedupe_key,'wireless.audit',observed_at,'{}','{}','completed','test',-50
         FROM octopus_core.wireless_frames;
         CREATE FUNCTION octopus_core.pause_radio_backfill() RETURNS trigger LANGUAGE plpgsql AS
           $$BEGIN PERFORM pg_advisory_xact_lock(8292700); RETURN NEW; END$$;
         CREATE TRIGGER pause_radio_backfill BEFORE UPDATE ON octopus_core.wireless_frames
           FOR EACH ROW EXECUTE FUNCTION octopus_core.pause_radio_backfill()",
    );
    let mut blocker = fixture.runtime.begin_worker().await.unwrap();
    let blocker_pid = blocker
        .query(
            "SELECT pg_backend_pid(), pg_advisory_xact_lock(8292700) IS NULL",
            &[],
        )
        .await
        .unwrap()[0]
        .get(0);
    let normalization = {
        let store = store.clone();
        tokio::spawn(async move { store.normalize_wireless_frames(10).await })
    };
    let normalization_pid = wait_for_blocked_backend(&fixture, blocker_pid).await;
    let graph_run = {
        let store = store.clone();
        tokio::spawn(async move { store.project_infrastructure_graph(1).await })
    };
    wait_for_blocked_backend(&fixture, normalization_pid).await;
    blocker.commit().await.unwrap();
    normalization.await.unwrap().unwrap();
    graph_run.await.unwrap().unwrap();
    assert_query(
        &fixture,
        "SELECT coverage_status='partial' AND projection_watermark_at=source_watermark_at
            AND (SELECT COUNT(*) FROM atheros_search.wireless_signal_summaries
                 WHERE frame_count=1 AND last_observed_at='2020-01-02 13:03:00+00'
                   AND rssi_sample_count=1 AND rssi_avg_dbm=-50) = 1
         FROM atheros_search.investigation_watermarks WHERE projection_name='wireless_evidence'",
    )
    .await;
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT coverage_status='complete'
            AND (SELECT COUNT(*) FROM atheros_search.wireless_signal_summaries
                 WHERE rssi_sample_count=1 AND rssi_avg_dbm=-50) = 2
         FROM atheros_search.investigation_watermarks WHERE projection_name='wireless_evidence'",
    )
    .await;
}

#[tokio::test]
async fn pair_pages_keep_full_evidence_and_write_every_roaming_match() {
    let Some(fixture) = Fixture::start().await else {
        return;
    };
    let store = ProjectionStore::new(fixture.runtime.clone());
    fixture.admin(
        "INSERT INTO octopus_core.devices(mac_id, mac_hint)
         SELECT mac, mac FROM unnest(ARRAY['02:00:00:00:00:01','02:00:00:00:00:02',
                                         '02:00:00:00:00:03']) AS mac",
    );
    store.project_infrastructure_graph(10).await.unwrap();
    fixture.admin(
        "INSERT INTO octopus_core.wireless_frames(dedupe_key, source_mac, bssid, bssid_oui, observed_at)
         SELECT mac_id || bssid, mac_id, bssid, oui, '2026-09-20 13:03:00+00'
         FROM octopus_core.devices
         CROSS JOIN (VALUES ('12:00:00:00:00:01', '120000'), ('14:00:00:00:00:01', '140000'))
                    AS ap(bssid, oui);
         INSERT INTO octopus_core.wireless_frame_radio(dedupe_key, frequency_mhz)
         SELECT dedupe_key, CASE bssid_oui WHEN '120000' THEN 2412 ELSE 5955 END
         FROM octopus_core.wireless_frames",
    );
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT count(*) FILTER (WHERE edge_kind = 'roaming') = 3
            AND count(*) FILTER (WHERE edge_kind = 'same_channel') = 1
            AND count(*) FILTER (WHERE edge_kind = 'vendor_link') = 1
            AND bool_and(weight = 2)
         FROM atheros_search.graph_edges
         WHERE edge_kind IN ('roaming','same_channel','vendor_link')",
    )
    .await;
    for _ in 0..2 {
        store.project_infrastructure_graph(1).await.unwrap();
    }
    assert_query(
        &fixture,
        "SELECT count(*) FILTER (WHERE edge_kind = 'same_channel') = 3
            AND count(*) FILTER (WHERE edge_kind = 'vendor_link') = 3
            AND bool_and(weight = 2)
         FROM atheros_search.graph_edges
         WHERE edge_kind IN ('same_channel','vendor_link')",
    )
    .await;
}
