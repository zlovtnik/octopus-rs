mod support;

use octopus::projections::{identity::persist_merge_candidate, ProjectionStore};
use support::Fixture;

async fn assert_query(fixture: &Fixture, sql: &str) {
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let rows = tx.query(sql, &[]).await.unwrap();
    assert_eq!(rows.len(), 1, "{sql}");
    assert!(rows[0].get::<_, bool>(0), "{sql}");
    tx.commit().await.unwrap();
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
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(
        &fixture,
        "SELECT count(*) = 3 AND bool_and(weight = 1 AND observed_at = '2026-09-20 12:03:00+00')
        FROM atheros_search.graph_edges WHERE source_node_id = 'device:04:00:00:00:00:01'
        AND edge_kind IN ('roaming','same_channel','vendor_link')",
    )
    .await;
    store.project_infrastructure_graph(1).await.unwrap();
    assert_query(&fixture, "SELECT count(*) = 3 FROM atheros_search.graph_edges
        WHERE source_node_id = 'device:06:00:00:00:00:01' AND edge_kind IN ('roaming','same_channel','vendor_link')").await;
    assert_query(
        &fixture,
        "SELECT count(*) = 1 FROM atheros_search.graph_edges WHERE edge_kind = 'same_device'",
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
}
