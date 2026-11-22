mod support;

use octopus::projections::ProjectionStore;

#[tokio::test]
async fn inventory_waits_for_normalization_before_marking_source_backed_frames() {
    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let store = ProjectionStore::new(fixture.runtime.clone());
    fixture.admin(
        "INSERT INTO octopus_core.sync_events
           (dedupe_key,stream_name,payload_ref,payload,observed_at,source_mac,ssid,dhcp_hostname,wps_device_name)
         VALUES('late','wireless.audit','inline://json/e30','{}',CURRENT_TIMESTAMP,
                'aa:bb:cc:dd:ee:01','late-network','late-host','late-device');
         INSERT INTO octopus_core.wireless_frames(dedupe_key,source_mac,ssid,observed_at,created_at)
         VALUES('late','aa:bb:cc:dd:ee:01','late-network',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP - INTERVAL '1 minute'),
               ('direct','aa:bb:cc:dd:ee:02','direct-network',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);
         INSERT INTO octopus_core.devices(mac_id,mac_hint,first_seen,last_seen)
         VALUES ('aa:bb:cc:dd:ee:03','aa:bb:cc:dd:ee:03',CURRENT_TIMESTAMP - INTERVAL '1 day',
                 CURRENT_TIMESTAMP - INTERVAL '1 day');",
    );

    assert!(store.project_wireless_inventory(1).await.unwrap() > 0);
    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let marked: Vec<String> = tx
        .query(
            "SELECT dedupe_key FROM wireless_inventory_projection_inputs",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(marked, ["direct"]);
    let mirrored: Vec<String> = tx
        .query("SELECT mac FROM atheros_search.devices", &[])
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(mirrored, ["aa:bb:cc:dd:ee:02"]);
    assert!(tx
        .query(
            "SELECT 1 FROM devices WHERE mac_id='aa:bb:cc:dd:ee:01'",
            &[]
        )
        .await
        .unwrap()
        .is_empty());
    tx.commit().await.unwrap();

    fixture.admin(
        "INSERT INTO octopus_core.wireless_frame_identity(dedupe_key,wps_device_name)
         VALUES('late','late-device')",
    );
    assert_eq!(store.project_wireless_inventory(1).await.unwrap(), 1);
    assert_eq!(store.project_wireless_inventory(1).await.unwrap(), 0);
    assert!(store.normalize_wireless_frames(10).await.unwrap() > 0);
    assert!(store.project_wireless_inventory(1).await.unwrap() > 0);
    assert_eq!(store.project_wireless_inventory(1).await.unwrap(), 0);

    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let device = tx
        .query(
            "SELECT display_name,hostname FROM devices WHERE mac_id='aa:bb:cc:dd:ee:01'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(device[0].get::<_, String>(0), "late-device");
    assert_eq!(device[0].get::<_, String>(1), "late-host");
    let count: i64 = tx
        .query(
            "SELECT probe_count FROM wireless_clients WHERE client_mac='aa:bb:cc:dd:ee:01'",
            &[],
        )
        .await
        .unwrap()[0]
        .get(0);
    assert_eq!(count, 1);
    let marked: i64 = tx
        .query(
            "SELECT count(*) FROM wireless_inventory_projection_inputs",
            &[],
        )
        .await
        .unwrap()[0]
        .get(0);
    assert_eq!(marked, 2);
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn overlapping_inventory_batches_count_each_frame_once() {
    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let store = ProjectionStore::new(fixture.runtime.clone());
    fixture.admin(
        "INSERT INTO octopus_core.wireless_frames(dedupe_key, source_mac, ssid, observed_at)
         VALUES ('concurrent', 'aa:bb:cc:dd:ee:01', 'network', CURRENT_TIMESTAMP)",
    );

    let (left, right) = tokio::join!(
        store.project_wireless_inventory(1),
        store.project_wireless_inventory(1),
    );
    assert_eq!(left.unwrap() + right.unwrap(), 3);

    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let rows = tx
        .query(
            "SELECT probe_count FROM wireless_clients WHERE ssid='network'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, i64>(0), 1);
    tx.commit().await.unwrap();
}
