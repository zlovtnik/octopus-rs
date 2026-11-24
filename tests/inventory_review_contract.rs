mod support;

use octopus::projections::ProjectionStore;
use std::time::Duration;

#[tokio::test]
async fn inventory_waits_for_normalization_before_marking_source_backed_frames() {
    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let store = ProjectionStore::new(fixture.runtime.clone());
    fixture.admin(
        "INSERT INTO octopus_core.sync_events (dedupe_key,stream_name,payload_ref,observed_at)
         VALUES('late','wireless.audit','inline://json/e30',CURRENT_TIMESTAMP);
         INSERT INTO octopus_core.wireless_frames(dedupe_key,source_mac,ssid,observed_at,created_at)
         VALUES('late','aa:bb:cc:dd:ee:01','late-network',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP - INTERVAL '1 minute'),
               ('direct','aa:bb:cc:dd:ee:02','direct-network',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);
         INSERT INTO octopus_core.devices(mac_id,mac_hint,first_seen,last_seen)
         VALUES ('aa:bb:cc:dd:ee:03','aa:bb:cc:dd:ee:03',CURRENT_TIMESTAMP - INTERVAL '1 day',
                 CURRENT_TIMESTAMP - INTERVAL '1 day');",
    );

    assert_eq!(store.normalize_wireless_frames(10).await.unwrap(), 0);
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
        "UPDATE octopus_core.sync_events SET payload='{}', source_mac='aa:bb:cc:dd:ee:01',
            ssid='late-network', dhcp_hostname='late-host', wps_device_name='late-device'
         WHERE dedupe_key='late' AND stream_name='wireless.audit';
         INSERT INTO octopus_core.wireless_frame_identity(dedupe_key,wps_device_name)
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
async fn a_late_audit_enriches_an_already_counted_direct_frame() {
    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    let store = ProjectionStore::new(fixture.runtime.clone());
    fixture.admin(
        "INSERT INTO octopus_core.wireless_frames(dedupe_key,source_mac,ssid,observed_at)
         VALUES('late-audit','aa:bb:cc:dd:ee:05','network',CURRENT_TIMESTAMP);",
    );
    assert_eq!(store.project_wireless_inventory(1).await.unwrap(), 3);
    fixture.admin(
        "INSERT INTO octopus_core.sync_events
           (dedupe_key,stream_name,payload_ref,observed_at,payload,dhcp_hostname,wps_device_name)
         VALUES('late-audit','wireless.audit','inline://json/e30',CURRENT_TIMESTAMP,'{}','late-host','late-device');",
    );

    assert!(store.normalize_wireless_frames(1).await.unwrap() > 0);
    assert_eq!(store.project_wireless_inventory(1).await.unwrap(), 1);
    assert_eq!(store.normalize_wireless_frames(1).await.unwrap(), 0);
    assert_eq!(store.project_wireless_inventory(1).await.unwrap(), 0);

    let mut tx = fixture.runtime.begin_worker().await.unwrap();
    let rows = tx
        .query(
            "SELECT d.display_name, d.hostname, c.probe_count, s.display_name
             FROM devices d JOIN wireless_clients c ON c.client_mac=d.mac_id
             JOIN atheros_search.devices s ON s.mac=d.mac_id
             WHERE d.mac_id='aa:bb:cc:dd:ee:05'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows[0].get::<_, String>(0), "late-device");
    assert_eq!(rows[0].get::<_, String>(1), "late-host");
    assert_eq!(rows[0].get::<_, i64>(2), 1);
    assert_eq!(rows[0].get::<_, String>(3), "late-device");
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

#[tokio::test]
async fn inventory_holds_claimed_frame_stable_between_upserts() {
    let Some(fixture) = support::Fixture::start().await else {
        return;
    };
    fixture.admin(
        "INSERT INTO octopus_core.wireless_frames(dedupe_key,source_mac,ssid,observed_at)
         VALUES('correctable','aa:bb:cc:dd:ee:01','network',CURRENT_TIMESTAMP);
         CREATE FUNCTION octopus_core.pause_inventory_client() RETURNS trigger LANGUAGE plpgsql AS
           $$BEGIN PERFORM pg_advisory_xact_lock(8292713); RETURN NEW; END$$;
         CREATE TRIGGER pause_inventory_client BEFORE INSERT ON octopus_core.wireless_clients
           FOR EACH ROW EXECUTE FUNCTION octopus_core.pause_inventory_client();",
    );
    let mut blocker = fixture.runtime.begin_worker().await.unwrap();
    blocker
        .query("SELECT pg_advisory_xact_lock(8292713) IS NULL", &[])
        .await
        .unwrap();
    let store = ProjectionStore::new(fixture.runtime.clone());
    let task = tokio::spawn(async move { store.project_wireless_inventory(1).await.unwrap() });
    let mut correction = fixture.runtime.begin_worker().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let waiting: bool = correction
                .query(
                    "SELECT EXISTS(SELECT 1 FROM pg_locks
                     WHERE locktype='advisory' AND objid=8292713 AND NOT granted)",
                    &[],
                )
                .await
                .unwrap()[0]
                .get(0);
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("inventory did not reach the client upsert");
    let err = correction
        .query(
            "SELECT source_mac FROM wireless_frames WHERE dedupe_key='correctable'
             FOR NO KEY UPDATE NOWAIT",
            &[],
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, octopus::postgres::PgError::Query { source, .. }
        if source.code() == Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE))
    );
    correction.rollback().await.unwrap();
    blocker.rollback().await.unwrap();
    assert_eq!(task.await.unwrap(), 3);
}
