//! Claim ready inventory inputs once and project the claimed frames.

// Parameters: batchLimit
pub(super) const CLAIM_INVENTORY_INPUTS: &str = r#"INSERT INTO wireless_inventory_projection_inputs (dedupe_key, projected_at)
         SELECT candidate.dedupe_key, CURRENT_TIMESTAMP
         FROM wireless_frames candidate
         WHERE NOT EXISTS (
           SELECT 1 FROM wireless_inventory_projection_inputs applied
           WHERE applied.dedupe_key = candidate.dedupe_key
         )
           AND (NOT EXISTS (
             SELECT 1 FROM sync_events event
             WHERE event.dedupe_key = candidate.dedupe_key AND event.stream_name = 'wireless.audit'
           ) OR (EXISTS (
             SELECT 1 FROM wireless_frame_identity identity_row
             WHERE identity_row.dedupe_key = candidate.dedupe_key
           ) AND EXISTS (
             SELECT 1 FROM wireless_frame_app_signals app_row
             WHERE app_row.dedupe_key = candidate.dedupe_key
           )))
         ORDER BY candidate.created_at, candidate.dedupe_key
         LIMIT $1::int FOR KEY SHARE OF candidate
         ON CONFLICT (dedupe_key) DO NOTHING
         RETURNING dedupe_key"#;

// Parameters: claimedKeys
pub(super) const UPSERT_OBSERVED_DEVICES: &str = r#"INSERT INTO devices (
               mac_id, display_name, username, hostname, os_hint, mac_hint,
               first_seen, last_seen, entity_version, updated_at
             )
             SELECT frame.source_mac,
                    MAX(NULLIF(identity_row.wps_device_name, '')),
                    MAX(NULLIF(identity_row.username, '')),
                    MAX(NULLIF(app_row.dhcp_hostname, '')),
                    MAX(NULLIF(identity_row.wps_manufacturer, '')),
                    frame.source_mac,
                    MIN(frame.observed_at), MAX(frame.observed_at), 1, CURRENT_TIMESTAMP
             FROM wireless_frames frame
             LEFT JOIN wireless_frame_identity identity_row ON identity_row.dedupe_key = frame.dedupe_key
             LEFT JOIN wireless_frame_app_signals app_row ON app_row.dedupe_key = frame.dedupe_key
             WHERE frame.dedupe_key = ANY($1::varchar[]) AND frame.source_mac IS NOT NULL
             GROUP BY frame.source_mac
             ON CONFLICT (mac_id) DO UPDATE SET
               entity_version = devices.entity_version + 1,
               display_name = COALESCE(EXCLUDED.display_name, devices.display_name),
               username = COALESCE(EXCLUDED.username, devices.username),
               hostname = COALESCE(EXCLUDED.hostname, devices.hostname),
               os_hint = COALESCE(EXCLUDED.os_hint, devices.os_hint),
               first_seen = LEAST(devices.first_seen, EXCLUDED.first_seen),
               last_seen = GREATEST(devices.last_seen, EXCLUDED.last_seen),
               updated_at = CURRENT_TIMESTAMP"#;

// Parameters: claimedKeys
pub(super) const UPSERT_WIRELESS_CLIENTS: &str = r#"INSERT INTO wireless_clients (
               ssid, client_mac, known_bssid, first_seen, last_seen,
               probe_count, location_id, updated_at
             )
             SELECT frame.ssid, frame.source_mac, MAX(frame.bssid),
                    MIN(frame.observed_at), MAX(frame.observed_at), COUNT(*),
                    MAX(frame.location_id), CURRENT_TIMESTAMP
             FROM wireless_frames frame
             WHERE frame.dedupe_key = ANY($1::varchar[]) AND frame.source_mac IS NOT NULL AND frame.ssid IS NOT NULL
             GROUP BY frame.ssid, frame.source_mac
             ON CONFLICT (ssid, client_mac) DO UPDATE SET
               known_bssid = COALESCE(EXCLUDED.known_bssid, wireless_clients.known_bssid),
               first_seen = LEAST(wireless_clients.first_seen, EXCLUDED.first_seen),
               last_seen = GREATEST(wireless_clients.last_seen, EXCLUDED.last_seen),
               probe_count = wireless_clients.probe_count + EXCLUDED.probe_count,
               location_id = COALESCE(EXCLUDED.location_id, wireless_clients.location_id),
               updated_at = CURRENT_TIMESTAMP"#;

// Mirror claimed devices first, with any spare capacity available for existing drift.
// Parameters: batchLimit, claimedKeys
pub(super) const UPSERT_SEARCH_DEVICES: &str = r#"INSERT INTO atheros_search.devices (
               mac, display_name, first_seen, last_seen, known_macs, updated_at
             )
             SELECT device.mac_id, device.display_name, device.first_seen,
                    device.last_seen, jsonb_build_array(device.mac_id), CURRENT_TIMESTAMP
             FROM devices device
             LEFT JOIN atheros_search.devices projected ON projected.mac = device.mac_id
             WHERE device.mac_id ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
               AND (projected.mac IS NULL
                 OR device.first_seen < projected.first_seen
                 OR device.last_seen > projected.last_seen
                 OR (device.display_name IS NOT NULL
                   AND device.display_name IS DISTINCT FROM projected.display_name))
             ORDER BY (device.mac_id IN (
               SELECT frame.source_mac FROM wireless_frames frame
               WHERE frame.dedupe_key = ANY($2::varchar[]) AND frame.source_mac IS NOT NULL
             )) DESC, device.last_seen, device.mac_id
             LIMIT $1::int
             ON CONFLICT (mac) DO UPDATE SET
               display_name = COALESCE(EXCLUDED.display_name, devices.display_name),
               first_seen = LEAST(devices.first_seen, EXCLUDED.first_seen),
               last_seen = GREATEST(devices.last_seen, EXCLUDED.last_seen),
               updated_at = CURRENT_TIMESTAMP"#;
