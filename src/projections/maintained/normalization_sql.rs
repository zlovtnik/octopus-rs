//! Statements that normalize retained wireless events into frame tables.

// Parameters: batchLimit
pub(super) const INSERT_MISSING_FRAMES: &str = r#"INSERT INTO wireless_frames (
               dedupe_key, sensor_id, location_id, schema_version, observed_at,
               frame_type, frame_subtype, source_mac, transmitter_mac, receiver_mac,
               bssid, destination_bssid, bssid_oui, ssid, created_at, updated_at
             )
             SELECT e.dedupe_key, e.sensor_id, e.location_id, COALESCE(e.schema_version, 1), e.observed_at,
                    e.frame_type, e.frame_subtype, e.source_mac, e.transmitter_mac, e.receiver_mac,
                    e.bssid, e.destination_bssid,
                    CASE
                      WHEN COALESCE(e.bssid, e.source_mac) IS NULL THEN NULL
                      ELSE UPPER(REPLACE(LEFT(COALESCE(e.bssid, e.source_mac), 8), ':', ''))
                    END,
                    e.ssid, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
             FROM sync_events e
             LEFT JOIN wireless_frames frame ON frame.dedupe_key = e.dedupe_key
              WHERE e.stream_name = 'wireless.audit'
                AND (e.payload IS NOT NULL OR e.payload_archived = true)
                AND frame.dedupe_key IS NULL
             ORDER BY e.observed_at, e.dedupe_key
             LIMIT $1::int
             ON CONFLICT (dedupe_key) DO UPDATE SET updated_at = EXCLUDED.updated_at"#;

// Parameters: batchLimit
pub(super) const INSERT_MISSING_RADIO_AND_TOUCH_FRAMES: &str = r#"WITH missing AS MATERIALIZED (SELECT frame.dedupe_key
           FROM wireless_frames frame
           WHERE NOT EXISTS (
             SELECT 1 FROM  wireless_frame_radio  child
             WHERE child.dedupe_key = frame.dedupe_key
           ) AND EXISTS (
             SELECT 1 FROM sync_events event
             WHERE event.dedupe_key = frame.dedupe_key AND event.stream_name = 'wireless.audit'
           )
           ORDER BY frame.observed_at, frame.dedupe_key
           LIMIT $1::int), inserted AS (INSERT INTO wireless_frame_radio (
               dedupe_key, signal_dbm, noise_dbm, frequency_mhz, channel_flags,
               data_rate_kbps, antenna_id, tsft, fragment_number, channel_number,
               tsft_delta_us, wall_clock_delta_ms
             )
             SELECT e.dedupe_key, e.signal_dbm, e.noise_dbm, e.frequency_mhz, e.channel_flags,
                    e.data_rate_kbps, e.antenna_id, e.tsft, e.fragment_number, e.channel_number,
                    e.tsft_delta_us, e.wall_clock_delta_ms
             FROM missing
             JOIN sync_events e ON e.dedupe_key = missing.dedupe_key
             WHERE e.stream_name = 'wireless.audit'
             ON CONFLICT (dedupe_key) DO NOTHING RETURNING dedupe_key)
           UPDATE wireless_frames frame SET updated_at = clock_timestamp()
           FROM inserted WHERE frame.dedupe_key = inserted.dedupe_key"#;

// Parameters: batchLimit
pub(super) const INSERT_MISSING_QOS: &str = r#"WITH missing AS MATERIALIZED (SELECT frame.dedupe_key
           FROM wireless_frames frame
           WHERE NOT EXISTS (
             SELECT 1 FROM  wireless_frame_qos  child
             WHERE child.dedupe_key = frame.dedupe_key
           ) AND EXISTS (
             SELECT 1 FROM sync_events event
             WHERE event.dedupe_key = frame.dedupe_key AND event.stream_name = 'wireless.audit'
           )
           ORDER BY frame.observed_at, frame.dedupe_key
           LIMIT $1::int) INSERT INTO wireless_frame_qos (
               dedupe_key, qos_tid, qos_eosp, qos_ack_policy, qos_ack_policy_label,
               qos_amsdu, more_data, retry, power_save, protected, frame_control_flags
             )
             SELECT e.dedupe_key, e.qos_tid, e.qos_eosp, e.qos_ack_policy, e.qos_ack_policy_label,
                    e.qos_amsdu, e.more_data, e.retry, e.power_save, e.protected, e.frame_control_flags
             FROM missing
             JOIN sync_events e ON e.dedupe_key = missing.dedupe_key
             WHERE e.stream_name = 'wireless.audit'
             ON CONFLICT (dedupe_key) DO NOTHING"#;

// Parameters: batchLimit
pub(super) const INSERT_MISSING_NETWORK: &str = r#"WITH missing AS MATERIALIZED (SELECT frame.dedupe_key
           FROM wireless_frames frame
           WHERE NOT EXISTS (
             SELECT 1 FROM  wireless_frame_network  child
             WHERE child.dedupe_key = frame.dedupe_key
           ) AND EXISTS (
             SELECT 1 FROM sync_events event
             WHERE event.dedupe_key = frame.dedupe_key AND event.stream_name = 'wireless.audit'
           )
           ORDER BY frame.observed_at, frame.dedupe_key
           LIMIT $1::int) INSERT INTO wireless_frame_network (
               dedupe_key, llc_oui, ethertype, ethertype_name, src_ip, dst_ip,
               ip_ttl, ip_protocol, ip_protocol_name, src_port, dst_port,
               transport_protocol, transport_length, transport_checksum, app_protocol
             )
             SELECT e.dedupe_key, e.llc_oui, e.ethertype, e.ethertype_name, e.src_ip, e.dst_ip,
                    e.ip_ttl, e.ip_protocol, e.ip_protocol_name, e.src_port, e.dst_port,
                    e.transport_protocol, e.transport_length, e.transport_checksum, e.app_protocol
             FROM missing
             JOIN sync_events e ON e.dedupe_key = missing.dedupe_key
             WHERE e.stream_name = 'wireless.audit'
             ON CONFLICT (dedupe_key) DO NOTHING"#;

// Parameters: batchLimit
pub(super) const INSERT_MISSING_APP_SIGNALS: &str = r#"WITH missing AS MATERIALIZED (SELECT frame.dedupe_key
           FROM wireless_frames frame
           WHERE NOT EXISTS (
             SELECT 1 FROM  wireless_frame_app_signals  child
             WHERE child.dedupe_key = frame.dedupe_key
           ) AND EXISTS (
             SELECT 1 FROM sync_events event
             WHERE event.dedupe_key = frame.dedupe_key AND event.stream_name = 'wireless.audit'
           )
           ORDER BY frame.observed_at, frame.dedupe_key
           LIMIT $1::int) INSERT INTO wireless_frame_app_signals (
               dedupe_key, ssdp_message_type, ssdp_st, ssdp_mx, ssdp_usn,
               dhcp_requested_ip, dhcp_hostname, dhcp_vendor_class, dns_query_name, mdns_name
             )
             SELECT e.dedupe_key, e.ssdp_message_type, e.ssdp_st, e.ssdp_mx, e.ssdp_usn,
                    e.dhcp_requested_ip, e.dhcp_hostname, e.dhcp_vendor_class, e.dns_query_name, e.mdns_name
             FROM missing
             JOIN sync_events e ON e.dedupe_key = missing.dedupe_key
             WHERE e.stream_name = 'wireless.audit'
             ON CONFLICT (dedupe_key) DO NOTHING"#;

// Parameters: batchLimit
pub(super) const INSERT_MISSING_IDENTITY: &str = r#"WITH missing AS MATERIALIZED (SELECT frame.dedupe_key
           FROM wireless_frames frame
           WHERE NOT EXISTS (
             SELECT 1 FROM  wireless_frame_identity  child
             WHERE child.dedupe_key = frame.dedupe_key
           ) AND EXISTS (
             SELECT 1 FROM sync_events event
             WHERE event.dedupe_key = frame.dedupe_key AND event.stream_name = 'wireless.audit'
           )
           ORDER BY frame.observed_at, frame.dedupe_key
           LIMIT $1::int) INSERT INTO wireless_frame_identity (
               dedupe_key, username, event_type, session_key, retransmit_key,
               frame_fingerprint, payload_visibility, identity_source, device_fingerprint,
               wps_device_name, wps_manufacturer, wps_model_name, handshake_captured, normalized_text
             )
             SELECT e.dedupe_key, e.username, e.event_type, e.session_key, e.retransmit_key,
                    e.frame_fingerprint, e.payload_visibility, e.identity_source, e.device_fingerprint,
                    e.wps_device_name, e.wps_manufacturer, e.wps_model_name,
                    e.handshake_captured, e.wireless_search_text
             FROM missing
             JOIN sync_events e ON e.dedupe_key = missing.dedupe_key
             WHERE e.stream_name = 'wireless.audit'
             ON CONFLICT (dedupe_key) DO NOTHING"#;

// Parameters: batchLimit
pub(super) const INSERT_MISSING_SECURITY: &str = r#"WITH missing AS MATERIALIZED (SELECT frame.dedupe_key
           FROM wireless_frames frame
           WHERE NOT EXISTS (
             SELECT 1 FROM  wireless_frame_security  child
             WHERE child.dedupe_key = frame.dedupe_key
           ) AND EXISTS (
             SELECT 1 FROM sync_events event
             WHERE event.dedupe_key = frame.dedupe_key AND event.stream_name = 'wireless.audit'
           )
           ORDER BY frame.observed_at, frame.dedupe_key
           LIMIT $1::int) INSERT INTO wireless_frame_security (
               dedupe_key, large_frame, mixed_encryption, dedupe_or_replay_suspect,
               raw_len, security_flags, risk_score, tags, signal_status, adjacent_mac_hint
             )
             SELECT e.dedupe_key, e.large_frame, e.mixed_encryption, e.dedupe_or_replay_suspect,
                    e.raw_len, e.security_flags, e.risk_score, COALESCE(e.tags, jsonb_build_array()),
                    e.signal_status, e.adjacent_mac_hint
             FROM missing
             JOIN sync_events e ON e.dedupe_key = missing.dedupe_key
             WHERE e.stream_name = 'wireless.audit'
             ON CONFLICT (dedupe_key) DO NOTHING"#;
