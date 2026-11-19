//! Source-selection SQL; each selection is bounded independently by kind.

pub const EVENT_CANDIDATES: &str = r#"SELECT frame.dedupe_key, frame.source_mac, frame.location_id, frame.sensor_id,
                  frame.observed_at, frame.bssid, frame.ssid, frame.frame_subtype,
                  security.security_flags, identity_row.handshake_captured,
                  COALESCE(NULLIF(identity_row.normalized_text, ''), CONCAT_WS(
                    ' ', frame.source_mac, frame.bssid, frame.ssid, frame.frame_subtype,
                    identity_row.wps_device_name, identity_row.wps_manufacturer,
                    identity_row.wps_model_name, network.app_protocol,
                    network.src_ip, network.dst_ip
                  )),
                  jsonb_build_object(
                    'dedupe_key', frame.dedupe_key,
                    'event_type', identity_row.event_type,
                    'identity_source', identity_row.identity_source,
                    'security_flags', security.security_flags
                  )
           FROM wireless_frames frame
           JOIN wireless_frame_identity identity_row ON identity_row.dedupe_key = frame.dedupe_key
           JOIN wireless_frame_security security ON security.dedupe_key = frame.dedupe_key
           LEFT JOIN wireless_frame_network network ON network.dedupe_key = frame.dedupe_key
           LEFT JOIN atheros_search.search_documents document
             ON document.source_table = 'wireless_frames'
            AND document.source_key = frame.dedupe_key
            AND document.source_kind = 'event'
            AND document.status = 'active'
           WHERE document.document_id IS NULL
           ORDER BY frame.observed_at, frame.dedupe_key
           LIMIT $1::int"#;

pub const DEVICE_CANDIDATES: &str = r#"SELECT device.mac, device.mac, device.location_id, CAST(NULL AS TEXT),
                  device.last_seen, CAST(NULL AS TEXT), CAST(NULL AS TEXT), CAST(NULL AS TEXT),
                  0, FALSE,
                  CONCAT_WS(' ', 'kind: device', device.mac, device.display_name, device.owner_id,
                    device.location_id),
                  jsonb_build_object(
                    'registered', device.registered,
                    'active', device.active,
                    'owner_id', device.owner_id,
                    'known_macs', device.known_macs,
                    'tags', device.tags
                  )
           FROM atheros_search.devices device
           LEFT JOIN atheros_search.search_documents document
             ON document.source_table = 'devices'
            AND document.source_key = device.mac
            AND document.source_kind = 'device'
            AND document.status = 'active'
           WHERE document.document_id IS NULL OR document.updated_at < device.updated_at
           ORDER BY device.last_seen, device.mac
           LIMIT $1::int"#;

pub const BEHAVIOUR_CANDIDATES: &str = r#"SELECT snapshot.snapshot_key, snapshot.source_mac, snapshot.location_id, snapshot.sensor_id,
                  snapshot.window_end, CAST(NULL AS TEXT), CAST(NULL AS TEXT),
                  CAST('behaviour_window' AS TEXT), 0, FALSE,
                  COALESCE(NULLIF(snapshot.embedding_text, ''), snapshot.text_summary),
                  jsonb_build_object(
                    'window_start', snapshot.window_start,
                    'window_end', snapshot.window_end,
                    'event_count', snapshot.event_count,
                    'protocol_mix', snapshot.protocol_mix,
                    'frame_type_distribution', snapshot.frame_type_distribution,
                    'text_summary', snapshot.text_summary
                  )
           FROM atheros_search.behaviour_snapshots snapshot
           LEFT JOIN atheros_search.search_documents document
             ON document.source_table = 'behaviour_snapshots'
            AND document.source_key = snapshot.snapshot_key
            AND document.source_kind = 'behaviour_window'
            AND document.status = 'active'
           WHERE (document.document_id IS NULL OR document.updated_at < snapshot.updated_at)
             AND COALESCE(NULLIF(snapshot.embedding_text, ''), NULLIF(snapshot.text_summary, '')) IS NOT NULL
           ORDER BY snapshot.window_end, snapshot.snapshot_key
           LIMIT $1::int"#;

pub const SEQUENCE_CANDIDATES: &str = r#"SELECT sequence_row.session_key, sequence_row.source_mac, sequence_row.location_id,
                  sequence_row.sensor_id, sequence_row.window_end, CAST(NULL AS TEXT), CAST(NULL AS TEXT),
                  CAST('frame_sequence' AS TEXT), 0, FALSE,
                  COALESCE(NULLIF(sequence_row.semantic_tokens, ''), sequence_row.sequence_tokens),
                  jsonb_build_object(
                    'window_start', sequence_row.window_start,
                    'window_end', sequence_row.window_end,
                    'frame_count', sequence_row.frame_count,
                    'sequence_tokens', sequence_row.sequence_tokens,
                    'semantic_tokens', sequence_row.semantic_tokens
                  )
           FROM atheros_search.frame_sequences sequence_row
           LEFT JOIN atheros_search.search_documents document
             ON document.source_table = 'frame_sequences'
            AND document.source_key = sequence_row.session_key
            AND document.source_kind = 'frame_sequence'
            AND document.status = 'active'
           WHERE (document.document_id IS NULL OR document.updated_at < sequence_row.updated_at)
             AND COALESCE(NULLIF(sequence_row.semantic_tokens, ''), NULLIF(sequence_row.sequence_tokens, '')) IS NOT NULL
           ORDER BY sequence_row.window_end, sequence_row.session_key
           LIMIT $1::int"#;
