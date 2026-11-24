//! Maintained projection queries. All identifiers are compile-time literals.

// Parameters: 1=minimumSimilarity .max(-1.0d) .min(1.0d), 2=limit.max(1)
pub const SELECT_SIMILARITY_EDGES: &str = r#"SELECT left_source_mac, right_source_mac, cosine_similarity
           FROM atheros_search.similarity_pairs pair
           JOIN atheros_search.search_documents left_document
             ON left_document.document_id = pair.left_document_id
            AND left_document.status = 'active'
           JOIN atheros_search.search_documents right_document
             ON right_document.document_id = pair.right_document_id
            AND right_document.status = 'active'
           WHERE pair.pair_kind = 'device_device'
             AND pair.left_source_mac IS NOT NULL
             AND pair.right_source_mac IS NOT NULL
             AND pair.left_source_mac <> pair.right_source_mac
             AND pair.cosine_similarity >= $1
             AND NOT EXISTS (
               SELECT 1 FROM octopus_core.dq_scope_policies policy
               WHERE policy.mode = 'enabled' AND (policy.authorized_scope = '*' OR (
                 EXISTS (SELECT 1 FROM atheros_search.devices device
                         WHERE device.mac = pair.left_source_mac AND device.location_id = policy.authorized_scope)
                 AND EXISTS (SELECT 1 FROM atheros_search.devices device
                         WHERE device.mac = pair.right_source_mac AND device.location_id = policy.authorized_scope)
               ))
             )
             AND NOT EXISTS (
               SELECT 1 FROM atheros_search.merge_candidates candidate
               WHERE candidate.confidence >= pair.cosine_similarity
                 AND ((candidate.mac_a = pair.left_source_mac AND candidate.mac_b = pair.right_source_mac)
                   OR (candidate.mac_a = pair.right_source_mac AND candidate.mac_b = pair.left_source_mac))
             )
           ORDER BY pair.computed_at, pair.pair_id
           LIMIT $2::int"#;

// Parameters: 1=AutomaticMergeSimilarity
pub const SELECT_APPROVED_IDENTITY_EDGES: &str = r#"SELECT candidate.mac_a, candidate.mac_b, candidate.confidence
           FROM atheros_search.merge_candidates candidate
           WHERE candidate.status = 'confirmed'
             AND (
               (candidate.confirmation_source = 'human' AND EXISTS (
                 SELECT 1
                 FROM atheros_search.merge_decisions decision
                 WHERE decision.candidate_id = candidate.candidate_id
                   AND decision.decision = 'merge'
               ))
               OR
               (candidate.confirmation_source = 'automatic'
                 AND candidate.confidence >= $1
                 AND candidate.trusted_registered_device_id IS NOT NULL
                 AND NOT EXISTS (
                   SELECT 1
                   FROM atheros_search.merge_decisions decision
                   WHERE decision.candidate_id = candidate.candidate_id
                 )
                 AND EXISTS (
                   SELECT 1
                   FROM atheros_search.devices left_device
                   JOIN atheros_search.devices right_device
                     ON right_device.mac = candidate.mac_b
                    AND right_device.registered
                    AND right_device.registered_device_id = left_device.registered_device_id
                   WHERE left_device.mac = candidate.mac_a
                     AND left_device.registered
                     AND left_device.registered_device_id IS NOT NULL
                     AND left_device.registered_device_id = candidate.trusted_registered_device_id
                 ))
             )
           ORDER BY candidate.confirmed_at, candidate.candidate_id"#;

// Parameters: 1=candidateId, 2=ordered.head, 3=ordered.last, 4=confidence .max(0.0d) .min(1.0d), 5=runId
pub const UPSERT_MERGE_CANDIDATE: &str = r#"WITH refreshed_reverse AS (
             UPDATE atheros_search.merge_candidates SET
               confidence = GREATEST(confidence, $4),
               computed_at = CURRENT_TIMESTAMP,
               expires_at = CURRENT_TIMESTAMP + INTERVAL '30 days',
               projection_run_id = $5,
               updated_at = CURRENT_TIMESTAMP
             WHERE mac_a = $3 AND mac_b = $2
             RETURNING candidate_id
           ), inserted AS (
           INSERT INTO atheros_search.merge_candidates (
             candidate_id, mac_a, mac_b, confidence, computed_at, status,
             evidence, expires_at, projection_run_id
           ) SELECT
             $1, $2, $3, $4,
             CURRENT_TIMESTAMP, 'pending',
             jsonb_build_object('source', 'similarity_pairs'),
             (CURRENT_TIMESTAMP + (30) * INTERVAL '1 day'), $5
           WHERE NOT EXISTS (SELECT 1 FROM refreshed_reverse)
           ON CONFLICT (mac_a, mac_b) DO UPDATE SET
             confidence = GREATEST(merge_candidates.confidence, EXCLUDED.confidence),
             computed_at = EXCLUDED.computed_at,
             expires_at = EXCLUDED.expires_at,
             projection_run_id = EXCLUDED.projection_run_id,
             updated_at = CURRENT_TIMESTAMP
           RETURNING candidate_id
           )
           SELECT candidate_id FROM refreshed_reverse
           UNION ALL SELECT candidate_id FROM inserted"#;

// Parameters: 1=limit.max(1)
pub const RESOLVE_STALE_DNS_THREATS: &str = r#"WITH stale AS (
             SELECT signal.source_key
             FROM atheros_search.threat_signals signal
             WHERE signal.signal_type = 'dns_blocked_host'
               AND signal.resolved_at IS NULL
               AND NOT EXISTS (
                 SELECT 1 FROM proxy_events event
                 WHERE event.host = substring(signal.source_key from 5)
                   AND event.blocked = TRUE
                   AND event.event_time >= CURRENT_TIMESTAMP - INTERVAL '7 days'
                   AND event.event_time <= CURRENT_TIMESTAMP
                 OFFSET 1 LIMIT 1
               )
             ORDER BY signal.detected_at, signal.source_key
             LIMIT $1::int
             FOR UPDATE SKIP LOCKED
           )
           UPDATE atheros_search.threat_signals signal
           SET resolved_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
           FROM stale WHERE signal.source_key = stale.source_key"#;

// Parameters: 1=limit.max(1)
pub const SELECT_DNS_THREAT_CANDIDATES: &str = r#"WITH hosts AS (
             SELECT host, COUNT(*) AS blocked_count,
                    LEAST(COALESCE(SUM(bytes_up::numeric + bytes_down::numeric), 0),
                          9223372036854775807::numeric)::bigint AS attempted_bytes,
                    SUM(CASE WHEN event_time >= CURRENT_TIMESTAMP - INTERVAL '1 day' THEN 1 ELSE 0 END) AS recent_count,
                    MAX(event_time) AS last_seen
             FROM proxy_events
             WHERE blocked = true
               AND event_time >= CURRENT_TIMESTAMP - INTERVAL '7 days'
               AND event_time <= CURRENT_TIMESTAMP
             GROUP BY host
             HAVING COUNT(*) > 1
           )
           SELECT hosts.host, hosts.blocked_count, hosts.attempted_bytes, hosts.recent_count, hosts.last_seen
           FROM hosts
           LEFT JOIN atheros_search.threat_signals signal ON signal.source_key = 'dns:' || hosts.host
           ORDER BY signal.updated_at ASC NULLS FIRST, hosts.last_seen DESC, hosts.host
           LIMIT $1::int"#;

// Parameters: 1=value.sourceKey, 2=value.score, 3=value.signalId, 4=value.severity, 5=s"uncalibrated seven-day blocked-observation intensity for ${value.sourceKey, 6=value.evidenceJson, 7=value.detectedAt, 8=value.projectionRunId
pub const UPSERT_DNS_THREAT: &str = r#"INSERT INTO atheros_search.threat_signals (
             source_key, near_duplicate, shadow_open, risk_score, ap_risk,
             threat_tag_count, signal_id, signal_type, dedupe_key,
             score, severity, explanation_text, evidence, detected_at,
             projection_run_id, updated_at
           ) VALUES (
             $1, FALSE, FALSE, $2, 0, 1,
             $3::text::uuid, 'dns_blocked_host', $3,
             $2, $4,
             $5,
             CAST($6::text AS JSON), $7, $8::text::uuid,
             CURRENT_TIMESTAMP
           ) ON CONFLICT (source_key) DO UPDATE SET
             risk_score = EXCLUDED.risk_score,
             score = EXCLUDED.score,
             severity = EXCLUDED.severity,
             explanation_text = EXCLUDED.explanation_text,
             evidence = EXCLUDED.evidence,
             detected_at = EXCLUDED.detected_at,
             resolved_at = NULL,
             projection_run_id = EXCLUDED.projection_run_id,
             updated_at = CURRENT_TIMESTAMP"#;

// Parameters: 1=limit.max(1)
pub const SELECT_ACCESS_POINT_RISK_CANDIDATES: &str = r#"WITH bssids AS (
             SELECT frame.bssid
             FROM wireless_frames frame
             LEFT JOIN atheros_search.ap_risk_scores risk ON risk.bssid = frame.bssid
             WHERE frame.bssid IS NOT NULL
             GROUP BY frame.bssid, risk.measured_at
             ORDER BY risk.measured_at ASC NULLS FIRST, MAX(frame.observed_at) DESC, frame.bssid
             LIMIT $1::int
           ),
           alert_scores AS (
             SELECT COALESCE(alert.primary_mac, alert.secondary_mac) AS bssid,
                    MAX(CASE WHEN alert.alert_type IN ('deauth_flood', 'rogue_cluster') THEN 1 ELSE 0 END) AS deauth_score,
                    MAX(CASE WHEN alert.alert_type IN ('signal_anomaly', 'rogue_cluster') THEN 1 ELSE 0 END) AS signal_score,
                    MAX(CASE WHEN alert.alert_type = 'rogue_cluster' THEN 1 ELSE 0 END) AS typosquat_score
             FROM wireless_alerts alert
             JOIN bssids ON bssids.bssid = COALESCE(alert.primary_mac, alert.secondary_mac)
             WHERE alert.detected_at >= (CURRENT_TIMESTAMP + (-1) * INTERVAL '1 hour')
             GROUP BY COALESCE(alert.primary_mac, alert.secondary_mac)
           ),
           vendor_counts AS (
             SELECT peer.ssid, COUNT(DISTINCT peer.bssid_oui) AS vendor_count
             FROM wireless_frames peer
             WHERE peer.ssid IS NOT NULL
               AND peer.observed_at >= (CURRENT_TIMESTAMP + (-1) * INTERVAL '1 hour')
             GROUP BY peer.ssid
           ),
           vendor_scores AS (
             SELECT frame.bssid,
                    GREATEST(MAX(vendor_counts.vendor_count) - 1, 0) AS vendor_score
             FROM wireless_frames frame
             JOIN bssids ON bssids.bssid = frame.bssid
             JOIN vendor_counts ON vendor_counts.ssid = frame.ssid
             WHERE frame.bssid IS NOT NULL AND frame.ssid IS NOT NULL
               AND frame.observed_at >= (CURRENT_TIMESTAMP + (-1) * INTERVAL '1 hour')
             GROUP BY frame.bssid
           ),
           attributed_outliers AS (
             SELECT left_document.bssid AS bssid, pair.cosine_distance
             FROM atheros_search.similarity_pairs pair
             JOIN atheros_search.search_documents left_document
               ON left_document.document_id = pair.left_document_id
             JOIN atheros_search.search_documents right_document
               ON right_document.document_id = pair.right_document_id
             WHERE pair.computed_at >= (CURRENT_TIMESTAMP + (-1) * INTERVAL '1 hour')
               AND pair.cosine_distance > 0.15
             UNION ALL
             SELECT right_document.bssid AS bssid, pair.cosine_distance
             FROM atheros_search.similarity_pairs pair
             JOIN atheros_search.search_documents left_document
               ON left_document.document_id = pair.left_document_id
             JOIN atheros_search.search_documents right_document
               ON right_document.document_id = pair.right_document_id
             WHERE pair.computed_at >= (CURRENT_TIMESTAMP + (-1) * INTERVAL '1 hour')
               AND pair.cosine_distance > 0.15
           ),
           outlier_scores AS (
             SELECT attributed.bssid, MAX(attributed.cosine_distance) AS outlier_score
             FROM attributed_outliers attributed
             JOIN bssids ON bssids.bssid = attributed.bssid
             GROUP BY attributed.bssid
           )
           SELECT bssids.bssid,
                  CAST(COALESCE(alert_scores.deauth_score, 0) AS DOUBLE PRECISION),
                  CAST(COALESCE(alert_scores.signal_score, 0) AS DOUBLE PRECISION),
                  CAST(COALESCE(alert_scores.typosquat_score, 0) AS DOUBLE PRECISION),
                  CAST(COALESCE(vendor_scores.vendor_score, 0) AS DOUBLE PRECISION),
                  COALESCE(outlier_scores.outlier_score, 0)
           FROM bssids
           LEFT JOIN alert_scores ON alert_scores.bssid = bssids.bssid
           LEFT JOIN vendor_scores ON vendor_scores.bssid = bssids.bssid
           LEFT JOIN outlier_scores ON outlier_scores.bssid = bssids.bssid
           ORDER BY bssids.bssid"#;

// Parameters: 1=value.bssid, 2=value.composite, 3=value.signalRisk, 4=value.identityRisk, 5=value.behaviorRisk, 6=value.evidenceJson, 7=value.projectionRunId
pub const UPSERT_ACCESS_POINT_RISK: &str = r#"INSERT INTO atheros_search.ap_risk_scores (
             bssid, composite_risk, signal_risk, identity_risk, behaviour_risk,
             evidence, measured_at, projection_run_id
           ) VALUES (
             $1, $2::double precision, $3::double precision,
             $4::double precision, $5::double precision,
             CAST($6::text AS JSON), CURRENT_TIMESTAMP, $7::text::uuid
           ) ON CONFLICT (bssid) DO UPDATE SET
             composite_risk = EXCLUDED.composite_risk,
             signal_risk = EXCLUDED.signal_risk,
             identity_risk = EXCLUDED.identity_risk,
             behaviour_risk = EXCLUDED.behaviour_risk,
             evidence = EXCLUDED.evidence,
             measured_at = EXCLUDED.measured_at,
             projection_run_id = EXCLUDED.projection_run_id"#;

// Parameters: 1=windowSeconds, 2=signalThresholdDbm, 3=presenceWindowSeconds, 4=batchLimit, 5=window, 6=presenceWindow, 7=runId
pub const SHADOW_ALERTS: &str = r#"WITH candidates AS MATERIALIZED (SELECT DISTINCT
           e.dedupe_key,
           e.source_mac,
           e.observed_at,
           COALESCE(e.destination_bssid, e.bssid) AS destination_bssid,
           e.ssid,
           e.sensor_id,
           e.location_id,
           e.signal_dbm
         FROM sync_events e
         WHERE e.stream_name = 'wireless.audit'
           AND e.observed_at >= (CURRENT_TIMESTAMP + (-$1::int) * INTERVAL '1 second')
           AND e.payload IS NOT NULL
           AND NOT EXISTS (
             SELECT 1 FROM wireless_shadow_alert_inputs applied
             WHERE applied.dedupe_key = e.dedupe_key
           )
           AND e.source_mac IS NOT NULL
           AND e.source_mac ~ '^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$'
           AND e.signal_dbm >= $2
           AND NOT EXISTS (
             SELECT 1 FROM wireless_authorized_networks awn
             WHERE awn.enabled = TRUE
               AND (awn.location_id IS NULL OR awn.location_id = e.location_id)
               AND (awn.ssid IS NULL OR (e.ssid IS NOT NULL AND awn.ssid = e.ssid))
               AND (
                 awn.bssid IS NULL
                 OR (
                   COALESCE(e.destination_bssid, e.bssid) IS NOT NULL
                   AND awn.bssid = COALESCE(e.destination_bssid, e.bssid)
                 )
               )
           )
           AND NOT EXISTS (
             SELECT 1 FROM devices d
             WHERE d.mac_id = e.source_mac
               AND d.last_seen >= (CURRENT_TIMESTAMP + (-$3::int) * INTERVAL '1 second')
           )
         ORDER BY e.observed_at, e.dedupe_key
         LIMIT $4::int),
             marked AS (
               INSERT INTO wireless_shadow_alert_inputs (dedupe_key, source_mac, projected_at)
               SELECT w.dedupe_key, w.source_mac, CURRENT_TIMESTAMP
               FROM candidates w
               ON CONFLICT (dedupe_key) DO NOTHING
               RETURNING dedupe_key
             ), ranked AS (
               SELECT candidates.*,
                      MIN(observed_at) OVER (PARTITION BY source_mac) AS first_seen,
                      COUNT(*) OVER (PARTITION BY source_mac) AS input_count,
                      ROW_NUMBER() OVER (
                        PARTITION BY source_mac ORDER BY observed_at DESC, dedupe_key DESC
                      ) AS position
               FROM candidates
               JOIN marked USING (dedupe_key)
             ), upserted AS (
             INSERT INTO wireless_shadow_alerts (
               source_mac, first_occurred_at, last_occurred_at, occurrence_count,
               destination_bssid, ssid, sensor_id, location_id, signal_dbm,
               reason, evidence, created_at, updated_at, projection_run_id
             )
             SELECT
               w.source_mac, w.first_seen, w.observed_at, w.input_count,
               w.destination_bssid, w.ssid, w.sensor_id, w.location_id, w.signal_dbm,
               'strong_wireless_without_proxy_presence',
               jsonb_build_object(
                 'window_seconds', $5::int,
                 'signal_threshold_dbm', $2::int,
                 'presence_window_seconds', $6::int
               ),
               CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, $7
             FROM ranked w
             WHERE w.position = 1
             ON CONFLICT (source_mac) DO UPDATE SET
               first_occurred_at = LEAST(wireless_shadow_alerts.first_occurred_at, EXCLUDED.first_occurred_at),
               last_occurred_at = GREATEST(wireless_shadow_alerts.last_occurred_at, EXCLUDED.last_occurred_at),
               occurrence_count = wireless_shadow_alerts.occurrence_count + EXCLUDED.occurrence_count,
               destination_bssid = CASE WHEN EXCLUDED.last_occurred_at >= wireless_shadow_alerts.last_occurred_at THEN EXCLUDED.destination_bssid ELSE wireless_shadow_alerts.destination_bssid END,
               ssid = CASE WHEN EXCLUDED.last_occurred_at >= wireless_shadow_alerts.last_occurred_at THEN EXCLUDED.ssid ELSE wireless_shadow_alerts.ssid END,
               sensor_id = CASE WHEN EXCLUDED.last_occurred_at >= wireless_shadow_alerts.last_occurred_at THEN EXCLUDED.sensor_id ELSE wireless_shadow_alerts.sensor_id END,
               location_id = CASE WHEN EXCLUDED.last_occurred_at >= wireless_shadow_alerts.last_occurred_at THEN EXCLUDED.location_id ELSE wireless_shadow_alerts.location_id END,
               signal_dbm = CASE WHEN EXCLUDED.last_occurred_at >= wireless_shadow_alerts.last_occurred_at THEN EXCLUDED.signal_dbm ELSE wireless_shadow_alerts.signal_dbm END,
               projection_run_id = EXCLUDED.projection_run_id,
               updated_at = CURRENT_TIMESTAMP
             RETURNING source_mac, first_occurred_at, last_occurred_at, occurrence_count,
                       destination_bssid, ssid, sensor_id, location_id, signal_dbm, reason, evidence
             )
             SELECT jsonb_build_object(
               'event_type', 'shadow_device',
               'first_occurred_at', first_occurred_at,
               'last_occurred_at', last_occurred_at,
               'source_mac', source_mac,
               'occurrence_count', occurrence_count,
               'destination_bssid', destination_bssid,
               'ssid', ssid,
               'sensor_id', sensor_id,
               'location_id', location_id,
               'signal_dbm', signal_dbm,
               'reason', reason,
               'evidence', evidence
             ) AS alert_json
             FROM upserted"#;
