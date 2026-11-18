//! Maintained projection queries. All identifiers are compile-time literals.

// Parameters: 1=AutomaticMergeSimilarity
pub const PROJECT_GRAPH_0: &str = r#"DELETE FROM atheros_search.graph_edges edge
                                       WHERE edge.edge_kind = 'same_device'
                                         AND NOT EXISTS (
                                           SELECT 1
                                           FROM atheros_search.merge_candidates candidate
                                           WHERE edge.edge_id = CONCAT('same-device:', candidate.candidate_id)
                                             AND candidate.status = 'confirmed'
                                             AND (
                                               (candidate.confirmation_source = 'human' AND EXISTS (
                                                 SELECT 1 FROM atheros_search.merge_decisions decision
                                                 WHERE decision.candidate_id = candidate.candidate_id
                                                   AND decision.decision = 'merge'
                                               ))
                                               OR
                                               (candidate.confirmation_source = 'automatic'
                                                 AND candidate.confidence >= $1
                                                 AND candidate.trusted_registered_device_id IS NOT NULL
                                                 AND NOT EXISTS (
                                                   SELECT 1 FROM atheros_search.merge_decisions decision
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
                                          )"#;

// Parameters:
pub const PROJECT_GRAPH_1: &str = r#"DELETE FROM atheros_search.graph_edges edge
                                           WHERE edge.edge_kind = 'identity_member'
                                             AND NOT EXISTS (
                                               SELECT 1
                                               FROM atheros_search.identity_cluster_members member
                                               WHERE edge.edge_id = CONCAT(
                                                 'identity-member:', member.cluster_id, ':', member.mac
                                               )
                                             )"#;

// Parameters:
pub const PROJECT_GRAPH_2: &str = r#"DELETE FROM atheros_search.graph_nodes node
                                     WHERE node.node_kind = 'identity_cluster'
                                       AND NOT EXISTS (
                                         SELECT 1
                                         FROM atheros_search.identity_clusters cluster
                                         WHERE node.node_id = CONCAT('identity:', cluster.cluster_id)
                                           AND cluster.status = 'active'
                                       )"#;

// Parameters: 1=projectionRunId, 2=batchLimit
pub const PROJECT_GRAPH_3: &str = r#"INSERT INTO atheros_search.graph_nodes (
                            node_id, node_kind, label, node_payload, location_id,
                            normalized_mac, is_threat, observed_at, projection_run_id
                          )
                          SELECT CONCAT('device:', device.mac_id), 'device', device.display_name,
                                 jsonb_build_object(
                                   'mac', device.mac_id,
                                   'explain_source_key', device.mac_id,
                                   'explain_kind', 'device',
                                   'username', registered.username,
                                   'hostname', registered.hostname,
                                   'os_hint', device.os_hint
                                 ), NULL, device.mac_id, FALSE,
                                 device.last_seen,
                                 $1
                          FROM devices device
                          LEFT JOIN octopus_core.registered_devices registered
                            ON registered.mac = device.mac_id
                          LEFT JOIN atheros_search.graph_nodes existing
                            ON existing.node_id = CONCAT('device:', device.mac_id)
                          ORDER BY (existing.node_id IS NULL) DESC,
                                   device.last_seen DESC, device.mac_id
                          LIMIT $2::int
                    ON CONFLICT (node_id) DO UPDATE SET
                      label = EXCLUDED.label,
                      node_payload = EXCLUDED.node_payload,
                      observed_at = GREATEST(
                        COALESCE(graph_nodes.observed_at, EXCLUDED.observed_at),
                        COALESCE(EXCLUDED.observed_at, graph_nodes.observed_at)
                      ),
                      updated_at = CURRENT_TIMESTAMP"#;

// Parameters: 1=projectionRunId, 2=batchLimit
pub const PROJECT_GRAPH_4: &str = r#"INSERT INTO atheros_search.graph_nodes (
                        node_id, node_kind, label, node_payload, location_id, sensor_id,
                        normalized_mac, normalized_ssid, is_threat, observed_at, projection_run_id
                      )
                      SELECT CONCAT('ap:', frame.bssid), 'access_point', MAX(frame.ssid),
                             jsonb_build_object(
                               'bssid', frame.bssid,
                               'risk_score', risk.composite_risk,
                               'alert_type', alert.alert_type,
                               'alert_severity', alert.severity,
                               'alert_evidence', alert.evidence,
                               'resolved_at', alert.resolved_at
                             ), MAX(frame.location_id), MAX(frame.sensor_id),
                             frame.bssid, MAX(frame.ssid), COALESCE(alert.severity IN ('high', 'critical'), FALSE), MAX(frame.observed_at), $1
                      FROM wireless_frames frame
                      LEFT JOIN atheros_search.ap_risk_scores risk
                        ON risk.bssid = frame.bssid
                      LEFT JOIN atheros_search.graph_nodes existing
                        ON existing.node_id = CONCAT('ap:', frame.bssid)
                      LEFT JOIN LATERAL (
                        SELECT wireless_alerts.alert_type,
                               wireless_alerts.severity,
                               wireless_alerts.resolved_at,
                               wireless_alerts.evidence
                        FROM octopus_core.wireless_alerts
                        WHERE wireless_alerts.subject_kind = 'access_point'
                          AND wireless_alerts.subject_id = frame.bssid
                          AND wireless_alerts.resolved_at IS NULL
                        ORDER BY wireless_alerts.detected_at DESC,
                                 CASE wireless_alerts.severity
                                   WHEN 'critical' THEN 1
                                   WHEN 'high' THEN 2
                                   WHEN 'medium' THEN 3
                                   WHEN 'low' THEN 4
                                   WHEN 'info' THEN 5
                                   ELSE 6
                                 END,
                                 wireless_alerts.alert_id
                        LIMIT 1
                      ) alert ON TRUE
                      WHERE frame.bssid IS NOT NULL
                      GROUP BY frame.bssid, risk.composite_risk, alert.alert_type, alert.severity,
                               alert.resolved_at, alert.evidence
                      ORDER BY COUNT(existing.node_id) = 0 DESC,
                               MAX(frame.observed_at) DESC, frame.bssid
                      LIMIT $2::int
                    ON CONFLICT (node_id) DO UPDATE SET
                      label = COALESCE(EXCLUDED.label, graph_nodes.label),
                      node_payload = EXCLUDED.node_payload,
                      location_id = COALESCE(EXCLUDED.location_id, graph_nodes.location_id),
                      sensor_id = COALESCE(EXCLUDED.sensor_id, graph_nodes.sensor_id),
                      is_threat = EXCLUDED.is_threat,
                      observed_at = GREATEST(
                        COALESCE(graph_nodes.observed_at, EXCLUDED.observed_at),
                        COALESCE(EXCLUDED.observed_at, graph_nodes.observed_at)
                      ),
                      updated_at = CURRENT_TIMESTAMP"#;

// Parameters: 1=projectionRunId, 2=batchLimit
pub const PROJECT_GRAPH_5: &str = r#"INSERT INTO atheros_search.graph_nodes (
                             node_id, node_kind, label, node_payload,
                             is_threat, observed_at, projection_run_id
                           )
                           SELECT CONCAT('identity:', cluster.cluster_id), 'identity_cluster',
                                  cluster.cluster_name,
                                  jsonb_build_object('cluster_size', cluster.cluster_size),
                                  FALSE, cluster.last_seen, $1
                           FROM atheros_search.identity_clusters cluster
                           WHERE cluster.status = 'active'
                           ORDER BY cluster.last_seen DESC, cluster.cluster_id
                           LIMIT $2::int
                    ON CONFLICT (node_id) DO UPDATE SET
                      label = EXCLUDED.label,
                      node_payload = EXCLUDED.node_payload,
                      observed_at = GREATEST(
                        COALESCE(graph_nodes.observed_at, EXCLUDED.observed_at),
                        COALESCE(EXCLUDED.observed_at, graph_nodes.observed_at)
                      ),
                      updated_at = CURRENT_TIMESTAMP"#;

// Parameters: 1=projectionRunId, 2=batchLimit
pub const PROJECT_GRAPH_6: &str = r#"INSERT INTO atheros_search.graph_edges (
                       edge_id, source_node_id, target_node_id, edge_kind,
                       weight, weight_basis, label, evidence, observed_at, projection_run_id
                     )
                     SELECT CONCAT('observed:', frame.source_mac, ':', frame.bssid),
                            CONCAT('device:', frame.source_mac), CONCAT('ap:', frame.bssid),
                            'observed_at', COUNT(*), 'frame_count', 'wireless observation',
                            jsonb_build_object('frame_count', COUNT(*)), MAX(frame.observed_at), $1
                     FROM wireless_frames frame
                     WHERE frame.source_mac IS NOT NULL AND frame.bssid IS NOT NULL
                       AND EXISTS (
                         SELECT 1 FROM atheros_search.graph_nodes device_node
                         WHERE device_node.node_id = CONCAT('device:', frame.source_mac)
                       )
                       AND EXISTS (
                         SELECT 1 FROM atheros_search.graph_nodes ap_node
                         WHERE ap_node.node_id = CONCAT('ap:', frame.bssid)
                       )
                     GROUP BY frame.source_mac, frame.bssid
                     ORDER BY NOT EXISTS (
                               SELECT 1 FROM atheros_search.graph_edges existing
                               WHERE existing.edge_id = CONCAT('observed:', frame.source_mac, ':', frame.bssid)
                             ) DESC,
                              MAX(frame.observed_at) DESC, frame.source_mac, frame.bssid
                     LIMIT $2::int
                     ON CONFLICT (edge_id) DO UPDATE SET
                       weight = EXCLUDED.weight,
                       weight_basis = EXCLUDED.weight_basis,
                       evidence = EXCLUDED.evidence,
                       observed_at = GREATEST(
                         COALESCE(graph_edges.observed_at, EXCLUDED.observed_at),
                         COALESCE(EXCLUDED.observed_at, graph_edges.observed_at)
                       ),
                       updated_at = CURRENT_TIMESTAMP"#;

// Parameters: 1=projectionRunId, 2=batchLimit
pub const PROJECT_GRAPH_7: &str = r#"INSERT INTO atheros_search.graph_edges (
                               edge_id, source_node_id, target_node_id, edge_kind,
                               weight, weight_basis, label, evidence, observed_at, projection_run_id
                             )
                             SELECT CONCAT('identity-member:', member.cluster_id, ':', member.mac),
                                    CONCAT('device:', member.mac), CONCAT('identity:', member.cluster_id),
                                    'identity_member', member.confidence, 'cluster_confidence',
                                    'approved identity membership',
                                    member.evidence, member.last_seen, $1
                             FROM atheros_search.identity_cluster_members member
                             WHERE EXISTS (
                               SELECT 1 FROM atheros_search.graph_nodes device_node
                               WHERE device_node.node_id = CONCAT('device:', member.mac)
                             )
                               AND EXISTS (
                               SELECT 1 FROM atheros_search.graph_nodes cluster_node
                               WHERE cluster_node.node_id = CONCAT('identity:', member.cluster_id)
                             )
                             ORDER BY member.last_seen DESC, member.cluster_id, member.mac
                             LIMIT $2::int
                             ON CONFLICT (edge_id) DO UPDATE SET
                               weight = EXCLUDED.weight,
                               weight_basis = EXCLUDED.weight_basis,
                               evidence = EXCLUDED.evidence,
                               observed_at = GREATEST(
                                 COALESCE(graph_edges.observed_at, EXCLUDED.observed_at),
                                 COALESCE(EXCLUDED.observed_at, graph_edges.observed_at)
                               ),
                                updated_at = CURRENT_TIMESTAMP"#;

// Parameters: 1=projectionRunId, 2=AutomaticMergeSimilarity, 3=batchLimit
pub const PROJECT_GRAPH_8: &str = r#"INSERT INTO atheros_search.graph_edges (
                                  edge_id, source_node_id, target_node_id, edge_kind,
                                  weight, weight_basis, label, evidence, observed_at, projection_run_id
                                )
                                SELECT CONCAT('same-device:', candidate.candidate_id),
                                       CONCAT('device:', candidate.mac_a), CONCAT('device:', candidate.mac_b),
                                       'same_device', candidate.confidence, 'cosine_similarity',
                                       'confirmed same device',
                                       jsonb_build_object(
                                         'candidate_id', candidate.candidate_id,
                                         'confirmation_source', candidate.confirmation_source
                                       ), candidate.confirmed_at, $1
                                FROM atheros_search.merge_candidates candidate
                                WHERE candidate.status = 'confirmed'
                                  AND (
                                    (candidate.confirmation_source = 'human' AND EXISTS (
                                      SELECT 1 FROM atheros_search.merge_decisions decision
                                      WHERE decision.candidate_id = candidate.candidate_id
                                        AND decision.decision = 'merge'
                                    ))
                                    OR
                                    (candidate.confirmation_source = 'automatic'
                                      AND candidate.confidence >= $2
                                      AND candidate.trusted_registered_device_id IS NOT NULL
                                      AND NOT EXISTS (
                                        SELECT 1 FROM atheros_search.merge_decisions decision
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
                                  AND EXISTS (
                                    SELECT 1 FROM atheros_search.graph_nodes left_node
                                    WHERE left_node.node_id = CONCAT('device:', candidate.mac_a)
                                  )
                                  AND EXISTS (
                                    SELECT 1 FROM atheros_search.graph_nodes right_node
                                    WHERE right_node.node_id = CONCAT('device:', candidate.mac_b)
                                  )
                                ORDER BY candidate.confirmed_at, candidate.candidate_id
                                LIMIT $3::int
                                ON CONFLICT (edge_id) DO UPDATE SET
                                  weight = EXCLUDED.weight,
                                  weight_basis = EXCLUDED.weight_basis,
                                  evidence = EXCLUDED.evidence,
                                  observed_at = EXCLUDED.observed_at,
                                  projection_run_id = EXCLUDED.projection_run_id,
                                  updated_at = CURRENT_TIMESTAMP"#;

// Parameters: 1=projectionRunId, 2=batchLimit
pub const PROJECT_GRAPH_9: &str = r#"INSERT INTO atheros_search.graph_edges (
                              edge_id, source_node_id, target_node_id, edge_kind,
                              weight, weight_basis, label, evidence, observed_at, projection_run_id
                            )
                            SELECT CONCAT('roaming:', pair.left_mac, ':', pair.right_mac),
                                   CONCAT('device:', LEAST(pair.left_mac, pair.right_mac)),
                                   CONCAT('device:', GREATEST(pair.left_mac, pair.right_mac)),
                                   'roaming', pair.shared_aps::double precision, 'time_overlap_windows',
                                   'devices observed on the same access points',
                                   jsonb_build_object('shared_bssids', pair.shared_aps, 'bssids', pair.bssid_list),
                                   pair.last_observed, $1
                            FROM (
                              SELECT LEAST(left_frame.source_mac, right_frame.source_mac) AS left_mac,
                                     GREATEST(left_frame.source_mac, right_frame.source_mac) AS right_mac,
                                     COUNT(DISTINCT left_frame.bssid) AS shared_aps,
                                     string_agg(DISTINCT left_frame.bssid, ',' ORDER BY left_frame.bssid) AS bssid_list,
                                     MAX(left_frame.observed_at) AS last_observed
                              FROM wireless_frames left_frame
                              JOIN wireless_frames right_frame
                                ON right_frame.bssid = left_frame.bssid
                               AND right_frame.source_mac IS NOT NULL
                               AND right_frame.source_mac <> left_frame.source_mac
                               AND right_frame.observed_at >= left_frame.observed_at - INTERVAL '10 minutes'
                               AND right_frame.observed_at <= left_frame.observed_at + INTERVAL '10 minutes'
                              WHERE left_frame.source_mac IS NOT NULL
                                AND left_frame.bssid IS NOT NULL
                              GROUP BY LEAST(left_frame.source_mac, right_frame.source_mac),
                                       GREATEST(left_frame.source_mac, right_frame.source_mac)
                            ) pair
                            WHERE EXISTS (
                              SELECT 1 FROM atheros_search.graph_nodes left_node
                              WHERE left_node.node_id = CONCAT('device:', pair.left_mac)
                            )
                              AND EXISTS (
                              SELECT 1 FROM atheros_search.graph_nodes right_node
                              WHERE right_node.node_id = CONCAT('device:', pair.right_mac)
                            )
                            ORDER BY pair.last_observed DESC, pair.left_mac, pair.right_mac
                            LIMIT $2::int
                            ON CONFLICT (edge_id) DO UPDATE SET
                              weight = EXCLUDED.weight,
                              weight_basis = EXCLUDED.weight_basis,
                              evidence = EXCLUDED.evidence,
                              observed_at = GREATEST(
                                COALESCE(graph_edges.observed_at, EXCLUDED.observed_at),
                                COALESCE(EXCLUDED.observed_at, graph_edges.observed_at)
                              ),
                              updated_at = CURRENT_TIMESTAMP"#;

// Parameters: 1=projectionRunId, 2=batchLimit
pub const PROJECT_GRAPH_10: &str = r#"INSERT INTO atheros_search.graph_edges (
                                  edge_id, source_node_id, target_node_id, edge_kind,
                                  weight, weight_basis, label, evidence, observed_at, projection_run_id
                                )
                                SELECT CONCAT('same-channel:', pair.left_mac, ':', pair.right_mac),
                                       CONCAT('device:', LEAST(pair.left_mac, pair.right_mac)),
                                       CONCAT('device:', GREATEST(pair.left_mac, pair.right_mac)),
                                       'same_channel', pair.shared_channels::double precision, 'channel_overlap',
                                       'devices observed on the same channel',
                                       jsonb_build_object('channels', pair.channel_list),
                                       pair.last_observed, $1
                                FROM (
                                  SELECT LEAST(left_frame.source_mac, right_frame.source_mac) AS left_mac,
                                         GREATEST(left_frame.source_mac, right_frame.source_mac) AS right_mac,
                                          COUNT(DISTINCT radio.channel_number) AS shared_channels,
                                          string_agg(DISTINCT radio.channel_number::text, ',' ORDER BY radio.channel_number::text) AS channel_list,
                                          MAX(left_frame.observed_at) AS last_observed
                                   FROM wireless_frames left_frame
                                   JOIN wireless_frames right_frame
                                     ON right_frame.source_mac IS NOT NULL
                                    AND right_frame.source_mac <> left_frame.source_mac
                                    AND right_frame.observed_at >= left_frame.observed_at - INTERVAL '10 minutes'
                                    AND right_frame.observed_at <= left_frame.observed_at + INTERVAL '10 minutes'
                                   JOIN wireless_frame_radio radio
                                     ON radio.dedupe_key = left_frame.dedupe_key
                                    AND radio.channel_number IS NOT NULL
                                   JOIN wireless_frame_radio right_radio
                                     ON right_radio.dedupe_key = right_frame.dedupe_key
                                    AND right_radio.channel_number = radio.channel_number
                                  WHERE left_frame.source_mac IS NOT NULL
                                  GROUP BY LEAST(left_frame.source_mac, right_frame.source_mac),
                                           GREATEST(left_frame.source_mac, right_frame.source_mac)
                                ) pair
                                WHERE pair.shared_channels >= 1
                                  AND EXISTS (
                                    SELECT 1 FROM atheros_search.graph_nodes left_node
                                    WHERE left_node.node_id = CONCAT('device:', pair.left_mac)
                                  )
                                  AND EXISTS (
                                    SELECT 1 FROM atheros_search.graph_nodes right_node
                                    WHERE right_node.node_id = CONCAT('device:', pair.right_mac)
                                  )
                                ORDER BY pair.last_observed DESC, pair.left_mac, pair.right_mac
                                LIMIT $2::int
                                ON CONFLICT (edge_id) DO UPDATE SET
                                  weight = EXCLUDED.weight,
                                  weight_basis = EXCLUDED.weight_basis,
                                  evidence = EXCLUDED.evidence,
                                  observed_at = GREATEST(
                                    COALESCE(graph_edges.observed_at, EXCLUDED.observed_at),
                                    COALESCE(EXCLUDED.observed_at, graph_edges.observed_at)
                                  ),
                                  updated_at = CURRENT_TIMESTAMP"#;

// Parameters: 1=projectionRunId, 2=batchLimit
pub const PROJECT_GRAPH_11: &str = r#"INSERT INTO atheros_search.graph_edges (
                                 edge_id, source_node_id, target_node_id, edge_kind,
                                 weight, weight_basis, label, evidence, observed_at, projection_run_id
                               )
                               SELECT CONCAT('vendor-link:', pair.left_mac, ':', pair.right_mac),
                                      CONCAT('device:', pair.left_mac),
                                      CONCAT('device:', pair.right_mac),
                                      'vendor_link', pair.shared_ouis::double precision, 'vendor_match',
                                      'devices observed with the same OUI vendor prefixes',
                                      jsonb_build_object('shared_ouis', pair.shared_ouis),
                                      pair.last_observed, $1
                               FROM (
                                 SELECT LEAST(left_oui.source_mac, right_oui.source_mac) AS left_mac,
                                        GREATEST(left_oui.source_mac, right_oui.source_mac) AS right_mac,
                                        COUNT(DISTINCT left_oui.bssid_oui) AS shared_ouis,
                                        MAX(left_oui.last_observed) AS last_observed
                                 FROM (
                                   SELECT frame.source_mac, frame.bssid_oui,
                                          MAX(frame.observed_at) AS last_observed
                                   FROM wireless_frames frame
                                   WHERE frame.source_mac IS NOT NULL
                                     AND frame.bssid_oui IS NOT NULL
                                   GROUP BY frame.source_mac, frame.bssid_oui
                                 ) left_oui
                                 JOIN (
                                   SELECT frame.source_mac, frame.bssid_oui
                                   FROM wireless_frames frame
                                   WHERE frame.source_mac IS NOT NULL
                                     AND frame.bssid_oui IS NOT NULL
                                   GROUP BY frame.source_mac, frame.bssid_oui
                                 ) right_oui
                                   ON right_oui.bssid_oui = left_oui.bssid_oui
                                  AND right_oui.source_mac > left_oui.source_mac
                                 GROUP BY LEAST(left_oui.source_mac, right_oui.source_mac),
                                          GREATEST(left_oui.source_mac, right_oui.source_mac)
                               ) pair
                               WHERE EXISTS (
                                 SELECT 1 FROM atheros_search.graph_nodes left_node
                                 WHERE left_node.node_id = CONCAT('device:', pair.left_mac)
                               )
                                 AND EXISTS (
                                 SELECT 1 FROM atheros_search.graph_nodes right_node
                                 WHERE right_node.node_id = CONCAT('device:', pair.right_mac)
                               )
                               ORDER BY pair.last_observed DESC, pair.left_mac, pair.right_mac
                               LIMIT $2::int
                               ON CONFLICT (edge_id) DO UPDATE SET
                                 weight = EXCLUDED.weight,
                                 weight_basis = EXCLUDED.weight_basis,
                                 evidence = EXCLUDED.evidence,
                                 observed_at = GREATEST(
                                   COALESCE(graph_edges.observed_at, EXCLUDED.observed_at),
                                   COALESCE(EXCLUDED.observed_at, graph_edges.observed_at)
                                 ),
                                 updated_at = CURRENT_TIMESTAMP"#;

// Parameters: 1=batchLimit
pub const PROJECT_GRAPH_12: &str = r#"INSERT INTO atheros_search.ap_catalog (
                           bssid, authorized, authorized_label, first_observed_at,
                           last_observed_at, last_sensor_id, updated_at
                         )
                         SELECT frame.bssid,
                                COALESCE(BOOL_OR(network.enabled), FALSE),
                                MAX(network.label) FILTER (WHERE network.enabled),
                                MIN(frame.observed_at), MAX(frame.observed_at),
                                MAX(frame.sensor_id), CURRENT_TIMESTAMP
                         FROM wireless_frames frame
                         LEFT JOIN octopus_core.wireless_authorized_networks network
                           ON network.bssid = frame.bssid
                         WHERE frame.bssid IS NOT NULL
                         GROUP BY frame.bssid
                         ORDER BY MAX(frame.observed_at) DESC, frame.bssid
                         LIMIT $1::int
                         ON CONFLICT (bssid) DO UPDATE SET
                           authorized = EXCLUDED.authorized,
                           authorized_label = EXCLUDED.authorized_label,
                           first_observed_at = LEAST(ap_catalog.first_observed_at, EXCLUDED.first_observed_at),
                           last_observed_at = GREATEST(ap_catalog.last_observed_at, EXCLUDED.last_observed_at),
                           last_sensor_id = EXCLUDED.last_sensor_id,
                           updated_at = CURRENT_TIMESTAMP"#;

// Parameters: 1=batchLimit
pub const PROJECT_GRAPH_13: &str = r#"WITH candidates AS MATERIALIZED (
                                 SELECT bucket.window_start, bucket.sensor_id, bucket.bssid,
                                        bucket.source_mac, bucket.bucket_updated_at,
                                        COALESCE(existing.projected_at, TIMESTAMPTZ 'epoch') AS projected_at
                                 FROM (
                                   SELECT date_trunc('hour', frame.observed_at)
                                            + floor(EXTRACT(minute FROM frame.observed_at) / 5) * INTERVAL '5 minutes'
                                            AS window_start,
                                          COALESCE(frame.sensor_id, 'unknown') AS sensor_id,
                                          frame.bssid AS bssid, frame.source_mac AS source_mac,
                                          MAX(frame.updated_at) AS bucket_updated_at
                                   FROM wireless_frames frame
                                   WHERE frame.source_mac IS NOT NULL
                                     AND frame.bssid IS NOT NULL
                                     AND frame.source_mac <> frame.bssid
                                     AND frame.source_mac NOT IN ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00')
                                     AND frame.bssid NOT IN ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00')
                                     AND GREATEST(frame.observed_at, frame.updated_at)
                                           >= CURRENT_TIMESTAMP - INTERVAL '7 days'
                                   GROUP BY 1, 2, 3, 4
                                 ) bucket
                                 LEFT JOIN atheros_search.wireless_signal_summaries existing
                                   ON existing.window_start = bucket.window_start
                                  AND existing.sensor_id = bucket.sensor_id
                                  AND existing.bssid = bucket.bssid
                                  AND existing.source_mac = bucket.source_mac
                                 ORDER BY COALESCE(existing.projected_at, TIMESTAMPTZ 'epoch') ASC,
                                          bucket.bucket_updated_at DESC
                                 LIMIT $1::int
                               )
                               INSERT INTO atheros_search.wireless_signal_summaries (
                                 window_start, sensor_id, location_id, bssid, source_mac,
                                 frame_count, rssi_sample_count, rssi_min_dbm, rssi_max_dbm,
                                 rssi_avg_dbm, first_observed_at, last_observed_at, projected_at
                               )
                               SELECT candidate.window_start, candidate.sensor_id,
                                      MAX(frame.location_id), candidate.bssid, candidate.source_mac,
                                      COUNT(*),
                                      COUNT(radio.signal_dbm), MIN(radio.signal_dbm), MAX(radio.signal_dbm),
                                      AVG(radio.signal_dbm)::double precision,
                                      MIN(frame.observed_at), MAX(frame.observed_at), CURRENT_TIMESTAMP
                               FROM candidates candidate
                               JOIN wireless_frames frame
                                 ON frame.bssid = candidate.bssid
                                AND frame.source_mac = candidate.source_mac
                                AND COALESCE(frame.sensor_id, 'unknown') = candidate.sensor_id
                                AND date_trunc('hour', frame.observed_at)
                                      + floor(EXTRACT(minute FROM frame.observed_at) / 5) * INTERVAL '5 minutes'
                                      = candidate.window_start
                               LEFT JOIN wireless_frame_radio radio ON radio.dedupe_key = frame.dedupe_key
                               GROUP BY candidate.window_start, candidate.sensor_id,
                                        candidate.bssid, candidate.source_mac
                               ON CONFLICT (window_start, sensor_id, bssid, source_mac) DO UPDATE SET
                                 location_id = EXCLUDED.location_id,
                                 frame_count = EXCLUDED.frame_count,
                                 rssi_sample_count = EXCLUDED.rssi_sample_count,
                                 rssi_min_dbm = EXCLUDED.rssi_min_dbm,
                                 rssi_max_dbm = EXCLUDED.rssi_max_dbm,
                                 rssi_avg_dbm = EXCLUDED.rssi_avg_dbm,
                                 first_observed_at = EXCLUDED.first_observed_at,
                                 last_observed_at = EXCLUDED.last_observed_at,
                                 projected_at = CURRENT_TIMESTAMP"#;

// Parameters:
pub const PROJECT_GRAPH_14: &str = r#"DELETE FROM atheros_search.wireless_signal_summaries summary
                                WHERE summary.window_start < CURRENT_TIMESTAMP - INTERVAL '1 day'
                                  AND NOT EXISTS (
                                    SELECT 1
                                    FROM wireless_frames frame
                                    WHERE frame.bssid = summary.bssid
                                      AND frame.source_mac = summary.source_mac
                                      AND COALESCE(frame.sensor_id, 'unknown') = summary.sensor_id
                                      AND frame.observed_at >= summary.window_start
                                      AND frame.observed_at < summary.window_start + INTERVAL '5 minutes'
                                  )"#;

// Parameters:
pub const PROJECT_GRAPH_15: &str = r#"DELETE FROM atheros_search.ap_catalog catalog
                              WHERE NOT EXISTS (
                                SELECT 1 FROM wireless_frames frame
                                WHERE frame.bssid = catalog.bssid
                              )"#;

// Parameters:
pub const PROJECT_GRAPH_16: &str = r#"WITH source AS (
                            SELECT MAX(observed_at) AS source_watermark_at
                            FROM wireless_frames
                          ),
                          projection AS (
                            SELECT MAX(last_observed_at) AS projection_watermark_at,
                                   MAX(projected_at) AS last_projected_at
                            FROM atheros_search.wireless_signal_summaries
                          )
                          INSERT INTO atheros_search.investigation_watermarks (
                            projection_name, source_watermark_at, projection_watermark_at,
                            coverage_status, coverage_reason, updated_at
                          )
                          SELECT 'wireless_evidence',
                                 source.source_watermark_at,
                                 projection.projection_watermark_at,
                                 CASE
                                   WHEN source.source_watermark_at IS NULL THEN 'unknown'
                                   WHEN projection.projection_watermark_at IS NULL THEN 'stalled'
                                   WHEN source.source_watermark_at - projection.projection_watermark_at
                                          > INTERVAL '15 minutes' THEN
                                     CASE WHEN projection.last_projected_at
                                               < CURRENT_TIMESTAMP - INTERVAL '6 hours'
                                          THEN 'stalled' ELSE 'partial' END
                                   ELSE 'complete'
                                 END,
                                 CASE
                                   WHEN source.source_watermark_at IS NULL
                                     THEN 'no retained wireless frames'
                                   WHEN projection.projection_watermark_at IS NULL
                                     THEN 'no five-minute signal summaries have been projected'
                                   WHEN source.source_watermark_at - projection.projection_watermark_at
                                          > INTERVAL '15 minutes' THEN
                                     'signal summaries lag the retained source watermark; '
                                       || 'the projection recomputes buckets written within the last seven days'
                                   ELSE NULL
                                 END,
                                 CURRENT_TIMESTAMP
                          FROM source, projection
                          ON CONFLICT (projection_name) DO UPDATE SET
                            source_watermark_at = EXCLUDED.source_watermark_at,
                            projection_watermark_at = EXCLUDED.projection_watermark_at,
                            coverage_status = EXCLUDED.coverage_status,
                            coverage_reason = EXCLUDED.coverage_reason,
                            updated_at = CURRENT_TIMESTAMP"#;

// Parameters:
pub const PROJECT_GRAPH_17: &str = r#"DELETE FROM atheros_search.graph_edges edge
                                     WHERE NOT EXISTS (
                                       SELECT 1 FROM atheros_search.graph_nodes source_node
                                       WHERE source_node.node_id = edge.source_node_id
                                     )
                                       OR NOT EXISTS (
                                       SELECT 1 FROM atheros_search.graph_nodes target_node
                                       WHERE target_node.node_id = edge.target_node_id
                                     )"#;

// Parameters:
pub const PROJECT_GRAPH_18: &str = r#"WITH source AS (
                                SELECT MAX(observed_at) AS source_watermark_at,
                                       COUNT(DISTINCT (source_mac, bssid)) AS pair_count,
                                       COUNT(DISTINCT source_mac) AS mac_count
                                FROM wireless_frames
                                WHERE source_mac IS NOT NULL AND bssid IS NOT NULL
                              ),
                              projection AS (
                                SELECT MAX(observed_at) AS projection_watermark_at,
                                       COUNT(*) AS pair_count
                                FROM atheros_search.graph_edges
                                WHERE edge_kind = 'observed_at'
                              ),
                              devices AS (
                                SELECT COUNT(*) AS device_count
                                FROM atheros_search.graph_nodes
                                WHERE node_kind = 'device'
                              )
                              INSERT INTO atheros_search.investigation_watermarks (
                                projection_name, source_watermark_at, projection_watermark_at,
                                coverage_status, coverage_reason, updated_at
                              )
                              SELECT 'graph_projection',
                                     source.source_watermark_at,
                                     projection.projection_watermark_at,
                                     CASE
                                       WHEN source.pair_count = 0 THEN 'unknown'
                                       WHEN projection.pair_count = 0 THEN 'stalled'
                                       WHEN projection.pair_count < source.pair_count THEN 'partial'
                                       ELSE 'complete'
                                     END,
                                     format(
                                       '%s of %s distinct (source_mac,bssid) pairs projected; %s device nodes vs %s frame source MACs',
                                       projection.pair_count, source.pair_count,
                                       devices.device_count, source.mac_count
                                     ),
                                     CURRENT_TIMESTAMP
                              FROM source, projection, devices
                              ON CONFLICT (projection_name) DO UPDATE SET
                                source_watermark_at = EXCLUDED.source_watermark_at,
                                projection_watermark_at = EXCLUDED.projection_watermark_at,
                                coverage_status = EXCLUDED.coverage_status,
                                coverage_reason = EXCLUDED.coverage_reason,
                                updated_at = CURRENT_TIMESTAMP"#;

// Parameters: 1=minimumSimilarity .max(-1.0d) .min(1.0d), 2=limit.max(1)
pub const SIMILARITY_EDGES_0: &str = r#"SELECT left_source_mac, right_source_mac, cosine_similarity
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
               WHERE candidate.mac_a = LEAST(pair.left_source_mac, pair.right_source_mac)
                 AND candidate.mac_b = GREATEST(pair.left_source_mac, pair.right_source_mac)
                 AND candidate.confidence >= pair.cosine_similarity
             )
           ORDER BY pair.computed_at, pair.pair_id
           LIMIT $2::int"#;

// Parameters: 1=AutomaticMergeSimilarity
pub const APPROVED_IDENTITY_EDGES_0: &str = r#"SELECT candidate.mac_a, candidate.mac_b, candidate.confidence
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
pub const PERSIST_MERGE_CANDIDATE_0: &str = r#"INSERT INTO atheros_search.merge_candidates (
             candidate_id, mac_a, mac_b, confidence, computed_at, status,
             evidence, expires_at, projection_run_id
           ) VALUES (
             $1, $2, $3, $4,
             CURRENT_TIMESTAMP, 'pending',
             jsonb_build_object('source', 'similarity_pairs'),
             (CURRENT_TIMESTAMP + (30) * INTERVAL '1 day'), $5
           ) ON CONFLICT (mac_a, mac_b) DO UPDATE SET
             confidence = GREATEST(merge_candidates.confidence, EXCLUDED.confidence),
             computed_at = EXCLUDED.computed_at,
             expires_at = EXCLUDED.expires_at,
             projection_run_id = EXCLUDED.projection_run_id,
             updated_at = CURRENT_TIMESTAMP"#;

// Parameters: 1=limit.max(1)
pub const RESOLVE_STALE_DNS_THREATS_0: &str = r#"WITH stale AS (
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
pub const DNS_CANDIDATES_0: &str = r#"WITH hosts AS (
             SELECT host, COUNT(*) AS blocked_count,
                    COALESCE(SUM(bytes_up + bytes_down), 0) AS attempted_bytes,
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
pub const PERSIST_DNS_THREAT_0: &str = r#"INSERT INTO atheros_search.threat_signals (
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
pub const AP_RISK_CANDIDATES_0: &str = r#"WITH bssids AS (
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
pub const PERSIST_AP_RISK_0: &str = r#"INSERT INTO atheros_search.ap_risk_scores (
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

// Parameters: batchLimit
pub const NORMALIZE_0: &str = r#"INSERT INTO wireless_frames (
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
pub const NORMALIZE_1: &str = r#"WITH missing AS MATERIALIZED (SELECT frame.dedupe_key
           FROM wireless_frames frame
           WHERE NOT EXISTS (
             SELECT 1 FROM  wireless_frame_radio  child
             WHERE child.dedupe_key = frame.dedupe_key
           ) AND EXISTS (
             SELECT 1 FROM sync_events event
             WHERE event.dedupe_key = frame.dedupe_key AND event.stream_name = 'wireless.audit'
           )
           ORDER BY frame.observed_at, frame.dedupe_key
           LIMIT $1::int) INSERT INTO wireless_frame_radio (
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
             ON CONFLICT (dedupe_key) DO NOTHING"#;

// Parameters: batchLimit
pub const NORMALIZE_2: &str = r#"WITH missing AS MATERIALIZED (SELECT frame.dedupe_key
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
pub const NORMALIZE_3: &str = r#"WITH missing AS MATERIALIZED (SELECT frame.dedupe_key
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
pub const NORMALIZE_4: &str = r#"WITH missing AS MATERIALIZED (SELECT frame.dedupe_key
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
pub const NORMALIZE_5: &str = r#"WITH missing AS MATERIALIZED (SELECT frame.dedupe_key
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
pub const NORMALIZE_6: &str = r#"WITH missing AS MATERIALIZED (SELECT frame.dedupe_key
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

// Parameters: batchLimit
pub const INVENTORY_0: &str = r#"INSERT INTO devices (
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
             JOIN (SELECT candidate.dedupe_key
         FROM wireless_frames candidate
         WHERE NOT EXISTS (
           SELECT 1 FROM wireless_inventory_projection_inputs applied
           WHERE applied.dedupe_key = candidate.dedupe_key
         )
         ORDER BY candidate.created_at, candidate.dedupe_key
         LIMIT $1::int) candidate
               ON candidate.dedupe_key = frame.dedupe_key
             LEFT JOIN wireless_frame_identity identity_row ON identity_row.dedupe_key = frame.dedupe_key
             LEFT JOIN wireless_frame_app_signals app_row ON app_row.dedupe_key = frame.dedupe_key
             WHERE frame.source_mac IS NOT NULL
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

// Parameters: batchLimit
pub const INVENTORY_1: &str = r#"INSERT INTO wireless_clients (
               ssid, client_mac, known_bssid, first_seen, last_seen,
               probe_count, location_id, updated_at
             )
             SELECT frame.ssid, frame.source_mac, MAX(frame.bssid),
                    MIN(frame.observed_at), MAX(frame.observed_at), COUNT(*),
                    MAX(frame.location_id), CURRENT_TIMESTAMP
             FROM wireless_frames frame
             JOIN (SELECT candidate.dedupe_key
         FROM wireless_frames candidate
         WHERE NOT EXISTS (
           SELECT 1 FROM wireless_inventory_projection_inputs applied
           WHERE applied.dedupe_key = candidate.dedupe_key
         )
         ORDER BY candidate.created_at, candidate.dedupe_key
         LIMIT $1::int) candidate
               ON candidate.dedupe_key = frame.dedupe_key
             WHERE frame.source_mac IS NOT NULL AND frame.ssid IS NOT NULL
             GROUP BY frame.ssid, frame.source_mac
             ON CONFLICT (ssid, client_mac) DO UPDATE SET
               known_bssid = COALESCE(EXCLUDED.known_bssid, wireless_clients.known_bssid),
               first_seen = LEAST(wireless_clients.first_seen, EXCLUDED.first_seen),
               last_seen = GREATEST(wireless_clients.last_seen, EXCLUDED.last_seen),
               probe_count = wireless_clients.probe_count + EXCLUDED.probe_count,
               location_id = COALESCE(EXCLUDED.location_id, wireless_clients.location_id),
               updated_at = CURRENT_TIMESTAMP"#;

// Parameters: batchLimit
pub const INVENTORY_2: &str = r#"INSERT INTO atheros_search.devices (
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
             ORDER BY device.last_seen, device.mac_id
             LIMIT $1::int
             ON CONFLICT (mac) DO UPDATE SET
               display_name = COALESCE(EXCLUDED.display_name, devices.display_name),
               first_seen = LEAST(devices.first_seen, EXCLUDED.first_seen),
               last_seen = GREATEST(devices.last_seen, EXCLUDED.last_seen),
               updated_at = CURRENT_TIMESTAMP"#;

// Parameters: batchLimit
pub const INVENTORY_3: &str = r#"INSERT INTO wireless_inventory_projection_inputs (dedupe_key, projected_at)
             SELECT candidate.dedupe_key, CURRENT_TIMESTAMP
             FROM (SELECT candidate.dedupe_key
         FROM wireless_frames candidate
         WHERE NOT EXISTS (
           SELECT 1 FROM wireless_inventory_projection_inputs applied
           WHERE applied.dedupe_key = candidate.dedupe_key
         )
         ORDER BY candidate.created_at, candidate.dedupe_key
         LIMIT $1::int) candidate
             ON CONFLICT (dedupe_key) DO UPDATE SET dedupe_key = EXCLUDED.dedupe_key"#;

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
