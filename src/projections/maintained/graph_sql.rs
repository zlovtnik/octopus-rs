//! Infrastructure graph, signal coverage, and projection watermark statements.

// Parameters: 1=AutomaticMergeSimilarity
const DELETE_STALE_SAME_DEVICE_EDGES: &str = r#"DELETE FROM atheros_search.graph_edges edge
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
                                                 AND NOT EXISTS (
                                                   SELECT 1 FROM atheros_search.merge_candidates reverse_candidate
                                                   JOIN atheros_search.merge_decisions decision USING (candidate_id)
                                                   WHERE reverse_candidate.mac_a = candidate.mac_b
                                                     AND reverse_candidate.mac_b = candidate.mac_a
                                                     AND decision.decision <> 'merge'
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
pub(super) const DELETE_STALE_IDENTITY_MEMBER_EDGES: &str = r#"DELETE FROM atheros_search.graph_edges edge
                                           WHERE edge.edge_kind = 'identity_member'
                                             AND NOT EXISTS (
                                               SELECT 1
                                               FROM atheros_search.identity_cluster_members member
                                               WHERE edge.edge_id = CONCAT(
                                                 'identity-member:', member.cluster_id, ':', member.mac
                                               )
                                             )"#;

pub(super) const DELETE_STALE_OBSERVATION_EDGES: &str = r#"DELETE FROM atheros_search.graph_edges edge
                              WHERE edge.edge_kind = 'observed_at'
                                AND NOT EXISTS (
                                  SELECT 1 FROM wireless_frames frame
                                  WHERE frame.source_mac = substr(edge.source_node_id, 8)
                                    AND frame.bssid = substr(edge.target_node_id, 4)
                                    AND edge.edge_id = CONCAT('observed:', frame.source_mac, ':', frame.bssid)
                                )"#;

// Parameters:
pub(super) const DELETE_STALE_IDENTITY_CLUSTER_EDGES: &str = r#"DELETE FROM atheros_search.graph_edges edge
                                     USING atheros_search.graph_nodes node
                                     WHERE node.node_kind = 'identity_cluster'
                                       AND node.node_id IN (edge.source_node_id, edge.target_node_id)
                                       AND NOT EXISTS (
                                         SELECT 1
                                         FROM atheros_search.identity_clusters cluster
                                         WHERE node.node_id = CONCAT('identity:', cluster.cluster_id)
                                           AND cluster.status = 'active'
                                       )"#;

pub(super) const DELETE_STALE_IDENTITY_CLUSTER_NODES: &str = r#"DELETE FROM atheros_search.graph_nodes node
                                     WHERE node.node_kind = 'identity_cluster'
                                       AND NOT EXISTS (
                                         SELECT 1
                                         FROM atheros_search.identity_clusters cluster
                                         WHERE node.node_id = CONCAT('identity:', cluster.cluster_id)
                                           AND cluster.status = 'active'
                                       )"#;

// Parameters: 1=projectionRunId, 2=batchLimit
pub(super) const UPSERT_DEVICE_NODES: &str = r#"INSERT INTO atheros_search.graph_nodes (
                            node_id, node_kind, label, node_payload, location_id,
                            normalized_mac, is_threat, observed_at, projection_run_id
                          )
                          SELECT CONCAT('device:', device.mac_id), 'device', device.display_name,
                                 payload.value, NULL, device.mac_id, FALSE,
                                 device.last_seen,
                                 $1
                          FROM devices device
                          LEFT JOIN octopus_core.registered_devices registered
                            ON registered.mac = device.mac_id
                          LEFT JOIN atheros_search.graph_nodes existing
                            ON existing.node_id = CONCAT('device:', device.mac_id)
                          CROSS JOIN LATERAL (
                            SELECT jsonb_build_object(
                              'mac', device.mac_id,
                              'explain_source_key', device.mac_id,
                              'explain_kind', 'device',
                              'username', registered.username,
                              'hostname', registered.hostname,
                              'os_hint', device.os_hint
                            ) AS value
                          ) payload
                          ORDER BY (existing.node_id IS NULL) DESC,
                                   (existing.label IS DISTINCT FROM device.display_name
                                    OR existing.node_payload IS DISTINCT FROM payload.value
                                    OR (device.last_seen IS NOT NULL AND
                                        (existing.observed_at IS NULL OR device.last_seen > existing.observed_at))) DESC,
                                   existing.updated_at ASC,
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
pub(super) const UPSERT_ACCESS_POINT_NODES: &str = r#"INSERT INTO atheros_search.graph_nodes (
                        node_id, node_kind, label, node_payload, location_id, sensor_id,
                        normalized_mac, normalized_ssid, is_threat, observed_at, projection_run_id
                      )
                      SELECT CONCAT('ap:', frame.bssid), 'access_point', MAX(frame.ssid),
                             payload.value, MAX(frame.location_id), MAX(frame.sensor_id),
                             frame.bssid, MAX(frame.ssid), payload.is_threat, MAX(frame.observed_at), $1
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
                      CROSS JOIN LATERAL (
                        SELECT jsonb_build_object(
                                 'bssid', frame.bssid,
                                 'risk_score', risk.composite_risk,
                                 'alert_type', alert.alert_type,
                                 'alert_severity', alert.severity,
                                 'alert_evidence', alert.evidence,
                                 'resolved_at', alert.resolved_at
                               ) AS value,
                               COALESCE(alert.severity IN ('high', 'critical'), FALSE) AS is_threat
                      ) payload
                      WHERE frame.bssid IS NOT NULL
                      GROUP BY frame.bssid, payload.value, payload.is_threat, existing.node_id
                      ORDER BY (existing.node_id IS NULL) DESC,
                               (existing.is_threat IS DISTINCT FROM payload.is_threat
                                OR existing.node_payload IS DISTINCT FROM payload.value
                                OR (MAX(frame.location_id) IS NOT NULL
                                    AND existing.location_id IS DISTINCT FROM MAX(frame.location_id))
                                OR (MAX(frame.sensor_id) IS NOT NULL
                                    AND existing.sensor_id IS DISTINCT FROM MAX(frame.sensor_id))
                                OR (MAX(frame.observed_at) IS NOT NULL AND
                                    (existing.observed_at IS NULL OR MAX(frame.observed_at) > existing.observed_at))
                                OR (MAX(frame.ssid) IS NOT NULL
                                    AND (existing.label IS DISTINCT FROM MAX(frame.ssid)
                                         OR existing.normalized_ssid IS DISTINCT FROM MAX(frame.ssid)))) DESC,
                               existing.updated_at ASC,
                               MAX(frame.observed_at) DESC, frame.bssid
                      LIMIT $2::int
                    ON CONFLICT (node_id) DO UPDATE SET
                      label = COALESCE(EXCLUDED.label, graph_nodes.label),
                      normalized_ssid = COALESCE(EXCLUDED.normalized_ssid, graph_nodes.normalized_ssid),
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
pub(super) const UPSERT_IDENTITY_CLUSTER_NODES: &str = r#"INSERT INTO atheros_search.graph_nodes (
                             node_id, node_kind, label, node_payload,
                             is_threat, observed_at, projection_run_id
                           )
                           SELECT CONCAT('identity:', cluster.cluster_id), 'identity_cluster',
                                  cluster.cluster_name,
                                  jsonb_build_object('cluster_size', cluster.cluster_size),
                                  FALSE, cluster.last_seen, $1
                           FROM atheros_search.identity_clusters cluster
                           LEFT JOIN atheros_search.graph_nodes existing
                             ON existing.node_id = CONCAT('identity:', cluster.cluster_id)
                           WHERE cluster.status = 'active'
                           ORDER BY (existing.node_id IS NULL) DESC,
                                    (existing.label IS DISTINCT FROM cluster.cluster_name
                                     OR existing.node_payload IS DISTINCT FROM jsonb_build_object('cluster_size', cluster.cluster_size)
                                     OR (cluster.last_seen IS NOT NULL AND
                                         (existing.observed_at IS NULL OR cluster.last_seen > existing.observed_at))) DESC,
                                    existing.updated_at ASC NULLS FIRST,
                                    cluster.last_seen DESC, cluster.cluster_id
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
pub(super) const UPSERT_OBSERVATION_EDGES: &str = r#"INSERT INTO atheros_search.graph_edges (
                       edge_id, source_node_id, target_node_id, edge_kind,
                       weight, weight_basis, label, evidence, observed_at, projection_run_id
                     )
                     SELECT CONCAT('observed:', frame.source_mac, ':', frame.bssid),
                            CONCAT('device:', frame.source_mac), CONCAT('ap:', frame.bssid),
                            'observed_at', COUNT(*), 'frame_count', 'wireless observation',
                            jsonb_build_object('frame_count', COUNT(*)), MAX(frame.observed_at), $1
                     FROM wireless_frames frame
                     LEFT JOIN atheros_search.graph_edges existing
                       ON existing.edge_id = CONCAT('observed:', frame.source_mac, ':', frame.bssid)
                     WHERE frame.source_mac IS NOT NULL AND frame.bssid IS NOT NULL
                       AND EXISTS (
                         SELECT 1 FROM atheros_search.graph_nodes device_node
                         WHERE device_node.node_id = CONCAT('device:', frame.source_mac)
                       )
                       AND EXISTS (
                         SELECT 1 FROM atheros_search.graph_nodes ap_node
                         WHERE ap_node.node_id = CONCAT('ap:', frame.bssid)
                       )
                     GROUP BY frame.source_mac, frame.bssid, existing.edge_id
                     ORDER BY (existing.edge_id IS NULL) DESC,
                              (existing.weight IS DISTINCT FROM COUNT(*)::double precision
                               OR existing.evidence->'frame_count' IS DISTINCT FROM to_jsonb(COUNT(*))
                               OR existing.observed_at IS NULL
                               OR MAX(frame.observed_at) > existing.observed_at) DESC,
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
pub(super) const UPSERT_IDENTITY_MEMBER_EDGES: &str = r#"INSERT INTO atheros_search.graph_edges (
                               edge_id, source_node_id, target_node_id, edge_kind,
                               weight, weight_basis, label, evidence, observed_at, projection_run_id
                             )
                             SELECT CONCAT('identity-member:', member.cluster_id, ':', member.mac),
                                    CONCAT('device:', member.mac), CONCAT('identity:', member.cluster_id),
                                    'identity_member', member.confidence, 'cluster_confidence',
                                    'approved identity membership',
                                    member.evidence, member.last_seen, $1
                             FROM atheros_search.identity_cluster_members member
                             LEFT JOIN atheros_search.graph_edges existing
                               ON existing.edge_id = CONCAT('identity-member:', member.cluster_id, ':', member.mac)
                             WHERE EXISTS (
                               SELECT 1 FROM atheros_search.graph_nodes device_node
                               WHERE device_node.node_id = CONCAT('device:', member.mac)
                             )
                               AND EXISTS (
                               SELECT 1 FROM atheros_search.graph_nodes cluster_node
                               WHERE cluster_node.node_id = CONCAT('identity:', member.cluster_id)
                             )
                             ORDER BY (existing.edge_id IS NULL
                                       OR existing.weight IS DISTINCT FROM member.confidence
                                       OR existing.evidence IS DISTINCT FROM member.evidence
                                       OR (member.last_seen IS NOT NULL AND
                                           (existing.observed_at IS NULL OR member.last_seen > existing.observed_at))) DESC,
                                      member.last_seen DESC, member.cluster_id, member.mac
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
pub(super) const UPSERT_SAME_DEVICE_EDGES: &str = r#"INSERT INTO atheros_search.graph_edges (
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
                                LEFT JOIN atheros_search.graph_edges existing
                                  ON existing.edge_id = CONCAT('same-device:', candidate.candidate_id)
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
                                      AND NOT EXISTS (
                                        SELECT 1 FROM atheros_search.merge_candidates reverse_candidate
                                        JOIN atheros_search.merge_decisions decision USING (candidate_id)
                                        WHERE reverse_candidate.mac_a = candidate.mac_b
                                          AND reverse_candidate.mac_b = candidate.mac_a
                                          AND decision.decision <> 'merge'
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
                                ORDER BY (existing.edge_id IS NULL
                                          OR existing.weight IS DISTINCT FROM candidate.confidence
                                          OR existing.observed_at IS DISTINCT FROM candidate.confirmed_at
                                          OR existing.evidence IS DISTINCT FROM jsonb_build_object(
                                            'candidate_id', candidate.candidate_id,
                                            'confirmation_source', candidate.confirmation_source
                                          )) DESC,
                                         candidate.confirmed_at, candidate.candidate_id
                                LIMIT $3::int
                                ON CONFLICT (edge_id) DO UPDATE SET
                                  weight = EXCLUDED.weight,
                                  weight_basis = EXCLUDED.weight_basis,
                                  evidence = EXCLUDED.evidence,
                                  observed_at = EXCLUDED.observed_at,
                                  projection_run_id = EXCLUDED.projection_run_id,
                                  updated_at = CURRENT_TIMESTAMP"#;

// Page the possible pairs before expanding their evidence. A shared BSSID can
// contain thousands of devices. Its ordered membership is linear in the input,
// while the number of pairs is quadratic. The graph lock serializes all cursor
// reads and advances with the corresponding writes.
pub(super) const LOCK_GRAPH_CURSORS: &str =
    "SELECT pg_advisory_xact_lock(hashtextextended('octopus-graph-roaming', 0)) IS NULL";

// Enumerate a bounded slice of each key's sorted membership before loading
// evidence. The cursor and every edge on its page commit together.
macro_rules! paged_observation_edges {
    ($shard:literal, $page_size:literal, $membership:literal, $edges:literal) => {
        concat!(
            r#"WITH cursor AS MATERIALIZED (
                                SELECT COALESCE((
                                  SELECT checkpoint_value::jsonb FROM octopus_core.processor_checkpoints
                                  WHERE processor_name = 'wireless-identity-projector' AND shard_id = '"#,
            $shard,
            r#"'
                                ), '[]'::jsonb) AS position,
                                "#,
            $page_size,
            r#" AS page_size
                              ), members AS MATERIALIZED (
                                SELECT source.*,
                                       ROW_NUMBER() OVER (PARTITION BY shared_key ORDER BY source_mac) AS member_index,
                                       COUNT(*) OVER (PARTITION BY shared_key) AS member_count
                                FROM ("#,
            $membership,
            r#") source
                              ), cursor_right AS (
                                SELECT MAX(member_index) AS member_index
                                FROM members CROSS JOIN cursor
                                WHERE shared_key = position->>0 AND source_mac <= position->>2
                              ), left_members AS (
                                SELECT shared_key, source_mac, member_count,
                                       CASE WHEN (shared_key, source_mac) = (position->>0, position->>1)
                                            THEN GREATEST(member.member_index + 1, cursor_right.member_index + 1)
                                            ELSE member.member_index + 1 END AS first_right
                                FROM members member CROSS JOIN cursor CROSS JOIN cursor_right
                                WHERE member.member_index < member_count
                                  AND (position->>0 IS NULL OR (shared_key, source_mac) >= (position->>0, position->>1))
                              ), page_spans AS (
                                SELECT *,
                                       COALESCE(SUM(member_count - first_right + 1) OVER (
                                         ORDER BY shared_key, source_mac ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
                                       ), 0) AS pairs_before
                                FROM left_members
                              ), page_indexes AS MATERIALIZED (
                                SELECT shared_key, source_mac AS left_mac, right_index
                                FROM page_spans CROSS JOIN cursor
                                CROSS JOIN LATERAL generate_series(
                                  first_right,
                                  LEAST(member_count, first_right - 1 + page_size - pairs_before)::bigint
                                ) right_index
                                WHERE pairs_before < page_size
                              ), page AS MATERIALIZED (
                                SELECT page_indexes.shared_key, left_mac, member.source_mac AS right_mac
                                FROM page_indexes JOIN members member
                                  ON member.shared_key = page_indexes.shared_key AND member.member_index = page_indexes.right_index
                              ), saved_position AS (
                                INSERT INTO octopus_core.processor_checkpoints AS checkpoint
                                  (processor_name, shard_id, checkpoint_value)
                                SELECT 'wireless-identity-projector', '"#,
            $shard,
            r#"',
                                       (SELECT jsonb_build_array(shared_key, left_mac, right_mac)::text FROM page
                                        WHERE (SELECT COUNT(*) FROM page) = cursor.page_size
                                        ORDER BY shared_key DESC, left_mac DESC, right_mac DESC
                                        LIMIT 1)
                                FROM cursor
                                ON CONFLICT (processor_name, shard_id) DO UPDATE SET
                                  checkpoint_value = EXCLUDED.checkpoint_value, updated_at = CURRENT_TIMESTAMP
                                WHERE checkpoint.checkpoint_value IS DISTINCT FROM EXCLUDED.checkpoint_value
                              ), candidate_pairs AS MATERIALIZED (
                                SELECT DISTINCT left_mac, right_mac FROM page
                              )"#,
            $edges
        )
    };
}

// Parameters: 1=projectionRunId, 2=batchLimit
pub(super) const UPSERT_ROAMING_EDGES: &str = paged_observation_edges!(
    "graph-roaming",
    "GREATEST($2::int, 64)",
    r#"SELECT DISTINCT frame.bssid AS shared_key, frame.source_mac
       FROM wireless_frames frame
       JOIN atheros_search.graph_nodes node ON node.node_id = CONCAT('device:', frame.source_mac)
       WHERE frame.source_mac IS NOT NULL AND frame.bssid IS NOT NULL"#,
    r#", matches AS (
                                SELECT candidate.left_mac, candidate.right_mac,
                                       evidence.shared_key, evidence.last_observed
                                FROM candidate_pairs candidate
                                CROSS JOIN LATERAL (
                                  SELECT left_observation.bssid AS shared_key,
                                         GREATEST(upper(left_observation.observed_times * right_observation.overlap_windows),
                                                  upper(right_observation.observed_times * left_observation.overlap_windows)) AS last_observed
                                  FROM (
                                    SELECT bssid,
                                           range_agg(tstzrange(observed_at, observed_at, '[]')) AS observed_times,
                                           range_agg(tstzrange(observed_at - INTERVAL '10 minutes',
                                                              observed_at + INTERVAL '10 minutes', '[]')) AS overlap_windows
                                    FROM wireless_frames
                                    WHERE source_mac = candidate.left_mac AND bssid IS NOT NULL
                                    GROUP BY bssid
                                  ) left_observation
                                  JOIN (
                                    SELECT bssid,
                                           range_agg(tstzrange(observed_at, observed_at, '[]')) AS observed_times,
                                           range_agg(tstzrange(observed_at - INTERVAL '10 minutes',
                                                              observed_at + INTERVAL '10 minutes', '[]')) AS overlap_windows
                                    FROM wireless_frames
                                    WHERE source_mac = candidate.right_mac AND bssid IS NOT NULL
                                    GROUP BY bssid
                                  ) right_observation
                                    ON right_observation.bssid = left_observation.bssid
                                   AND left_observation.observed_times && right_observation.overlap_windows
                                ) evidence
                              )
                              INSERT INTO atheros_search.graph_edges (
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
                                  SELECT left_mac, right_mac,
                                         COUNT(DISTINCT shared_key) AS shared_aps,
                                         string_agg(DISTINCT shared_key, ',' ORDER BY shared_key) AS bssid_list,
                                         MAX(last_observed) AS last_observed
                                  FROM matches
                                  GROUP BY left_mac, right_mac
                            ) pair
                            ON CONFLICT (edge_id) DO UPDATE SET
                              weight = EXCLUDED.weight,
                              weight_basis = EXCLUDED.weight_basis,
                              evidence = EXCLUDED.evidence,
                              observed_at = GREATEST(
                                COALESCE(graph_edges.observed_at, EXCLUDED.observed_at),
                                COALESCE(EXCLUDED.observed_at, graph_edges.observed_at)
                              ),
                              updated_at = CURRENT_TIMESTAMP"#
);

// Parameters: 1=projectionRunId, 2=batchLimit
// Seek qualifying right devices one left device at a time and stop at a full
// page. Combine overlapping time windows before looking up right-hand frames.
pub(super) const UPSERT_SAME_CHANNEL_EDGES: &str = r#"WITH RECURSIVE cursor AS MATERIALIZED (
                                SELECT checkpoint_value::jsonb AS position
                                FROM octopus_core.processor_checkpoints
                                WHERE processor_name = 'wireless-identity-projector' AND shard_id = 'graph-same-channel'
                              ), radio_members AS MATERIALIZED (
                                SELECT DISTINCT frame.source_mac, radio.frequency_mhz, radio.channel_number
                                FROM wireless_frames frame
                                JOIN wireless_frame_radio radio USING (dedupe_key)
                                JOIN atheros_search.graph_nodes node ON node.node_id = CONCAT('device:', frame.source_mac)
                                WHERE frame.source_mac IS NOT NULL
                                  AND (radio.channel_number IS NOT NULL OR radio.frequency_mhz IS NOT NULL)
                              ), shared_frequencies AS (
                                SELECT frequency_mhz FROM radio_members
                                WHERE frequency_mhz IS NOT NULL
                                GROUP BY frequency_mhz HAVING MIN(source_mac) <> MAX(source_mac)
                              ), shared_channels AS (
                                SELECT channel_number FROM radio_members
                                WHERE channel_number IS NOT NULL
                                GROUP BY channel_number
                                HAVING MIN(source_mac) <> MAX(source_mac) AND BOOL_OR(frequency_mhz IS NULL)
                              ), sources AS MATERIALIZED (
                                SELECT cursor.position, ARRAY(
                                  SELECT DISTINCT member.source_mac::text
                                  FROM radio_members member
                                  LEFT JOIN shared_frequencies frequency USING (frequency_mhz)
                                  LEFT JOIN shared_channels channel USING (channel_number)
                                  WHERE (frequency.frequency_mhz IS NOT NULL OR channel.channel_number IS NOT NULL)
                                    AND (cursor.position IS NULL OR member.source_mac >= cursor.position->>1)
                                  ORDER BY 1
                                ) AS macs
                                FROM (VALUES (1)) seed LEFT JOIN cursor ON TRUE
                              ), pages(left_index, remaining, right_macs) AS (
                                SELECT 0, $2::int, ARRAY[]::text[]
                                UNION ALL
                                SELECT pages.left_index + 1, pages.remaining - cardinality(matches.macs), matches.macs
                                FROM pages CROSS JOIN sources
                                CROSS JOIN LATERAL (SELECT sources.macs[pages.left_index + 1]) left_member(left_mac)
                                CROSS JOIN LATERAL (SELECT ARRAY(
                                  SELECT DISTINCT right_frame.source_mac::text
                                  FROM (
                                    SELECT radio.frequency_mhz, radio.channel_number,
                                           range_agg(tstzrange(frame.observed_at - INTERVAL '10 minutes',
                                                              frame.observed_at + INTERVAL '10 minutes', '[]')) AS windows
                                    FROM wireless_frames frame JOIN wireless_frame_radio radio USING (dedupe_key)
                                    WHERE frame.source_mac = left_member.left_mac
                                      AND (radio.channel_number IS NOT NULL OR radio.frequency_mhz IS NOT NULL)
                                    GROUP BY radio.frequency_mhz, radio.channel_number
                                  ) left_radio
                                  CROSS JOIN LATERAL unnest(left_radio.windows) AS windows(span)
                                  JOIN wireless_frames right_frame
                                    ON right_frame.observed_at BETWEEN lower(windows.span) AND upper(windows.span)
                                   AND right_frame.source_mac > CASE WHEN left_member.left_mac = sources.position->>1
                                                                     THEN sources.position->>2 ELSE left_member.left_mac END
                                  JOIN wireless_frame_radio right_radio ON right_radio.dedupe_key = right_frame.dedupe_key
                                  JOIN atheros_search.graph_nodes node ON node.node_id = CONCAT('device:', right_frame.source_mac)
                                  WHERE left_radio.frequency_mhz = right_radio.frequency_mhz
                                     OR ((left_radio.frequency_mhz IS NULL OR right_radio.frequency_mhz IS NULL)
                                         AND left_radio.channel_number = right_radio.channel_number)
                                  ORDER BY 1
                                  LIMIT pages.remaining
                                )) matches(macs)
                                WHERE pages.remaining > 0 AND pages.left_index < cardinality(sources.macs) - 1
                              ), candidate_pairs AS MATERIALIZED (
                                SELECT sources.macs[pages.left_index] AS left_mac, right_mac
                                FROM pages CROSS JOIN sources CROSS JOIN LATERAL unnest(pages.right_macs) right_mac
                              ), saved_position AS (
                                INSERT INTO octopus_core.processor_checkpoints AS checkpoint
                                  (processor_name, shard_id, checkpoint_value)
                                VALUES ('wireless-identity-projector', 'graph-same-channel', (
                                  SELECT jsonb_build_array('', left_mac, right_mac)::text FROM candidate_pairs
                                  WHERE EXISTS (SELECT 1 FROM pages WHERE remaining = 0)
                                  ORDER BY left_mac DESC, right_mac DESC LIMIT 1
                                ))
                                ON CONFLICT (processor_name, shard_id) DO UPDATE SET
                                  checkpoint_value = EXCLUDED.checkpoint_value, updated_at = CURRENT_TIMESTAMP
                                WHERE checkpoint.checkpoint_value IS DISTINCT FROM EXCLUDED.checkpoint_value
                              ), observations AS MATERIALIZED (
                                SELECT frame.source_mac, radio.channel_number, radio.frequency_mhz,
                                       range_agg(tstzrange(frame.observed_at, frame.observed_at, '[]')) AS observed_times,
                                       range_agg(tstzrange(frame.observed_at - INTERVAL '10 minutes',
                                                          frame.observed_at + INTERVAL '10 minutes', '[]')) AS overlap_windows
                                FROM wireless_frames frame
                                     JOIN wireless_frame_radio radio USING (dedupe_key)
                                JOIN (SELECT left_mac AS mac FROM candidate_pairs UNION SELECT right_mac FROM candidate_pairs) source
                                  ON source.mac = frame.source_mac
                                WHERE radio.channel_number IS NOT NULL OR radio.frequency_mhz IS NOT NULL
                                GROUP BY frame.source_mac, radio.channel_number, radio.frequency_mhz
                              ), pair_observations AS MATERIALIZED (
                                SELECT page.left_mac, page.right_mac, observation.*
                                FROM candidate_pairs page JOIN observations observation
                                  ON observation.source_mac IN (page.left_mac, page.right_mac)
                              ), unresolved_channels AS MATERIALIZED (
                                SELECT left_observation.left_mac, left_observation.right_mac, left_observation.channel_number
                                FROM pair_observations left_observation
                                JOIN pair_observations right_observation
                                  ON (right_observation.left_mac, right_observation.right_mac) =
                                     (left_observation.left_mac, left_observation.right_mac)
                                 AND right_observation.source_mac = right_observation.right_mac
                                 AND right_observation.channel_number = left_observation.channel_number
                                 AND left_observation.observed_times && right_observation.overlap_windows
                                WHERE left_observation.source_mac = left_observation.left_mac
                                  AND left_observation.frequency_mhz IS NULL AND right_observation.frequency_mhz IS NULL
                              ), matches AS MATERIALIZED (
                                SELECT left_observation.source_mac AS left_mac,
                                       right_observation.source_mac AS right_mac,
                                       left_observation.channel_number AS left_channel,
                                       right_observation.channel_number AS right_channel,
                                       COALESCE(left_observation.frequency_mhz, right_observation.frequency_mhz) AS frequency_mhz,
                                       -- Keep point sets only where channel-only evidence needs resolution.
                                       CASE WHEN unresolved_left.channel_number IS NOT NULL
                                              OR unresolved_right.channel_number IS NOT NULL THEN (left_observation.observed_times * right_observation.overlap_windows)
                                                + (right_observation.observed_times * left_observation.overlap_windows)
                                       END AS matched_times,
                                       GREATEST(upper(left_observation.observed_times * right_observation.overlap_windows),
                                                upper(right_observation.observed_times * left_observation.overlap_windows)) AS last_observed,
                                       COALESCE(left_observation.frequency_mhz::text || ' MHz',
                                              right_observation.frequency_mhz::text || ' MHz',
                                              'channel ' || left_observation.channel_number::text) AS shared_key
                              FROM pair_observations left_observation
                              JOIN pair_observations right_observation
                                ON (right_observation.left_mac, right_observation.right_mac) =
                                   (left_observation.left_mac, left_observation.right_mac)
                               AND right_observation.source_mac = right_observation.right_mac
                               AND left_observation.observed_times && right_observation.overlap_windows
                               AND ((left_observation.frequency_mhz IS NOT NULL
                                     AND right_observation.frequency_mhz IS NOT NULL
                                     AND left_observation.frequency_mhz = right_observation.frequency_mhz)
                                 OR ((left_observation.frequency_mhz IS NULL OR right_observation.frequency_mhz IS NULL)
                                     AND left_observation.channel_number = right_observation.channel_number))
                              LEFT JOIN unresolved_channels unresolved_left
                                ON unresolved_left.left_mac = left_observation.source_mac
                               AND unresolved_left.right_mac = right_observation.source_mac
                               AND unresolved_left.channel_number = left_observation.channel_number
                              LEFT JOIN unresolved_channels unresolved_right
                                ON unresolved_right.left_mac = left_observation.source_mac
                               AND unresolved_right.right_mac = right_observation.source_mac
                               AND unresolved_right.channel_number = right_observation.channel_number
                              WHERE left_observation.source_mac = left_observation.left_mac
                              ), resolved_channels AS (
                                -- Expand time ranges only for channels with unresolved evidence.
                                SELECT match.left_mac, match.right_mac, unresolved.channel_number,
                                       range_agg(tstzrange(lower(observed_time) - INTERVAL '10 minutes',
                                                          upper(observed_time) + INTERVAL '10 minutes', '[]')) AS resolved_windows
                                FROM matches match
                                JOIN unresolved_channels unresolved
                                  ON unresolved.left_mac = match.left_mac AND unresolved.right_mac = match.right_mac
                                 AND unresolved.channel_number IN (match.left_channel, match.right_channel)
                                CROSS JOIN LATERAL unnest(match.matched_times) observed_time
                                WHERE match.frequency_mhz IS NOT NULL
                                GROUP BY match.left_mac, match.right_mac, unresolved.channel_number
                              ), classified AS (
                                -- Keep the timestamp even when its channel key is already resolved.
                                SELECT match.left_mac, match.right_mac, match.last_observed,
                                       CASE WHEN match.frequency_mhz IS NULL
                                              AND match.matched_times <@ resolved.resolved_windows
                                            THEN NULL ELSE match.shared_key END AS shared_key
                                FROM matches match
                                LEFT JOIN resolved_channels resolved
                                  ON resolved.left_mac = match.left_mac AND resolved.right_mac = match.right_mac
                                 AND resolved.channel_number = match.left_channel
                              )
                              INSERT INTO atheros_search.graph_edges (
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
                                  SELECT left_mac, right_mac,
                                         COUNT(DISTINCT shared_key) AS shared_channels,
                                         string_agg(DISTINCT shared_key, ',' ORDER BY shared_key) AS channel_list,
                                         MAX(last_observed) AS last_observed
                                  FROM classified
                                  GROUP BY left_mac, right_mac
                                ) pair
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
pub(super) const UPSERT_VENDOR_LINK_EDGES: &str = paged_observation_edges!(
    "graph-vendor-link",
    "$2::int",
    r#"SELECT DISTINCT frame.bssid_oui AS shared_key, frame.source_mac
       FROM wireless_frames frame
       JOIN atheros_search.graph_nodes node ON node.node_id = CONCAT('device:', frame.source_mac)
       WHERE frame.source_mac IS NOT NULL AND frame.bssid_oui IS NOT NULL"#,
    r#" INSERT INTO atheros_search.graph_edges (
                                 edge_id, source_node_id, target_node_id, edge_kind,
                                 weight, weight_basis, label, evidence, observed_at, projection_run_id
                               )
                               SELECT CONCAT('vendor-link:', pair.left_mac, ':', pair.right_mac),
                                      CONCAT('device:', pair.left_mac),
                                      CONCAT('device:', pair.right_mac),
                                      'vendor_link', evidence.shared_ouis::double precision, 'vendor_match',
                                      'devices observed with the same OUI vendor prefixes',
                                      jsonb_build_object('shared_ouis', evidence.shared_ouis),
                                      evidence.last_observed, $1
                               FROM candidate_pairs pair
                               CROSS JOIN LATERAL (
                                 SELECT COUNT(*) AS shared_ouis,
                                        MAX(GREATEST(left_oui.last_observed, right_oui.last_observed)) AS last_observed
                                 FROM (
                                   SELECT frame.bssid_oui, MAX(frame.observed_at) AS last_observed
                                   FROM wireless_frames frame
                                   WHERE frame.source_mac = pair.left_mac AND frame.bssid_oui IS NOT NULL
                                   GROUP BY frame.bssid_oui
                                 ) left_oui
                                 JOIN (
                                   SELECT frame.bssid_oui, MAX(frame.observed_at) AS last_observed
                                   FROM wireless_frames frame
                                   WHERE frame.source_mac = pair.right_mac AND frame.bssid_oui IS NOT NULL
                                   GROUP BY frame.bssid_oui
                                 ) right_oui
                                 USING (bssid_oui)
                               ) evidence
                               ON CONFLICT (edge_id) DO UPDATE SET
                                 weight = EXCLUDED.weight,
                                 weight_basis = EXCLUDED.weight_basis,
                                 evidence = EXCLUDED.evidence,
                                 observed_at = GREATEST(
                                   COALESCE(graph_edges.observed_at, EXCLUDED.observed_at),
                                   COALESCE(EXCLUDED.observed_at, graph_edges.observed_at)
                                 ),
                                 updated_at = CURRENT_TIMESTAMP"#
);

// Parameters: 1=batchLimit
pub(super) const UPSERT_ACCESS_POINT_CATALOG: &str = r#"WITH observed AS (
                         SELECT frame.bssid, MIN(frame.observed_at) AS first_observed_at,
                                MAX(frame.observed_at) AS last_observed_at,
                                (array_agg(frame.sensor_id ORDER BY frame.observed_at DESC, frame.dedupe_key DESC))[1] AS last_sensor_id
                         FROM wireless_frames frame
                         WHERE frame.bssid IS NOT NULL
                         GROUP BY frame.bssid
                       ), networks AS (
                         SELECT bssid, BOOL_OR(enabled) AS authorized,
                                MAX(label) FILTER (WHERE enabled) AS authorized_label
                         FROM octopus_core.wireless_authorized_networks
                         GROUP BY bssid
                       )
                       INSERT INTO atheros_search.ap_catalog (
                           bssid, authorized, authorized_label, first_observed_at,
                           last_observed_at, last_sensor_id, updated_at
                         )
                         SELECT observed.bssid,
                                COALESCE(network.authorized, FALSE), network.authorized_label,
                                observed.first_observed_at, observed.last_observed_at,
                                observed.last_sensor_id, CURRENT_TIMESTAMP
                         FROM observed
                         LEFT JOIN networks network USING (bssid)
                         LEFT JOIN atheros_search.ap_catalog existing USING (bssid)
                         WHERE existing.bssid IS NULL
                            OR COALESCE(network.authorized, FALSE) IS DISTINCT FROM existing.authorized
                            OR network.authorized_label IS DISTINCT FROM existing.authorized_label
                            OR observed.first_observed_at < existing.first_observed_at
                            OR observed.last_observed_at > existing.last_observed_at
                            OR (observed.last_observed_at = existing.last_observed_at
                                AND observed.last_sensor_id IS DISTINCT FROM existing.last_sensor_id)
                         ORDER BY observed.last_observed_at DESC, observed.bssid
                         LIMIT $1::int
                         ON CONFLICT (bssid) DO UPDATE SET
                           authorized = EXCLUDED.authorized,
                           authorized_label = EXCLUDED.authorized_label,
                           first_observed_at = LEAST(ap_catalog.first_observed_at, EXCLUDED.first_observed_at),
                           last_observed_at = GREATEST(ap_catalog.last_observed_at, EXCLUDED.last_observed_at),
                           last_sensor_id = CASE WHEN EXCLUDED.last_observed_at >= ap_catalog.last_observed_at
                                                THEN EXCLUDED.last_sensor_id ELSE ap_catalog.last_sensor_id END,
                           updated_at = CURRENT_TIMESTAMP"#;

// Radio backfill touches the parent frame's updated_at in the same transaction.
// Parameters: 1=batchLimit
pub(super) const UPSERT_WIRELESS_SIGNAL_SUMMARIES: &str = r#"WITH ranked AS (
                                 SELECT bucket.window_start, bucket.sensor_id, bucket.bssid, bucket.source_mac,
                                        work.kind, ROW_NUMBER() OVER (
                                          PARTITION BY work.kind
                                          ORDER BY existing.projected_at ASC, bucket.bucket_updated_at DESC,
                                                   bucket.window_start, bucket.sensor_id, bucket.bssid, bucket.source_mac
                                        ) AS work_rank
                                 FROM (
                                   SELECT date_trunc('hour', frame.observed_at)
                                            + floor(EXTRACT(minute FROM frame.observed_at) / 5) * INTERVAL '5 minutes'
                                            AS window_start,
                                          COALESCE(frame.sensor_id, 'unknown') AS sensor_id,
                                          frame.bssid AS bssid, frame.source_mac AS source_mac,
                                          MAX(frame.updated_at) AS bucket_updated_at,
                                          MAX(frame.observed_at) AS last_observed_at,
                                          COUNT(*) AS retained_count
                                   FROM wireless_frames frame
                                   WHERE frame.source_mac IS NOT NULL
                                     AND frame.bssid IS NOT NULL
                                     AND frame.source_mac <> frame.bssid
                                     AND frame.source_mac NOT IN ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00')
                                     AND frame.bssid NOT IN ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00')
                                   GROUP BY 1, 2, 3, 4
                                 ) bucket
                                 LEFT JOIN atheros_search.wireless_signal_summaries existing
                                   ON existing.window_start = bucket.window_start
                                  AND existing.sensor_id = bucket.sensor_id
                                  AND existing.bssid = bucket.bssid
                                  AND existing.source_mac = bucket.source_mac
                                 CROSS JOIN LATERAL (
                                   SELECT existing.frame_count IS DISTINCT FROM bucket.retained_count
                                       OR existing.last_observed_at IS DISTINCT FROM bucket.last_observed_at
                                       OR existing.projected_at < bucket.bucket_updated_at AS stale
                                 ) state
                                 CROSS JOIN LATERAL (SELECT CASE
                                   WHEN existing.window_start IS NULL THEN 'new'
                                   WHEN state.stale THEN 'repair'
                                   ELSE 'refresh' END AS kind) work
                                 WHERE GREATEST(bucket.last_observed_at, bucket.bucket_updated_at)
                                         >= CURRENT_TIMESTAMP - INTERVAL '7 days'
                                    OR (existing.window_start IS NOT NULL AND state.stale)
                               ), candidates AS MATERIALIZED (
                                 SELECT * FROM ranked
                                 ORDER BY (kind = 'refresh'), work_rank,
                                          (kind = CASE WHEN $1::int = 1 THEN COALESCE((
                                             SELECT checkpoint_value FROM octopus_core.processor_checkpoints
                                             WHERE processor_name = 'wireless-identity-projector'
                                               AND shard_id = 'signal-summary-single-slot'
                                           ), 'new') ELSE 'new' END)
                                 LIMIT $1::int
                               ), saved_choice AS (
                                 -- A one-slot batch alternates when both queues have work.
                                 INSERT INTO octopus_core.processor_checkpoints AS checkpoint
                                   (processor_name, shard_id, checkpoint_value)
                                 SELECT 'wireless-identity-projector', 'signal-summary-single-slot', kind
                                 FROM candidates WHERE $1::int = 1 AND kind <> 'refresh'
                                 ON CONFLICT (processor_name, shard_id) DO UPDATE SET
                                   checkpoint_value = EXCLUDED.checkpoint_value, updated_at = CURRENT_TIMESTAMP
                                 WHERE checkpoint.checkpoint_value IS DISTINCT FROM EXCLUDED.checkpoint_value
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
                                      MIN(frame.observed_at), MAX(frame.observed_at), statement_timestamp()
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
                                 projected_at = EXCLUDED.projected_at"#;

// Parameters:
pub(super) const DELETE_STALE_SIGNAL_SUMMARIES: &str = r#"DELETE FROM atheros_search.wireless_signal_summaries summary
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
pub(super) const DELETE_STALE_ACCESS_POINT_CATALOG: &str = r#"DELETE FROM atheros_search.ap_catalog catalog
                              WHERE NOT EXISTS (
                                SELECT 1 FROM wireless_frames frame
                                WHERE frame.bssid = catalog.bssid
                              )"#;

// Parameters:
pub(super) const UPSERT_WIRELESS_EVIDENCE_WATERMARK: &str = r#"WITH buckets AS (
                            SELECT date_trunc('hour', observed_at)
                                     + floor(EXTRACT(minute FROM observed_at) / 5) * INTERVAL '5 minutes'
                                     AS window_start,
                                   COALESCE(sensor_id, 'unknown') AS sensor_id, bssid, source_mac,
                                   MAX(observed_at) AS last_observed_at,
                                   MAX(updated_at) AS last_source_change,
                                   COUNT(*) AS retained_count
                            FROM wireless_frames
                            WHERE source_mac IS NOT NULL AND bssid IS NOT NULL
                              AND source_mac <> bssid
                              AND source_mac NOT IN ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00')
                              AND bssid NOT IN ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00')
                            GROUP BY 1, 2, 3, 4
                          ),
                          coverage AS (
                            SELECT MAX(bucket.last_observed_at) AS source_watermark_at,
                                   MAX(summary.last_observed_at) AS projection_watermark_at,
                                   MAX(summary.projected_at) AS last_projected_at,
                                   COUNT(*) FILTER (WHERE summary.frame_count IS DISTINCT FROM bucket.retained_count
                                                       OR summary.last_observed_at IS DISTINCT FROM bucket.last_observed_at
                                                       OR summary.projected_at < bucket.last_source_change) AS missing_buckets
                            FROM buckets bucket
                            LEFT JOIN atheros_search.wireless_signal_summaries summary
                              USING (window_start, sensor_id, bssid, source_mac)
                          )
                          INSERT INTO atheros_search.investigation_watermarks (
                            projection_name, source_watermark_at, projection_watermark_at,
                            coverage_status, coverage_reason, updated_at
                          )
                          SELECT 'wireless_evidence',
                                 coverage.source_watermark_at,
                                 coverage.projection_watermark_at,
                                 CASE
                                   WHEN coverage.source_watermark_at IS NULL THEN 'unknown'
                                   WHEN coverage.projection_watermark_at IS NULL THEN 'stalled'
                                   WHEN coverage.missing_buckets > 0
                                     OR coverage.source_watermark_at - coverage.projection_watermark_at
                                          > INTERVAL '15 minutes' THEN
                                     CASE WHEN coverage.last_projected_at
                                               < CURRENT_TIMESTAMP - INTERVAL '6 hours'
                                          THEN 'stalled' ELSE 'partial' END
                                   ELSE 'complete'
                                 END,
                                 CASE
                                   WHEN coverage.source_watermark_at IS NULL
                                     THEN 'no eligible retained wireless frames'
                                   WHEN coverage.projection_watermark_at IS NULL
                                     THEN 'no five-minute signal summaries have been projected'
                                   WHEN coverage.missing_buckets > 0
                                     THEN format('%s retained five-minute signal buckets have missing or mismatched summaries', coverage.missing_buckets)
                                   WHEN coverage.source_watermark_at - coverage.projection_watermark_at
                                          > INTERVAL '15 minutes' THEN
                                     'signal summaries lag the retained source watermark; '
                                       || 'the projection recomputes buckets written within the last seven days'
                                   ELSE NULL
                                 END,
                                 CURRENT_TIMESTAMP
                          FROM coverage
                          ON CONFLICT (projection_name) DO UPDATE SET
                            source_watermark_at = EXCLUDED.source_watermark_at,
                            projection_watermark_at = EXCLUDED.projection_watermark_at,
                            coverage_status = EXCLUDED.coverage_status,
                            coverage_reason = EXCLUDED.coverage_reason,
                            updated_at = CURRENT_TIMESTAMP"#;

// Parameters:
pub(super) const DELETE_ORPHANED_EDGES: &str = r#"DELETE FROM atheros_search.graph_edges edge
                                     WHERE NOT EXISTS (
                                       SELECT 1 FROM atheros_search.graph_nodes source_node
                                       WHERE source_node.node_id = edge.source_node_id
                                     )
                                       OR NOT EXISTS (
                                       SELECT 1 FROM atheros_search.graph_nodes target_node
                                       WHERE target_node.node_id = edge.target_node_id
                                     )
                                       OR (edge.edge_kind = 'roaming' AND NOT EXISTS (
                                         SELECT 1 FROM wireless_frames left_frame
                                         WHERE left_frame.source_mac = substr(edge.source_node_id, 8)
                                           AND left_frame.bssid IS NOT NULL
                                           AND EXISTS (
                                             SELECT 1 FROM wireless_frames right_frame
                                             WHERE right_frame.source_mac = substr(edge.target_node_id, 8)
                                               AND right_frame.bssid = left_frame.bssid
                                               AND right_frame.observed_at BETWEEN left_frame.observed_at - INTERVAL '10 minutes'
                                                                             AND left_frame.observed_at + INTERVAL '10 minutes'
                                           )
                                       ))
                                       OR (edge.edge_kind = 'same_channel' AND NOT EXISTS (
                                         SELECT 1 FROM wireless_frames left_frame
                                         JOIN wireless_frame_radio radio USING (dedupe_key)
                                         WHERE left_frame.source_mac = substr(edge.source_node_id, 8)
                                           AND (radio.channel_number IS NOT NULL OR radio.frequency_mhz IS NOT NULL)
                                           AND EXISTS (
                                             SELECT 1 FROM wireless_frames right_frame
                                             JOIN wireless_frame_radio right_radio USING (dedupe_key)
                                             WHERE right_frame.source_mac = substr(edge.target_node_id, 8)
                                               AND (right_radio.channel_number IS NOT NULL OR right_radio.frequency_mhz IS NOT NULL)
                                               AND right_frame.observed_at BETWEEN left_frame.observed_at - INTERVAL '10 minutes'
                                                                             AND left_frame.observed_at + INTERVAL '10 minutes'
                                               AND ((radio.frequency_mhz IS NOT NULL AND right_radio.frequency_mhz IS NOT NULL
                                                     AND radio.frequency_mhz = right_radio.frequency_mhz)
                                                 OR ((radio.frequency_mhz IS NULL OR right_radio.frequency_mhz IS NULL)
                                                     AND radio.channel_number = right_radio.channel_number))
                                           )
                                       ))
                                       OR (edge.edge_kind = 'vendor_link' AND NOT EXISTS (
                                         SELECT 1 FROM wireless_frames left_frame
                                         WHERE left_frame.source_mac = substr(edge.source_node_id, 8)
                                           AND left_frame.bssid_oui IS NOT NULL
                                           AND EXISTS (
                                             SELECT 1 FROM wireless_frames right_frame
                                             WHERE right_frame.source_mac = substr(edge.target_node_id, 8)
                                               AND right_frame.bssid_oui = left_frame.bssid_oui
                                           )
                                       ))"#;

// The decision writer locks candidates, so the graph can observe changes
// between statements. Use one snapshot for the final deletion and watermark.
// Parameters: 1=AutomaticMergeSimilarity
pub(super) fn upsert_graph_projection_watermark() -> String {
    format!(
        r#"WITH deleted_same_device_edges AS ({DELETE_STALE_SAME_DEVICE_EDGES} RETURNING 1),
                              retained_pairs AS MATERIALIZED (
                                SELECT source_mac, bssid, MAX(observed_at) AS observed_at,
                                       MIN(observed_at) AS first_observed_at,
                                       COUNT(*) AS frame_count
                                FROM wireless_frames
                                WHERE source_mac IS NOT NULL AND bssid IS NOT NULL
                                GROUP BY source_mac,bssid
                              ), classified AS (
                                SELECT pair.source_mac, pair.observed_at, pair.first_observed_at,
                                       COALESCE(edge.observed_at >= pair.observed_at
                                             AND edge.weight = pair.frame_count::double precision
                                             AND edge.evidence->'frame_count' = to_jsonb(pair.frame_count), FALSE) AS current
                                FROM retained_pairs pair
                                LEFT JOIN atheros_search.graph_edges edge
                                  ON edge.edge_id = CONCAT('observed:', pair.source_mac, ':', pair.bssid)
                                 AND edge.edge_kind = 'observed_at'
                              ), coverage AS (
                                SELECT MAX(observed_at) AS source_watermark_at,
                                       COUNT(*) AS pair_count,
                                       COUNT(DISTINCT source_mac) AS mac_count,
                                       COUNT(*) FILTER (WHERE current) AS current_count,
                                       MIN(first_observed_at) FILTER (WHERE NOT current) AS first_gap_at
                                FROM classified
                              ),
                              projection AS (
                                SELECT MAX(pair.observed_at) AS projection_watermark_at
                                FROM classified pair CROSS JOIN coverage
                                WHERE pair.current
                                  AND (coverage.first_gap_at IS NULL OR pair.observed_at < coverage.first_gap_at)
                              ),
                              stale_edges AS (
                                SELECT COUNT(*) AS edge_count
                                FROM atheros_search.graph_edges edge
                                WHERE edge.edge_kind = 'observed_at'
                                  AND NOT EXISTS (
                                    SELECT 1 FROM retained_pairs pair
                                    WHERE edge.edge_id = CONCAT('observed:', pair.source_mac, ':', pair.bssid)
                                  )
                              ),
                              devices AS (
                                SELECT COUNT(*) AS device_count
                                FROM atheros_search.graph_nodes
                                WHERE node_kind = 'device'
                              ), watermark AS (
                              INSERT INTO atheros_search.investigation_watermarks (
                                projection_name, source_watermark_at, projection_watermark_at,
                                coverage_status, coverage_reason, updated_at
                              )
                              SELECT 'graph_projection',
                                     coverage.source_watermark_at,
                                     projection.projection_watermark_at,
                                     CASE
                                       WHEN coverage.pair_count = 0 THEN 'unknown'
                                       WHEN coverage.current_count = 0 THEN 'stalled'
                                       WHEN coverage.current_count < coverage.pair_count OR stale_edges.edge_count > 0
                                         THEN 'partial'
                                       ELSE 'complete'
                                     END,
                                     format(
                                       '%s of %s distinct (source_mac,bssid) pairs current; %s device nodes vs %s frame source MACs; %s stale observed edges',
                                       coverage.current_count, coverage.pair_count,
                                       devices.device_count, coverage.mac_count, stale_edges.edge_count
                                     ),
                                     CURRENT_TIMESTAMP
                              FROM coverage, projection, devices, stale_edges
                              ON CONFLICT (projection_name) DO UPDATE SET
                                source_watermark_at = EXCLUDED.source_watermark_at,
                                projection_watermark_at = EXCLUDED.projection_watermark_at,
                                coverage_status = EXCLUDED.coverage_status,
                                coverage_reason = EXCLUDED.coverage_reason,
                                updated_at = CURRENT_TIMESTAMP
                              RETURNING 1
                              )
                              SELECT (SELECT COUNT(*) FROM deleted_same_device_edges)
                                   + (SELECT COUNT(*) FROM watermark)"#
    )
}
