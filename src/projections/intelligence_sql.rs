//! Parameterized PostgreSQL queries ported from the canonical Scala operations.

// Parameters: 1=batchLimit

pub const BEHAVIOR_CANDIDATES_0: &str = r#"WITH source_windows AS (
             SELECT frame.source_mac,
                    FLOOR(EXTRACT(EPOCH FROM frame.observed_at) / 3600) AS window_bucket,
                    COUNT(*) AS source_event_count,
                    COUNT(*) FILTER (WHERE qos.retry) AS retry_count,
                    COUNT(*) FILTER (WHERE qos.protected) AS protected_count
             FROM wireless_frames frame
             LEFT JOIN wireless_frame_qos qos ON qos.dedupe_key = frame.dedupe_key
             WHERE frame.source_mac IS NOT NULL
             GROUP BY frame.source_mac, window_bucket
           ), candidate_windows AS (
             SELECT source.source_mac, source.window_bucket
             FROM source_windows source
             LEFT JOIN atheros_search.behaviour_snapshots snapshot
               ON snapshot.snapshot_key = CONCAT(
                 source.source_mac, ':', CAST(source.window_bucket * 3600 AS TEXT)
               )
             WHERE snapshot.snapshot_key IS NULL
                OR snapshot.event_count <> source.source_event_count
                OR snapshot.retry_count IS DISTINCT FROM source.retry_count
                OR snapshot.protected_count IS DISTINCT FROM source.protected_count
             ORDER BY source.window_bucket, source.source_mac
             LIMIT $1::int
           )
           SELECT frame.dedupe_key, frame.source_mac, frame.location_id, frame.sensor_id, frame.observed_at, frame.frame_type, frame.frame_subtype, radio.signal_dbm, COALESCE(qos.retry, false), COALESCE(qos.protected, false), frame.bssid, network_row.app_protocol, security_row.adjacent_mac_hint, radio.tsft_delta_us, radio.wall_clock_delta_ms, identity_row.session_key 
           FROM wireless_frames frame
           JOIN candidate_windows candidate
             ON candidate.source_mac = frame.source_mac
            AND candidate.window_bucket = FLOOR(EXTRACT(EPOCH FROM frame.observed_at) / 3600)
           LEFT JOIN wireless_frame_radio radio ON radio.dedupe_key = frame.dedupe_key
           LEFT JOIN wireless_frame_qos qos ON qos.dedupe_key = frame.dedupe_key
           LEFT JOIN wireless_frame_network network_row ON network_row.dedupe_key = frame.dedupe_key
           LEFT JOIN wireless_frame_security security_row ON security_row.dedupe_key = frame.dedupe_key
           LEFT JOIN wireless_frame_identity identity_row ON identity_row.dedupe_key = frame.dedupe_key
           ORDER BY frame.source_mac, candidate.window_bucket, frame.observed_at, frame.dedupe_key"#;

// Parameters: 1=batchLimit

pub const TIMING_CANDIDATES_0: &str = r#"WITH source_windows AS (
             SELECT frame.source_mac,
                    FLOOR(EXTRACT(EPOCH FROM frame.observed_at) / 3600) AS window_bucket,
                    COUNT(*) AS source_event_count,
                    MAX(frame.updated_at) AS updated_at
             FROM wireless_frames frame
             WHERE frame.source_mac IS NOT NULL
             GROUP BY frame.source_mac, window_bucket
           ), candidate_windows AS (
             SELECT source.source_mac, source.window_bucket
             FROM source_windows source
             LEFT JOIN atheros_search.timing_profiles profile
               ON profile.profile_key = CONCAT(
                 source.source_mac, ':', CAST(source.window_bucket * 3600 AS TEXT)
               )
             WHERE profile.profile_key IS NULL
                OR profile.source_event_count <> source.source_event_count
                OR profile.updated_at < source.updated_at
             ORDER BY source.window_bucket, source.source_mac
             LIMIT $1::int
           )
           SELECT frame.dedupe_key, frame.source_mac, frame.location_id, frame.sensor_id, frame.observed_at, frame.frame_type, frame.frame_subtype, radio.signal_dbm, COALESCE(qos.retry, false), COALESCE(qos.protected, false), frame.bssid, network_row.app_protocol, security_row.adjacent_mac_hint, radio.tsft_delta_us, radio.wall_clock_delta_ms, identity_row.session_key 
           FROM wireless_frames frame
           JOIN candidate_windows candidate
             ON candidate.source_mac = frame.source_mac
            AND candidate.window_bucket = FLOOR(EXTRACT(EPOCH FROM frame.observed_at) / 3600)
           LEFT JOIN wireless_frame_radio radio ON radio.dedupe_key = frame.dedupe_key
           LEFT JOIN wireless_frame_qos qos ON qos.dedupe_key = frame.dedupe_key
           LEFT JOIN wireless_frame_network network_row ON network_row.dedupe_key = frame.dedupe_key
           LEFT JOIN wireless_frame_security security_row ON security_row.dedupe_key = frame.dedupe_key
           LEFT JOIN wireless_frame_identity identity_row ON identity_row.dedupe_key = frame.dedupe_key
           ORDER BY frame.source_mac, candidate.window_bucket, frame.observed_at, frame.dedupe_key"#;

// Parameters: 1=batchLimit

pub const SEQUENCE_CANDIDATES_0: &str = r#"WITH source_sessions AS (
             SELECT identity_row.session_key, COUNT(*) AS source_event_count
             FROM wireless_frame_identity identity_row
             JOIN wireless_frames frame ON frame.dedupe_key = identity_row.dedupe_key
             WHERE identity_row.session_key IS NOT NULL AND frame.source_mac IS NOT NULL
             GROUP BY identity_row.session_key
           ), candidate_sessions AS (
             SELECT source.session_key
             FROM source_sessions source
             LEFT JOIN atheros_search.frame_sequences sequence_row
               ON sequence_row.session_key = source.session_key
             WHERE sequence_row.session_key IS NULL
                OR sequence_row.frame_count <> source.source_event_count
             ORDER BY source.session_key
             LIMIT $1::int
           )
           SELECT frame.dedupe_key, frame.source_mac, frame.location_id, frame.sensor_id, frame.observed_at, frame.frame_type, frame.frame_subtype, radio.signal_dbm, COALESCE(qos.retry, false), COALESCE(qos.protected, false), frame.bssid, network_row.app_protocol, security_row.adjacent_mac_hint, radio.tsft_delta_us, radio.wall_clock_delta_ms, identity_row.session_key 
           FROM wireless_frames frame
           JOIN wireless_frame_identity identity_row ON identity_row.dedupe_key = frame.dedupe_key
           JOIN candidate_sessions candidate ON candidate.session_key = identity_row.session_key
           LEFT JOIN wireless_frame_radio radio ON radio.dedupe_key = frame.dedupe_key
           LEFT JOIN wireless_frame_qos qos ON qos.dedupe_key = frame.dedupe_key
           LEFT JOIN wireless_frame_network network_row ON network_row.dedupe_key = frame.dedupe_key
           LEFT JOIN wireless_frame_security security_row ON security_row.dedupe_key = frame.dedupe_key
           WHERE frame.source_mac IS NOT NULL
           ORDER BY identity_row.session_key, frame.observed_at, frame.dedupe_key"#;

// Parameters: 1=batchLimit

pub const BASELINE_CANDIDATES_0: &str = r#"WITH source_bssids AS (
             SELECT frame.bssid, COUNT(*) AS source_event_count
             FROM wireless_frames frame
             JOIN wireless_frame_radio radio ON radio.dedupe_key = frame.dedupe_key
             WHERE frame.bssid IS NOT NULL AND radio.signal_dbm IS NOT NULL
             GROUP BY frame.bssid
           ), candidate_bssids AS (
             SELECT source.bssid
             FROM source_bssids source
             LEFT JOIN atheros_search.baseline_profiles baseline
               ON baseline.bssid = source.bssid AND baseline.metric = 'signal_dbm'
             WHERE baseline.baseline_id IS NULL
                OR baseline.sample_count <> source.source_event_count
             ORDER BY source.bssid
             LIMIT $1::int
           )
           SELECT frame.bssid, CAST(radio.signal_dbm AS DOUBLE PRECISION)
           FROM wireless_frames frame
           JOIN wireless_frame_radio radio ON radio.dedupe_key = frame.dedupe_key
           JOIN candidate_bssids candidate ON candidate.bssid = frame.bssid
           WHERE radio.signal_dbm IS NOT NULL
           ORDER BY frame.bssid, frame.observed_at, frame.dedupe_key"#;

// Parameters: 1=value.snapshotId, 2=value.snapshotKey, 3=value.sourceMac, 4=value.locationId, 5=value.sensorId, 6=value.windowStart, 7=value.windowEnd, 8=value.eventCount, 9=value.textSummary, 10=Some(value.textSummary), 11=value.protocolMixJson, 12=value.frameDistributionJson, 13=value.signalMin, 14=value.signalMax, 15=value.signalAverage, 16=value.retryCount, 17=value.protectedCount, 18=value.unprotectedCount, 19=value.uniqueBssidCount, 20=value.rotationIndicatorsJson, 21=value.projectionRunId

pub const PERSIST_BEHAVIOR_0: &str = r#"INSERT INTO atheros_search.behaviour_snapshots (
             snapshot_id, snapshot_key, source_mac, location_id, sensor_id,
             window_start, window_end, event_count, text_summary, embedding_text,
             protocol_mix, frame_type_distribution, signal_min_dbm, signal_max_dbm,
             signal_avg_dbm, retry_count, protected_count, unprotected_count,
             unique_bssid_count, mac_rotation_indicators, projection_run_id
           ) VALUES (
             $1::text::uuid, $2, $3,
             $4, $5, $6, $7,
             $8, $9, $10,
             CAST($11::text AS JSON), CAST($12::text AS JSON),
             $13, $14, $15, $16,
             $17, $18, $19,
             CAST($20::text AS JSON), $21::text::uuid
           ) ON CONFLICT (snapshot_key) DO UPDATE SET
             location_id = EXCLUDED.location_id,
             sensor_id = EXCLUDED.sensor_id,
             window_start = EXCLUDED.window_start,
             window_end = EXCLUDED.window_end,
             event_count = EXCLUDED.event_count,
             text_summary = EXCLUDED.text_summary,
             embedding_text = EXCLUDED.embedding_text,
             protocol_mix = EXCLUDED.protocol_mix,
             frame_type_distribution = EXCLUDED.frame_type_distribution,
             signal_min_dbm = EXCLUDED.signal_min_dbm,
             signal_max_dbm = EXCLUDED.signal_max_dbm,
             signal_avg_dbm = EXCLUDED.signal_avg_dbm,
             retry_count = EXCLUDED.retry_count,
             protected_count = EXCLUDED.protected_count,
             unprotected_count = EXCLUDED.unprotected_count,
             unique_bssid_count = EXCLUDED.unique_bssid_count,
             mac_rotation_indicators = EXCLUDED.mac_rotation_indicators,
             projection_run_id = EXCLUDED.projection_run_id,
             updated_at = CURRENT_TIMESTAMP"#;

// Parameters: 1=value.profileId, 2=value.profileKey, 3=value.sourceMac, 4=value.sensorId, 5=value.locationId, 6=value.windowStart, 7=value.windowEnd, 8=value.tsftP50, 9=value.tsftP95, 10=value.tsftJitter, 11=value.wallP50, 12=value.wallJitter, 13=value.sourceEventCount, 14=value.projectionRunId

pub const PERSIST_TIMING_0: &str = r#"INSERT INTO atheros_search.timing_profiles (
             profile_id, profile_key, source_mac, sensor_id, location_id,
             window_start, window_end, embedding_text, tsft_p50_us, tsft_p95_us,
             tsft_jitter, wall_p50_ms, wall_jitter_ms, source_event_count, projection_run_id
           ) VALUES (
             $1::text::uuid, $2, $3, $4,
             $5, $6, $7, NULL,
             $8, $9, $10,
             $11, $12, $13, $14::text::uuid
           ) ON CONFLICT (profile_key) DO UPDATE SET
             sensor_id = EXCLUDED.sensor_id,
             location_id = EXCLUDED.location_id,
             window_start = EXCLUDED.window_start,
             window_end = EXCLUDED.window_end,
             tsft_p50_us = EXCLUDED.tsft_p50_us,
             tsft_p95_us = EXCLUDED.tsft_p95_us,
             tsft_jitter = EXCLUDED.tsft_jitter,
             wall_p50_ms = EXCLUDED.wall_p50_ms,
             wall_jitter_ms = EXCLUDED.wall_jitter_ms,
             source_event_count = EXCLUDED.source_event_count,
             projection_run_id = EXCLUDED.projection_run_id,
             updated_at = CURRENT_TIMESTAMP"#;

// Parameters: 1=value.sessionKey

pub const PERSIST_SEQUENCE_0: &str = r#"SELECT previous_token
                            FROM atheros_search.sequence_previous_totals
                            WHERE session_key = $1
                              AND sequence_kind = 'frame_sequence'"#;

// Parameters: 1=value.sessionKey, 2=value.sourceMac, 3=value.locationId, 4=value.sensorId, 5=value.windowStart, 6=value.windowEnd, 7=tokenText, 8=value.tokens.size.toLong, 9=value.projectionRunId

pub const PERSIST_SEQUENCE_1: &str = r#"INSERT INTO atheros_search.frame_sequences (
                          session_key, source_mac, location_id, sensor_id, window_start, window_end,
                          sequence_tokens, semantic_tokens, frame_count, projection_run_id
                        ) VALUES (
                          $1, $2, $3, $4,
                          $5, $6, $7, $7,
                          $8, $9::text::uuid
                        ) ON CONFLICT (session_key) DO UPDATE SET
                          source_mac = EXCLUDED.source_mac,
                          location_id = EXCLUDED.location_id,
                          sensor_id = EXCLUDED.sensor_id,
                          window_start = EXCLUDED.window_start,
                          window_end = EXCLUDED.window_end,
                          sequence_tokens = EXCLUDED.sequence_tokens,
                          semantic_tokens = EXCLUDED.semantic_tokens,
                          frame_count = EXCLUDED.frame_count,
                          projection_run_id = EXCLUDED.projection_run_id,
                          updated_at = CURRENT_TIMESTAMP"#;

// Parameters: 1=value.sessionKey

pub const PERSIST_SEQUENCE_2: &str = r#"DELETE FROM atheros_search.sequence_transition_contributions
                  WHERE session_key = $1
                    AND sequence_kind = 'frame_sequence'"#;

// Parameters: 1=value.sessionKey

pub const PERSIST_SEQUENCE_3: &str = r#"DELETE FROM atheros_search.sequence_previous_totals
                  WHERE session_key = $1
                    AND sequence_kind = 'frame_sequence'"#;

// Parameters: 1=value.sessionKey, 2=previous.value, 3=next.value, 4=count, 5=totals(previous), 6=value.projectionRunId

pub const PERSIST_SEQUENCE_4: &str = r#"INSERT INTO atheros_search.sequence_transition_contributions (
               session_key, previous_token, next_token, sequence_kind,
               transition_count, previous_total, projection_run_id
             ) VALUES (
               $1, $2, $3, 'frame_sequence',
               $4, $5, $6::text::uuid
             )"#;

// Parameters: 1=value.sessionKey, 2=previous.value, 3=total, 4=value.projectionRunId

pub const PERSIST_SEQUENCE_5: &str = r#"INSERT INTO atheros_search.sequence_previous_totals (
               session_key, previous_token, sequence_kind, previous_total, projection_run_id
             ) VALUES (
               $1, $2, 'frame_sequence', $3,
               $4::text::uuid
             )"#;

// Parameters: 1=previous

pub const PERSIST_SEQUENCE_6: &str = r#"DELETE FROM atheros_search.sequence_transitions
                            WHERE previous_token = $1
                              AND sequence_kind = 'frame_sequence'"#;

// Parameters: 1=FrameToken.values.length.toLong, 2=value.projectionRunId, 3=previous

pub const PERSIST_SEQUENCE_7: &str = r#"INSERT INTO atheros_search.sequence_transitions (
                              previous_token, next_token, sequence_kind, transition_count,
                              previous_total, vocabulary_size, probability, projection_run_id
                            )
                            SELECT contribution.previous_token, contribution.next_token,
                                   contribution.sequence_kind,
                                   SUM(contribution.transition_count), totals.previous_total,
                                   $1,
                                   SUM(contribution.transition_count) / NULLIF(totals.previous_total, 0),
                                   $2::text::uuid
                            FROM atheros_search.sequence_transition_contributions contribution
                            JOIN (
                              SELECT previous_token, sequence_kind, SUM(previous_total) AS previous_total
                              FROM atheros_search.sequence_previous_totals
                              WHERE previous_token = $3
                                AND sequence_kind = 'frame_sequence'
                              GROUP BY previous_token, sequence_kind
                            ) totals
                              ON totals.previous_token = contribution.previous_token
                             AND totals.sequence_kind = contribution.sequence_kind
                            WHERE contribution.previous_token = $3
                              AND contribution.sequence_kind = 'frame_sequence'
                            GROUP BY contribution.previous_token, contribution.next_token,
                                     contribution.sequence_kind, totals.previous_total"#;

// Parameters: 1=value.baselineId, 2=value.bssid, 3=value.metric, 4=value.p5, 5=value.p50, 6=value.p95, 7=value.sampleCount, 8=value.projectionRunId

pub const PERSIST_BASELINE_0: &str = r#"INSERT INTO atheros_search.baseline_profiles (
             baseline_id, bssid, metric, p5, p50, p95, sample_count, projection_run_id
           ) VALUES (
             $1::text::uuid, $2, $3, $4,
             $5, $6, $7, $8::text::uuid
           ) ON CONFLICT (bssid, metric) DO UPDATE SET
             p5 = EXCLUDED.p5,
             p50 = EXCLUDED.p50,
             p95 = EXCLUDED.p95,
             sample_count = EXCLUDED.sample_count,
             projection_run_id = EXCLUDED.projection_run_id,
             updated_at = CURRENT_TIMESTAMP"#;
