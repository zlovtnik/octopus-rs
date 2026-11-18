//! Deterministic wireless window, sequence, identity and risk preparation.
use super::{ProjectionError, ProjectionStore};
use crate::postgres::PgTransaction;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use tokio_postgres::Row;

#[path = "intelligence_sql.rs"]
mod sql;

pub fn stable_id(namespace: &str, parts: &[&str]) -> String {
    let input = std::iter::once(namespace)
        .chain(parts.iter().copied())
        .collect::<Vec<_>>()
        .join("\u{1f}");
    let mut bytes: [u8; 16] = Sha256::digest(input.as_bytes())[..16]
        .try_into()
        .expect("sixteen digest bytes");
    // The Scala contract hardcodes version 5 and variant nibble 'a'.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x0f) | 0xa0;
    uuid::Uuid::from_bytes(bytes).to_string()
}

pub fn percentile(values: &[f64], probability: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let position = probability.clamp(0.0, 1.0) * (sorted.len() - 1) as f64;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    Some(sorted[lower] + (sorted[upper] - sorted[lower]) * (position - lower as f64))
}
pub fn median_absolute_deviation(values: &[f64]) -> Option<f64> {
    let median = percentile(values, 0.5)?;
    percentile(
        &values
            .iter()
            .map(|v| (v - median).abs())
            .collect::<Vec<_>>(),
        0.5,
    )
}
pub fn weighted_risk(components: &[(f64, f64)]) -> f64 {
    components
        .iter()
        .map(|(score, weight)| score.clamp(0.0, 100.0) * weight.max(0.0))
        .sum::<f64>()
        .clamp(0.0, 100.0)
}
pub fn cosine_similarity(left: &[f64], right: &[f64]) -> Option<f64> {
    if left.is_empty() || left.len() != right.len() {
        return None;
    }
    let dot = left.iter().zip(right).map(|(l, r)| l * r).sum::<f64>();
    let norm = left.iter().map(|v| v * v).sum::<f64>().sqrt()
        * right.iter().map(|v| v * v).sum::<f64>().sqrt();
    Some(if norm == 0.0 {
        0.0
    } else {
        (dot / norm).clamp(-1.0, 1.0)
    })
}
pub fn frame_token(kind: Option<&str>, subtype: Option<&str>) -> &'static str {
    let kind = kind
        .unwrap_or("")
        .trim_matches(|c| c <= '\u{20}')
        .to_lowercase();
    let subtype = subtype
        .unwrap_or("")
        .trim_matches(|c| c <= '\u{20}')
        .to_lowercase()
        .replace(['-', ' '], "_");
    match subtype.as_str() {
        "beacon" => "beacon",
        "probe_request" => "probe_request",
        "probe_response" => "probe_response",
        "authentication" | "auth" => "authentication",
        "association_request" | "assoc_request" => "association_request",
        "association_response" | "assoc_response" => "association_response",
        "reassociation_request" | "reassoc_request" => "reassociation_request",
        "reassociation_response" | "reassoc_response" => "reassociation_response",
        "disassociation" | "disassoc" => "disassociation",
        "deauthentication" | "deauth" => "deauthentication",
        "action" => "action",
        _ if kind == "data" => "data",
        _ => "other",
    }
}
pub fn transition_probabilities(tokens: &[&str]) -> BTreeMap<(String, String), f64> {
    let mut totals = BTreeMap::<&str, i64>::new();
    let mut pairs = BTreeMap::<(&str, &str), i64>::new();
    for pair in tokens.windows(2) {
        *totals.entry(pair[0]).or_default() += 1;
        *pairs.entry((pair[0], pair[1])).or_default() += 1;
    }
    pairs
        .into_iter()
        .map(|((left, right), n)| ((left.into(), right.into()), n as f64 / totals[left] as f64))
        .collect()
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProjectionFrame {
    pub dedupe_key: String,
    pub source_mac: String,
    pub location_id: Option<String>,
    pub sensor_id: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub frame_type: Option<String>,
    pub frame_subtype: Option<String>,
    pub signal_dbm: Option<i32>,
    pub retry: bool,
    pub protected: bool,
    pub bssid: Option<String>,
    pub app_protocol: Option<String>,
    pub adjacent_mac_hint: Option<String>,
    pub tsft_delta_us: Option<i64>,
    pub wall_clock_delta_ms: Option<i64>,
    pub session_key: Option<String>,
}
impl ProjectionFrame {
    fn from_row(row: Row) -> Self {
        Self {
            dedupe_key: row.get(0),
            source_mac: row.get(1),
            location_id: row.get(2),
            sensor_id: row.get(3),
            observed_at: row.get(4),
            frame_type: row.get(5),
            frame_subtype: row.get(6),
            signal_dbm: row.get(7),
            retry: row.get(8),
            protected: row.get(9),
            bssid: row.get(10),
            app_protocol: row.get(11),
            adjacent_mac_hint: row.get(12),
            tsft_delta_us: row.get(13),
            wall_clock_delta_ms: row.get(14),
            session_key: row.get(15),
        }
    }
}
#[derive(Clone, Debug, PartialEq)]
pub struct BehaviorSnapshot {
    pub snapshot_id: String,
    pub snapshot_key: String,
    pub source_mac: String,
    pub location_id: Option<String>,
    pub sensor_id: Option<String>,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub event_count: i64,
    pub text_summary: String,
    pub protocol_mix: String,
    pub frame_distribution: String,
    pub signal_min: Option<i32>,
    pub signal_max: Option<i32>,
    pub signal_average: Option<f64>,
    pub retry_count: i64,
    pub protected_count: i64,
    pub unprotected_count: i64,
    pub unique_bssid_count: i64,
    pub rotation_indicators: String,
    pub run_id: String,
}
#[derive(Clone, Debug, PartialEq)]
pub struct TimingProfile {
    pub profile_id: String,
    pub profile_key: String,
    pub source_mac: String,
    pub sensor_id: Option<String>,
    pub location_id: Option<String>,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub tsft_p50: Option<f64>,
    pub tsft_p95: Option<f64>,
    pub tsft_jitter: Option<f64>,
    pub wall_p50: Option<f64>,
    pub wall_jitter: Option<f64>,
    pub source_event_count: i64,
    pub run_id: String,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Sequence {
    pub session_key: String,
    pub source_mac: Option<String>,
    pub location_id: Option<String>,
    pub sensor_id: Option<String>,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub tokens: Vec<&'static str>,
    pub run_id: String,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Baseline {
    pub baseline_id: String,
    pub bssid: String,
    pub metric: String,
    pub p5: f64,
    pub p50: f64,
    pub p95: f64,
    pub sample_count: i64,
    pub run_id: String,
}

fn groups(frames: &[ProjectionFrame]) -> BTreeMap<(&str, i64), Vec<&ProjectionFrame>> {
    let mut result: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for frame in frames {
        result
            .entry((
                frame.source_mac.as_str(),
                frame.observed_at.timestamp().div_euclid(3600) * 3600,
            ))
            .or_default()
            .push(frame);
    }
    for group in result.values_mut() {
        group.sort_by_key(|f| f.observed_at.timestamp_millis());
    }
    result
}
fn counts<'a>(values: impl Iterator<Item = &'a str>) -> String {
    let mut result = BTreeMap::<String, i64>::new();
    for value in values.filter(|v| !v.is_empty()) {
        *result.entry(value.into()).or_default() += 1;
    }
    serde_json::to_string(&result).expect("count map encodes")
}
pub fn behavior(frames: &[ProjectionFrame]) -> Vec<BehaviorSnapshot> {
    groups(frames).into_iter().map(|((mac,seconds),group)|{
        let start=DateTime::from_timestamp(seconds,0).expect("hour remains valid timestamp"); let end=start+Duration::hours(1);
        let key=format!("{mac}:{seconds}"); let signals:Vec<_>=group.iter().filter_map(|f|f.signal_dbm).collect();
        let protocols:Vec<_>=group.iter().filter_map(|f|f.app_protocol.as_ref()).map(|v|v.to_lowercase()).collect();
        let adjacent:BTreeSet<_>=group.iter().filter_map(|f|f.adjacent_mac_hint.as_ref()).collect();
        BehaviorSnapshot{snapshot_id:stable_id("behavior",&[&key]),snapshot_key:key.clone(),source_mac:mac.into(),location_id:group.iter().rev().find_map(|f|f.location_id.clone()),sensor_id:group.iter().rev().find_map(|f|f.sensor_id.clone()),window_start:start,window_end:end,event_count:group.len() as i64,
            text_summary:format!("{} wireless frames for {mac} from {} to {}",group.len(),start.to_rfc3339_opts(SecondsFormat::Secs,true),end.to_rfc3339_opts(SecondsFormat::Secs,true)),
            protocol_mix:counts(protocols.iter().map(String::as_str)),frame_distribution:counts(group.iter().map(|f|frame_token(f.frame_type.as_deref(),f.frame_subtype.as_deref()))),
            signal_min:signals.iter().copied().min(),signal_max:signals.iter().copied().max(),signal_average:(!signals.is_empty()).then(||signals.iter().map(|v|f64::from(*v)).sum::<f64>()/signals.len() as f64),
            retry_count:group.iter().filter(|f|f.retry).count() as i64,protected_count:group.iter().filter(|f|f.protected).count() as i64,unprotected_count:group.iter().filter(|f|!f.protected).count() as i64,
            unique_bssid_count:group.iter().filter_map(|f|f.bssid.as_ref()).collect::<BTreeSet<_>>().len() as i64,
            rotation_indicators:json!({"adjacent_mac_count":adjacent.len(),"adjacent_macs":adjacent,"rotation_suspected":!adjacent.is_empty()}).to_string(),run_id:stable_id("behavior-run",&[&key])}
    }).collect()
}
pub fn timing(frames: &[ProjectionFrame]) -> Vec<TimingProfile> {
    groups(frames)
        .into_iter()
        .map(|((mac, seconds), group)| {
            let start = DateTime::from_timestamp(seconds, 0).expect("hour remains valid timestamp");
            let key = format!("{mac}:{seconds}");
            let tsft: Vec<_> = group
                .iter()
                .filter_map(|f| f.tsft_delta_us)
                .map(|v| v as f64)
                .collect();
            let wall: Vec<_> = group
                .iter()
                .filter_map(|f| f.wall_clock_delta_ms)
                .map(|v| v as f64)
                .collect();
            TimingProfile {
                profile_id: stable_id("timing", &[&key]),
                profile_key: key.clone(),
                source_mac: mac.into(),
                sensor_id: group.iter().rev().find_map(|f| f.sensor_id.clone()),
                location_id: group.iter().rev().find_map(|f| f.location_id.clone()),
                window_start: start,
                window_end: start + Duration::hours(1),
                tsft_p50: percentile(&tsft, 0.5),
                tsft_p95: percentile(&tsft, 0.95),
                tsft_jitter: median_absolute_deviation(&tsft),
                wall_p50: percentile(&wall, 0.5),
                wall_jitter: median_absolute_deviation(&wall),
                source_event_count: group.len() as i64,
                run_id: stable_id("timing-run", &[&key]),
            }
        })
        .collect()
}
pub fn sequences(frames: &[ProjectionFrame]) -> Vec<Sequence> {
    let mut groups: BTreeMap<&str, Vec<&ProjectionFrame>> = BTreeMap::new();
    for frame in frames {
        if let Some(key) = frame.session_key.as_deref() {
            groups.entry(key).or_default().push(frame);
        }
    }
    groups
        .into_iter()
        .map(|(key, mut group)| {
            group.sort_by_key(|f| f.observed_at.timestamp_millis());
            Sequence {
                session_key: key.into(),
                source_mac: Some(group[0].source_mac.clone()),
                location_id: group.iter().rev().find_map(|f| f.location_id.clone()),
                sensor_id: group.iter().rev().find_map(|f| f.sensor_id.clone()),
                window_start: group[0].observed_at,
                window_end: group[group.len() - 1].observed_at,
                tokens: group
                    .iter()
                    .map(|f| frame_token(f.frame_type.as_deref(), f.frame_subtype.as_deref()))
                    .collect(),
                run_id: stable_id("sequence-run", &[key]),
            }
        })
        .collect()
}
pub fn baseline(bssid: &str, signals: &[f64]) -> Option<Baseline> {
    Some(Baseline {
        baseline_id: stable_id("baseline", &[bssid, "signal_dbm"]),
        bssid: bssid.into(),
        metric: "signal_dbm".into(),
        p5: percentile(signals, 0.05)?,
        p50: percentile(signals, 0.5)?,
        p95: percentile(signals, 0.95)?,
        sample_count: signals.len() as i64,
        run_id: stable_id("baseline-run", &[bssid, "signal_dbm"]),
    })
}

#[derive(Clone, Debug, PartialEq)]
pub struct IdentityCluster {
    pub cluster_id: String,
    pub members: Vec<String>,
    pub confidence: f64,
    pub run_id: String,
}
pub fn identity_clusters(edges: &[(String, String, f64)]) -> Vec<IdentityCluster> {
    let mut graph: BTreeMap<&str, BTreeMap<&str, f64>> = BTreeMap::new();
    for (left, right, confidence) in edges
        .iter()
        .filter(|(l, r, c)| !l.is_empty() && !r.is_empty() && l != r && c.is_finite() && *c >= 0.0)
    {
        for (from, to) in [(left, right), (right, left)] {
            let value = graph.entry(from).or_default().entry(to).or_insert(0.0);
            *value = value.max(confidence.clamp(0.0, 1.0));
        }
    }
    let mut remaining: BTreeSet<_> = graph.keys().copied().collect();
    let mut result = Vec::new();
    while let Some(start) = remaining.first().copied() {
        let mut frontier = vec![start];
        let mut members = BTreeSet::new();
        let mut confidence: f64 = 1.0;
        while let Some(node) = frontier.pop() {
            if members.insert(node) {
                remaining.remove(node);
                for (&neighbor, &weight) in &graph[node] {
                    confidence = confidence.min(weight);
                    if !members.contains(neighbor) {
                        frontier.push(neighbor);
                    }
                }
            }
        }
        let parts: Vec<_> = members.into_iter().collect();
        let id = stable_id("identity-cluster", &parts);
        result.push(IdentityCluster {
            cluster_id: id.clone(),
            members: parts.into_iter().map(str::to_owned).collect(),
            confidence,
            run_id: stable_id("identity-cluster-run", &[&id]),
        });
    }
    result
}

#[derive(Clone, Debug, PartialEq)]
pub struct DnsThreat {
    pub source_key: String,
    pub signal_id: String,
    pub score: f64,
    pub severity: &'static str,
    pub evidence: Value,
    pub detected_at: DateTime<Utc>,
    pub run_id: String,
}
pub fn dns_threat(
    host: &str,
    blocked_count: i64,
    attempted_bytes: i64,
    recent_count: i64,
    last_seen: DateTime<Utc>,
) -> DnsThreat {
    let blocked = blocked_count.max(0);
    let denominator = blocked.max(1) as f64;
    let bytes = attempted_bytes.max(0) as f64;
    let recent = recent_count.clamp(0, blocked) as f64;
    let weight = 1.0 + 2.0 * recent / denominator;
    let score = blocked as f64 * (bytes / denominator + 1.0) * weight;
    DnsThreat {
        source_key: format!("dns:{host}"),
        signal_id: stable_id("dns-threat", &[host]),
        score,
        severity: if score >= 1000.0 {
            "critical"
        } else if score >= 500.0 {
            "high"
        } else if score >= 100.0 {
            "medium"
        } else {
            "low"
        },
        evidence: json!({"blocked_count_7d":blocked_count,"attempted_bytes_7d":attempted_bytes,"recent_count_24h":recent_count,"legacy_recency_weight":weight,"score_version":"legacy-blocked-intensity-v1","calibration_status":"uncalibrated","count_semantics":"retained_observations_not_attempts","byte_semantics":"legacy_scalar_sum_not_validated_transfer","confirmed_threat":false}),
        detected_at: last_seen,
        run_id: stable_id("dns-threat-run", &[host]),
    }
}
#[derive(Clone, Debug, PartialEq)]
pub struct ApRisk {
    pub bssid: String,
    pub composite: f64,
    pub signal: f64,
    pub identity: f64,
    pub behavior: f64,
    pub evidence: Value,
    pub run_id: String,
}
pub fn ap_risk(bssid: &str, inputs: [f64; 5]) -> Result<ApRisk, ProjectionError> {
    if !inputs.iter().all(|v| v.is_finite()) {
        return Err(ProjectionError::Invalid("AP risk inputs must be finite"));
    }
    let bounded = inputs.map(|v| v.clamp(0.0, 1.0));
    let signal = bounded[0] * 0.25 + bounded[1] * 0.20;
    let identity = bounded[2] * 0.20 + bounded[3] * 0.15;
    let behavior = bounded[4] * 0.20;
    Ok(ApRisk {
        bssid: bssid.into(),
        composite: (signal + identity + behavior).clamp(0.0, 1.0),
        signal,
        identity,
        behavior,
        evidence: json!({"deauth_score":inputs[0],"signal_anomaly_score":inputs[1],"typosquat_score":inputs[2],"vendor_mismatch_score":inputs[3],"embedding_outlier_score":inputs[4],"weights":[0.25,0.20,0.20,0.15,0.20]}),
        run_id: stable_id("ap-risk-run", &[bssid]),
    })
}

impl ProjectionStore {
    pub async fn project_behavior(&self, limit: i32) -> Result<i32, ProjectionError> {
        let mut tx = self.runtime.begin_worker().await?;
        let frames = tx
            .query(sql::BEHAVIOR_CANDIDATES_0, &[&limit.max(1)])
            .await?
            .into_iter()
            .map(ProjectionFrame::from_row)
            .collect::<Vec<_>>();
        let mut count = 0;
        for value in behavior(&frames) {
            count += tx
                .execute(
                    sql::PERSIST_BEHAVIOR_0,
                    &[
                        &value.snapshot_id,
                        &value.snapshot_key,
                        &value.source_mac,
                        &value.location_id,
                        &value.sensor_id,
                        &value.window_start,
                        &value.window_end,
                        &value.event_count,
                        &value.text_summary,
                        &Some(&value.text_summary),
                        &value.protocol_mix,
                        &value.frame_distribution,
                        &value.signal_min,
                        &value.signal_max,
                        &value.signal_average,
                        &value.retry_count,
                        &value.protected_count,
                        &value.unprotected_count,
                        &value.unique_bssid_count,
                        &value.rotation_indicators,
                        &value.run_id,
                    ],
                )
                .await? as i32;
        }
        tx.commit().await?;
        Ok(count)
    }
    pub async fn project_timing(&self, limit: i32) -> Result<i32, ProjectionError> {
        let mut tx = self.runtime.begin_worker().await?;
        let frames = tx
            .query(sql::TIMING_CANDIDATES_0, &[&limit.max(1)])
            .await?
            .into_iter()
            .map(ProjectionFrame::from_row)
            .collect::<Vec<_>>();
        let mut count = 0;
        for value in timing(&frames) {
            count += tx
                .execute(
                    sql::PERSIST_TIMING_0,
                    &[
                        &value.profile_id,
                        &value.profile_key,
                        &value.source_mac,
                        &value.sensor_id,
                        &value.location_id,
                        &value.window_start,
                        &value.window_end,
                        &value.tsft_p50,
                        &value.tsft_p95,
                        &value.tsft_jitter,
                        &value.wall_p50,
                        &value.wall_jitter,
                        &value.source_event_count,
                        &value.run_id,
                    ],
                )
                .await? as i32;
        }
        tx.commit().await?;
        Ok(count)
    }
    pub async fn project_sequences(&self, limit: i32) -> Result<i32, ProjectionError> {
        let mut tx = self.runtime.begin_worker().await?;
        // Aggregate transition replacement reads across sessions. Serialize this
        // operation so overlapping instances cannot lose another session's rows.
        tx.query("SELECT pg_advisory_xact_lock(hashtextextended('octopus-sequence-transitions',0)) IS NULL",&[]).await?;
        let frames = tx
            .query(sql::SEQUENCE_CANDIDATES_0, &[&limit.max(1)])
            .await?
            .into_iter()
            .map(ProjectionFrame::from_row)
            .collect::<Vec<_>>();
        let mut count = 0;
        for value in sequences(&frames) {
            count += persist_sequence(&mut tx, &value).await?;
        }
        tx.commit().await?;
        Ok(count)
    }
    pub async fn project_baselines(&self, limit: i32) -> Result<i32, ProjectionError> {
        let mut tx = self.runtime.begin_worker().await?;
        let rows = tx
            .query(sql::BASELINE_CANDIDATES_0, &[&limit.max(1)])
            .await?;
        let mut grouped = BTreeMap::<String, Vec<f64>>::new();
        for row in rows {
            grouped.entry(row.get(0)).or_default().push(row.get(1));
        }
        let mut count = 0;
        for (bssid, signals) in grouped {
            if let Some(v) = baseline(&bssid, &signals) {
                count += tx
                    .execute(
                        sql::PERSIST_BASELINE_0,
                        &[
                            &v.baseline_id,
                            &v.bssid,
                            &v.metric,
                            &v.p5,
                            &v.p50,
                            &v.p95,
                            &v.sample_count,
                            &v.run_id,
                        ],
                    )
                    .await? as i32;
            }
        }
        tx.commit().await?;
        Ok(count)
    }
}

async fn persist_sequence(tx: &mut PgTransaction, v: &Sequence) -> Result<i32, ProjectionError> {
    let old = tx.query(sql::PERSIST_SEQUENCE_0, &[&v.session_key]).await?;
    let mut affected: BTreeSet<String> = old.iter().map(|r| r.get(0)).collect();
    let token_text = v.tokens.join(" ");
    let n = v.tokens.len() as i64;
    let mut count = tx
        .execute(
            sql::PERSIST_SEQUENCE_1,
            &[
                &v.session_key,
                &v.source_mac,
                &v.location_id,
                &v.sensor_id,
                &v.window_start,
                &v.window_end,
                &token_text,
                &n,
                &v.run_id,
            ],
        )
        .await? as i32;
    tx.execute(sql::PERSIST_SEQUENCE_2, &[&v.session_key])
        .await?;
    tx.execute(sql::PERSIST_SEQUENCE_3, &[&v.session_key])
        .await?;
    let mut transitions = BTreeMap::<(&str, &str), i64>::new();
    let mut totals = BTreeMap::<&str, i64>::new();
    for pair in v.tokens.windows(2) {
        *transitions.entry((pair[0], pair[1])).or_default() += 1;
        *totals.entry(pair[0]).or_default() += 1;
    }
    for ((previous, next), n) in transitions {
        count += tx
            .execute(
                sql::PERSIST_SEQUENCE_4,
                &[
                    &v.session_key,
                    &previous,
                    &next,
                    &n,
                    &totals[previous],
                    &v.run_id,
                ],
            )
            .await? as i32;
    }
    for (previous, total) in totals {
        count += tx
            .execute(
                sql::PERSIST_SEQUENCE_5,
                &[&v.session_key, &previous, &total, &v.run_id],
            )
            .await? as i32;
        affected.insert(previous.into());
    }
    for previous in affected {
        count += tx.execute(sql::PERSIST_SEQUENCE_6, &[&previous]).await? as i32;
        count += tx
            .execute(sql::PERSIST_SEQUENCE_7, &[&13_i64, &v.run_id, &previous])
            .await? as i32;
    }
    Ok(count)
}
