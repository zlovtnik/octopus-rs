use super::*;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub mac_a: String,
    pub mac_b: String,
    pub confidence: f64,
    pub pair_id: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reconciliation {
    pub candidate_id: String,
    pub decision: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub candidate_count: usize,
    pub reconciliation_count: usize,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub run_id: String,
    pub attempt_id: String,
    pub fence: i64,
    pub operation: String,
    pub source_revision_digest: String,
    pub policy_version: String,
    pub candidates: Vec<Candidate>,
    pub reconciliations: Vec<Reconciliation>,
    pub summary: Summary,
}
fn array<'a>(v: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    v[key]
        .as_array()
        .ok_or_else(|| error(400, &format!("snapshot_{key}_invalid")))
}
pub fn validate(run: &Value, snapshot: &Value, output: &Value) -> Result<Proposal> {
    let p: Proposal = serde_json::from_value(output.clone())
        .map_err(|_| error(400, "proposal_schema_invalid"))?;
    let attempt = &run["current_attempt"];
    let parameters = &run["parameters"];
    let limit = dq::int(parameters, "max_candidates")?;
    if p.run_id != dq::text(run, "run_id")?
        || p.attempt_id != dq::text(attempt, "attempt_id")?
        || p.fence != dq::long(attempt, "fence")?
        || p.operation != dq::text(run, "operation")?
        || p.policy_version != dq::text(run, "policy_version")?
        || p.source_revision_digest != dq::text(run, "source_revision_digest")?
        || p.source_revision_digest != dq::text(snapshot, "source_revision_digest")?
        || !super::snapshot::validate_digest(snapshot)?
        || snapshot["installation_id"] != run["installation_id"]
        || snapshot["namespace"] != run["namespace"]
        || snapshot["operation"] != p.operation
        || snapshot["policy_version"] != p.policy_version
        || snapshot["authorized_scope"] != parameters["authorized_scope"]
        || dq::text(run, "processor_id")? != "atheros.dedup"
        || limit < 0
        || p.candidates.len() > limit as usize
        || p.summary.candidate_count != p.candidates.len()
        || p.summary.reconciliation_count != p.reconciliations.len()
    {
        return Err(error(400, "proposal_identity_mismatch"));
    }
    let pairs = array(snapshot, "pairs")?;
    let decisions = array(snapshot, "decisions")?;
    let candidates = array(snapshot, "candidates")?;
    let devices = array(snapshot, "devices")?;
    let macs = devices
        .iter()
        .map(|d| dq::text(d, "mac"))
        .collect::<Result<BTreeSet<_>>>()?;
    let mac = regex::Regex::new(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$").expect("constant regex");
    let mut seen = BTreeSet::new();
    for c in &p.candidates {
        let pair_matches = pairs.iter().any(|s| {
            s["pair_id"] == c.pair_id
                && s["mac_a"] == c.mac_a
                && s["mac_b"] == c.mac_b
                && s["confidence"].as_f64() == Some(c.confidence)
        });
        let decided = candidates
            .iter()
            .find(|s| s["mac_a"] == c.mac_a && s["mac_b"] == c.mac_b)
            .is_some_and(|c| {
                decisions
                    .iter()
                    .any(|d| d["candidate_id"] == c["candidate_id"])
            });
        if !mac.is_match(&c.mac_a)
            || !mac.is_match(&c.mac_b)
            || c.mac_a >= c.mac_b
            || !c.confidence.is_finite()
            || !(0.0..=1.0).contains(&c.confidence)
            || !pair_matches
            || decided
            || !macs.contains(c.mac_a.as_str())
            || !macs.contains(c.mac_b.as_str())
        {
            return Err(error(400, "proposal_candidate_forbidden"));
        }
        if !seen.insert((&c.mac_a, &c.mac_b)) {
            return Err(error(400, "proposal_duplicate_pair"));
        }
    }
    match p.operation.as_str() {
        "prepare_candidates" => {
            if !p.reconciliations.is_empty() {
                return Err(error(400, "proposal_operation_mismatch"));
            }
        }
        "reconcile_decision" => {
            if !p.candidates.is_empty()
                || p.reconciliations.len() != 1
                || !p.reconciliations.iter().all(|r| {
                    parameters["candidate_id"] == r.candidate_id
                        && candidates
                            .iter()
                            .any(|c| c["candidate_id"] == r.candidate_id)
                        && decisions.iter().any(|d| {
                            d["candidate_id"] == r.candidate_id && d["decision"] == r.decision
                        })
                })
            {
                return Err(error(400, "proposal_decision_forbidden"));
            }
        }
        _ => return Err(error(400, "proposal_operation_unsupported")),
    }
    Ok(p)
}
pub fn shadow_comparison(snapshot: &Value, p: &Proposal) -> Result<Value> {
    let mut legacy = BTreeMap::<(&str, &str), f64>::new();
    for pair in array(snapshot, "pairs")? {
        let key = (dq::text(pair, "mac_a")?, dq::text(pair, "mac_b")?);
        let confidence = pair["confidence"]
            .as_f64()
            .ok_or_else(|| error(400, "source_confidence_invalid"))?;
        legacy
            .entry(key)
            .and_modify(|v| *v = v.max(confidence))
            .or_insert(confidence);
    }
    let proposed: BTreeMap<_, _> = p
        .candidates
        .iter()
        .map(|v| ((v.mac_a.as_str(), v.mac_b.as_str()), v.confidence))
        .collect();
    Ok(
        json!({"source_revision_digest":p.source_revision_digest,"legacy_candidate_count":legacy.len(),"proposal_candidate_count":proposed.len(),"missing_pairs":legacy.keys().filter(|k|!proposed.contains_key(*k)).count(),"additional_pairs":proposed.keys().filter(|k|!legacy.contains_key(*k)).count(),"confidence_differences":legacy.iter().filter(|(k,v)|proposed.get(*k).is_some_and(|c|c!=*v)).count(),"reconciliation_count":p.reconciliations.len()}),
    )
}
impl DqStore {
    pub async fn apply_output(
        &self,
        owner: &str,
        run: &Value,
        snapshot: &Value,
        output: &Value,
        minimum_similarity: f64,
    ) -> Result<bool> {
        let proposal = validate(run, snapshot, output)?;
        let shadow = dq::text(run, "execution_mode")? == "shadow";
        let mut tx = self.transaction().await?;
        tx.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", &[])
            .await
            .map_err(database)?;
        if !self
            .guard_output_tx(
                &mut tx,
                &proposal.run_id,
                &proposal.attempt_id,
                proposal.fence,
                owner,
                &proposal.source_revision_digest,
            )
            .await?
        {
            tx.commit().await.map_err(database)?;
            return Ok(false);
        }
        self.lock_snapshot(&mut tx, snapshot).await?;
        let current = self.snapshot_tx(&mut tx, run, minimum_similarity).await?;
        if dq::text(&current, "source_revision_digest")? != proposal.source_revision_digest {
            return Err(error(409, "source_revision_changed"));
        }
        let ids = if shadow {
            Vec::new()
        } else {
            let candidates = proposal
                .candidates
                .iter()
                .map(|c| (c.mac_a.clone(), c.mac_b.clone(), c.confidence))
                .collect::<Vec<_>>();
            let reconciliations = proposal
                .reconciliations
                .iter()
                .map(|r| r.candidate_id.clone())
                .collect::<Vec<_>>();
            crate::projections::identity::apply_identity_candidates(
                &mut tx,
                &candidates,
                &reconciliations,
            )
            .await
            .map_err(|_| error(503, "projection_dependency_failure"))?
        };
        let review_ids = ids
            .into_iter()
            .chain(
                proposal
                    .reconciliations
                    .iter()
                    .map(|r| r.candidate_id.clone()),
            )
            .collect::<BTreeSet<_>>();
        let mut summary = json!({"candidate_count":proposal.candidates.len(),"reconciliation_count":proposal.reconciliations.len(),"review_candidate_ids":review_ids});
        if shadow {
            summary["shadow_comparison"] = shadow_comparison(snapshot, &proposal)?;
        }
        if !self
            .complete_output_tx(
                &mut tx,
                &proposal.run_id,
                &proposal.attempt_id,
                proposal.fence,
                owner,
                &proposal.source_revision_digest,
                !shadow,
                &summary,
            )
            .await?
        {
            return Err(error(409, "application_fence_lost"));
        }
        tx.commit().await.map_err(database)?;
        Ok(true)
    }
}
