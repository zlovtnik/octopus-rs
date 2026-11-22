use super::{
    intelligence::{identity_clusters, stable_id},
    queries as q, ProjectionError, ProjectionStore,
};
use crate::postgres::PgTransaction;
use chrono::{DateTime, Utc};
use std::collections::BTreeSet;

pub(super) const AUTOMATIC_MERGE_SIMILARITY: f64 = 0.98;

const RECONCILE_PREDICATE:&str="CASE WHEN $1::text[] IS NULL THEN NOT EXISTS (SELECT 1 FROM octopus_core.dq_scope_policies policy WHERE policy.mode='enabled' AND (policy.authorized_scope='*' OR (EXISTS (SELECT 1 FROM atheros_search.devices device WHERE device.mac=candidate.mac_a AND device.location_id=policy.authorized_scope) AND EXISTS (SELECT 1 FROM atheros_search.devices device WHERE device.mac=candidate.mac_b AND device.location_id=policy.authorized_scope)))) ELSE candidate.candidate_id=ANY($1::text[]) END";

pub async fn persist_merge_candidate(
    tx: &mut PgTransaction,
    left: &str,
    right: &str,
    confidence: f64,
) -> Result<String, ProjectionError> {
    if !confidence.is_finite() {
        return Err(ProjectionError::Invalid("nonfinite identity confidence"));
    }
    let (left, right) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    let id = stable_id("merge-candidate", &[left, right]);
    let run = stable_id("merge-candidate-run", &[&id]);
    let rows = tx
        .query(
            q::UPSERT_MERGE_CANDIDATE,
            &[&id, &left, &right, &confidence.clamp(0.0, 1.0), &run],
        )
        .await?;
    Ok(rows[0].get(0))
}
async fn reconcile(
    tx: &mut PgTransaction,
    ids: Option<Vec<String>>,
) -> Result<i32, ProjectionError> {
    tx.query(&format!("SELECT candidate.candidate_id FROM atheros_search.merge_candidates candidate WHERE {RECONCILE_PREDICATE} ORDER BY candidate.candidate_id FOR UPDATE OF candidate"),&[&ids]).await?;
    let statement=format!("WITH classified AS (SELECT candidate.candidate_id,
        CASE WHEN decision.decision='merge' THEN 'confirmed' WHEN decision.candidate_id IS NOT NULL THEN decision.decision
          WHEN candidate.confidence >= $2 AND left_device.registered AND right_device.registered
            AND left_device.registered_device_id IS NOT NULL AND left_device.registered_device_id=right_device.registered_device_id THEN 'confirmed' ELSE 'pending' END AS next_status,
        CASE WHEN decision.decision='merge' THEN 'human' WHEN decision.candidate_id IS NULL AND candidate.confidence >= $2 AND left_device.registered AND right_device.registered AND left_device.registered_device_id IS NOT NULL AND left_device.registered_device_id=right_device.registered_device_id THEN 'automatic' ELSE NULL END AS next_source,
        CASE WHEN decision.candidate_id IS NULL AND candidate.confidence >= $2 AND left_device.registered AND right_device.registered AND left_device.registered_device_id IS NOT NULL AND left_device.registered_device_id=right_device.registered_device_id THEN left_device.registered_device_id ELSE NULL END AS next_registered_device_id
        FROM atheros_search.merge_candidates candidate
        LEFT JOIN atheros_search.merge_decisions decision ON decision.candidate_id=candidate.candidate_id
        LEFT JOIN atheros_search.devices left_device ON left_device.mac=candidate.mac_a
        LEFT JOIN atheros_search.devices right_device ON right_device.mac=candidate.mac_b
        WHERE {RECONCILE_PREDICATE})
        UPDATE atheros_search.merge_candidates candidate SET status=classified.next_status,confirmation_source=classified.next_source,
        trusted_registered_device_id=classified.next_registered_device_id,
        confirmed_at=CASE WHEN classified.next_status='confirmed' THEN COALESCE(candidate.confirmed_at,CURRENT_TIMESTAMP) ELSE NULL END,
        updated_at=CURRENT_TIMESTAMP FROM classified WHERE classified.candidate_id=candidate.candidate_id
        AND (candidate.status,candidate.confirmation_source,candidate.trusted_registered_device_id)
        IS DISTINCT FROM (classified.next_status,classified.next_source,classified.next_registered_device_id)");
    Ok(tx
        .execute(&statement, &[&ids, &AUTOMATIC_MERGE_SIMILARITY])
        .await? as i32)
}
pub async fn reconcile_merge_confirmations_for(
    tx: &mut PgTransaction,
    ids: &[String],
) -> Result<i32, ProjectionError> {
    if ids.is_empty() {
        return Ok(0);
    }
    reconcile(
        tx,
        Some(
            ids.iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        ),
    )
    .await
}
pub async fn replace_approved_clusters(tx: &mut PgTransaction) -> Result<i32, ProjectionError> {
    let edges = tx
        .query(
            q::SELECT_APPROVED_IDENTITY_EDGES,
            &[&AUTOMATIC_MERGE_SIMILARITY],
        )
        .await?
        .into_iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect::<Vec<_>>();
    let clusters = identity_clusters(&edges);
    let mut total=tx.execute("UPDATE atheros_search.identity_clusters SET status='inactive',updated_at=CURRENT_TIMESTAMP WHERE status='active'",&[]).await? as i32;
    total += tx
        .execute("DELETE FROM atheros_search.identity_cluster_members", &[])
        .await? as i32;
    for v in clusters {
        let rows=tx.query("SELECT MIN(first_seen),MAX(last_seen) FROM atheros_search.devices WHERE mac=ANY($1::text[])",&[&v.members]).await?;
        let first: Option<DateTime<Utc>> = rows[0].get(0);
        let last: Option<DateTime<Utc>> = rows[0].get(1);
        let Some(first) = first.or(last) else {
            continue;
        };
        let last = last.unwrap_or(first);
        let name = format!("identity-{}", &v.cluster_id[..8]);
        let size = v.members.len() as i32;
        total+=tx.execute("INSERT INTO atheros_search.identity_clusters(cluster_id,cluster_name,cluster_size,first_seen,last_seen,status,projection_run_id) VALUES($1,$2,$3,$4,$5,'active',$6) ON CONFLICT(cluster_id) DO UPDATE SET cluster_size=EXCLUDED.cluster_size,first_seen=LEAST(identity_clusters.first_seen,EXCLUDED.first_seen),last_seen=GREATEST(identity_clusters.last_seen,EXCLUDED.last_seen),status='active',projection_run_id=EXCLUDED.projection_run_id,updated_at=CURRENT_TIMESTAMP",&[&v.cluster_id,&name,&size,&first,&last,&v.run_id]).await? as i32;
        for mac in v.members {
            total+=tx.execute("INSERT INTO atheros_search.identity_cluster_members(cluster_id,mac,confidence,evidence,first_seen,last_seen) SELECT $1,device.mac,$2,jsonb_build_object('source','confirmed_identity_edge'),device.first_seen,device.last_seen FROM atheros_search.devices device WHERE device.mac=$3 ON CONFLICT(mac) DO UPDATE SET cluster_id=EXCLUDED.cluster_id,confidence=EXCLUDED.confidence,evidence=EXCLUDED.evidence,first_seen=LEAST(identity_cluster_members.first_seen,EXCLUDED.first_seen),last_seen=GREATEST(identity_cluster_members.last_seen,EXCLUDED.last_seen),updated_at=CURRENT_TIMESTAMP",&[&v.cluster_id,&v.confidence,&mac]).await? as i32;
        }
    }
    Ok(total)
}
async fn lock_identity_clusters(tx: &mut PgTransaction) -> Result<(), ProjectionError> {
    tx.query(
        "SELECT pg_advisory_xact_lock(hashtextextended('octopus-identity-clusters',0)) IS NULL",
        &[],
    )
    .await?;
    Ok(())
}

/// Runs inside the DQ caller's authorization/fence transaction. This deliberately
/// rebuilds clusters from all approved edges after reconciling the scoped input.
pub async fn apply_identity_candidates(
    tx: &mut PgTransaction,
    candidates: &[(String, String, f64)],
    reconciliation_ids: &[String],
) -> Result<Vec<String>, ProjectionError> {
    lock_identity_clusters(tx).await?;
    let mut ids = Vec::new();
    for (left, right, confidence) in candidates {
        ids.push(persist_merge_candidate(tx, left, right, *confidence).await?);
    }
    let mut reconciliation_ids = reconciliation_ids.to_vec();
    reconciliation_ids.extend(ids.iter().cloned());
    reconcile_merge_confirmations_for(tx, &reconciliation_ids).await?;
    replace_approved_clusters(tx).await?;
    Ok(ids)
}
impl ProjectionStore {
    pub async fn project_cluster_candidates(
        &self,
        limit: i32,
        minimum_similarity: f64,
    ) -> Result<i32, ProjectionError> {
        if !minimum_similarity.is_finite() {
            return Err(ProjectionError::Invalid("nonfinite similarity threshold"));
        }
        let mut tx = self.runtime.begin_worker().await?;
        let edges = tx
            .query(
                q::SELECT_SIMILARITY_EDGES,
                &[&minimum_similarity.clamp(-1.0, 1.0), &limit.max(1)],
            )
            .await?;
        let mut seen = BTreeSet::new();
        let mut total = 0;
        for row in edges {
            let left: String = row.get(0);
            let right: String = row.get(1);
            let pair = if left <= right {
                (left, right)
            } else {
                (right, left)
            };
            if seen.insert(pair.clone()) {
                persist_merge_candidate(&mut tx, &pair.0, &pair.1, row.get(2)).await?;
                total += 1;
            }
        }
        tx.commit().await?;
        Ok(total)
    }
    pub async fn project_approved_identities(
        &self,
        candidate_changes: i32,
    ) -> Result<i32, ProjectionError> {
        let mut tx = self.runtime.begin_worker().await?;
        lock_identity_clusters(&mut tx).await?;
        let reconciled = reconcile(&mut tx, None).await?;
        let total = if reconciled == 0 && candidate_changes <= 0 {
            0
        } else {
            replace_approved_clusters(&mut tx).await?
        };
        tx.commit().await?;
        Ok(total)
    }
}
