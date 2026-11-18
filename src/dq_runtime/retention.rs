use super::*;
use crate::config::DqConfig;
pub fn allowed_key(key: &str, config: &DqConfig) -> bool {
    let parts = key.split('/').collect::<Vec<_>>();
    let scoped = parts.first().copied() == Some(config.installation_id.as_str())
        && parts.get(1).copied() == Some(config.namespace.as_str());
    scoped
        && parts.iter().all(|p| artifacts::safe_segment(p))
        && matches!(
            parts.as_slice(),
            [_, _, "inputs", _, _] | [_, _, "runs", _, "attempts", _, _]
        )
}
fn reference_key(reference: &Value, config: &DqConfig) -> Result<String> {
    let prefix = format!("s3://{}/", config.artifact_bucket);
    let key = dq::text(reference, "uri")?
        .strip_prefix(&prefix)
        .ok_or_else(|| error(400, "forbidden_retention_reference"))?;
    if !allowed_key(key, config) || dq::text(reference, "version_id")? == "null" {
        return Err(error(400, "forbidden_retention_reference"));
    }
    Ok(key.into())
}
const REOPEN: &str = r#"WITH reopened AS(SELECT r.run_id FROM octopus_core.dq_runs r WHERE r.installation_id=$1 AND r.namespace=$2 AND r.projection_applied AND(jsonb_typeof(r.summary->'review_candidate_ids') IS DISTINCT FROM 'array' OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(COALESCE(r.summary->'review_candidate_ids','[]'::jsonb)) ids(candidate_id) LEFT JOIN atheros_search.merge_candidates c USING(candidate_id) WHERE c.candidate_id IS NULL OR c.status NOT IN('confirmed','rejected','not_match'))) AND EXISTS(SELECT 1 FROM octopus_core.dq_artifacts a WHERE a.run_id=r.run_id AND a.closed_at IS NOT NULL) ORDER BY r.run_id LIMIT $3) UPDATE octopus_core.dq_artifacts a SET closed_at=NULL,retained_until=NULL FROM reopened WHERE a.run_id=reopened.run_id AND a.closed_at IS NOT NULL"#;
const CLOSE: &str = r#"WITH eligible AS(SELECT r.run_id,GREATEST(r.completed_at,COALESCE((SELECT max(GREATEST(c.updated_at,d.decided_at)) FROM jsonb_array_elements_text(COALESCE(r.summary->'review_candidate_ids','[]'::jsonb)) ids(candidate_id) JOIN atheros_search.merge_candidates c USING(candidate_id) LEFT JOIN atheros_search.merge_decisions d USING(candidate_id)),r.completed_at)) closed_at FROM octopus_core.dq_runs r WHERE r.installation_id=$1 AND r.namespace=$2 AND r.status IN('succeeded','failed','cancelled') AND r.completed_at IS NOT NULL AND(NOT r.projection_applied OR jsonb_typeof(r.summary->'review_candidate_ids')='array') AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(COALESCE(r.summary->'review_candidate_ids','[]'::jsonb)) ids(candidate_id) LEFT JOIN atheros_search.merge_candidates c USING(candidate_id) WHERE c.candidate_id IS NULL OR c.status NOT IN('confirmed','rejected','not_match')) AND EXISTS(SELECT 1 FROM octopus_core.dq_artifacts a WHERE a.run_id=r.run_id AND(a.closed_at IS NULL OR a.retained_until<=CURRENT_TIMESTAMP))),closed AS(SELECT e.run_id,e.closed_at FROM eligible e WHERE EXISTS(SELECT 1 FROM octopus_core.dq_artifacts a WHERE a.run_id=e.run_id AND(a.closed_at IS NULL OR a.closed_at<e.closed_at)) ORDER BY e.closed_at,e.run_id LIMIT $3) UPDATE octopus_core.dq_artifacts a SET closed_at=closed.closed_at,retained_until=closed.closed_at+INTERVAL '90 days' FROM closed WHERE a.run_id=closed.run_id AND(a.closed_at IS NULL OR a.closed_at<closed.closed_at)"#;
const EXPIRED: &str = r#"SELECT a.reference FROM octopus_core.dq_artifacts a JOIN octopus_core.dq_runs r ON r.run_id=a.run_id WHERE a.installation_id=$1 AND a.namespace=$2 AND a.retained_until<=CURRENT_TIMESTAMP AND r.status IN('succeeded','failed','cancelled') AND(NOT r.projection_applied OR jsonb_typeof(r.summary->'review_candidate_ids')='array') AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(COALESCE(r.summary->'review_candidate_ids','[]'::jsonb)) ids(candidate_id) LEFT JOIN atheros_search.merge_candidates c USING(candidate_id) LEFT JOIN atheros_search.merge_decisions d USING(candidate_id) WHERE c.candidate_id IS NULL OR c.status NOT IN('confirmed','rejected','not_match') OR GREATEST(c.updated_at,d.decided_at)>CURRENT_TIMESTAMP-INTERVAL '90 days') ORDER BY a.retained_until,a.artifact_id LIMIT $3"#;
impl DqStore {
    pub async fn retention_batch(
        &self,
        artifacts: &artifacts::DqArtifacts,
        config: &DqConfig,
    ) -> Result<u64> {
        let mut tx = self.transaction().await?;
        let mut changed = 0;
        for sql in [REOPEN, CLOSE] {
            changed += tx
                .execute(
                    sql,
                    &[
                        &self.settings.installation_id,
                        &self.settings.namespace,
                        &100i64,
                    ],
                )
                .await
                .map_err(database)?;
        }
        let rows = tx
            .query(
                EXPIRED,
                &[
                    &self.settings.installation_id,
                    &self.settings.namespace,
                    &100i64,
                ],
            )
            .await
            .map_err(database)?;
        tx.commit().await.map_err(database)?;
        for row in rows {
            let reference: Value = row.get(0);
            match reference_key(&reference, config) {
                Ok(key) => {
                    let version = dq::text(&reference, "version_id")?;
                    let artifact = dq::text(&reference, "artifact_id")?;
                    artifacts
                        .objects()
                        .delete(&key, Some(version))
                        .await
                        .map_err(|_| error(503, "retention_dependency_failure"))?;
                    let mut tx = self.transaction().await?;
                    changed+=tx.execute("DELETE FROM octopus_core.dq_artifacts WHERE artifact_id=$1 AND reference->>'version_id'=$2 AND retained_until<=CURRENT_TIMESTAMP",&[&artifact,&version]).await.map_err(database)?;
                    tx.commit().await.map_err(database)?;
                }
                Err(e) if e.status < 500 => {
                    let mut tx = self.transaction().await?;
                    changed+=tx.execute("DELETE FROM octopus_core.dq_artifacts WHERE installation_id=$1 AND namespace=$2 AND reference=$3 AND retained_until<=CURRENT_TIMESTAMP",&[&self.settings.installation_id,&self.settings.namespace,&reference]).await.map_err(database)?;
                    tx.commit().await.map_err(database)?;
                }
                Err(e) => return Err(e),
            }
        }
        let mut tx = self.transaction().await?;
        let runs=tx.query("SELECT r.run_id FROM octopus_core.dq_runs r WHERE r.installation_id=$1 AND r.namespace=$2 AND r.status IN('succeeded','failed','cancelled') AND r.completed_at<CURRENT_TIMESTAMP-INTERVAL '90 days' AND NOT EXISTS(SELECT 1 FROM octopus_core.dq_artifacts a WHERE a.run_id=r.run_id) AND NOT EXISTS(SELECT 1 FROM octopus_core.dq_outbox o WHERE o.payload->>'run_id'=r.run_id AND o.status<>'published') ORDER BY r.completed_at,r.run_id FOR UPDATE SKIP LOCKED LIMIT 100",&[&self.settings.installation_id,&self.settings.namespace]).await.map_err(database)?;
        for run in runs {
            let run: String = run.get(0);
            tx.execute(
                "DELETE FROM octopus_core.dq_attempts WHERE run_id=$1",
                &[&run],
            )
            .await
            .map_err(database)?;
            changed += tx
                .execute("DELETE FROM octopus_core.dq_runs WHERE run_id=$1", &[&run])
                .await
                .map_err(database)?;
        }
        for sql in[
            "DELETE FROM octopus_core.dq_receipts WHERE ctid IN(SELECT ctid FROM octopus_core.dq_receipts WHERE installation_id=$1 AND namespace=$2 AND received_at<CURRENT_TIMESTAMP-INTERVAL '90 days' LIMIT 1000)",
            "DELETE FROM octopus_core.dq_audit WHERE audit_id IN(SELECT audit_id FROM octopus_core.dq_audit WHERE installation_id=$1 AND namespace=$2 AND created_at<CURRENT_TIMESTAMP-INTERVAL '180 days' LIMIT 1000)",
            "DELETE FROM octopus_core.dq_outbox WHERE outbox_id IN(SELECT outbox_id FROM octopus_core.dq_outbox WHERE status='published' AND payload->>'installation_id'=$1 AND payload->>'namespace'=$2 AND published_at<CURRENT_TIMESTAMP-INTERVAL '180 days' LIMIT 1000)",
            "DELETE FROM octopus_core.dq_workers WHERE worker_instance_id IN(SELECT w.worker_instance_id FROM octopus_core.dq_workers w WHERE w.installation_id=$1 AND w.namespace=$2 AND w.last_seen_at<CURRENT_TIMESTAMP-INTERVAL '1 day' AND NOT EXISTS(SELECT 1 FROM octopus_core.dq_attempts a WHERE a.worker_instance_id=w.worker_instance_id AND a.status IN('reserved','accepted','running','applying')) LIMIT 1000)",
        ]{changed+=tx.execute(sql,&[&self.settings.installation_id,&self.settings.namespace]).await.map_err(database)?;}
        tx.commit().await.map_err(database)?;
        Ok(changed)
    }
    pub async fn collect_retention(
        &self,
        artifacts: &artifacts::DqArtifacts,
        config: &DqConfig,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(240);
        loop {
            if self.retention_batch(artifacts, config).await? == 0
                || tokio::time::Instant::now() >= deadline
            {
                break;
            }
        }
        Ok(())
    }
}
