use super::*;
use crate::config::DqConfig;
use std::time::Duration;
use tokio::time::Instant;

const RETENTION_BUDGET: Duration = Duration::from_secs(240);
const ARTIFACT_BATCH_SIZE: usize = 100;

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
fn reference_key(reference: &Value, run: &str, config: &DqConfig) -> Result<String> {
    let prefix = format!("s3://{}/", config.artifact_bucket);
    let key = dq::text(reference, "uri")?
        .strip_prefix(&prefix)
        .ok_or_else(|| error(400, "forbidden_retention_reference"))?;
    let version = dq::text(reference, "version_id")?;
    if !allowed_key(key, config)
        || key.split('/').nth(3) != Some(run)
        || crate::util::java_is_blank(version)
        || version == "null"
    {
        return Err(error(400, "forbidden_retention_reference"));
    }
    Ok(key.into())
}
const REOPEN: &str = r#"WITH reopened AS(SELECT r.run_id FROM octopus_core.dq_runs r WHERE r.installation_id=$1 AND r.namespace=$2 AND r.projection_applied AND(jsonb_typeof(r.summary->'review_candidate_ids') IS DISTINCT FROM 'array' OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(r.summary->'review_candidate_ids')='array' THEN r.summary->'review_candidate_ids' ELSE '[]'::jsonb END) ids(candidate_id) LEFT JOIN atheros_search.merge_candidates c USING(candidate_id) WHERE c.candidate_id IS NULL OR c.status NOT IN('confirmed','rejected','not_match'))) AND EXISTS(SELECT 1 FROM octopus_core.dq_artifacts a WHERE a.run_id=r.run_id AND a.closed_at IS NOT NULL AND a.retained_until IS DISTINCT FROM '-infinity'::timestamptz) ORDER BY r.run_id LIMIT $3) UPDATE octopus_core.dq_artifacts a SET closed_at=NULL,retained_until=NULL FROM reopened WHERE a.run_id=reopened.run_id AND a.closed_at IS NOT NULL AND a.retained_until IS DISTINCT FROM '-infinity'::timestamptz"#;
const CLOSE: &str = r#"WITH eligible AS(SELECT r.run_id,GREATEST(r.completed_at,COALESCE((SELECT max(GREATEST(c.updated_at,d.decided_at)) FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(r.summary->'review_candidate_ids')='array' THEN r.summary->'review_candidate_ids' ELSE '[]'::jsonb END) ids(candidate_id) JOIN atheros_search.merge_candidates c USING(candidate_id) LEFT JOIN atheros_search.merge_decisions d USING(candidate_id)),r.completed_at)) closed_at FROM octopus_core.dq_runs r WHERE r.installation_id=$1 AND r.namespace=$2 AND r.status IN('succeeded','failed','cancelled') AND r.completed_at IS NOT NULL AND(NOT r.projection_applied OR jsonb_typeof(r.summary->'review_candidate_ids')='array') AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(r.summary->'review_candidate_ids')='array' THEN r.summary->'review_candidate_ids' ELSE '[]'::jsonb END) ids(candidate_id) LEFT JOIN atheros_search.merge_candidates c USING(candidate_id) WHERE c.candidate_id IS NULL OR c.status NOT IN('confirmed','rejected','not_match')) AND EXISTS(SELECT 1 FROM octopus_core.dq_artifacts a WHERE a.run_id=r.run_id AND a.retained_until IS DISTINCT FROM '-infinity'::timestamptz AND(a.closed_at IS NULL OR a.retained_until<=CURRENT_TIMESTAMP))),closed AS(SELECT e.run_id,e.closed_at FROM eligible e WHERE EXISTS(SELECT 1 FROM octopus_core.dq_artifacts a WHERE a.run_id=e.run_id AND a.retained_until IS DISTINCT FROM '-infinity'::timestamptz AND(a.closed_at IS NULL OR a.closed_at<e.closed_at)) ORDER BY e.closed_at,e.run_id LIMIT $3) UPDATE octopus_core.dq_artifacts a SET closed_at=closed.closed_at,retained_until=closed.closed_at+INTERVAL '90 days' FROM closed WHERE a.run_id=closed.run_id AND a.retained_until IS DISTINCT FROM '-infinity'::timestamptz AND(a.closed_at IS NULL OR a.closed_at<closed.closed_at)"#;
// A pending exact-version deletion is durable and cannot be reopened. Finite
// deadlines keep the usual review and accessibility behavior until claimed.
// Keep legacy shared versions until conflicting ownership is repaired.
const EXPIRED: &str = r#"
  SELECT a.artifact_id, a.run_id, a.reference, a.retained_until::text AS cursor_time,
         a.retained_until = '-infinity'::timestamptz AS already_claimed
  FROM octopus_core.dq_artifacts a JOIN octopus_core.dq_runs r ON r.run_id = a.run_id
  WHERE a.installation_id = $1 AND a.namespace = $2
    AND ($4::text IS NULL OR a.artifact_id = $4)
    AND ($5::text IS NULL OR (a.retained_until, a.artifact_id) > ($5::text::timestamptz, $6::text))
    AND a.retained_until <= CURRENT_TIMESTAMP
    AND (a.retained_until = '-infinity'::timestamptz OR (
      r.status IN ('succeeded','failed','cancelled')
      AND (NOT r.projection_applied OR jsonb_typeof(r.summary->'review_candidate_ids') = 'array')
      AND NOT EXISTS (
        SELECT 1
        FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(r.summary->'review_candidate_ids') = 'array'
             THEN r.summary->'review_candidate_ids' ELSE '[]'::jsonb END) ids(candidate_id)
        LEFT JOIN atheros_search.merge_candidates c USING (candidate_id)
        LEFT JOIN atheros_search.merge_decisions d USING (candidate_id)
        WHERE c.candidate_id IS NULL OR c.status NOT IN ('confirmed','rejected','not_match')
          OR GREATEST(c.updated_at,d.decided_at) > CURRENT_TIMESTAMP - INTERVAL '90 days'
      )
    ))
    AND NOT EXISTS (
      SELECT 1 FROM octopus_core.dq_artifacts alias
      WHERE alias.artifact_id <> a.artifact_id
        AND alias.reference->>'uri' = a.reference->>'uri'
        AND alias.reference->>'version_id' = a.reference->>'version_id'
    )
    AND NOT EXISTS (
      SELECT 1 FROM octopus_core.dq_runs other
      CROSS JOIN LATERAL (VALUES
        (jsonb_build_array(jsonb_build_object('artifact_id', a.artifact_id))),
        (jsonb_build_array(jsonb_build_object('uri', a.reference->>'uri',
                                             'version_id', a.reference->>'version_id')))
      ) AS alias(ref)
      WHERE other.run_id <> r.run_id
        AND other.installation_id = a.installation_id AND other.namespace = a.namespace
        AND (other.input_refs @> alias.ref OR other.output_refs @> alias.ref)
    )
  ORDER BY a.retained_until, a.artifact_id
  LIMIT $3"#;

const MARK_EXPIRED: &str = r#"
UPDATE octopus_core.dq_artifacts a SET retained_until = '-infinity'::timestamptz
FROM expired WHERE a.artifact_id = expired.artifact_id
RETURNING a.run_id, a.reference, expired.already_claimed"#;

const UNLINK_EXPIRED: &str = r#"
UPDATE octopus_core.dq_runs r
SET input_refs = (SELECT COALESCE(jsonb_agg(ref ORDER BY ord), '[]'::jsonb)
                  FROM jsonb_array_elements(r.input_refs) WITH ORDINALITY AS refs(ref, ord)
                  WHERE (ref->>'artifact_id') IS DISTINCT FROM $1),
    output_refs = (SELECT COALESCE(jsonb_agg(ref ORDER BY ord), '[]'::jsonb)
                   FROM jsonb_array_elements(r.output_refs) WITH ORDINALITY AS refs(ref, ord)
                   WHERE (ref->>'artifact_id') IS DISTINCT FROM $1)
WHERE r.run_id IN (SELECT run_id FROM octopus_core.dq_artifacts WHERE artifact_id = $1)"#;

impl DqStore {
    pub async fn retention_batch(
        &self,
        artifacts: &artifacts::DqArtifacts,
        config: &DqConfig,
    ) -> Result<u64> {
        self.retention_batch_before(artifacts, config, Instant::now() + RETENTION_BUDGET)
            .await
    }

    async fn retention_batch_before(
        &self,
        artifacts: &artifacts::DqArtifacts,
        config: &DqConfig,
        deadline: Instant,
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
        // Page past invalid durable claims without spending a slot on them.
        let expired = format!("{EXPIRED} FOR UPDATE OF a SKIP LOCKED");
        let mut selected = Vec::with_capacity(ARTIFACT_BATCH_SIZE);
        let (mut cursor_time, mut cursor_id): (Option<String>, Option<String>) = (None, None);
        loop {
            let rows = tx
                .query(
                    &expired,
                    &[
                        &self.settings.installation_id,
                        &self.settings.namespace,
                        &(ARTIFACT_BATCH_SIZE as i64),
                        &None::<&str>,
                        &cursor_time,
                        &cursor_id,
                    ],
                )
                .await
                .map_err(database)?;
            tx.commit().await.map_err(database)?;
            for row in &rows {
                let artifact: String = row.get("artifact_id");
                let already_claimed: bool = row.get("already_claimed");
                if already_claimed {
                    let run: String = row.get("run_id");
                    let reference: Value = row.get("reference");
                    match reference_key(&reference, &run, config) {
                        Ok(_) => {}
                        Err(e) if e.status < 500 => continue,
                        Err(e) => return Err(e),
                    }
                }
                selected.push(artifact);
                if selected.len() == ARTIFACT_BATCH_SIZE {
                    break;
                }
            }
            if selected.len() == ARTIFACT_BATCH_SIZE
                || rows.len() < ARTIFACT_BATCH_SIZE
                || Instant::now() >= deadline
            {
                break;
            }
            let last = &rows[ARTIFACT_BATCH_SIZE - 1];
            cursor_time = Some(last.get("cursor_time"));
            cursor_id = Some(last.get("artifact_id"));
            tx = self.transaction().await?;
        }

        let claim_expired = format!("WITH expired AS ({expired}) {MARK_EXPIRED}");
        for artifact in selected {
            let mut tx = self.transaction().await?;
            let claimed = tx
                .query(
                    &claim_expired,
                    &[
                        &self.settings.installation_id,
                        &self.settings.namespace,
                        &1i64,
                        &artifact,
                        &None::<&str>,
                        &None::<&str>,
                    ],
                )
                .await
                .map_err(database)?;
            let Some(row) = claimed.first() else {
                tx.commit().await.map_err(database)?;
                continue;
            };
            let run: String = row.get(0);
            let reference: Value = row.get(1);
            let already_claimed: bool = row.get(2);
            tx.execute(UNLINK_EXPIRED, &[&artifact])
                .await
                .map_err(database)?;
            tx.commit().await.map_err(database)?;

            match reference_key(&reference, &run, config) {
                Ok(key) => {
                    let version = dq::text(&reference, "version_id")?;
                    match artifacts.objects().delete(&key, Some(version)).await {
                        Ok(())
                        | Err(crate::archive::ArchiveError::Storage {
                            status: Some(404), ..
                        }) => {}
                        Err(_) => return Err(error(503, "retention_dependency_failure")),
                    }
                }
                Err(e) if e.status < 500 => {
                    changed += u64::from(!already_claimed);
                    continue;
                }
                Err(e) => return Err(e),
            }
            let mut tx = self.transaction().await?;
            changed += tx.execute(
                "DELETE FROM octopus_core.dq_artifacts
                 WHERE artifact_id = $1 AND reference = $2 AND retained_until = '-infinity'::timestamptz",
                &[&artifact, &reference],
            ).await.map_err(database)?;
            tx.commit().await.map_err(database)?;
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
        let deadline = Instant::now() + RETENTION_BUDGET;
        loop {
            if self
                .retention_batch_before(artifacts, config, deadline)
                .await?
                == 0
                || Instant::now() >= deadline
            {
                break;
            }
        }
        Ok(())
    }
}
