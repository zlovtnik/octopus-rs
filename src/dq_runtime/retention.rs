use super::*;
use crate::config::DqConfig;
use std::time::Duration;
use tokio::time::{timeout_at, Instant};

const RETENTION_BUDGET: Duration = Duration::from_secs(240);
const PRUNE_BUDGET: Duration = Duration::from_secs(10);
const ARTIFACT_BATCH_SIZE: usize = 100;

enum ScanProgress {
    Continue,
    Wrapped,
    End,
}

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

macro_rules! active_review {
    () => {
        r#"SELECT 1
        FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(r.summary->'review_candidate_ids') = 'array'
             THEN r.summary->'review_candidate_ids' ELSE '[]'::jsonb END) ids(candidate_id)
        LEFT JOIN atheros_search.merge_candidates c USING (candidate_id)
        LEFT JOIN atheros_search.merge_decisions d USING (candidate_id)
        WHERE c.candidate_id IS NULL OR c.status NOT IN ('confirmed','rejected','not_match')
          OR GREATEST(c.updated_at,d.decided_at) > CURRENT_TIMESTAMP - INTERVAL '90 days'"#
    };
}

// A pending exact-version deletion is durable and cannot be reopened. Finite
// deadlines keep the usual review and accessibility behavior until claimed.
// Keep legacy shared versions until conflicting ownership is repaired.
const EXPIRED: &str = concat!(
    r#"
  SELECT a.artifact_id, a.run_id, a.reference, due.at::text AS cursor_time,
         a.retained_until = '-infinity'::timestamptz AS already_claimed
  FROM octopus_core.dq_artifacts a JOIN octopus_core.dq_runs r ON r.run_id = a.run_id
  LEFT JOIN octopus_core.work_leases retry
    ON retry.resource_type = 'dq-artifact-retention'
    AND retry.resource_id = encode(sha256(convert_to(a.artifact_id, 'UTF8')), 'hex')
    AND a.retained_until = '-infinity'::timestamptz
  CROSS JOIN LATERAL (VALUES (COALESCE(retry.next_attempt_at, a.retained_until))) due(at)
  WHERE a.installation_id = $1 AND a.namespace = $2
    AND ($4::text IS NULL OR a.artifact_id = $4)
    AND ($5::text IS NULL OR (due.at, a.artifact_id) > ($5::text::timestamptz, $6::text))
    AND ($8::text IS NULL OR a.run_id = $8)
    AND a.retained_until <= CURRENT_TIMESTAMP
    AND due.at <= CURRENT_TIMESTAMP
    AND (a.retained_until = '-infinity'::timestamptz OR (
      r.status IN ('succeeded','failed','cancelled')
      AND (NOT r.projection_applied OR jsonb_typeof(r.summary->'review_candidate_ids') = 'array')
      AND NOT EXISTS ("#,
    active_review!(),
    r#"
          OR ($7::text[] IS NOT NULL AND ids.candidate_id <> ALL($7))
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
  ORDER BY due.at, a.artifact_id
  LIMIT $3"#
);

const MARK_EXPIRED: &str = r#"
UPDATE octopus_core.dq_artifacts a SET retained_until = '-infinity'::timestamptz
FROM expired WHERE a.artifact_id = expired.artifact_id
RETURNING a.reference, expired.already_claimed, expired.cursor_time"#;

const LOCK_REVIEW_CANDIDATES: &str = r#"
SELECT c.candidate_id
FROM octopus_core.dq_runs r
CROSS JOIN LATERAL jsonb_array_elements_text(CASE
    WHEN jsonb_typeof(r.summary->'review_candidate_ids') = 'array'
    THEN r.summary->'review_candidate_ids' ELSE '[]'::jsonb END) ids(candidate_id)
JOIN atheros_search.merge_candidates c USING (candidate_id)
WHERE r.run_id = $1
ORDER BY c.candidate_id FOR UPDATE OF c"#;

const RETRY_EXPIRED: &str = r#"
INSERT INTO octopus_core.work_leases (resource_type, resource_id, next_attempt_at, last_error)
SELECT 'dq-artifact-retention', $3, clock_timestamp() + INTERVAL '1 minute', 'retention_dependency_failure'
FROM octopus_core.dq_artifacts
WHERE artifact_id = $1 AND reference = $2 AND retained_until = '-infinity'::timestamptz
FOR UPDATE
ON CONFLICT (resource_type, resource_id) DO UPDATE
SET next_attempt_at = EXCLUDED.next_attempt_at, last_error = EXCLUDED.last_error,
    updated_at = clock_timestamp()"#;

const UNLINK_EXPIRED: &str = r#"
UPDATE octopus_core.dq_runs r
SET input_refs = (SELECT COALESCE(jsonb_agg(ref ORDER BY ord), '[]'::jsonb)
                  FROM jsonb_array_elements(r.input_refs) WITH ORDINALITY AS refs(ref, ord)
                  WHERE (ref->>'artifact_id') IS DISTINCT FROM $1),
    output_refs = (SELECT COALESCE(jsonb_agg(ref ORDER BY ord), '[]'::jsonb)
                   FROM jsonb_array_elements(r.output_refs) WITH ORDINALITY AS refs(ref, ord)
                   WHERE (ref->>'artifact_id') IS DISTINCT FROM $1)
WHERE r.run_id IN (SELECT run_id FROM octopus_core.dq_artifacts WHERE artifact_id = $1)"#;

const REMOVE_EXPIRED: &str = r#"
DELETE FROM octopus_core.dq_artifacts
WHERE artifact_id = $1 AND reference = $2 AND retained_until = '-infinity'::timestamptz"#;

macro_rules! prunable_runs {
    ($review_guard:literal, $suffix:literal) => {
        concat!(
    r#"
SELECT r.run_id FROM octopus_core.dq_runs r
WHERE r.installation_id = $1 AND r.namespace = $2
  AND r.status IN ('succeeded','failed','cancelled')
  AND r.completed_at < CURRENT_TIMESTAMP - INTERVAL '90 days'
  AND NOT EXISTS (SELECT 1 FROM octopus_core.dq_artifacts a WHERE a.run_id = r.run_id)
  AND NOT EXISTS (
    SELECT 1 FROM octopus_core.dq_outbox o
    WHERE o.payload->>'run_id' = r.run_id AND o.status <> 'published'
  )
  AND NOT EXISTS (
    SELECT 1 FROM octopus_core.dq_artifacts a
    CROSS JOIN LATERAL (VALUES
      (jsonb_build_array(jsonb_build_object('artifact_id', a.artifact_id))),
      (jsonb_build_array(jsonb_build_object('uri', a.reference->>'uri',
                                           'version_id', a.reference->>'version_id')))
    ) AS alias(ref)
    WHERE a.run_id <> r.run_id
      AND a.installation_id = r.installation_id AND a.namespace = r.namespace
      AND (r.input_refs @> alias.ref OR r.output_refs @> alias.ref)
      AND (
        a.retained_until IS NULL OR a.retained_until > CURRENT_TIMESTAMP
        OR (r.projection_applied AND jsonb_typeof(r.summary->'review_candidate_ids') IS DISTINCT FROM 'array')
        OR EXISTS ("#,
    active_review!(),
    $review_guard,
    r#"
        )
      )
  )"#,
            $suffix
        )
    };
}

const PRUNE_RUNS: &str = prunable_runs!(
    "",
    " ORDER BY r.completed_at, r.run_id FOR UPDATE OF r SKIP LOCKED LIMIT 100"
);
const RECHECK_PRUNE_RUN: &str = prunable_runs!(
    " OR ids.candidate_id <> ALL($4::text[])",
    " AND r.run_id = $3"
);

impl DqStore {
    pub async fn retention_batch(
        &self,
        artifacts: &artifacts::DqArtifacts,
        config: &DqConfig,
    ) -> Result<u64> {
        self.retention_batch_before(artifacts, config, Instant::now() + RETENTION_BUDGET)
            .await
            .map(|(changed, _)| changed)
    }

    async fn retention_batch_before(
        &self,
        artifacts: &artifacts::DqArtifacts,
        config: &DqConfig,
        deadline: Instant,
    ) -> Result<(u64, ScanProgress)> {
        let mut changed = 0;
        let mut deletion_failed = false;
        // Keep time for database-only cleanup even when object storage stalls.
        let remaining = deadline.saturating_duration_since(Instant::now());
        let artifact_deadline = deadline - PRUNE_BUDGET.min(remaining / 4);
        let progress = timeout_at(
            artifact_deadline,
            self.retention_page(
                artifacts,
                config,
                artifact_deadline,
                &mut changed,
                &mut deletion_failed,
            ),
        )
        .await
        .unwrap_or(Ok(ScanProgress::End))?;
        if Instant::now() < deadline {
            changed += timeout_at(deadline, self.prune_retention())
                .await
                .unwrap_or(Ok(0))?;
        }
        if deletion_failed {
            return Err(error(503, "retention_dependency_failure"));
        }
        Ok((changed, progress))
    }

    async fn retention_page(
        &self,
        artifacts: &artifacts::DqArtifacts,
        config: &DqConfig,
        deadline: Instant,
        changed: &mut u64,
        deletion_failed: &mut bool,
    ) -> Result<ScanProgress> {
        if Instant::now() >= deadline {
            return Ok(ScanProgress::End);
        }
        let mut tx = self.transaction().await?;
        let shard = crate::util::sha256_hex(
            json!([self.settings.installation_id, self.settings.namespace])
                .to_string()
                .as_bytes(),
        );
        let checkpoint: Option<String> = tx
            .query(
                "SELECT checkpoint_value FROM octopus_core.processor_checkpoints
                 WHERE processor_name = 'dq-artifact-retention' AND shard_id = $1",
                &[&shard],
            )
            .await
            .map_err(database)?
            .first()
            .and_then(|row| row.get(0));
        let cursor: Option<(String, String)> = checkpoint
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| error(503, "invalid_retention_checkpoint"))?;
        let mut renewed = 0;
        for sql in [REOPEN, CLOSE] {
            renewed += tx
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
        tx.commit().await.map_err(database)?;
        *changed += renewed;

        let expired = format!("{EXPIRED} FOR UPDATE OF a SKIP LOCKED");
        let claim_expired = format!("WITH expired AS ({expired}) {MARK_EXPIRED}");
        let mut tx = self.transaction().await?;
        let cursor_time = cursor.as_ref().map(|(time, _)| time);
        let cursor_id = cursor.as_ref().map(|(_, id)| id);
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
                    &None::<Vec<String>>,
                    &None::<&str>,
                ],
            )
            .await
            .map_err(database)?;
        tx.commit().await.map_err(database)?;
        for row in &rows {
            if Instant::now() >= deadline {
                return Ok(ScanProgress::End);
            }
            let artifact: String = row.get("artifact_id");
            let run: String = row.get("run_id");
            let already_claimed: bool = row.get("already_claimed");
            if already_claimed {
                let reference: Value = row.get("reference");
                match reference_key(&reference, &run, config) {
                    Ok(_) => {}
                    Err(e) if e.status < 500 => continue,
                    Err(e) => return Err(e),
                }
            }
            match self
                .collect_artifact(
                    artifacts,
                    config,
                    &claim_expired,
                    &artifact,
                    &run,
                    already_claimed,
                )
                .await?
            {
                Some(count) => *changed += count,
                None => *deletion_failed = true,
            }
        }

        if Instant::now() >= deadline {
            return Ok(ScanProgress::End);
        }
        let more_artifacts = rows.len() == ARTIFACT_BATCH_SIZE;
        let cursor: Option<(String, String)> = rows
            .last()
            .filter(|_| more_artifacts)
            .map(|row| (row.get("cursor_time"), row.get("artifact_id")));
        let mut tx = self.transaction().await?;
        let next_checkpoint = cursor.map(|cursor| json!(cursor).to_string());
        if next_checkpoint != checkpoint {
            tx.execute(
                "INSERT INTO octopus_core.processor_checkpoints AS current
                   (processor_name, shard_id, checkpoint_value)
                 VALUES ('dq-artifact-retention', $1, $2)
                 ON CONFLICT (processor_name, shard_id) DO UPDATE
                 SET checkpoint_value = EXCLUDED.checkpoint_value, updated_at = CURRENT_TIMESTAMP
                 WHERE current.checkpoint_value IS NOT DISTINCT FROM $3",
                &[&shard, &next_checkpoint, &checkpoint],
            )
            .await
            .map_err(database)?;
        }
        tx.commit().await.map_err(database)?;
        if more_artifacts {
            Ok(ScanProgress::Continue)
        } else if checkpoint.is_some() {
            Ok(ScanProgress::Wrapped)
        } else {
            Ok(ScanProgress::End)
        }
    }

    async fn prune_retention(&self) -> Result<u64> {
        let mut tx = self.transaction().await?;
        tx.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED", &[])
            .await
            .map_err(database)?;
        let mut pruned = 0;
        let runs = tx
            .query(
                PRUNE_RUNS,
                &[&self.settings.installation_id, &self.settings.namespace],
            )
            .await
            .map_err(database)?;
        for run in runs {
            let run: String = run.get(0);
            let candidates: Vec<String> = tx
                .query(LOCK_REVIEW_CANDIDATES, &[&run])
                .await
                .map_err(database)?
                .iter()
                .map(|row| row.get(0))
                .collect();
            // A review can reopen while its candidate lock is held by a writer.
            if tx
                .query(
                    RECHECK_PRUNE_RUN,
                    &[
                        &self.settings.installation_id,
                        &self.settings.namespace,
                        &run,
                        &candidates,
                    ],
                )
                .await
                .map_err(database)?
                .is_empty()
            {
                continue;
            }
            tx.execute(
                "DELETE FROM octopus_core.dq_attempts WHERE run_id=$1",
                &[&run],
            )
            .await
            .map_err(database)?;
            pruned += tx
                .execute("DELETE FROM octopus_core.dq_runs WHERE run_id=$1", &[&run])
                .await
                .map_err(database)?;
        }
        for sql in[
            "DELETE FROM octopus_core.dq_receipts WHERE ctid IN(SELECT ctid FROM octopus_core.dq_receipts WHERE installation_id=$1 AND namespace=$2 AND received_at<CURRENT_TIMESTAMP-INTERVAL '90 days' LIMIT 1000)",
            "DELETE FROM octopus_core.dq_audit WHERE audit_id IN(SELECT audit_id FROM octopus_core.dq_audit WHERE installation_id=$1 AND namespace=$2 AND created_at<CURRENT_TIMESTAMP-INTERVAL '180 days' LIMIT 1000)",
            "DELETE FROM octopus_core.dq_outbox WHERE outbox_id IN(SELECT outbox_id FROM octopus_core.dq_outbox WHERE status='published' AND payload->>'installation_id'=$1 AND payload->>'namespace'=$2 AND published_at<CURRENT_TIMESTAMP-INTERVAL '180 days' LIMIT 1000)",
            "DELETE FROM octopus_core.dq_workers WHERE worker_instance_id IN(SELECT w.worker_instance_id FROM octopus_core.dq_workers w WHERE w.installation_id=$1 AND w.namespace=$2 AND w.last_seen_at<CURRENT_TIMESTAMP-INTERVAL '1 day' AND NOT EXISTS(SELECT 1 FROM octopus_core.dq_attempts a WHERE a.worker_instance_id=w.worker_instance_id AND a.status IN('reserved','accepted','running','applying')) LIMIT 1000)",
        ]{pruned+=tx.execute(sql,&[&self.settings.installation_id,&self.settings.namespace]).await.map_err(database)?;}
        tx.commit().await.map_err(database)?;
        Ok(pruned)
    }

    async fn collect_artifact(
        &self,
        artifacts: &artifacts::DqArtifacts,
        config: &DqConfig,
        claim_expired: &str,
        artifact: &str,
        run: &str,
        already_claimed: bool,
    ) -> Result<Option<u64>> {
        let mut tx = self.transaction().await?;
        tx.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED", &[])
            .await
            .map_err(database)?;
        if tx
            .query(
                "SELECT run_id FROM octopus_core.dq_runs WHERE run_id = $1 FOR UPDATE SKIP LOCKED",
                &[&run],
            )
            .await
            .map_err(database)?
            .is_empty()
        {
            tx.commit().await.map_err(database)?;
            return Ok(Some(0));
        }
        // Review writers lock the candidate before updating it or its decision.
        // Recheck eligibility in a new statement after taking those same locks.
        let candidates: Vec<String> = if already_claimed {
            Vec::new()
        } else {
            tx.execute("SET LOCAL lock_timeout = '500ms'", &[])
                .await
                .map_err(database)?;
            let locked = match tx.query(LOCK_REVIEW_CANDIDATES, &[&run]).await {
                Ok(locked) => locked,
                Err(PgError::Query { source, .. })
                    if source.code()
                        == Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE) =>
                {
                    tx.rollback().await.map_err(database)?;
                    return Ok(Some(0));
                }
                Err(error) => return Err(database(error)),
            };
            tx.execute("SET LOCAL lock_timeout TO DEFAULT", &[])
                .await
                .map_err(database)?;
            locked.iter().map(|row| row.get(0)).collect()
        };
        let claimed = tx
            .query(
                claim_expired,
                &[
                    &self.settings.installation_id,
                    &self.settings.namespace,
                    &1i64,
                    &artifact,
                    &None::<&str>,
                    &None::<&str>,
                    &candidates,
                    &run,
                ],
            )
            .await
            .map_err(database)?;
        let Some(row) = claimed.first() else {
            tx.commit().await.map_err(database)?;
            return Ok(Some(0));
        };
        let reference: Value = row.get(0);
        let already_claimed: bool = row.get(1);
        tx.execute(UNLINK_EXPIRED, &[&artifact])
            .await
            .map_err(database)?;
        let key = match reference_key(&reference, run, config) {
            Ok(key) => key,
            Err(e) if e.status < 500 => {
                let changed = if already_claimed {
                    0
                } else {
                    tx.execute(REMOVE_EXPIRED, &[&artifact, &reference])
                        .await
                        .map_err(database)?
                };
                tx.commit().await.map_err(database)?;
                return Ok(Some(changed));
            }
            Err(e) => return Err(e),
        };
        let retry_id = crate::util::sha256_hex(artifact.as_bytes());
        if !already_claimed {
            // Preserve the scan order if shutdown interrupts deletion after commit.
            let due: String = row.get(2);
            tx.execute(
                "INSERT INTO octopus_core.work_leases (resource_type, resource_id, next_attempt_at)
                 VALUES ('dq-artifact-retention', $1, $2::text::timestamptz)",
                &[&retry_id, &due],
            )
            .await
            .map_err(database)?;
        }
        tx.commit().await.map_err(database)?;

        let version = dq::text(&reference, "version_id")?;
        let deleted = artifacts
            .objects()
            .delete(&key, Some(version))
            .await
            .is_ok();
        let mut tx = self.transaction().await?;
        if !deleted {
            tx.execute(RETRY_EXPIRED, &[&artifact, &reference, &retry_id])
                .await
                .map_err(database)?;
            tx.commit().await.map_err(database)?;
            return Ok(None);
        }
        let changed = tx
            .execute(REMOVE_EXPIRED, &[&artifact, &reference])
            .await
            .map_err(database)?;
        if changed != 0 {
            tx.execute(
                "DELETE FROM octopus_core.work_leases
                 WHERE resource_type = 'dq-artifact-retention' AND resource_id = $1",
                &[&retry_id],
            )
            .await
            .map_err(database)?;
        }
        tx.commit().await.map_err(database)?;
        Ok(Some(changed))
    }

    pub async fn collect_retention(
        &self,
        artifacts: &artifacts::DqArtifacts,
        config: &DqConfig,
    ) -> Result<()> {
        let deadline = Instant::now() + RETENTION_BUDGET;
        let mut wrapped = false;
        loop {
            let (changed, progress) = self
                .retention_batch_before(artifacts, config, deadline)
                .await?;
            let keep_scanning = match progress {
                ScanProgress::Continue => true,
                ScanProgress::Wrapped if !wrapped => {
                    // A resumed scan may have skipped eligible work before its cursor.
                    wrapped = true;
                    true
                }
                _ => changed != 0,
            };
            if !keep_scanning || Instant::now() >= deadline {
                break;
            }
        }
        Ok(())
    }
}
