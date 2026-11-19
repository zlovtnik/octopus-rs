use super::*;
const SOURCE: &str = r#"WITH selected_pairs AS MATERIALIZED (
 SELECT pair.*,
 (('x'||substr(md5(to_jsonb(left_document)::text),1,15))::bit(60)::bigint) AS left_revision,
 (('x'||substr(md5(to_jsonb(right_document)::text),1,15))::bit(60)::bigint) AS right_revision
 FROM atheros_search.similarity_pairs pair
 JOIN atheros_search.search_documents left_document ON left_document.document_id=pair.left_document_id AND left_document.status='active'
 JOIN atheros_search.search_documents right_document ON right_document.document_id=pair.right_document_id AND right_document.status='active'
 JOIN atheros_search.devices left_device ON left_device.mac=pair.left_source_mac
 JOIN atheros_search.devices right_device ON right_device.mac=pair.right_source_mac
 WHERE $2='prepare_candidates' AND pair.pair_kind='device_device' AND pair.left_source_mac<>pair.right_source_mac
 AND pair.cosine_similarity >= $5 AND($1='*' OR(left_device.location_id=$1 AND right_device.location_id=$1))
 AND NOT EXISTS(SELECT 1 FROM atheros_search.merge_candidates candidate
 WHERE candidate.mac_a=LEAST(pair.left_source_mac,pair.right_source_mac) AND candidate.mac_b=GREATEST(pair.left_source_mac,pair.right_source_mac)
 AND(candidate.confidence>=pair.cosine_similarity OR candidate.status<>'pending' OR EXISTS(SELECT 1 FROM atheros_search.merge_decisions decision WHERE decision.candidate_id=candidate.candidate_id)))
 ORDER BY pair.computed_at,pair.pair_id LIMIT $3
), selected_candidates AS MATERIALIZED (
 SELECT candidate.* FROM atheros_search.merge_candidates candidate
 JOIN atheros_search.devices left_device ON left_device.mac=candidate.mac_a
 JOIN atheros_search.devices right_device ON right_device.mac=candidate.mac_b
 WHERE($1='*' OR(left_device.location_id=$1 AND right_device.location_id=$1))
 AND(($2='reconcile_decision' AND candidate.candidate_id=$4) OR EXISTS(SELECT 1 FROM selected_pairs pair
 WHERE candidate.mac_a=LEAST(pair.left_source_mac,pair.right_source_mac) AND candidate.mac_b=GREATEST(pair.left_source_mac,pair.right_source_mac)))
), selected_macs AS MATERIALIZED (
 SELECT left_source_mac AS mac FROM selected_pairs UNION SELECT right_source_mac FROM selected_pairs
 UNION SELECT mac_a FROM selected_candidates UNION SELECT mac_b FROM selected_candidates
)
SELECT jsonb_build_object(
 'pairs',COALESCE((SELECT jsonb_agg(jsonb_build_object('pair_id',pair.pair_id,'mac_a',LEAST(pair.left_source_mac,pair.right_source_mac),'mac_b',GREATEST(pair.left_source_mac,pair.right_source_mac),'confidence',pair.cosine_similarity,'left_revision',pair.left_revision,'right_revision',pair.right_revision,'pair_revision',(('x'||substr(md5((to_jsonb(pair)-'left_revision'-'right_revision')::text),1,15))::bit(60)::bigint)) ORDER BY pair.computed_at,pair.pair_id) FROM selected_pairs pair),'[]'::jsonb),
 'devices',COALESCE((SELECT jsonb_agg(jsonb_build_object('mac',device.mac,'registered',device.registered,'registered_device_id',COALESCE(device.registered_device_id::text,''),'revision',(('x'||substr(md5(to_jsonb(device)::text),1,15))::bit(60)::bigint)) ORDER BY device.mac) FROM atheros_search.devices device JOIN selected_macs selected ON selected.mac=device.mac),'[]'::jsonb),
 'candidates',COALESCE((SELECT jsonb_agg(jsonb_build_object('candidate_id',candidate.candidate_id,'mac_a',candidate.mac_a,'mac_b',candidate.mac_b,'confidence',candidate.confidence,'status',candidate.status,'revision',(('x'||substr(md5(to_jsonb(candidate)::text),1,15))::bit(60)::bigint)) ORDER BY candidate.candidate_id) FROM selected_candidates candidate),'[]'::jsonb),
 'decisions',COALESCE((SELECT jsonb_agg(jsonb_build_object('candidate_id',decision.candidate_id,'decision',decision.decision,'decided_at',decision.decided_at) ORDER BY decision.candidate_id) FROM atheros_search.merge_decisions decision JOIN selected_candidates candidate ON candidate.candidate_id=decision.candidate_id),'[]'::jsonb))"#;
pub fn validate_digest(snapshot: &Value) -> Result<bool> {
    let mut value = snapshot.clone();
    let digest = dq::text(snapshot, "source_revision_digest")?;
    if let Some(o) = value.as_object_mut() {
        o.remove("source_revision_digest");
    }
    Ok(crate::util::sha256_hex(dq::canonical(&value)?) == digest)
}
impl DqStore {
    pub async fn prepare_snapshot(&self, run: &Value, minimum_similarity: f64) -> Result<Value> {
        let mut tx = self.transaction().await?;
        let snapshot = self.snapshot_tx(&mut tx, run, minimum_similarity).await?;
        tx.commit().await.map_err(database)?;
        Ok(snapshot)
    }
    pub(super) async fn snapshot_tx(
        &self,
        tx: &mut PgTransaction,
        run: &Value,
        minimum_similarity: f64,
    ) -> Result<Value> {
        let parameters = dq::field(run, "parameters")?;
        let scope = dq::text(parameters, "authorized_scope")?;
        let operation = dq::text(run, "operation")?;
        let limit = dq::int(parameters, "max_candidates")?;
        let candidate = dq::optional(parameters, "candidate_id");
        if !(1..=1000).contains(&limit) {
            return Err(error(400, "candidate_limit_invalid"));
        }
        if !matches!(operation, "prepare_candidates" | "reconcile_decision")
            || (operation == "reconcile_decision" && candidate.is_none_or(str::is_empty))
        {
            return Err(error(400, "operation_invalid"));
        }
        let mut value: Value = tx
            .query(
                SOURCE,
                &[
                    &scope,
                    &operation,
                    &i64::from(limit),
                    &candidate,
                    &minimum_similarity,
                ],
            )
            .await
            .map_err(database)?[0]
            .get(0);
        value["installation_id"] = json!(dq::text(run, "installation_id")?);
        value["namespace"] = json!(dq::text(run, "namespace")?);
        value["authorized_scope"] = json!(scope);
        value["operation"] = json!(operation);
        value["policy_version"] = json!(dq::text(run, "policy_version")?);
        if let Some(candidate) = candidate {
            value["candidate_id"] = json!(candidate);
        }
        let digest = crate::util::sha256_hex(dq::canonical(&value)?);
        if dq::optional(parameters, "snapshot_revision")
            .is_some_and(|r| !r.is_empty() && r != digest)
        {
            return Err(error(409, "source_revision_changed"));
        }
        value["source_revision_digest"] = json!(digest);
        Ok(value)
    }
    pub(super) async fn lock_snapshot(
        &self,
        tx: &mut PgTransaction,
        snapshot: &Value,
    ) -> Result<()> {
        for sql in [
            "SELECT c.candidate_id FROM atheros_search.merge_candidates c JOIN jsonb_array_elements(($1::jsonb)->'candidates') item ON item->>'candidate_id'=c.candidate_id ORDER BY c.candidate_id FOR UPDATE OF c",
            "SELECT d.mac FROM atheros_search.devices d JOIN jsonb_array_elements(($1::jsonb)->'devices') item ON item->>'mac'=d.mac ORDER BY d.mac FOR SHARE OF d",
            "SELECT p.pair_id::text FROM atheros_search.similarity_pairs p JOIN jsonb_array_elements(($1::jsonb)->'pairs') item ON(item->>'pair_id')::uuid=p.pair_id ORDER BY p.pair_id FOR SHARE OF p",
            "SELECT d.document_id::text FROM atheros_search.search_documents d WHERE d.document_id IN(SELECT p.left_document_id FROM atheros_search.similarity_pairs p JOIN jsonb_array_elements(($1::jsonb)->'pairs') item ON(item->>'pair_id')::uuid=p.pair_id UNION SELECT p.right_document_id FROM atheros_search.similarity_pairs p JOIN jsonb_array_elements(($1::jsonb)->'pairs') item ON(item->>'pair_id')::uuid=p.pair_id) ORDER BY d.document_id FOR SHARE OF d",
        ]{tx.query(sql,&[&snapshot]).await.map_err(database)?;}
        Ok(())
    }
}
