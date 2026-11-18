use super::*;
use crate::{
    archive::MinioStore,
    config::{ArchiveConfig, DqConfig},
};
use std::time::Duration;

#[derive(Clone)]
pub struct DqArtifacts {
    objects: MinioStore,
    config: DqConfig,
}
fn storage(_: crate::archive::ArchiveError) -> DqError {
    error(503, "artifact_dependency_failure")
}
pub fn safe_segment(value: &str) -> bool {
    let b = value.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(c))
}
pub fn object_key(
    reference: &Value,
    run: &Value,
    output: bool,
    config: &DqConfig,
) -> Result<String> {
    let installation = dq::text(run, "installation_id")?;
    let namespace = dq::text(run, "namespace")?;
    let run_id = dq::text(run, "run_id")?;
    let uri = dq::text(reference, "uri")?;
    let prefix = format!("s3://{}/", config.artifact_bucket);
    let key = uri
        .strip_prefix(&prefix)
        .ok_or_else(|| error(400, "forbidden_artifact_reference"))?;
    let parts: Vec<_> = key.split('/').collect();
    let attempt = run["current_attempt"]["attempt_id"].as_str();
    let expected = if output {
        vec![
            installation,
            namespace,
            "runs",
            run_id,
            "attempts",
            attempt.ok_or_else(|| error(400, "forbidden_artifact_reference"))?,
        ]
    } else {
        vec![installation, namespace, "inputs"]
    };
    let schema = if output {
        "atheros.dedup.proposal.v1"
    } else {
        "atheros.dedup.snapshot.v1"
    };
    if installation != config.installation_id
        || namespace != config.namespace
        || dq::text(reference, "installation_id")? != installation
        || dq::text(reference, "namespace")? != namespace
        || !parts.iter().all(|p| safe_segment(p))
        || !parts.starts_with(&expected)
        || parts.len() != expected.len() + if output { 1 } else { 2 }
        || dq::text(reference, "schema_id")? != schema
        || dq::text(reference, "media_type")? != "application/json"
        || !dq::hash(dq::text(reference, "sha256")?)
        || dq::text(reference, "version_id")? == "null"
        || (output
            && (dq::text(reference, "producer_run_id")? != run_id
                || dq::optional(reference, "producer_attempt_id") != attempt))
    {
        return Err(error(400, "forbidden_artifact_reference"));
    }
    Ok(key.into())
}
impl DqArtifacts {
    pub fn new(config: DqConfig, storage_config: &ArchiveConfig) -> Result<Self> {
        let objects = MinioStore::with_timeout(
            &storage_config.endpoint,
            &storage_config.access_key,
            &storage_config.secret_key,
            &storage_config.region,
            &config.artifact_bucket,
            Duration::from_secs((config.lease_seconds / 8).clamp(1, 10) as u64),
        )
        .map_err(storage)?;
        Ok(Self { objects, config })
    }
    pub async fn initialize(&self) -> Result<()> {
        self.objects
            .initialize_existing_versioned_encrypted()
            .await
            .map_err(storage)
    }
    pub async fn put_snapshot(&self, run: &Value, snapshot: &Value, pinned_limit: usize) -> Result<Value> {
        let limit = pinned_limit.min(self.config.max_artifact_bytes as usize);
        let payload = dq::canonical_with_limit(snapshot, limit)
            .map_err(|e| if e.code == "record_too_large" { error(400, "snapshot_size_exceeded") } else { e })?
            .into_bytes();
        let hash = crate::util::sha256_hex(&payload);
        let installation = dq::text(run, "installation_id")?;
        let namespace = dq::text(run, "namespace")?;
        let run_id = dq::text(run, "run_id")?;
        if installation != self.config.installation_id
            || namespace != self.config.namespace
            || !safe_segment(run_id)
        {
            return Err(error(400, "snapshot_scope_invalid"));
        }
        let key = format!("{installation}/{namespace}/inputs/{run_id}/{hash}");
        let stored = self
            .objects
            .put_versioned(&key, &payload, &hash)
            .await
            .map_err(storage)?;
        let version = stored
            .version_id
            .filter(|v| !v.is_empty() && v != "null")
            .ok_or_else(|| error(400, "artifact_version_missing"))?;
        let reference = json!({"artifact_id":dq::sha256(&json!([run_id,hash]))?,"producer_run_id":run_id,"installation_id":installation,"namespace":namespace,"uri":format!("s3://{}/{}",self.config.artifact_bucket,key),"version_id":version,"etag":stored.etag,"sha256":hash,"schema_id":"atheros.dedup.snapshot.v1","media_type":"application/json","size_bytes":payload.len()});
        self.read(&reference, run, false, pinned_limit).await?;
        Ok(reference)
    }
    pub async fn read(&self, reference: &Value, run: &Value, output: bool, pinned_limit: usize) -> Result<Value> {
        let key = object_key(reference, run, output, &self.config)?;
        let version = dq::text(reference, "version_id")?;
        let size = dq::long(reference, "size_bytes")?;
        let limit = pinned_limit.min(self.config.max_artifact_bytes as usize);
        if usize::try_from(size).map_or(true, |size| size > limit) {
            return Err(error(400, "artifact_size_exceeded"));
        }
        let stat = self
            .objects
            .stat_versioned(&key, Some(version))
            .await
            .map_err(storage)?
            .ok_or_else(|| error(400, "artifact_metadata_mismatch"))?;
        if stat.size != size || stat.etag != dq::text(reference, "etag")? {
            return Err(error(400, "artifact_metadata_mismatch"));
        }
        let bytes = self
            .objects
            .get_versioned(&key, Some(version), limit)
            .await
            .map_err(storage)?;
        if bytes.len() as i64 != size
            || crate::util::sha256_hex(&bytes) != dq::text(reference, "sha256")?
        {
            return Err(error(400, "artifact_integrity_failed"));
        }
        serde_json::from_slice(&bytes).map_err(|_| error(400, "artifact_json_invalid"))
    }
    pub async fn authorized_access(&self, reference: &Value) -> Result<Value> {
        let uri = dq::text(reference, "uri")?;
        let prefix = format!("s3://{}/", self.config.artifact_bucket);
        let scoped_prefix = format!(
            "{}{}/{}/",
            prefix, self.config.installation_id, self.config.namespace
        );
        let key = uri
            .strip_prefix(&prefix)
            .ok_or_else(|| error(400, "forbidden_artifact_reference"))?;
        let version = dq::text(reference, "version_id")?;
        if !uri.starts_with(&scoped_prefix)
            || !key.split('/').all(safe_segment)
            || version.is_empty() || version == "null"
        {
            return Err(error(400, "forbidden_artifact_reference"));
        }
        let url = self
            .objects
            .presign_get(key, version, 60)
            .map_err(storage)?;
        Ok(json!({"url":url,"expires_at":(Utc::now()+chrono::Duration::seconds(60)).to_rfc3339()}))
    }
    pub fn objects(&self) -> &MinioStore {
        &self.objects
    }
}
