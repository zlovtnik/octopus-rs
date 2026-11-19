//! Durable DQ control plane. Broker offsets are owned by the consumer boundary.
use crate::{
    config::DqSettings,
    dq::{self, DqError, DqOutbox, DqPrincipal},
    postgres::{PgError, PgRuntime, PgTransaction},
};
use chrono::Utc;
use serde_json::{json, Value};
use std::sync::Arc;
pub mod apply;
pub mod artifacts;
mod control;
pub mod retention;
pub mod runner;
pub mod snapshot;
mod work;
pub use artifacts::DqArtifacts;
pub use runner::DqRuntime;

pub type Result<T> = std::result::Result<T, DqError>;
fn error(status: u16, code: &str) -> DqError {
    DqError {
        status,
        code: code.into(),
    }
}
fn database(source: PgError) -> DqError {
    tracing::warn!(classification = %crate::postgres::PostgresErrorClass::classify(&source).wire_value(), "DQ database operation failed");
    if let PgError::Query { source, .. } = &source {
        if source.code().is_some_and(|code| code.code() == "40001") {
            return error(503, "serialization_retry");
        }
    }
    error(503, "control_unavailable")
}
fn role(principal: &DqPrincipal, allowed: &[&str]) -> Result<()> {
    principal.require_role(&allowed.iter().map(|v| (*v).into()).collect())
}
fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}
fn without(value: &Value, fields: &[&str]) -> Value {
    let mut v = value.clone();
    if let Some(object) = v.as_object_mut() {
        for key in fields {
            object.remove(*key);
        }
    }
    v
}

#[derive(Clone)]
pub struct DqStore {
    runtime: Arc<PgRuntime>,
    pub settings: DqSettings,
}
impl DqStore {
    pub fn new(runtime: Arc<PgRuntime>, settings: DqSettings) -> Self {
        Self { runtime, settings }
    }
    async fn transaction(&self) -> Result<PgTransaction> {
        self.runtime.begin_worker().await.map_err(database)
    }
    async fn artifact_limits_tx(
        &self,
        tx: &mut PgTransaction,
        run: &str,
    ) -> Result<(usize, usize)> {
        let rows = tx.query(
            "SELECT manifest->'resources' FROM octopus_core.dq_runs WHERE run_id=$1 AND installation_id=$2 AND namespace=$3",
            &[&run, &self.settings.installation_id, &self.settings.namespace],
        ).await.map_err(database)?;
        let resources: Value = rows
            .first()
            .ok_or_else(|| error(404, "run_not_found"))?
            .get(0);
        let limit = |key| {
            usize::try_from(dq::long(&resources, key)?)
                .ok()
                .filter(|size| *size > 0)
                .ok_or_else(|| error(400, "invalid_resources"))
        };
        Ok((limit("max_input_bytes")?, limit("max_output_bytes")?))
    }
    async fn artifact_limits(&self, run: &str) -> Result<(usize, usize)> {
        let mut tx = self.transaction().await?;
        let limits = self.artifact_limits_tx(&mut tx, run).await?;
        tx.commit().await.map_err(database)?;
        Ok(limits)
    }
    async fn run_tx(&self, tx: &mut PgTransaction, run: &str) -> Result<Value> {
        let rows = tx.query("SELECT r.document || jsonb_build_object('installation_id',r.installation_id,'namespace',r.namespace,'run_id',r.run_id,'status',r.status,'state_revision',r.state_revision,'input_refs',r.input_refs,'output_refs',r.output_refs,'source_revision_digest',r.source_revision_digest,'execution_mode',r.execution_mode,'created_at',r.created_at,'deadline_at',r.deadline_at,'completed_at',r.completed_at,'projection_applied',r.projection_applied,'error_code',r.error_code,'summary',r.summary,'current_attempt',(SELECT to_jsonb(a) FROM octopus_core.dq_attempts a WHERE a.attempt_id=r.current_attempt_id)) FROM octopus_core.dq_runs r WHERE r.run_id=$1 AND r.installation_id=$2 AND r.namespace=$3", &[&run,&self.settings.installation_id,&self.settings.namespace]).await.map_err(database)?;
        rows.first()
            .map(|row| row.get(0))
            .ok_or_else(|| error(404, "run_not_found"))
    }
    async fn lock_run(&self, tx: &mut PgTransaction, run: &str) -> Result<()> {
        if tx
            .query(
                "SELECT run_id FROM octopus_core.dq_runs WHERE run_id=$1 AND installation_id=$2 AND namespace=$3 FOR UPDATE",
                &[&run, &self.settings.installation_id, &self.settings.namespace],
            )
            .await
            .map_err(database)?
            .is_empty()
        {
            return Err(error(404, "run_not_found"));
        }
        Ok(())
    }
    async fn checked_run(
        &self,
        tx: &mut PgTransaction,
        p: &DqPrincipal,
        run: &str,
    ) -> Result<Value> {
        let mut value = self.run_tx(tx, run).await?;
        dq::scoped(p, &value, &self.settings)?;
        if !p.permits(dq::scope(dq::field(&value, "parameters")?)?) {
            return Err(error(403, "forbidden_scope"));
        }
        if !p.roles.contains("service") {
            if let Some(a) = value
                .get_mut("current_attempt")
                .and_then(Value::as_object_mut)
            {
                a.remove("lease_token");
            }
        }
        Ok(value)
    }
    async fn manifest_tx(
        &self,
        tx: &mut PgTransaction,
        processor: &str,
        version: &str,
    ) -> Result<Value> {
        tx.query("SELECT manifest FROM octopus_core.dq_processor_versions WHERE installation_id=$1 AND namespace=$2 AND processor_id=$3 AND version=$4", &[&self.settings.installation_id,&self.settings.namespace,&processor,&version]).await.map_err(database)?.first().map(|r|r.get(0)).ok_or_else(||error(404,"processor_version_not_found"))
    }
    async fn enqueue(
        &self,
        tx: &mut PgTransaction,
        topic: &str,
        key: &str,
        payload: &Value,
    ) -> Result<()> {
        dq::bounded(payload)?;
        tx.execute("INSERT INTO octopus_core.dq_outbox(outbox_id,topic,message_key,payload) VALUES ($1,$2,$3,$4)", &[&id(),&topic,&key,&payload]).await.map_err(database)?;
        Ok(())
    }
    async fn audit(
        &self,
        tx: &mut PgTransaction,
        actor: &str,
        action: &str,
        run: Option<&str>,
        details: Value,
    ) -> Result<()> {
        let audit_id = id();
        tx.execute("INSERT INTO octopus_core.dq_audit(audit_id,installation_id,namespace,actor,action,run_id,details) VALUES ($1,$2,$3,$4,$5,$6,$7)", &[&audit_id,&self.settings.installation_id,&self.settings.namespace,&actor,&action,&run,&details]).await.map_err(database)?;
        self.enqueue(tx,"dq.audit.v1",&audit_id,&json!({"schema_version":1,"event_id":audit_id,"event_type":action,"installation_id":self.settings.installation_id,"namespace":self.settings.namespace,"actor":actor,"run_id":run,"details":details})).await
    }
    async fn event(
        &self,
        tx: &mut PgTransaction,
        run: &str,
        kind: &str,
        topic: &str,
    ) -> Result<()> {
        let r = self.run_tx(tx, run).await?;
        let a = &r["current_attempt"];
        self.enqueue(tx,topic,&format!("{}/{}/{}",self.settings.installation_id,self.settings.namespace,run),&json!({"schema_version":1,"event_id":id(),"event_type":kind,"installation_id":self.settings.installation_id,"namespace":self.settings.namespace,"run_id":run,"processor_id":r["processor_id"],"processor_version":r["processor_version"],"state_revision":r["state_revision"],"attempt_id":a["attempt_id"],"fence":a["fence"],"occurred_at":Utc::now().to_rfc3339(),"correlation_id":run,"source_revision_digest":r["source_revision_digest"],"parameters":if kind=="cancelled"{Value::Null}else{r["parameters"].clone()},"artifacts":r[if matches!(kind,"succeeded"|"failed"){"output_refs"}else{"input_refs"}],"traceparent":r["traceparent"],"tracestate":r["tracestate"],"error_code":r["error_code"]})).await
    }
    pub async fn get_run(&self, p: &DqPrincipal, run: &str) -> Result<Value> {
        role(p, &["viewer", "operator", "admin", "automation", "service"])?;
        let mut tx = self.transaction().await?;
        let r = self.checked_run(&mut tx, p, run).await?;
        tx.commit().await.map_err(database)?;
        Ok(r)
    }
    pub async fn invocation(&self, p: &DqPrincipal, key: &str) -> Result<Value> {
        role(p, &["operator", "admin", "automation"])?;
        let mut tx = self.transaction().await?;
        let rows=tx.query("SELECT run_id FROM octopus_core.dq_runs WHERE installation_id=$1 AND namespace=$2 AND idempotency_key=$3", &[&self.settings.installation_id,&self.settings.namespace,&key]).await.map_err(database)?;
        let run: String = rows
            .first()
            .ok_or_else(|| error(404, "invocation_not_found"))?
            .get(0);
        let r = self.checked_run(&mut tx, p, &run).await?;
        tx.commit().await.map_err(database)?;
        Ok(r)
    }
    pub async fn catalog(&self, p: &DqPrincipal) -> Result<Value> {
        role(p, &["viewer", "operator", "admin", "automation", "service"])?;
        let mut tx = self.transaction().await?;
        let values:Vec<Value>=tx.query("SELECT v.manifest FROM octopus_core.dq_processors p JOIN octopus_core.dq_processor_versions v USING(installation_id,namespace,processor_id) WHERE p.installation_id=$1 AND p.namespace=$2 AND p.default_version=v.version ORDER BY v.processor_id", &[&self.settings.installation_id,&self.settings.namespace]).await.map_err(database)?.iter().map(|r|r.get(0)).collect();
        tx.commit().await.map_err(database)?;
        Ok(json!({"items":values}))
    }
    pub async fn manifest(&self, p: &DqPrincipal, processor: &str, version: &str) -> Result<Value> {
        role(p, &["viewer", "operator", "admin", "automation", "service"])?;
        let mut tx = self.transaction().await?;
        let r = self.manifest_tx(&mut tx, processor, version).await?;
        tx.commit().await.map_err(database)?;
        Ok(r)
    }
    pub async fn register(&self, p: &DqPrincipal, value: &Value) -> Result<Value> {
        role(p, &["processor_owner", "admin"])?;
        dq::scoped(p, value, &self.settings)?;
        let processor = dq::text(value, "processor_id")?;
        if processor != "atheros.dedup" {
            return Err(error(400, "unsupported_processor"));
        }
        let version = dq::text(value, "version")?;
        let digest = dq::text(value, "implementation_digest")?;
        let manifest_hash = dq::text(value, "manifest_sha256")?;
        let schema = dq::field(value, "parameter_schema")?;
        dq::check_schema(schema)?;
        if !dq::identifier(processor)
            || !dq::identifier(version)
            || !self.settings.approved_digests.contains(digest)
            || manifest_hash != dq::sha256(&without(value, &["manifest_sha256"]))?
            || dq::text(value, "parameter_schema_sha256")? != dq::sha256(schema)?
            || dq::text(value, "policy_version")? != self.settings.policy_version
            || dq::text(value, "protocol_version")? != "dq.v1"
        {
            return Err(error(400, "unapproved_manifest"));
        }
        let resources = dq::field(value, "resources")?;
        if !(1..=256).contains(&dq::int(resources, "concurrency")?)
            || !(1..=3600).contains(&dq::int(resources, "timeout_seconds")?)
            || dq::long(resources, "max_input_bytes")? < 1
            || dq::long(resources, "max_output_bytes")? < 1
        {
            return Err(error(400, "invalid_resources"));
        }
        dq::bounded(value)?;
        let mut tx = self.transaction().await?;
        let inserted=tx.execute("INSERT INTO octopus_core.dq_processor_versions(installation_id,namespace,processor_id,version,manifest,manifest_sha256,implementation_digest,parameter_schema_sha256,policy_version,registered_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING", &[&self.settings.installation_id,&self.settings.namespace,&processor,&version,&value,&manifest_hash,&digest,&dq::text(value,"parameter_schema_sha256")?,&self.settings.policy_version,&p.actor]).await.map_err(database)?;
        let existing = self.manifest_tx(&mut tx, processor, version).await?;
        if dq::canonical(&existing)? != dq::canonical(value)? {
            return Err(error(409, "immutable_version_conflict"));
        }
        tx.execute("INSERT INTO octopus_core.dq_processors(installation_id,namespace,processor_id,default_version) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING", &[&self.settings.installation_id,&self.settings.namespace,&processor,&version]).await.map_err(database)?;
        if inserted == 1 {
            self.audit(
                &mut tx,
                &p.actor,
                "register",
                None,
                json!({"manifest_sha256":manifest_hash}),
            )
            .await?;
            self.enqueue(
                &mut tx,
                "dq.registry.v1",
                &format!(
                    "{}/{}/{}/{}",
                    self.settings.installation_id, self.settings.namespace, processor, version
                ),
                value,
            )
            .await?;
        }
        tx.commit().await.map_err(database)?;
        Ok(existing)
    }
    fn policy(&self, r: &Value) -> Result<bool> {
        Ok(self.settings.mode(dq::scope(dq::field(r, "parameters")?)?)
            == Some(dq::text(r, "execution_mode")?)
            && dq::text(r, "policy_version")? == self.settings.policy_version
            && self
                .settings
                .approved_digests
                .contains(dq::text(r, "implementation_digest")?))
    }
    async fn current_policy(&self, tx: &mut PgTransaction, r: &Value) -> Result<bool> {
        let scope = dq::scope(dq::field(r, "parameters")?)?;
        let mode = dq::text(r, "execution_mode")?;
        Ok(self.policy(r)?&&tx.query("SELECT EXISTS(SELECT 1 FROM octopus_core.dq_scope_policies WHERE installation_id=$1 AND namespace=$2 AND authorized_scope=$3 AND mode=$4 AND policy_version=$5)",&[&self.settings.installation_id,&self.settings.namespace,&scope,&mode,&self.settings.policy_version]).await.map_err(database)?[0].get::<_,bool>(0))
    }
}
