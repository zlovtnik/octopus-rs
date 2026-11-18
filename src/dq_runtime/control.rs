use super::*;
impl DqStore {
    pub async fn admit(&self, p: &DqPrincipal, request: &Value) -> Result<Value> {
        let mut tx = self.transaction().await?;
        let r = self.admit_tx(&mut tx, p, request).await?;
        tx.commit().await.map_err(database)?;
        Ok(r)
    }
    async fn admit_tx(
        &self,
        tx: &mut PgTransaction,
        p: &DqPrincipal,
        request: &Value,
    ) -> Result<Value> {
        role(p, &["operator", "admin", "automation", "service"])?;
        dq::scoped(p, request, &self.settings)?;
        dq::bounded(request)?;
        let allowed = [
            "installation_id",
            "namespace",
            "processor_id",
            "processor_version",
            "operation",
            "parameters",
            "idempotency_key",
            "deadline_at",
            "traceparent",
            "tracestate",
        ];
        if request
            .as_object()
            .is_some_and(|v| v.keys().any(|k| !allowed.contains(&k.as_str())))
        {
            return Err(error(400, "unsupported_admission_field"));
        }
        let processor = dq::text(request, "processor_id")?;
        let parameters = dq::field(request, "parameters")?;
        let scope = dq::scope(parameters)?;
        let key = dq::text(request, "idempotency_key")?;
        let operation = dq::text(request, "operation")?;
        if !dq::identifier(processor)
            || crate::util::java_is_blank(key)
            || crate::util::utf16_length(key) > 256
            || !matches!(operation, "prepare_candidates" | "reconcile_decision")
        {
            return Err(error(400, "invalid_admission"));
        }
        let fingerprint = dq::sha256(&without(request, &["traceparent", "tracestate"]))?;
        let lock = format!(
            "{}/{}",
            self.settings.installation_id, self.settings.namespace
        );
        tx.query(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            &[&lock],
        )
        .await
        .map_err(database)?;
        let prior=tx.query("SELECT run_id,request_fingerprint FROM octopus_core.dq_runs WHERE installation_id=$1 AND namespace=$2 AND idempotency_key=$3",&[&self.settings.installation_id,&self.settings.namespace,&key]).await.map_err(database)?;
        if let Some(row) = prior.first() {
            if row.get::<_, String>(1) != fingerprint {
                return Err(error(409, "idempotency_conflict"));
            }
            return self.checked_run(tx, p, &row.get::<_, String>(0)).await;
        }
        let mode = self
            .settings
            .mode(scope)
            .ok_or_else(|| error(403, "beta_disabled"))?;
        let active:bool=tx.query("SELECT EXISTS(SELECT 1 FROM octopus_core.dq_scope_policies WHERE installation_id=$1 AND namespace=$2 AND authorized_scope=$3 AND mode=$4 AND policy_version=$5)",&[&self.settings.installation_id,&self.settings.namespace,&scope,&mode,&self.settings.policy_version]).await.map_err(database)?[0].get(0);
        if !active {
            return Err(error(403, "beta_disabled"));
        }
        let version = if request.get("processor_version").is_some() {
            dq::text(request, "processor_version")?.to_owned()
        } else {
            tx.query("SELECT default_version FROM octopus_core.dq_processors WHERE installation_id=$1 AND namespace=$2 AND processor_id=$3",&[&self.settings.installation_id,&self.settings.namespace,&processor]).await.map_err(database)?.first().ok_or_else(||error(404,"processor_not_found"))?.get(0)
        };
        let pinned = self.manifest_tx(tx, processor, &version).await?;
        if !self
            .settings
            .approved_digests
            .contains(dq::text(&pinned, "implementation_digest")?)
            || dq::text(&pinned, "policy_version")? != self.settings.policy_version
        {
            return Err(error(403, "unapproved_manifest"));
        }
        dq::validate(dq::field(&pinned, "parameter_schema")?, parameters)?;
        if processor == "atheros.dedup"
            && (dq::text(parameters, "policy_version")? != self.settings.policy_version
                || !(1..=1000).contains(&dq::int(parameters, "max_candidates")?))
        {
            return Err(error(400, "invalid_dedup_parameters"));
        }
        let counts=tx.query("SELECT COUNT(*),COUNT(*) FILTER(WHERE authorized_scope=$3) FROM octopus_core.dq_runs WHERE installation_id=$1 AND namespace=$2 AND status NOT IN ('succeeded','failed','cancelled')",&[&self.settings.installation_id,&self.settings.namespace,&scope]).await.map_err(database)?;
        let quota =
            (self.settings.max_queued / (self.settings.scope_modes.len().max(1) as i32)).max(1);
        if counts[0].get::<_, i64>(0) >= i64::from(self.settings.max_queued)
            || counts[0].get::<_, i64>(1) >= i64::from(quota)
        {
            return Err(error(429, "admission_capacity"));
        }
        let run = id();
        let now = Utc::now();
        let until = dq::deadline(request, now)?;
        if until <= now || until > now + chrono::Duration::days(1) {
            return Err(error(400, "invalid_deadline"));
        }
        let mut doc = request.clone();
        doc["processor_version"] = json!(version);
        doc["implementation_digest"] = pinned["implementation_digest"].clone();
        doc["parameters_sha256"] = json!(dq::sha256(parameters)?);
        doc["policy_version"] = json!(self.settings.policy_version);
        doc["release_channel"] = json!("beta");
        tx.execute("INSERT INTO octopus_core.dq_runs(run_id,installation_id,namespace,processor_id,processor_version,authorized_scope,operation,idempotency_key,request_fingerprint,document,manifest,policy_version,execution_mode,status,deadline_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'queued',$14)",&[&run,&self.settings.installation_id,&self.settings.namespace,&processor,&version,&scope,&operation,&key,&fingerprint,&doc,&pinned,&self.settings.policy_version,&mode,&until]).await.map_err(database)?;
        if operation == "reconcile_decision" {
            self.record_decision(tx, scope, mode, dq::text(parameters, "candidate_id")?, &run)
                .await?;
        }
        self.audit(
            tx,
            &p.actor,
            "invoke",
            Some(&run),
            json!({"request_fingerprint":fingerprint}),
        )
        .await?;
        self.run_tx(tx, &run).await
    }
    async fn record_decision(
        &self,
        tx: &mut PgTransaction,
        scope: &str,
        mode: &str,
        candidate: &str,
        run: &str,
    ) -> Result<()> {
        let rows=tx.execute("INSERT INTO octopus_core.dq_decision_sources(candidate_id,decision,decision_revision,run_id) SELECT d.candidate_id,d.decision,encode(sha256(convert_to(jsonb_build_array($1::text,$2::text,$3::text,$4::text,$5::text,d.candidate_id,d.decision)::text,'UTF8')),'hex'),$7 FROM atheros_search.merge_decisions d JOIN atheros_search.merge_candidates c USING(candidate_id) JOIN atheros_search.devices l ON l.mac=c.mac_a JOIN atheros_search.devices r ON r.mac=c.mac_b WHERE d.candidate_id=$6 AND ($3='*' OR(l.location_id=$3 AND r.location_id=$3)) ON CONFLICT(candidate_id,decision_revision) DO UPDATE SET run_id=EXCLUDED.run_id WHERE dq_decision_sources.completed_at IS NULL AND EXISTS(SELECT 1 FROM octopus_core.dq_runs prior WHERE prior.run_id=dq_decision_sources.run_id AND prior.status IN ('failed','cancelled'))",&[&self.settings.installation_id,&self.settings.namespace,&scope,&self.settings.policy_version,&mode,&candidate,&run]).await.map_err(database)?;
        // An already completed immutable decision is not an available admission.
        if rows == 0 {
            let exists:bool=tx.query("SELECT EXISTS(SELECT 1 FROM atheros_search.merge_decisions d JOIN atheros_search.merge_candidates c USING(candidate_id) JOIN atheros_search.devices l ON l.mac=c.mac_a JOIN atheros_search.devices r ON r.mac=c.mac_b WHERE d.candidate_id=$1 AND ($2='*' OR(l.location_id=$2 AND r.location_id=$2)))",&[&candidate,&scope]).await.map_err(database)?[0].get(0);
            if !exists {
                return Err(error(404, "decision_not_found"));
            }
            return Err(error(409, "decision_revision_already_claimed"));
        }
        Ok(())
    }
    pub async fn cancel(&self, p: &DqPrincipal, run: &str) -> Result<Value> {
        let mut tx = self.transaction().await?;
        let r = self.cancel_tx(&mut tx, p, run).await?;
        tx.commit().await.map_err(database)?;
        Ok(r)
    }
    async fn cancel_tx(&self, tx: &mut PgTransaction, p: &DqPrincipal, run: &str) -> Result<Value> {
        role(p, &["operator", "admin"])?;
        self.lock_run(tx, run).await?;
        self.checked_run(tx, p, run).await?;
        let changed=tx.execute("UPDATE octopus_core.dq_runs SET status='cancelled',fence=fence+1,state_revision=state_revision+1,completed_at=CURRENT_TIMESTAMP,work_owner=NULL,work_expires_at=NULL WHERE run_id=$1 AND status NOT IN ('succeeded','failed','cancelled')",&[&run]).await.map_err(database)?;
        if changed == 1 {
            tx.execute("UPDATE octopus_core.dq_attempts SET status='cancelled',finished_at=CURRENT_TIMESTAMP WHERE run_id=$1 AND status IN ('reserved','accepted','running','applying')",&[&run]).await.map_err(database)?;
            self.audit(tx, &p.actor, "cancel", Some(run), json!({}))
                .await?;
            self.event(tx, run, "cancel", "dq.commands.v1").await?;
            self.event(tx, run, "cancelled", "dq.events.v1").await?;
        }
        self.checked_run(tx, p, run).await
    }
    pub async fn replay(&self, p: &DqPrincipal, run: &str, request: &Value) -> Result<Value> {
        role(p, &["operator", "admin"])?;
        let mut tx = self.transaction().await?;
        let r = self.checked_run(&mut tx, p, run).await?;
        if !matches!(dq::text(&r, "status")?, "failed" | "cancelled") {
            return Err(error(409, "run_not_replayable"));
        }
        let key = dq::text(request, "idempotency_key")?;
        if key == dq::text(&r, "idempotency_key")? {
            return Err(error(409, "replay_requires_new_key"));
        }
        let request = json!({"installation_id":r["installation_id"],"namespace":r["namespace"],"processor_id":r["processor_id"],"processor_version":r["processor_version"],"operation":r["operation"],"parameters":r["parameters"],"idempotency_key":key});
        let result = self.admit_tx(&mut tx, p, &request).await?;
        self.audit(
            &mut tx,
            &p.actor,
            "replay",
            Some(dq::text(&result, "run_id")?),
            json!({"source_run_id":run}),
        )
        .await?;
        tx.commit().await.map_err(database)?;
        Ok(result)
    }
    pub async fn heartbeat(&self, request: &Value) -> Result<Value> {
        dq::scoped(&DqPrincipal::internal(), request, &self.settings)?;
        let worker = dq::text(request, "worker_instance_id")?;
        let processor = dq::text(request, "processor_id")?;
        let version = dq::text(request, "processor_version")?;
        let digest = dq::text(request, "implementation_digest")?;
        let address = dq::text(request, "address")?;
        let concurrency = dq::int(request, "concurrency")?;
        let ready = request["ready"]
            .as_bool()
            .ok_or_else(|| error(400, "invalid_ready"))?;
        if !dq::identifier(worker)
            || !regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9.-]*:[0-9]{1,5}$")
                .expect("constant regex")
                .is_match(address)
            || !address.rsplit_once(':').and_then(|(_, port)| port.parse::<u16>().ok()).is_some_and(|port| port > 0)
            || !(1..=256).contains(&concurrency)
        {
            return Err(error(400, "invalid_worker"));
        }
        let mut tx = self.transaction().await?;
        let manifest = self.manifest_tx(&mut tx, processor, version).await?;
        if dq::text(&manifest, "implementation_digest")? != digest
            || !self.settings.approved_digests.contains(digest)
        {
            return Err(error(409, "worker_digest_mismatch"));
        }
        let changed=tx.execute("INSERT INTO octopus_core.dq_workers(worker_instance_id,installation_id,namespace,processor_id,processor_version,implementation_digest,address,concurrency,ready) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(worker_instance_id) DO UPDATE SET ready=EXCLUDED.ready,last_seen_at=CURRENT_TIMESTAMP WHERE dq_workers.installation_id=EXCLUDED.installation_id AND dq_workers.namespace=EXCLUDED.namespace AND dq_workers.processor_id=EXCLUDED.processor_id AND dq_workers.processor_version=EXCLUDED.processor_version AND dq_workers.implementation_digest=EXCLUDED.implementation_digest AND dq_workers.address=EXCLUDED.address AND dq_workers.concurrency=EXCLUDED.concurrency",&[&worker,&self.settings.installation_id,&self.settings.namespace,&processor,&version,&digest,&address,&concurrency,&ready]).await.map_err(database)?;
        if changed != 1 {
            return Err(error(409, "immutable_worker_identity"));
        }
        tx.commit().await.map_err(database)?;
        Ok(json!({"accepted":true}))
    }
    pub async fn dispatches(&self, limit: i32) -> Result<Value> {
        if !(1..=100).contains(&limit) {
            return Err(error(400, "invalid_dispatch_limit"));
        }
        let mut tx = self.transaction().await?;
        let rows=tx.query("SELECT run_id FROM octopus_core.dq_runs r WHERE installation_id=$1 AND namespace=$2 AND deadline_at>CURRENT_TIMESTAMP AND ((status IN ('preparing','retrying') AND jsonb_array_length(input_refs)>0 AND next_attempt_at<=CURRENT_TIMESTAMP AND work_owner IS NULL) OR(status='running' AND EXISTS(SELECT 1 FROM octopus_core.dq_attempts a WHERE a.attempt_id=r.current_attempt_id AND a.status='reserved' AND a.lease_expires_at>CURRENT_TIMESTAMP))) ORDER BY created_at,run_id LIMIT $3::int",&[&self.settings.installation_id,&self.settings.namespace,&limit]).await.map_err(database)?;
        let mut values = Vec::new();
        for row in rows {
            let r = self.run_tx(&mut tx, &row.get::<_, String>(0)).await?;
            let manifest = self
                .manifest_tx(
                    &mut tx,
                    dq::text(&r, "processor_id")?,
                    dq::text(&r, "processor_version")?,
                )
                .await?;
            values.push(json!({"manifest":manifest,"attempt":r["current_attempt"],"run":r}));
        }
        let page = dq::dispatch_page(&values)?;
        tx.commit().await.map_err(database)?;
        Ok(page)
    }
    pub async fn reserve(&self, run: &str, request: &Value) -> Result<Value> {
        dq::scoped(&DqPrincipal::internal(), request, &self.settings)?;
        let worker = dq::text(request, "worker_instance_id")?;
        let slot = dq::int(request, "worker_slot")?;
        let mut tx = self.transaction().await?;
        self.lock_run(&mut tx, run).await?;
        let r = self.run_tx(&mut tx, run).await?;
        if !self.current_policy(&mut tx, &r).await? {
            return Err(error(409, "policy_changed"));
        }
        let prior=tx.query("SELECT attempt_id FROM octopus_core.dq_attempts WHERE run_id=$1 AND status IN ('reserved','accepted','running','applying') AND lease_expires_at>CURRENT_TIMESTAMP",&[&run]).await.map_err(database)?;
        if prior.is_empty() {
            let rows=tx.query("SELECT processor_id,processor_version,implementation_digest,concurrency,ready,last_seen_at>CURRENT_TIMESTAMP-INTERVAL '30 seconds' FROM octopus_core.dq_workers WHERE worker_instance_id=$1 AND installation_id=$2 AND namespace=$3 FOR UPDATE",&[&worker,&self.settings.installation_id,&self.settings.namespace]).await.map_err(database)?;
            let w = rows
                .first()
                .ok_or_else(|| error(409, "worker_unavailable"))?;
            if w.get::<_, String>(0) != dq::text(&r, "processor_id")?
                || w.get::<_, String>(1) != dq::text(&r, "processor_version")?
                || w.get::<_, String>(2) != dq::text(&r, "implementation_digest")?
                || slot < 0
                || slot >= w.get::<_, i32>(3)
                || !w.get::<_, bool>(4)
                || !w.get::<_, bool>(5)
            {
                return Err(error(409, "worker_unavailable"));
            }
            if tx.query("SELECT EXISTS(SELECT 1 FROM octopus_core.dq_attempts WHERE worker_instance_id=$1 AND worker_slot=$2 AND status IN ('reserved','accepted','running'))",&[&worker,&slot]).await.map_err(database)?[0].get::<_,bool>(0){return Err(error(409,"worker_slot_busy"));}
            if tx.execute("UPDATE octopus_core.dq_runs SET status='running',fence=fence+1,attempt_count=attempt_count+1,state_revision=state_revision+1 WHERE run_id=$1 AND status IN ('preparing','retrying') AND jsonb_array_length(input_refs)>0 AND attempt_count<5 AND next_attempt_at<=CURRENT_TIMESTAMP AND deadline_at>CURRENT_TIMESTAMP AND work_owner IS NULL",&[&run]).await.map_err(database)?!=1{return Err(error(409,"run_not_dispatchable"));}
            let attempt = id();
            let token = id();
            tx.execute("INSERT INTO octopus_core.dq_attempts(attempt_id,run_id,attempt_number,worker_instance_id,worker_slot,lease_token,fence,lease_expires_at,status) SELECT $1,run_id,attempt_count,$3,$4,$5,fence,LEAST(deadline_at,CURRENT_TIMESTAMP+$6::int*INTERVAL '1 second'),'reserved' FROM octopus_core.dq_runs WHERE run_id=$2",&[&attempt,&run,&worker,&slot,&token,&self.settings.lease_seconds]).await.map_err(database)?;
            tx.execute(
                "UPDATE octopus_core.dq_runs SET current_attempt_id=$2 WHERE run_id=$1",
                &[&run, &attempt],
            )
            .await
            .map_err(database)?;
        }
        let result = self.run_tx(&mut tx, run).await?;
        let manifest = self
            .manifest_tx(
                &mut tx,
                dq::text(&result, "processor_id")?,
                dq::text(&result, "processor_version")?,
            )
            .await?;
        let address:String=tx.query("SELECT w.address FROM octopus_core.dq_workers w JOIN octopus_core.dq_attempts a ON a.worker_instance_id=w.worker_instance_id WHERE a.attempt_id=$1",&[&dq::text(&result["current_attempt"],"attempt_id")?]).await.map_err(database)?[0].get(0);
        tx.commit().await.map_err(database)?;
        Ok(
            json!({"attempt":result["current_attempt"],"run":result,"manifest":manifest,"worker_address":address}),
        )
    }
    pub async fn accepted(&self, attempt: &str, request: &Value) -> Result<Value> {
        self.lease(attempt, request, true).await
    }
    pub async fn renew(&self, attempt: &str, request: &Value) -> Result<Value> {
        self.lease(attempt, request, false).await
    }
    async fn lease(&self, attempt: &str, request: &Value, accept: bool) -> Result<Value> {
        dq::scoped(&DqPrincipal::internal(), request, &self.settings)?;
        let run = dq::text(request, "run_id")?;
        let worker = dq::text(request, "worker_instance_id")?;
        let token = dq::text(request, "lease_token")?;
        let fence = dq::long(request, "fence")?;
        let mut tx = self.transaction().await?;
        self.lock_run(&mut tx, run).await?;
        let r = self.run_tx(&mut tx, run).await?;
        if !self.current_policy(&mut tx, &r).await? {
            return Err(error(409, "policy_changed"));
        }
        let deadline = dq::text(&r, "deadline_at")?;
        let changed=tx.execute("WITH sampled AS MATERIALIZED (SELECT clock_timestamp() AS now) UPDATE octopus_core.dq_attempts SET status=CASE WHEN $6 AND status='reserved' THEN 'accepted' ELSE status END,lease_expires_at=LEAST($7::text::timestamptz,sampled.now+$8::int*INTERVAL '1 second') FROM sampled WHERE attempt_id=$1 AND run_id=$2 AND worker_instance_id=$3 AND lease_token=$4 AND fence=$5 AND status IN ('reserved','accepted','running','applying') AND lease_expires_at>sampled.now AND $7::text::timestamptz>sampled.now AND EXISTS(SELECT 1 FROM octopus_core.dq_runs WHERE run_id=$2 AND current_attempt_id=$1 AND fence=$5 AND status IN ('running','applying'))",&[&attempt,&run,&worker,&token,&fence,&accept,&deadline,&self.settings.lease_seconds]).await.map_err(database)?;
        if changed != 1 {
            return Err(error(409, "stale_lease"));
        }
        let r = self.run_tx(&mut tx, run).await?;
        tx.commit().await.map_err(database)?;
        Ok(r["current_attempt"].clone())
    }
    pub async fn artifact(&self, p: &DqPrincipal, artifact: &str, access: bool) -> Result<Value> {
        role(p, &["viewer", "operator", "admin"])?;
        let mut tx = self.transaction().await?;
        let rows = tx
            .query(
                "SELECT run_id,reference FROM octopus_core.dq_artifacts WHERE artifact_id=$1",
                &[&artifact],
            )
            .await
            .map_err(database)?;
        let row = rows
            .first()
            .ok_or_else(|| error(404, "artifact_not_found"))?;
        let run: String = row.get(0);
        let reference: Value = row.get(1);
        self.checked_run(&mut tx, p, &run).await?;
        if access {
            self.audit(
                &mut tx,
                &p.actor,
                "artifact_access",
                Some(&run),
                json!({"artifact_id":artifact}),
            )
            .await?;
        }
        tx.commit().await.map_err(database)?;
        Ok(reference)
    }
    pub async fn reconcile_policies(&self) -> Result<()> {
        let mut tx = self.transaction().await?;
        if crate::util::java_is_blank(&self.settings.installation_id)
            || crate::util::java_is_blank(&self.settings.namespace)
        {
            if tx.query("SELECT EXISTS(SELECT 1 FROM octopus_core.dq_scope_policies WHERE mode='enabled')",&[]).await.map_err(database)?[0].get::<_,bool>(0){return Err(error(503,"rollback_requires_installation_scope"));}
        } else {
            tx.execute("UPDATE octopus_core.dq_scope_policies SET mode='disabled' WHERE installation_id=$1 AND namespace=$2",&[&self.settings.installation_id,&self.settings.namespace]).await.map_err(database)?;
            for (scope, mode) in &self.settings.scope_modes {
                tx.execute("INSERT INTO octopus_core.dq_scope_policies(installation_id,namespace,authorized_scope,mode,policy_version) VALUES($1,$2,$3,$4,$5) ON CONFLICT(installation_id,namespace,authorized_scope) DO UPDATE SET mode=EXCLUDED.mode,policy_version=EXCLUDED.policy_version",&[&self.settings.installation_id,&self.settings.namespace,&scope,&mode,&self.settings.policy_version]).await.map_err(database)?;
            }
        }
        let rows=tx.query("SELECT run_id FROM octopus_core.dq_runs WHERE installation_id=$1 AND namespace=$2 AND status NOT IN ('succeeded','failed','cancelled') ORDER BY run_id",&[&self.settings.installation_id,&self.settings.namespace]).await.map_err(database)?;
        let p = DqPrincipal {
            actor: "policy-reconcile".into(),
            roles: ["admin".into()].into(),
            scopes: ["*".into()].into(),
        };
        for row in rows {
            let run: String = row.get(0);
            self.lock_run(&mut tx, &run).await?;
            if !self.policy(&self.run_tx(&mut tx, &run).await?)? {
                self.cancel_tx(&mut tx, &p, &run).await?;
            }
        }
        tx.commit().await.map_err(database)
    }
}
