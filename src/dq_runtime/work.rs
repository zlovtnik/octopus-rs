use super::*;
impl DqStore {
    pub async fn claim_preparation(
        &self,
        owner: &str,
        seconds: i32,
        limit: i32,
    ) -> Result<Vec<Value>> {
        let mut tx = self.transaction().await?;
        let rows=tx.query("WITH selected AS(SELECT run_id FROM octopus_core.dq_runs WHERE installation_id=$1 AND namespace=$2 AND status IN ('queued','preparing','retrying') AND jsonb_array_length(input_refs)=0 AND(work_owner IS NULL OR work_expires_at<=CURRENT_TIMESTAMP) AND next_attempt_at<=CURRENT_TIMESTAMP AND deadline_at>CURRENT_TIMESTAMP AND preparation_attempts<5 ORDER BY created_at,run_id FOR UPDATE SKIP LOCKED LIMIT $5::int) UPDATE octopus_core.dq_runs r SET status='preparing',work_owner=$3,work_expires_at=CURRENT_TIMESTAMP+$4::int*INTERVAL '1 second',preparation_attempts=preparation_attempts+1 FROM selected WHERE selected.run_id=r.run_id RETURNING r.run_id",&[&self.settings.installation_id,&self.settings.namespace,&owner,&seconds.max(1),&limit.clamp(1,100)]).await.map_err(database)?;
        let mut values = Vec::new();
        for row in rows {
            values.push(self.run_tx(&mut tx, &row.get::<_, String>(0)).await?);
        }
        tx.commit().await.map_err(database)?;
        Ok(values)
    }
    async fn artifacts_tx(&self, tx: &mut PgTransaction, run: &str, refs: &Value) -> Result<()> {
        for reference in refs.as_array().into_iter().flatten() {
            let artifact = dq::text(reference, "artifact_id")?;
            tx.execute("INSERT INTO octopus_core.dq_artifacts(artifact_id,run_id,reference,installation_id,namespace) VALUES($1,$2,$3,$4,$5) ON CONFLICT(artifact_id) DO NOTHING",&[&artifact,&run,&reference,&self.settings.installation_id,&self.settings.namespace]).await.map_err(database)?;
            let existing: Value = tx
                .query(
                    "SELECT reference FROM octopus_core.dq_artifacts WHERE artifact_id=$1",
                    &[&artifact],
                )
                .await
                .map_err(database)?[0]
                .get(0);
            if dq::canonical(&existing)? != dq::canonical(reference)? {
                return Err(error(409, "artifact_identity_conflict"));
            }
        }
        Ok(())
    }
    pub async fn complete_preparation(
        &self,
        run: &str,
        owner: &str,
        refs: &Value,
        revision: &str,
    ) -> Result<bool> {
        dq::validate_artifacts(refs, &self.settings, run, None, true)?;
        if refs.as_array().is_none_or(Vec::is_empty) || !dq::hash(revision) {
            return Err(error(400, "invalid_preparation"));
        }
        let mut tx = self.transaction().await?;
        self.lock_run(&mut tx, run).await?;
        let r = self.run_tx(&mut tx, run).await?;
        let changed = if self.current_policy(&mut tx, &r).await? {
            tx.execute("UPDATE octopus_core.dq_runs SET input_refs=$3,source_revision_digest=$4,state_revision=state_revision+1,work_owner=NULL,work_expires_at=NULL WHERE run_id=$1 AND status='preparing' AND work_owner=$2 AND work_expires_at>CURRENT_TIMESTAMP AND deadline_at>CURRENT_TIMESTAMP",&[&run,&owner,&refs,&revision]).await.map_err(database)?
        } else {
            0
        };
        if changed == 1 {
            self.artifacts_tx(&mut tx, run, refs).await?;
            self.event(&mut tx, run, "invoke", "dq.commands.v1").await?;
        }
        tx.commit().await.map_err(database)?;
        Ok(changed == 1)
    }
    pub async fn claim_output(&self, owner: &str, seconds: i32, limit: i32) -> Result<Vec<Value>> {
        let mut tx = self.transaction().await?;
        let rows=tx.query("WITH selected AS(SELECT run_id FROM octopus_core.dq_runs WHERE status='applying' AND installation_id=$1 AND namespace=$2 AND(work_owner IS NULL OR work_expires_at<=CURRENT_TIMESTAMP) AND deadline_at>CURRENT_TIMESTAMP AND next_attempt_at<=CURRENT_TIMESTAMP AND application_attempts<5 ORDER BY created_at,run_id FOR UPDATE SKIP LOCKED LIMIT $5::int) UPDATE octopus_core.dq_runs r SET work_owner=$3,application_attempts=application_attempts+1,work_expires_at=CURRENT_TIMESTAMP+$4::int*INTERVAL '1 second' FROM selected WHERE selected.run_id=r.run_id RETURNING r.run_id",&[&self.settings.installation_id,&self.settings.namespace,&owner,&seconds.max(1),&limit.clamp(1,100)]).await.map_err(database)?;
        let mut values = Vec::new();
        for row in rows {
            values.push(self.run_tx(&mut tx, &row.get::<_, String>(0)).await?);
        }
        tx.commit().await.map_err(database)?;
        Ok(values)
    }
    pub async fn guard_output_tx(
        &self,
        tx: &mut PgTransaction,
        run: &str,
        attempt: &str,
        fence: i64,
        owner: &str,
        revision: &str,
    ) -> Result<bool> {
        self.lock_run(tx, run).await?;
        let r = self.run_tx(tx, run).await?;
        let valid:bool=tx.query("SELECT EXISTS(SELECT 1 FROM octopus_core.dq_runs r JOIN octopus_core.dq_attempts a ON a.attempt_id=r.current_attempt_id WHERE r.run_id=$1 AND r.status='applying' AND r.work_owner=$4 AND r.work_expires_at>CURRENT_TIMESTAMP AND r.deadline_at>CURRENT_TIMESTAMP AND r.source_revision_digest=$5 AND a.attempt_id=$2 AND a.fence=$3 AND r.fence=$3 AND a.status='applying')",&[&run,&attempt,&fence,&owner,&revision]).await.map_err(database)?[0].get(0);
        Ok(valid && self.current_policy(tx, &r).await?)
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_output_tx(
        &self,
        tx: &mut PgTransaction,
        run: &str,
        attempt: &str,
        fence: i64,
        owner: &str,
        revision: &str,
        applied: bool,
        summary: &Value,
    ) -> Result<bool> {
        if !self
            .guard_output_tx(tx, run, attempt, fence, owner, revision)
            .await?
        {
            return Ok(false);
        }
        tx.execute("UPDATE octopus_core.dq_runs SET status='succeeded',state_revision=state_revision+1,projection_applied=$2,summary=$3,completed_at=CURRENT_TIMESTAMP,work_owner=NULL,work_expires_at=NULL WHERE run_id=$1",&[&run,&applied,&summary]).await.map_err(database)?;
        tx.execute("UPDATE octopus_core.dq_attempts SET status='succeeded',finished_at=CURRENT_TIMESTAMP WHERE attempt_id=$1",&[&attempt]).await.map_err(database)?;
        tx.execute("UPDATE octopus_core.dq_decision_sources SET completed_at=CURRENT_TIMESTAMP WHERE run_id=$1",&[&run]).await.map_err(database)?;
        self.event(tx, run, "succeeded", "dq.events.v1").await?;
        Ok(true)
    }
    async fn terminal_or_retry(&self, tx: &mut PgTransaction, run: &str) -> Result<()> {
        let r = self.run_tx(tx, run).await?;
        if dq::text(&r, "status")? == "failed" {
            self.event(tx, run, "failed", "dq.events.v1").await?;
            self.event(tx, run, "failed", "dq.dlq.v1").await?;
        } else if r["input_refs"].as_array().is_some_and(|a| !a.is_empty()) {
            self.event(tx, run, "retry_dispatch", "dq.commands.v1")
                .await?;
        }
        Ok(())
    }
    pub async fn fail_work(
        &self,
        run: &str,
        owner: &str,
        code: &str,
        permanent: bool,
        needs_preparation: bool,
    ) -> Result<()> {
        let mut tx = self.transaction().await?;
        self.lock_run(&mut tx, run).await?;
        let changed=tx.execute("UPDATE octopus_core.dq_runs SET status=CASE WHEN $4 OR($5 AND(preparation_attempts>=5 OR attempt_count>=5)) OR(NOT $5 AND application_attempts>=5) THEN 'failed' WHEN NOT $5 AND status='applying' THEN 'applying' ELSE 'retrying' END,error_code=$3,fence=CASE WHEN $5 OR $4 THEN fence+1 ELSE fence END,state_revision=state_revision+1,completed_at=CASE WHEN $4 OR($5 AND(preparation_attempts>=5 OR attempt_count>=5)) OR(NOT $5 AND application_attempts>=5) THEN CURRENT_TIMESTAMP ELSE NULL END,input_refs=CASE WHEN $5 THEN '[]'::jsonb ELSE input_refs END,output_refs=CASE WHEN $5 THEN '[]'::jsonb ELSE output_refs END,current_attempt_id=CASE WHEN $5 OR $4 THEN NULL ELSE current_attempt_id END,work_owner=NULL,work_expires_at=NULL,next_attempt_at=CURRENT_TIMESTAMP+(random()*LEAST(60,POWER(2,GREATEST(application_attempts,preparation_attempts)-1)))*INTERVAL '1 second' WHERE run_id=$1 AND status IN ('preparing','applying') AND work_owner=$2 AND work_expires_at>CURRENT_TIMESTAMP",&[&run,&owner,&code,&permanent,&needs_preparation]).await.map_err(database)?;
        if changed == 1 {
            tx.execute("UPDATE octopus_core.dq_attempts SET status='failed',finished_at=CURRENT_TIMESTAMP WHERE run_id=$1 AND status IN ('reserved','accepted','running','applying') AND($2 OR $3 OR EXISTS(SELECT 1 FROM octopus_core.dq_runs WHERE run_id=$1 AND status='failed'))",&[&run,&needs_preparation,&permanent]).await.map_err(database)?;
            self.terminal_or_retry(&mut tx, run).await?;
        }
        tx.commit().await.map_err(database)
    }
    pub async fn expire_attempts(&self) -> Result<u64> {
        let mut tx = self.transaction().await?;
        let rows=tx.query("SELECT run_id FROM octopus_core.dq_runs WHERE installation_id=$1 AND namespace=$2 AND status NOT IN ('succeeded','failed','cancelled') AND(deadline_at<=CURRENT_TIMESTAMP OR(work_expires_at<=CURRENT_TIMESTAMP AND((status='applying' AND application_attempts>=5) OR(status='preparing' AND preparation_attempts>=5))) OR EXISTS(SELECT 1 FROM octopus_core.dq_attempts a WHERE a.attempt_id=current_attempt_id AND a.status IN ('reserved','accepted','running') AND a.lease_expires_at<=CURRENT_TIMESTAMP)) ORDER BY run_id LIMIT 100",&[&self.settings.installation_id,&self.settings.namespace]).await.map_err(database)?;
        let mut count = 0;
        for row in rows {
            let run: String = row.get(0);
            self.lock_run(&mut tx, &run).await?;
            let changed=tx.execute("UPDATE octopus_core.dq_runs SET status=CASE WHEN attempt_count>=5 OR preparation_attempts>=5 OR application_attempts>=5 OR deadline_at<=CURRENT_TIMESTAMP THEN 'failed' ELSE 'retrying' END,fence=fence+1,state_revision=state_revision+1,current_attempt_id=NULL,work_owner=NULL,work_expires_at=NULL,error_code='lease_expired',output_refs='[]'::jsonb,completed_at=CASE WHEN attempt_count>=5 OR preparation_attempts>=5 OR application_attempts>=5 OR deadline_at<=CURRENT_TIMESTAMP THEN CURRENT_TIMESTAMP ELSE NULL END,next_attempt_at=CURRENT_TIMESTAMP+(random()*LEAST(60,POWER(2,attempt_count-1)))*INTERVAL '1 second' WHERE run_id=$1 AND status NOT IN ('succeeded','failed','cancelled') AND(deadline_at<=CURRENT_TIMESTAMP OR(work_expires_at<=CURRENT_TIMESTAMP AND((status='applying' AND application_attempts>=5) OR(status='preparing' AND preparation_attempts>=5))) OR EXISTS(SELECT 1 FROM octopus_core.dq_attempts a WHERE a.attempt_id=current_attempt_id AND a.status IN ('reserved','accepted','running') AND a.lease_expires_at<=CURRENT_TIMESTAMP))",&[&run]).await.map_err(database)?;
            if changed == 1 {
                tx.execute("UPDATE octopus_core.dq_attempts SET status='expired',finished_at=CURRENT_TIMESTAMP WHERE run_id=$1 AND status IN ('reserved','accepted','running','applying')",&[&run]).await.map_err(database)?;
                self.terminal_or_retry(&mut tx, &run).await?;
            }
            count += changed;
        }
        tx.commit().await.map_err(database)?;
        Ok(count)
    }
    pub async fn claim_outbox(
        &self,
        owner: &str,
        seconds: i32,
        limit: i32,
    ) -> Result<Vec<DqOutbox>> {
        let token = id();
        let mut tx = self.transaction().await?;
        let rows=tx.query("WITH selected AS(SELECT outbox_id FROM octopus_core.dq_outbox WHERE(status='pending' AND next_attempt_at<=CURRENT_TIMESTAMP) OR(status='leased' AND lease_expires_at<=CURRENT_TIMESTAMP) ORDER BY created_at,outbox_id FOR UPDATE SKIP LOCKED LIMIT $4::int) UPDATE octopus_core.dq_outbox o SET status='leased',owner=$1,token=$2,fence=fence+1,lease_expires_at=CURRENT_TIMESTAMP+$3::int*INTERVAL '1 second',attempt_count=attempt_count+1 FROM selected WHERE selected.outbox_id=o.outbox_id RETURNING o.outbox_id,o.topic,o.message_key,o.payload,o.fence",&[&owner,&token,&seconds.max(1),&limit.clamp(1,100)]).await.map_err(database)?;
        let values = rows
            .iter()
            .map(|r| DqOutbox {
                id: r.get(0),
                topic: r.get(1),
                key: r.get(2),
                payload: r.get(3),
                owner: owner.into(),
                token: token.clone(),
                fence: r.get(4),
            })
            .collect();
        tx.commit().await.map_err(database)?;
        Ok(values)
    }
    pub async fn acknowledge_outbox(&self, item: &DqOutbox) -> Result<bool> {
        let mut tx = self.transaction().await?;
        let count=tx.execute("UPDATE octopus_core.dq_outbox SET status='published',published_at=CURRENT_TIMESTAMP,owner=NULL,token=NULL,lease_expires_at=NULL WHERE outbox_id=$1 AND status='leased' AND owner=$2 AND token=$3 AND fence=$4 AND lease_expires_at>CURRENT_TIMESTAMP",&[&item.id,&item.owner,&item.token,&item.fence]).await.map_err(database)?;
        tx.commit().await.map_err(database)?;
        Ok(count == 1)
    }
    pub async fn fail_outbox(&self, item: &DqOutbox) -> Result<()> {
        let mut tx = self.transaction().await?;
        tx.execute("UPDATE octopus_core.dq_outbox SET status='pending',owner=NULL,token=NULL,lease_expires_at=NULL,next_attempt_at=CURRENT_TIMESTAMP+(random()*LEAST(60,POWER(2,LEAST(6,attempt_count-1))))*INTERVAL '1 second' WHERE outbox_id=$1 AND status='leased' AND owner=$2 AND token=$3 AND fence=$4 AND lease_expires_at>CURRENT_TIMESTAMP",&[&item.id,&item.owner,&item.token,&item.fence]).await.map_err(database)?;
        tx.commit().await.map_err(database)
    }
    async fn quarantine(
        &self,
        tx: &mut PgTransaction,
        group: &str,
        topic: &str,
        partition: i32,
        offset: i64,
        reason: &str,
    ) -> Result<()> {
        tx.execute("UPDATE octopus_core.dq_receipts SET quarantine_reason=$5 WHERE consumer_group=$1 AND topic=$2 AND partition_id=$3 AND offset_id=$4",&[&group,&topic,&partition,&offset,&reason]).await.map_err(database)?;
        self.enqueue(tx,"dq.dlq.v1",&format!("{topic}/{partition}/{offset}"),&json!({"schema_version":1,"event_id":id(),"event_type":"quarantined","installation_id":self.settings.installation_id,"namespace":self.settings.namespace,"source_topic":topic,"source_partition":partition,"source_offset":offset,"error_code":reason})).await
    }
    pub async fn receive_receipt(&self, request: &Value) -> Result<Value> {
        dq::scoped(&DqPrincipal::internal(), request, &self.settings)?;
        let group = dq::text(request, "consumer_group")?;
        let topic = dq::text(request, "topic")?;
        let partition = dq::int(request, "partition")?;
        let offset = dq::long(request, "offset")?;
        let event = dq::text(request, "event_id")?;
        let hash = dq::text(request, "payload_sha256")?;
        let envelope = request.get("envelope").filter(|v| !v.is_null());
        let quarantine = dq::optional(request, "quarantine_reason");
        if let Some(e) = envelope {
            dq::bounded(e)?;
        }
        if !matches!(topic, "dq.commands.v1" | "dq.worker-reports.v1")
            || partition < 0
            || offset < 0
            || !dq::hash(hash)
            || crate::util::java_is_blank(event)
            || crate::util::utf16_length(event) > 256
            || crate::util::java_is_blank(group)
            || crate::util::utf16_length(group) > 256
            || (envelope.is_none() && quarantine.is_none())
        {
            return Err(error(400, "invalid_receipt"));
        }
        let mut tx = self.transaction().await?;
        tx.query(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            &[&event],
        )
        .await
        .map_err(database)?;
        let same=tx.query("SELECT payload_sha256,quarantine_reason FROM octopus_core.dq_receipts WHERE consumer_group=$1 AND topic=$2 AND partition_id=$3 AND offset_id=$4",&[&group,&topic,&partition,&offset]).await.map_err(database)?;
        let checks=tx.query("SELECT EXISTS(SELECT 1 FROM octopus_core.dq_receipts WHERE event_id=$1 AND payload_sha256=$2),EXISTS(SELECT 1 FROM octopus_core.dq_receipts WHERE event_id=$1 AND payload_sha256<>$2)",&[&event,&hash]).await.map_err(database)?;
        let duplicate: bool = checks[0].get(0);
        let conflict_event: bool = checks[0].get(1);
        let reason =
            if same.first().is_some_and(|r| r.get::<_, String>(0) != hash) || conflict_event {
                Some("receipt_integrity_conflict".to_owned())
            } else {
                same.first()
                    .and_then(|r| r.get::<_, Option<String>>(1))
                    .or_else(|| quarantine.map(str::to_owned))
            };
        let result = if !same.is_empty() {
            if let Some(why) = &reason {
                self.audit(
                    &mut tx,
                    "broker-consumer",
                    "receipt_conflict",
                    None,
                    json!({"event_id":event,"payload_sha256":hash,"error_code":why}),
                )
                .await?;
            }
            json!({"duplicate":true,"quarantined":reason.is_some()})
        } else {
            tx.execute("INSERT INTO octopus_core.dq_receipts(consumer_group,topic,partition_id,offset_id,event_id,payload_sha256,installation_id,namespace,envelope,quarantine_reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",&[&group,&topic,&partition,&offset,&event,&hash,&self.settings.installation_id,&self.settings.namespace,&envelope,&reason]).await.map_err(database)?;
            let mut applied = false;
            if !duplicate && reason.is_none() {
                if let Some(e) = envelope {
                    let valid = (|| {
                        dq::scoped(&DqPrincipal::internal(), e, &self.settings)?;
                        if dq::int(e, "schema_version")? != 1
                            || dq::text(e, "event_id")? != event
                            || !dq::identifier(dq::text(e, "run_id")?)
                            || chrono::DateTime::parse_from_rfc3339(dq::text(e, "occurred_at")?)
                                .is_err()
                        {
                            return Err(error(400, "invalid_envelope"));
                        }
                        Ok(())
                    })();
                    if valid.is_err() {
                        self.quarantine(
                            &mut tx,
                            group,
                            topic,
                            partition,
                            offset,
                            "invalid_envelope",
                        )
                        .await?;
                    } else if topic == "dq.worker-reports.v1" {
                        // Validation errors are handled before any report mutation.
                        match self.report(&mut tx, e).await {
                            Ok(value) => applied = value,
                            Err(e) if e.status != 503 => {
                                self.quarantine(
                                    &mut tx,
                                    group,
                                    topic,
                                    partition,
                                    offset,
                                    "invalid_or_stale_report",
                                )
                                .await?
                            }
                            Err(e) => return Err(e),
                        }
                    } else {
                        applied = true;
                    }
                }
            }
            if let Some(why) = reason {
                self.quarantine(&mut tx, group, topic, partition, offset, &why)
                    .await?;
            }
            let parked:bool=tx.query("SELECT quarantine_reason IS NOT NULL FROM octopus_core.dq_receipts WHERE consumer_group=$1 AND topic=$2 AND partition_id=$3 AND offset_id=$4",&[&group,&topic,&partition,&offset]).await.map_err(database)?[0].get(0);
            json!({"duplicate":duplicate,"applied":applied,"quarantined":parked})
        };
        tx.commit().await.map_err(database)?;
        Ok(result)
    }
    async fn report(&self, tx: &mut PgTransaction, e: &Value) -> Result<bool> {
        let run = dq::text(e, "run_id")?;
        let attempt = dq::text(e, "attempt_id")?;
        let fence = dq::long(e, "fence")?;
        let kind = dq::text(e, "event_type")?;
        let sequence = dq::long(e, "sequence")?;
        self.lock_run(tx, run).await?;
        let r = self.run_tx(tx, run).await?;
        let valid:bool=tx.query("SELECT EXISTS(SELECT 1 FROM octopus_core.dq_attempts a JOIN octopus_core.dq_runs r ON r.run_id=a.run_id WHERE a.attempt_id=$1 AND a.run_id=$2 AND a.fence=$3 AND r.fence=$3 AND r.current_attempt_id=$1 AND r.status IN ('running','applying') AND r.deadline_at>CURRENT_TIMESTAMP AND a.status IN ('reserved','accepted','running','applying') AND a.lease_expires_at>CURRENT_TIMESTAMP AND a.report_sequence<$4)",&[&attempt,&run,&fence,&sequence]).await.map_err(database)?[0].get(0);
        if !valid
            || !self.current_policy(tx, &r).await?
            || dq::text(e, "processor_id")? != dq::text(&r, "processor_id")?
            || dq::text(e, "processor_version")? != dq::text(&r, "processor_version")?
        {
            return Err(error(409, "stale_report"));
        }
        if !matches!(
            kind,
            "started" | "progress" | "output_ready" | "attempt_failed"
        ) {
            return Err(error(409, "unknown_report"));
        }
        if matches!(kind, "output_ready" | "attempt_failed") && dq::text(&r, "status")? != "running"
        {
            return Err(error(409, "report_after_output"));
        }
        if kind == "output_ready" {
            let refs = dq::field(e, "artifacts")?;
            dq::validate_artifacts(refs, &self.settings, run, Some(attempt), false)?;
            if refs.as_array().is_none_or(|a| a.len() != 1)
                || dq::optional(e, "source_revision_digest")
                    != Some(dq::text(&r, "source_revision_digest")?)
            {
                return Err(error(400, "invalid_output"));
            }
            self.artifacts_tx(tx, run, refs).await?;
            tx.execute("UPDATE octopus_core.dq_runs SET status='applying',output_refs=$2,state_revision=state_revision+1 WHERE run_id=$1 AND status='running'",&[&run,&refs]).await.map_err(database)?;
            tx.execute("UPDATE octopus_core.dq_attempts SET status='applying',report_sequence=$2 WHERE attempt_id=$1",&[&attempt,&sequence]).await.map_err(database)?;
        } else if kind == "attempt_failed" {
            let permanent = dq::optional(e, "error_class") == Some("permanent");
            tx.execute("UPDATE octopus_core.dq_runs SET status=CASE WHEN $2 OR attempt_count>=5 THEN 'failed' ELSE 'retrying' END,error_code='worker_failure',current_attempt_id=NULL,fence=fence+1,state_revision=state_revision+1,completed_at=CASE WHEN $2 OR attempt_count>=5 THEN CURRENT_TIMESTAMP ELSE NULL END,next_attempt_at=CURRENT_TIMESTAMP+(random()*LEAST(60,POWER(2,attempt_count-1)))*INTERVAL '1 second' WHERE run_id=$1 AND status='running'",&[&run,&permanent]).await.map_err(database)?;
            tx.execute("UPDATE octopus_core.dq_attempts SET status='failed',report_sequence=$2,finished_at=CURRENT_TIMESTAMP WHERE attempt_id=$1",&[&attempt,&sequence]).await.map_err(database)?;
            self.terminal_or_retry(tx, run).await?;
        } else {
            tx.execute("UPDATE octopus_core.dq_attempts SET status=CASE WHEN status='applying' THEN status ELSE 'running' END,started_at=COALESCE(started_at,CURRENT_TIMESTAMP),report_sequence=$2 WHERE attempt_id=$1",&[&attempt,&sequence]).await.map_err(database)?;
            self.event(tx, run, kind, "dq.events.v1").await?;
        }
        Ok(true)
    }
}
