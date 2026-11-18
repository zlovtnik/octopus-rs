use super::{
    intelligence::{ap_risk, dns_threat},
    queries as q, ProjectionError, ProjectionStore,
};

impl ProjectionStore {
    pub async fn normalize_wireless_frames(&self, limit: i32) -> Result<i32, ProjectionError> {
        if self.wireless.projection_only() {
            return Ok(0);
        }
        let mut tx = self.runtime.begin_worker().await?;
        let mut total = 0;
        for statement in [
            q::NORMALIZE_0,
            q::NORMALIZE_1,
            q::NORMALIZE_2,
            q::NORMALIZE_3,
            q::NORMALIZE_4,
            q::NORMALIZE_5,
            q::NORMALIZE_6,
        ] {
            total += tx.execute(statement, &[&limit.max(1)]).await? as i32;
        }
        tx.commit().await?;
        Ok(total)
    }
    pub async fn project_wireless_inventory(&self, limit: i32) -> Result<i32, ProjectionError> {
        let mut tx = self.runtime.begin_worker().await?;
        let mut total = 0;
        // Selection, additive client counts and marking share a serialization
        // point so competing instances cannot count one input twice.
        tx.query("SELECT pg_advisory_xact_lock(hashtextextended('octopus-inventory-projection',0)) IS NULL",&[]).await?;
        for statement in [q::INVENTORY_0, q::INVENTORY_1, q::INVENTORY_2] {
            total += tx.execute(statement, &[&limit.max(1)]).await? as i32;
        }
        tx.execute(q::INVENTORY_3, &[&limit.max(1)]).await?;
        tx.commit().await?;
        Ok(total)
    }
    pub async fn generate_rf_alerts(&self, limit: i32) -> Result<Vec<String>, ProjectionError> {
        let mut tx = self.runtime.begin_worker().await?;
        let run = uuid::Uuid::new_v4().to_string();
        let rows = tx
            .query(
                q::SHADOW_ALERTS,
                &[
                    &60_i32,
                    &-50_i32,
                    &300_i32,
                    &limit.max(1),
                    &60_i32,
                    &300_i32,
                    &run,
                ],
            )
            .await?;
        let result = rows
            .into_iter()
            .map(|r| r.get::<_, serde_json::Value>(0).to_string())
            .collect();
        tx.commit().await?;
        Ok(result)
    }
    pub async fn project_dns_threats(&self, limit: i32) -> Result<i32, ProjectionError> {
        let mut tx = self.runtime.begin_worker().await?;
        let budget = limit.max(1);
        let mut total = tx
            .execute(q::RESOLVE_STALE_DNS_THREATS_0, &[&budget])
            .await? as i32;
        if total < budget {
            let rows = tx.query(q::DNS_CANDIDATES_0, &[&(budget - total)]).await?;
            for row in rows {
                let v = dns_threat(
                    &row.get::<_, String>(0),
                    row.get(1),
                    row.get(2),
                    row.get(3),
                    row.get(4),
                );
                let explanation=format!("uncalibrated seven-day blocked-observation intensity for {}; not a confirmed threat",v.source_key);
                total += tx
                    .execute(
                        q::PERSIST_DNS_THREAT_0,
                        &[
                            &v.source_key,
                            &v.score,
                            &v.signal_id,
                            &v.severity,
                            &explanation,
                            &v.evidence.to_string(),
                            &v.detected_at,
                            &v.run_id,
                        ],
                    )
                    .await? as i32;
            }
        }
        tx.commit().await?;
        Ok(total)
    }
    pub async fn project_risk(&self, limit: i32) -> Result<i32, ProjectionError> {
        let mut tx = self.runtime.begin_worker().await?;
        let mut total = 0;
        for row in tx.query(q::AP_RISK_CANDIDATES_0, &[&limit.max(1)]).await? {
            let v = ap_risk(
                &row.get::<_, String>(0),
                [row.get(1), row.get(2), row.get(3), row.get(4), row.get(5)],
            )?;
            total += tx
                .execute(
                    q::PERSIST_AP_RISK_0,
                    &[
                        &v.bssid,
                        &v.composite,
                        &v.signal,
                        &v.identity,
                        &v.behavior,
                        &v.evidence.to_string(),
                        &v.run_id,
                    ],
                )
                .await? as i32;
        }
        tx.commit().await?;
        Ok(total)
    }
    pub async fn project_infrastructure_graph(&self, limit: i32) -> Result<i32, ProjectionError> {
        let mut tx = self.runtime.begin_worker().await?;
        let mut total = 0;
        let run = uuid::Uuid::new_v4().to_string();
        let limit = limit.max(1);
        total += tx.execute(q::PROJECT_GRAPH_0, &[&0.98_f64]).await? as i32;
        total += tx.execute(q::PROJECT_GRAPH_1, &[]).await? as i32;
        total += tx.execute(q::PROJECT_GRAPH_2, &[]).await? as i32;
        for statement in [
            q::PROJECT_GRAPH_3,
            q::PROJECT_GRAPH_4,
            q::PROJECT_GRAPH_5,
            q::PROJECT_GRAPH_6,
            q::PROJECT_GRAPH_7,
        ] {
            total += tx.execute(statement, &[&run, &limit]).await? as i32;
        }
        total += tx
            .execute(q::PROJECT_GRAPH_8, &[&run, &0.98_f64, &limit])
            .await? as i32;
        for statement in [q::PROJECT_GRAPH_9, q::PROJECT_GRAPH_10, q::PROJECT_GRAPH_11] {
            total += tx.execute(statement, &[&run, &limit]).await? as i32;
        }
        for statement in [q::PROJECT_GRAPH_12, q::PROJECT_GRAPH_13] {
            total += tx.execute(statement, &[&limit]).await? as i32;
        }
        for statement in [
            q::PROJECT_GRAPH_14,
            q::PROJECT_GRAPH_15,
            q::PROJECT_GRAPH_16,
            q::PROJECT_GRAPH_17,
            q::PROJECT_GRAPH_18,
        ] {
            total += tx.execute(statement, &[]).await? as i32;
        }
        tx.commit().await?;
        Ok(total)
    }
}
