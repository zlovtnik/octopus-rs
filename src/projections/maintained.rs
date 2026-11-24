mod graph_sql;
mod inventory_sql;
mod normalization_sql;

use super::{
    identity::AUTOMATIC_MERGE_SIMILARITY,
    intelligence::{ap_risk, dns_threat},
    queries as q, ProjectionError, ProjectionStore,
};

// A radio backfill's frame timestamp can precede its commit. Hold this lock
// through commit so the signal summary reads the backfill and timestamp together.
const LOCK_WIRELESS_RADIO: &str =
    "SELECT pg_advisory_xact_lock(hashtextextended('octopus-wireless-radio',0)) IS NULL";
const LOCK_WIRELESS_INVENTORY: &str =
    "SELECT pg_advisory_xact_lock(hashtextextended('octopus-inventory-projection',0)) IS NULL";

impl ProjectionStore {
    pub async fn normalize_wireless_frames(&self, limit: i32) -> Result<i32, ProjectionError> {
        if self.wireless.projection_only() {
            return Ok(0);
        }
        let mut tx = self.runtime.begin_worker().await?;
        tx.query(LOCK_WIRELESS_RADIO, &[]).await?;
        tx.query(LOCK_WIRELESS_INVENTORY, &[]).await?;
        let limit = limit.max(1);
        let mut total = 0;
        for statement in [
            normalization_sql::INSERT_MISSING_FRAMES,
            normalization_sql::INSERT_MISSING_RADIO_AND_TOUCH_FRAMES,
            normalization_sql::INSERT_MISSING_QOS,
            normalization_sql::INSERT_MISSING_NETWORK,
        ] {
            total += tx.execute(statement, &[&limit]).await? as i32;
        }
        let mut enriched: Vec<String> = Vec::new();
        for statement in [
            normalization_sql::INSERT_MISSING_APP_SIGNALS,
            normalization_sql::INSERT_MISSING_IDENTITY,
        ] {
            let rows = tx.query(statement, &[&limit]).await?;
            total += rows.len() as i32;
            enriched.extend(rows.into_iter().map(|row| row.get::<_, String>(0)));
        }
        total += tx
            .execute(normalization_sql::INSERT_MISSING_SECURITY, &[&limit])
            .await? as i32;
        if !enriched.is_empty() {
            let previously_claimed: Vec<String> = tx
                .query(
                    inventory_sql::SELECT_ENRICHED_INVENTORY_INPUTS,
                    &[&enriched],
                )
                .await?
                .into_iter()
                .map(|row| row.get(0))
                .collect();
            // A direct frame may already have contributed its probe count.
            if !previously_claimed.is_empty() {
                tx.execute(
                    inventory_sql::UPSERT_OBSERVED_DEVICES,
                    &[&previously_claimed],
                )
                .await?;
            }
        }
        tx.commit().await?;
        Ok(total)
    }
    pub async fn project_wireless_inventory(&self, limit: i32) -> Result<i32, ProjectionError> {
        let mut tx = self.runtime.begin_worker().await?;
        // Serialize inventory writers through commit. The marker also claims the
        // exact inputs before either upsert and rolls back with their writes.
        tx.query(LOCK_WIRELESS_INVENTORY, &[]).await?;
        let limit = limit.max(1);
        let claimed: Vec<String> = tx
            .query(inventory_sql::CLAIM_INVENTORY_INPUTS, &[&limit])
            .await?
            .into_iter()
            .map(|row| row.get(0))
            .collect();
        let mut total = 0;
        if !claimed.is_empty() {
            for statement in [
                inventory_sql::UPSERT_OBSERVED_DEVICES,
                inventory_sql::UPSERT_WIRELESS_CLIENTS,
            ] {
                total += tx.execute(statement, &[&claimed]).await? as i32;
            }
        }
        total += tx
            .execute(inventory_sql::UPSERT_SEARCH_DEVICES, &[&limit, &claimed])
            .await? as i32;
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
        let mut total = tx.execute(q::RESOLVE_STALE_DNS_THREATS, &[&budget]).await? as i32;
        if total < budget {
            let rows = tx
                .query(q::SELECT_DNS_THREAT_CANDIDATES, &[&(budget - total)])
                .await?;
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
                        q::UPSERT_DNS_THREAT,
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
        for row in tx
            .query(q::SELECT_ACCESS_POINT_RISK_CANDIDATES, &[&limit.max(1)])
            .await?
        {
            let v = ap_risk(
                &row.get::<_, String>(0),
                [row.get(1), row.get(2), row.get(3), row.get(4), row.get(5)],
            )?;
            total += tx
                .execute(
                    q::UPSERT_ACCESS_POINT_RISK,
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
        tx.query(graph_sql::LOCK_GRAPH_CURSORS, &[]).await?;
        let mut total = 0;
        let run = uuid::Uuid::new_v4().to_string();
        let limit = limit.max(1);
        total += tx
            .execute(graph_sql::DELETE_STALE_IDENTITY_MEMBER_EDGES, &[])
            .await? as i32;
        total += tx
            .execute(graph_sql::DELETE_STALE_OBSERVATION_EDGES, &[])
            .await? as i32;
        total += tx
            .execute(graph_sql::DELETE_STALE_IDENTITY_CLUSTER_EDGES, &[])
            .await? as i32;
        total += tx
            .execute(graph_sql::DELETE_STALE_IDENTITY_CLUSTER_NODES, &[])
            .await? as i32;
        for statement in [
            graph_sql::UPSERT_DEVICE_NODES,
            graph_sql::UPSERT_ACCESS_POINT_NODES,
            graph_sql::UPSERT_IDENTITY_CLUSTER_NODES,
            graph_sql::UPSERT_OBSERVATION_EDGES,
            graph_sql::UPSERT_IDENTITY_MEMBER_EDGES,
        ] {
            total += tx.execute(statement, &[&run, &limit]).await? as i32;
        }
        total += tx
            .execute(
                graph_sql::UPSERT_SAME_DEVICE_EDGES,
                &[&run, &AUTOMATIC_MERGE_SIMILARITY, &limit],
            )
            .await? as i32;
        for statement in [
            graph_sql::UPSERT_ROAMING_EDGES,
            graph_sql::UPSERT_SAME_CHANNEL_EDGES,
            graph_sql::UPSERT_VENDOR_LINK_EDGES,
        ] {
            total += tx.execute(statement, &[&run, &limit]).await? as i32;
        }
        total += tx
            .execute(graph_sql::UPSERT_ACCESS_POINT_CATALOG, &[&limit])
            .await? as i32;
        tx.query(LOCK_WIRELESS_RADIO, &[]).await?;
        total += tx
            .execute(graph_sql::UPSERT_WIRELESS_SIGNAL_SUMMARIES, &[&limit])
            .await? as i32;
        for statement in [
            graph_sql::DELETE_STALE_SIGNAL_SUMMARIES,
            graph_sql::DELETE_STALE_ACCESS_POINT_CATALOG,
            graph_sql::UPSERT_WIRELESS_EVIDENCE_WATERMARK,
            graph_sql::DELETE_ORPHANED_EDGES,
        ] {
            total += tx.execute(statement, &[]).await? as i32;
        }
        let counts = tx
            .query(
                &graph_sql::upsert_graph_projection_watermark(),
                &[&AUTOMATIC_MERGE_SIMILARITY],
            )
            .await?;
        total += counts[0].get::<_, i64>(0) as i32;
        tx.commit().await?;
        Ok(total)
    }
}
