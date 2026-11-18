//! In-process telemetry. HTTP reads snapshots; it never samples the database.
use crate::{postgres::{PgError, PgRuntime}, processor::ProcessorId};
use chrono::{DateTime, Utc};
use opentelemetry::{global, trace::TracerProvider};
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::{propagation::TraceContextPropagator, trace::SdkTracerProvider, Resource};
use prometheus::{Encoder, IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};
use serde_json::{json, Value};
use std::{collections::VecDeque, sync::{Arc, Mutex}, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub struct Telemetry { provider: SdkTracerProvider }
impl Telemetry {
    pub fn initialize() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        global::set_text_map_propagator(TraceContextPropagator::new());
        let mut builder = SdkTracerProvider::builder().with_resource(
            Resource::builder().with_service_name("octopus").build());
        if std::env::var("OTEL_SDK_DISABLED").as_deref() != Ok("true")
            && std::env::var("OTEL_TRACES_EXPORTER").as_deref() != Ok("none") {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http().with_protocol(Protocol::HttpBinary).build()?;
            builder = builder.with_batch_exporter(exporter);
        }
        let provider = builder.build();
        let tracer = provider.tracer("com.sslproxy.octopus");
        global::set_tracer_provider(provider.clone());
        tracing_subscriber::registry()
            .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
            .with(tracing_subscriber::fmt::layer().json().with_target(false))
            .with(tracing_opentelemetry::layer().with_tracer(tracer)).try_init()?;
        Ok(Self { provider })
    }
    pub fn shutdown(&self) -> Result<(), opentelemetry_sdk::error::OTelSdkError> {
        self.provider.shutdown_with_timeout(Duration::from_secs(10))
    }
}

#[derive(Default)]
struct Readings {
    started_ms: i64,
    pending: i64,
    pressure: bool,
    state_at: i64,
    processed_at: i64,
    last_success: Option<i64>,
    committed: VecDeque<(i64, u64)>,
    lag: Option<(i64, i64)>,
    peaks: Option<Value>,
}
#[derive(Clone)]
pub struct Metrics {
    registry: Registry,
    committed: IntCounter,
    pending: IntGauge,
    pressure: IntGauge,
    last_success: IntGauge,
    lifecycle: prometheus::IntGaugeVec,
    retries: IntCounterVec,
    readings: Arc<Mutex<Readings>>,
}
impl Metrics {
    pub fn new() -> Result<Self, prometheus::Error> { Self::at(Utc::now().timestamp_millis()) }
    fn at(started_ms: i64) -> Result<Self, prometheus::Error> {
        let registry = Registry::new();
        let committed = IntCounter::new("coordinator_broker_records_committed_total", "Broker records durably handled and successfully committed")?;
        let pending = IntGauge::new("coordinator_pending_ledger_count", "Pending and processing durable ledger entries")?;
        let pressure = IntGauge::new("coordinator_backpressure_active", "One while admission is throttled")?;
        let last_success = IntGauge::new("coordinator_ingest_ledger_last_success_timestamp_seconds", "Last successful ingest time")?;
        let lifecycle = prometheus::IntGaugeVec::new(Opts::new("coordinator_processor_lifecycle", "Processor lifecycle state"), &["processor"])?;
        let retries = IntCounterVec::new(Opts::new("coordinator_processor_retries_total", "Processor retries"), &["processor"])?;
        for collector in [Box::new(committed.clone()) as Box<dyn prometheus::core::Collector>,Box::new(pending.clone()),Box::new(pressure.clone()),Box::new(last_success.clone()),Box::new(lifecycle.clone()),Box::new(retries.clone())] { registry.register(collector)?; }
        Ok(Self { registry, committed, pending, pressure, last_success, lifecycle, retries,
            readings: Arc::new(Mutex::new(Readings { started_ms, ..Readings::default() })) })
    }
    pub fn broker_committed(&self, count: u64) { self.committed_at(count, Utc::now().timestamp_millis()); }
    fn committed_at(&self, count: u64, now: i64) {
        if count == 0 { return; }
        self.committed.inc_by(count);
        let mut r = self.readings.lock().unwrap_or_else(|e| e.into_inner());
        r.processed_at = now;
        while r.committed.front().is_some_and(|(at,_)| now.saturating_sub(*at) >= 300_000) { r.committed.pop_front(); }
        let second = now.div_euclid(1000) * 1000;
        if let Some((at,n)) = r.committed.back_mut().filter(|(at,_)| *at == second) { let _ = at; *n=n.saturating_add(count); }
        else { r.committed.push_back((second,count)); }
    }
    pub fn sample_state(&self, pending: i64, pressure: bool) {
        self.sample_state_at(pending, pressure, Utc::now().timestamp_millis());
    }
    fn sample_state_at(&self, pending: i64, pressure: bool, now: i64) {
        self.pending.set(pending); self.pressure.set(i64::from(pressure));
        let mut r = self.readings.lock().unwrap_or_else(|e| e.into_inner());
        r.pending=pending; r.pressure=pressure; r.state_at=now;
    }
    pub fn ingest_processed(&self, _count: u64) {
        let now = Utc::now(); self.last_success.set(now.timestamp());
        let mut r = self.readings.lock().unwrap_or_else(|e|e.into_inner());
        r.processed_at=now.timestamp_millis(); r.last_success=Some(now.timestamp());
    }
    pub fn broker_lag(&self, count: Option<i64>) {
        self.readings.lock().unwrap_or_else(|e| e.into_inner()).lag = count.filter(|n|*n>=0).map(|n|(n,Utc::now().timestamp_millis()));
    }
    pub fn processor(&self, id: ProcessorId, lifecycle: i64) { self.lifecycle.with_label_values(&[id.as_str()]).set(lifecycle); }
    pub fn retry(&self, id: ProcessorId) { self.retries.with_label_values(&[id.as_str()]).inc(); }
    pub fn live(&self, now: DateTime<Utc>) -> Value {
        let r=self.readings.lock().unwrap_or_else(|e| e.into_inner());
        let ms=now.timestamp_millis();
        let fresh=|at:i64|at>0&&ms>=at&&ms-at<=60_000;
        if ms.saturating_sub(r.started_ms)<300_000||!fresh(r.state_at)||!fresh(r.processed_at)||r.pending<0 { return Value::Null; }
        let rate=r.committed.iter().filter(|(at,_)|*at<=ms&&ms-*at<300_000).map(|(_,n)|*n as f64).sum::<f64>()/300.0;
        json!({"ingestProcessedRatePerSec":rate,"pendingLedgerCount":r.pending,
            "brokerLagCount":r.lag.filter(|(_,at)|fresh(*at)).map(|(n,_)|n),
            "lastIngestSuccessAt":r.last_success.and_then(|s|DateTime::from_timestamp(s,0)).map(iso),
            "backpressureActive":r.pressure})
    }
    pub fn public_snapshot(&self, now: DateTime<Utc>) -> Value {
        let cached=self.readings.lock().unwrap_or_else(|e| e.into_inner()).peaks.clone();
        let mut value=cached.unwrap_or_else(||json!({"peaksComputedAt":null,"peakRecordsDay":null,"peakRecordsDayDate":null,"peakRecordsWeek":null,"peakRecordsWeekStart":null,"peakRecordsWeekEnd":null}));
        value["asOf"]=iso(now).into(); value["liveStrip"]=self.live(now); value
    }
    pub async fn refresh_peaks(&self, runtime:&PgRuntime) -> Result<(),PgError> {
        let mut tx=runtime.begin_worker().await?;
        let day=tx.query("SELECT count(*)::bigint,to_char(date_trunc('day',first_seen_at AT TIME ZONE 'UTC'),'YYYY-MM-DD') AS day FROM ingestion_evidence GROUP BY 2 ORDER BY 1 DESC,day ASC LIMIT 1",&[]).await?;
        let week=tx.query("SELECT count(*)::bigint,to_char(date_trunc('week',first_seen_at AT TIME ZONE 'UTC'),'YYYY-MM-DD') AS week_start,to_char(date_trunc('week',first_seen_at AT TIME ZONE 'UTC')+INTERVAL '6 days','YYYY-MM-DD') FROM ingestion_evidence GROUP BY 2,3 ORDER BY 1 DESC,week_start ASC LIMIT 1",&[]).await?;
        tx.commit().await?;
        self.readings.lock().unwrap_or_else(|e| e.into_inner()).peaks=Some(json!({"peaksComputedAt":iso(Utc::now()),
            "peakRecordsDay":day.first().map(|r|r.get::<_,i64>(0)),"peakRecordsDayDate":day.first().map(|r|r.get::<_,String>(1)),
            "peakRecordsWeek":week.first().map(|r|r.get::<_,i64>(0)),"peakRecordsWeekStart":week.first().map(|r|r.get::<_,String>(1)),"peakRecordsWeekEnd":week.first().map(|r|r.get::<_,String>(2))}));
        Ok(())
    }
    pub async fn peaks_loop(&self, runtime:Arc<PgRuntime>, interval:Duration, stop:CancellationToken) {
        loop {
            tokio::select! {biased;_=stop.cancelled()=>return,result=self.refresh_peaks(&runtime)=>{if result.is_err(){tracing::warn!(event="public_peaks_refresh_failed");}}}
            tokio::select! { _=stop.cancelled()=>return,_=tokio::time::sleep(interval)=>{} }
        }
    }
    pub fn scrape(&self) -> Result<String,prometheus::Error> {
        let mut bytes=Vec::new(); TextEncoder::new().encode(&self.registry.gather(),&mut bytes)?;
        let mut text=String::from_utf8(bytes).map_err(|_|prometheus::Error::Msg("invalid metric encoding".into()))?;
        text.push_str(&format!("# TYPE process_uptime_seconds gauge\nprocess_uptime_seconds {}\n", (Utc::now().timestamp_millis()-self.readings.lock().unwrap_or_else(|e|e.into_inner()).started_ms).max(0) as f64/1000.0));
        if let Ok(status)=std::fs::read_to_string("/proc/self/status") {
            for (field,metric,multiplier) in [("VmRSS:","process_resident_memory_bytes",1024),("Threads:","process_threads",1)] {
                if let Some(value)=status.lines().find_map(|line|line.strip_prefix(field)).and_then(|s|s.split_whitespace().next()).and_then(|s|s.parse::<u64>().ok()).and_then(|n|n.checked_mul(multiplier)) {text.push_str(&format!("# TYPE {metric} gauge\n{metric} {value}\n"));}
            }
        }
        Ok(text)
    }
}
pub fn iso(at:DateTime<Utc>)->String { at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi,true) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn live_readings_require_warmup_recent_samples_and_nonnegative_counts() {
        let metrics=Metrics::at(1_000_000).unwrap(); let now=DateTime::from_timestamp_millis(1_300_000).unwrap();
        assert!(metrics.live(now).is_null()); metrics.sample_state_at(8,true,1_300_000); metrics.committed_at(300,1_300_000);
        assert_eq!(metrics.live(now)["ingestProcessedRatePerSec"],1.0);
        assert_eq!(metrics.live(now)["pendingLedgerCount"],8);
        assert!(metrics.live(now-chrono::Duration::milliseconds(1)).is_null());
        assert!(!metrics.live(now+chrono::Duration::seconds(60)).is_null());
        assert!(metrics.live(now+chrono::Duration::seconds(61)).is_null());
        metrics.sample_state_at(-1,false,1_300_000);assert!(metrics.live(now).is_null());
    }
    #[test]
    fn committed_rate_excludes_stale_and_future_samples_and_bounds_storage() {
        let metrics=Metrics::at(1).unwrap();for i in 1..1000{metrics.committed_at(1, i*1000);}
        assert!(metrics.readings.lock().unwrap().committed.len()<=300);
        metrics.sample_state_at(0,false,999_000);let now=DateTime::from_timestamp_millis(999_000).unwrap();
        assert_eq!(metrics.live(now)["ingestProcessedRatePerSec"],1.0);
        let snapshot=metrics.public_snapshot(now);assert!(snapshot["peaksComputedAt"].is_null());
        assert_eq!(snapshot["asOf"],"1970-01-01T00:16:39Z");
        assert!(metrics.scrape().unwrap().contains("coordinator_broker_records_committed_total 999"));
    }
}
