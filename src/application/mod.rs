mod workloads;

use octopus::{
    config::AppConfig,
    dq_runtime::{DqArtifacts, DqRuntime, DqStore},
    http::{DqHttp, HealthChecks, HttpState},
    observability::Metrics,
    postgres::PgRuntime,
    processor::{select_workloads, selected_processors, ProcessorId},
    runtime::{self, Backpressure},
    supervision::Supervisor,
};
use std::{error::Error, sync::Arc, time::Duration};
use tokio::{net::TcpListener, task::JoinSet};
use tokio_util::sync::CancellationToken;

pub type Result<T = ()> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

pub async fn run(config: AppConfig) -> Result {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let signal = async move {
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = term.recv() => Ok(()),
        }
    };
    tokio::pin!(signal);
    let stop = CancellationToken::new();
    let mut tasks = JoinSet::new();

    let started = tokio::select! {
        result = &mut signal => return Ok(result?),
        result = start(config, stop.clone(), &mut tasks) => result,
    };
    started?;
    let result = tokio::select! {
        result = &mut signal => result.map_err(Into::into),
        task = tasks.join_next() => match task {
            Some(Ok(Err(error))) => Err(error),
            Some(Err(error)) => Err(error.into()),
            _ => Err("coordinator task exited unexpectedly".into()),
        },
    };
    stop.cancel();
    let drain = async {
        let mut failure = None;
        while let Some(task) = tasks.join_next().await {
            let result = task.map_err(Into::into).and_then(|result| result);
            if let Err(error) = result {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    };
    let shutdown = tokio::time::timeout(Duration::from_secs(30), drain).await;
    if shutdown.is_err() {
        tasks.shutdown().await;
    }
    result?;
    shutdown??;
    Ok(())
}

async fn start(config: AppConfig, stop: CancellationToken, tasks: &mut JoinSet<Result>) -> Result {
    let enabled = selected_processors(&config.processors.enabled, config.runtime.consumers_enabled)?;
    workloads::validate(&enabled)?;
    let db = Arc::new(PgRuntime::connect(&config.postgres).await?);
    let metrics = Metrics::new()?;
    let backpressure = Backpressure::new(
        db.clone(),
        config.cron.ingest_batch_size,
        config.backpressure.budget_multiplier,
    )?;
    let workloads = workloads::build(&config, &enabled, db.clone(), backpressure.clone(), &metrics)?;
    let ids: Vec<_> = workloads.iter().map(|workload| workload.id).collect();
    select_workloads(&enabled, &ids)?;
    let has_backpressure = enabled.contains(&ProcessorId::SyncJobPlanner);
    let supervisor = Supervisor::create(config.processors.clone(), enabled, db.clone()).await?;

    // Reconcile the durable DQ scope policy before any legacy writes are allowed.
    let dq_store = DqStore::new(db.clone(), config.dq.settings());
    dq_store.reconcile_policies().await?;
    let dq = if config.dq.enabled {
        let artifacts = DqArtifacts::new(config.dq.clone(), &config.archive)?;
        let runtime = DqRuntime::new(
            dq_store.clone(),
            config.dq.clone(),
            config.kafka.clone(),
            artifacts.clone(),
            config.processors.behavior_similarity_threshold,
        )?;
        runtime.initialize().await?;
        Some((runtime, artifacts))
    } else {
        None
    };

    octopus::dispatch::DispatchStore::new(db.clone())
        .ensure_cursors(&config.ingest.stream_names)
        .await?;
    let listener = TcpListener::bind(([0, 0, 0, 0], config.http.port as u16)).await?;
    let health = HealthChecks {
        database: {
            let db = db.clone();
            Arc::new(move || {
                let db = db.clone();
                Box::pin(async move { db.health_check().await })
            })
        },
        processors: {
            let supervisor = supervisor.clone();
            Arc::new(move || {
                let ready = supervisor.ready();
                Box::pin(async move { ready })
            })
        },
        dq: {
            let dq = dq.as_ref().map(|(runtime, _)| runtime.clone());
            Arc::new(move || {
                let ready = dq.as_ref().is_none_or(DqRuntime::ready);
                Box::pin(async move { ready })
            })
        },
        timeout: Duration::from_millis(config.postgres.connection_timeout_ms as u64),
    };
    let routes = octopus::http::router(HttpState {
        health,
        metrics: metrics.clone(),
        public_stats: config.public_stats.clone(),
        dq: dq.as_ref().map(|(_, artifacts)| DqHttp {
            store: dq_store.clone(),
            artifacts: artifacts.clone(),
            control_token: config.dq.control_token.clone(),
        }),
    });
    let shutdown = stop.clone();
    tasks.spawn(async move {
        axum::serve(listener, routes)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await?;
        Ok(())
    });

    let shutdown = stop.clone();
    tasks.spawn(async move {
        supervisor.run(workloads, shutdown).await?;
        Ok(())
    });
    if config.runtime.any_enabled() {
        let db = db.clone();
        let shutdown = stop.clone();
        tasks.spawn(async move {
            runtime::schema_refresher(
                db,
                config.postgres.manifest_sha256,
                Duration::from_secs(config.cron.schema_refresh_interval_seconds as u64),
                Duration::from_secs(config.cron.scan_retry_backoff_seconds as u64),
                shutdown,
            )
            .await?;
            Ok(())
        });
    }
    if has_backpressure {
        let metrics = metrics.clone();
        let shutdown = stop.clone();
        tasks.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(config.cron.idle_sleep_ms as u64));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! { biased; _ = shutdown.cancelled() => return Ok(()), _ = interval.tick() => {} }
                let result = tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => return Ok(()),
                    result = backpressure.check_and_act() => result,
                };
                match result {
                    Ok(pending) => metrics.sample_state(pending, backpressure.suspended()),
                    Err(error) => tracing::warn!(error = %octopus::errors::message(&error), "backpressure sampling failed"),
                }
            }
        });
    }
    if config.public_stats.enabled {
        let shutdown = stop.clone();
        tasks.spawn(async move {
            metrics
                .peaks_loop(
                    db,
                    Duration::from_secs(config.public_stats.peaks_refresh_seconds as u64),
                    shutdown,
                )
                .await;
            Ok(())
        });
    }
    if let Some((dq, artifacts)) = dq {
        let shutdown = stop.clone();
        tasks.spawn(async move {
            dq.run(shutdown).await?;
            Ok(())
        });
        tasks.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! { biased; _ = stop.cancelled() => return Ok(()), _ = interval.tick() => {} }
                let result = tokio::select! {
                    biased;
                    _ = stop.cancelled() => return Ok(()),
                    result = dq_store.collect_retention(&artifacts, &config.dq) => result,
                };
                if let Err(error) = result {
                    tracing::warn!(error_code = %error.code, "DQ retention retry");
                }
            }
        });
    }
    tracing::info!(port = config.http.port, "Octopus started");
    Ok(())
}
