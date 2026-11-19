mod application;

use octopus::{config::AppConfig, observability::Telemetry};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Octopus: {}", octopus::errors::message(error.as_ref()));
            ExitCode::FAILURE
        }
    }
}

async fn run() -> application::Result {
    let config = AppConfig::load_args(std::env::args().skip(1))?;
    if !config.postgres.enabled {
        println!("PostgreSQL sink disabled (set POSTGRES_ENABLED=true to enable)");
        return Ok(());
    }
    let telemetry = Telemetry::initialize()?;
    let result = application::run(config).await;
    let shutdown = telemetry.shutdown();
    result?;
    shutdown?;
    Ok(())
}
