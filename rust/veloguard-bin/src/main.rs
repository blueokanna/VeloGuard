use anyhow::Result;
use veloguard_core::{
    api::create_router,
    connection_pool::ConnectionPool,
    health_check::{HealthChecker, HealthMonitor, HealthCheckConfig},
    traffic_stats::TrafficStatsManager,
    VeloGuard, Config,
};
use clap::Parser;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::Level;

/// VeloGuard - A custom protocol network proxy
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config.yaml")]
    config: String,

    /// Test configuration and exit
    #[arg(short, long)]
    test_config: bool,

    /// Log file path
    #[arg(long)]
    log_file: Option<String>,

    /// API server address
    #[arg(long, default_value = "127.0.0.1:9090")]
    api_addr: String,

    /// Enable API server
    #[arg(long)]
    api: bool,
}

#[cfg(unix)]
async fn wait_for_signal(shutdown_tx: tokio::sync::mpsc::Sender<()>) {
    use futures::StreamExt;
    if let Ok(mut signals) = signal_hook_tokio::Signals::new([
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
    ]) {
        if signals.next().await.is_some() {
            let _ = shutdown_tx.send(()).await;
        }
    }
}

#[cfg(windows)]
async fn wait_for_signal(shutdown_tx: tokio::sync::mpsc::Sender<()>) {
    // On Windows, use tokio's ctrl_c signal
    if tokio::signal::ctrl_c().await.is_ok() {
        let _ = shutdown_tx.send(()).await;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Load configuration
    let config_content = fs::read_to_string(&args.config)?;
    let config: Config = serde_yaml::from_str(&config_content)?;

    // Test config if requested
    if args.test_config {
        println!("Configuration test passed!");
        return Ok(());
    }

    // Create VeloGuard instance
    let veloguard = VeloGuard::new(config).await?;

    // Initialize additional services
    let connection_pool = Arc::new(ConnectionPool::new(Default::default()));
    let health_monitor = Arc::new(HealthMonitor::new(HealthCheckConfig::default()));
    let traffic_stats = Arc::new(TrafficStatsManager::new());

    // Initialize health checker
    let health_checker = HealthChecker::new(Arc::clone(&health_monitor));
    // TODO: Add health checkable proxies to the checker

    // Start health checker in background
    health_checker.start().await?;

    // Start API server if enabled
    let api_handle = if args.api {
        let api_addr: SocketAddr = args.api_addr.parse()?;
        let router = create_router(
            veloguard.proxy_manager(),
            Arc::clone(&health_monitor),
            Arc::clone(&traffic_stats),
        );

        let listener = TcpListener::bind(api_addr).await?;
        println!("API server listening on http://{}", api_addr);

        Some(tokio::spawn(async move {
            axum::serve(listener, router).await
        }))
    } else {
        None
    };

    // Setup signal handling
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel(1);

    tokio::spawn(wait_for_signal(shutdown_tx));

    // Start VeloGuard
    veloguard.start().await?;

    println!("VeloGuard started successfully. Press Ctrl+C to stop.");
    if args.api {
        println!("API server is available at http://{}", args.api_addr);
    }

    // Wait for shutdown signal
    shutdown_rx.recv().await;

    println!("Shutting down VeloGuard...");

    // Stop API server
    if let Some(handle) = api_handle {
        handle.abort();
        println!("API server stopped.");
    }

    // Shutdown additional services
    connection_pool.shutdown().await?;
    health_monitor.clear();

    // Stop VeloGuard
    veloguard.stop().await?;

    println!("VeloGuard stopped.");
    Ok(())
}
