// MIS Policy Engine v2.0 - Main entry point
// New features:
// - gRPC server (Tonic) for dynamic policy management
// - Async Kill on anomaly detection in learning mode
// - DEFCON event monitoring and response
// - Cgroup-based process tracking

use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::signal;
use tracing::{info, warn, error};

mod config;
mod policy;
mod grpc_server;
mod kill_manager;
mod defcon_monitor;
mod learning;

use config::Config;
use policy::PolicyEngine;
use grpc_server::GrpcServer;
use kill_manager::KillManager;
use defcon_monitor::DefconMonitor;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .json()
        .init();

    info!("MIS Policy Engine v2.0.0 starting...");

    // Load configuration
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/mis/config.toml".to_string());
    
    let config = Config::load(Path::new(&config_path))
        .context("Failed to load configuration")?;
    
    info!("Configuration loaded from {}", config_path);

    // Initialize policy engine
    let policy_engine = Arc::new(RwLock::new(
        PolicyEngine::new(&config).await
            .context("Failed to initialize policy engine")?
    ));

    info!("Policy engine initialized");

    // Initialize Kill Manager (for DEFCON 1 and anomaly kills)
    let kill_manager = Arc::new(
        KillManager::new(policy_engine.clone())
            .context("Failed to initialize kill manager")?
    );

    info!("Kill manager initialized");

    // Initialize DEFCON Monitor
    let defcon_monitor = Arc::new(RwLock::new(
        DefconMonitor::new(policy_engine.clone(), kill_manager.clone())
            .context("Failed to initialize DEFCON monitor")?
    ));

    info!("DEFCON monitor initialized");

    // Start gRPC server if enabled
    let grpc_handle = if config.grpc.enabled {
        info!("Starting gRPC server on {}:{}", config.grpc.bind_address, config.grpc.port);
        
        let grpc_server = GrpcServer::new(
            policy_engine.clone(),
            kill_manager.clone(),
            config.grpc.clone(),
        );
        
        Some(tokio::spawn(async move {
            if let Err(e) = grpc_server.serve().await {
                error!("gRPC server error: {}", e);
            }
        }))
    } else {
        info!("gRPC server disabled");
        None
    };

    // Start event processing loop
    let engine_handle = {
        let engine = policy_engine.clone();
        tokio::spawn(async move {
            if let Err(e) = engine.write().await.run_event_loop().await {
                error!("Event loop error: {}", e);
            }
        })
    };

    // Start DEFCON monitor
    let defcon_handle = {
        let monitor = defcon_monitor.clone();
        tokio::spawn(async move {
            if let Err(e) = monitor.write().await.run().await {
                error!("DEFCON monitor error: {}", e);
            }
        })
    };

    // Start kill manager worker
    let kill_handle = {
        let km = kill_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = km.run_worker().await {
                error!("Kill manager error: {}", e);
            }
        })
    };

    info!("All services started. Press Ctrl+C to shut down.");

    // Wait for shutdown signal
    signal::ctrl_c().await.context("Failed to listen for Ctrl+C")?;
    info!("Shutdown signal received, cleaning up...");

    // Graceful shutdown
    engine_handle.abort();
    defcon_handle.abort();
    kill_handle.abort();
    
    if let Some(h) = grpc_handle {
        h.abort();
    }

    info!("MIS Policy Engine v2.0.0 stopped");
    Ok(())
}
