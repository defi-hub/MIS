// MIS Orchestrator v2.1.1 - Production implementation
//
// Architecture:
// 1. TokenService: Ed25519 signing + SHA256 hashing
// 2. BpfInterface: Kernel map operations
// 3. IntentCompiler: YAML → capability bitmasks
// 4. SessionManager: Lifecycle management
// 5. GrpcServer: API endpoint

use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::signal;
use tracing::{info, warn, error};

mod config;
mod token_service;
mod bpf_ops;
mod intent_compiler;
mod session_manager;
mod grpc_server;

use config::Config;
use token_service::TokenService;
use bpf_ops::BpfInterface;
use session_manager::SessionManager;
use grpc_server::GrpcServer;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string())
        )
        .json()
        .init();
    
    info!("MIS Orchestrator v2.1.1 starting...");
    
    // Load configuration
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/mis/config.toml".to_string());
    
    let config = Config::load(Path::new(&config_path))
        .context("Failed to load configuration")?;
    
    info!("Configuration loaded from {}", config_path);
    
    // Initialize TokenService
    let token_service = if config.paths.bpf_object.exists() {
        // Load existing key
        match TokenService::from_key_file(&config.paths.bpf_object) {
            Ok(svc) => {
                info!("Loaded existing signing key");
                Arc::new(svc)
            }
            Err(_) => {
                warn!("Failed to load key, generating new one");
                let svc = TokenService::new();
                Arc::new(svc)
            }
        }
    } else {
        info!("Generating new signing key");
        Arc::new(TokenService::new())
    };
    
    // Initialize BPF interface
    let bpf = Arc::new(RwLock::new(
        BpfInterface::new(&config.paths.bpf_object)
            .context("Failed to load BPF object")?
    ));
    
    info!("BPF enforcer loaded and attached");
    
    // Initialize SessionManager
    let session_manager = Arc::new(
        SessionManager::new(token_service.clone(), bpf.clone())
    );
    
    info!("Session manager initialized");
    
    // Start gRPC server
    let grpc_server = GrpcServer::new(
        session_manager.clone(),
        bpf.clone(),
        config.grpc.clone(),
    );
    
    info!(
        "Starting gRPC server on {}:{}",
        config.grpc.bind_address,
        config.grpc.port
    );
    
    let grpc_handle = tokio::spawn(async move {
        if let Err(e) = grpc_server.serve().await {
            error!("gRPC server error: {}", e);
        }
    });
    
    // Display startup info
    info!("=== MIS Orchestrator Ready ===");
    info!("gRPC API: {}:{}", config.grpc.bind_address, config.grpc.port);
    info!("Built-in intents: RESEARCH, DEPLOY, TEST, ANALYZE");
    info!("Press Ctrl+C to shut down");
    
    // Wait for shutdown signal
    signal::ctrl_c().await.context("Failed to listen for Ctrl+C")?;
    info!("Shutdown signal received, cleaning up...");
    
    // Graceful shutdown
    grpc_handle.abort();
    
    // Terminate all active sessions
    info!("Terminating active sessions...");
    let sessions = session_manager.list_sessions().await;
    for session in sessions {
        if let Err(e) = session_manager.terminate_session(session.session_id).await {
            warn!("Failed to terminate session {}: {}", session.session_id, e);
        }
    }
    
    info!("MIS Orchestrator v2.1.1 stopped");
    Ok(())
}
