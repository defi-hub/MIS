// gRPC Server for dynamic policy management
// Allows runtime policy updates without restart

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{info, warn};

use crate::policy::PolicyEngine;
use crate::kill_manager::KillManager;
use crate::config::GrpcConfig;

// gRPC proto definitions
pub mod proto {
    tonic::include_proto!("mis.policy.v1");
}

use proto::policy_service_server::{PolicyService, PolicyServiceServer};
use proto::*;

pub struct GrpcServer {
    policy_engine: Arc<RwLock<PolicyEngine>>,
    kill_manager: Arc<KillManager>,
    config: GrpcConfig,
}

impl GrpcServer {
    pub fn new(
        policy_engine: Arc<RwLock<PolicyEngine>>,
        kill_manager: Arc<KillManager>,
        config: GrpcConfig,
    ) -> Self {
        Self {
            policy_engine,
            kill_manager,
            config,
        }
    }

    pub async fn serve(self) -> Result<()> {
        let addr = format!("{}:{}", self.config.bind_address, self.config.port)
            .parse()
            .context("Invalid bind address")?;

        let service = PolicyServiceServer::new(PolicyServiceImpl {
            policy_engine: self.policy_engine.clone(),
            kill_manager: self.kill_manager.clone(),
        });

        info!("gRPC server listening on {}", addr);

        if self.config.tls_enabled {
            // TODO: Add TLS support
            warn!("TLS not yet implemented for gRPC");
        }

        Server::builder()
            .add_service(service)
            .serve(addr)
            .await
            .context("gRPC server failed")?;

        Ok(())
    }
}

pub struct PolicyServiceImpl {
    policy_engine: Arc<RwLock<PolicyEngine>>,
    kill_manager: Arc<KillManager>,
}

#[tonic::async_trait]
impl PolicyService for PolicyServiceImpl {
    async fn add_rule(
        &self,
        request: Request<AddRuleRequest>,
    ) -> Result<Response<AddRuleResponse>, Status> {
        let req = request.into_inner();
        
        info!("gRPC: Adding rule for inode {} syscall {}", req.inode, req.syscall_nr);
        
        let mut engine = self.policy_engine.write().await;
        
        let action = match req.action {
            0 => crate::config::Action::Allow,
            1 => crate::config::Action::Deny,
            2 => crate::config::Action::Trace,
            _ => return Err(Status::invalid_argument("Invalid action")),
        };
        
        engine.add_rule(req.inode, req.dev_id, req.syscall_nr, action, req.ttl_secs)
            .map_err(|e| Status::internal(format!("Failed to add rule: {}", e)))?;
        
        Ok(Response::new(AddRuleResponse { success: true }))
    }

    async fn remove_rule(
        &self,
        request: Request<RemoveRuleRequest>,
    ) -> Result<Response<RemoveRuleResponse>, Status> {
        let req = request.into_inner();
        
        info!("gRPC: Removing rule for inode {} syscall {}", req.inode, req.syscall_nr);
        
        let mut engine = self.policy_engine.write().await;
        
        engine.remove_rule(req.inode, req.dev_id, req.syscall_nr)
            .map_err(|e| Status::internal(format!("Failed to remove rule: {}", e)))?;
        
        Ok(Response::new(RemoveRuleResponse { success: true }))
    }

    async fn reload_policy(
        &self,
        _request: Request<ReloadPolicyRequest>,
    ) -> Result<Response<ReloadPolicyResponse>, Status> {
        info!("gRPC: Reloading policy from disk");
        
        let mut engine = self.policy_engine.write().await;
        
        engine.reload_policy()
            .await
            .map_err(|e| Status::internal(format!("Failed to reload policy: {}", e)))?;
        
        Ok(Response::new(ReloadPolicyResponse { success: true }))
    }

    async fn get_stats(
        &self,
        _request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        let engine = self.policy_engine.read().await;
        
        let stats = engine.get_stats()
            .map_err(|e| Status::internal(format!("Failed to get stats: {}", e)))?;
        
        Ok(Response::new(GetStatsResponse {
            cache_hits: stats.cache_hits,
            cache_misses: stats.cache_misses,
            denied: stats.denied,
            allowed: stats.allowed,
            defcon_escalations: stats.defcon_escalations,
            processes_killed: stats.processes_killed,
        }))
    }

    async fn kill_process(
        &self,
        request: Request<KillProcessRequest>,
    ) -> Result<Response<KillProcessResponse>, Status> {
        let req = request.into_inner();
        
        warn!("gRPC: Kill request for cgroup {}", req.cgroup_id);
        
        self.kill_manager.kill_by_cgroup(req.cgroup_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to kill process: {}", e)))?;
        
        Ok(Response::new(KillProcessResponse { success: true }))
    }

    async fn set_learning_mode(
        &self,
        request: Request<SetLearningModeRequest>,
    ) -> Result<Response<SetLearningModeResponse>, Status> {
        let req = request.into_inner();
        
        info!("gRPC: Setting learning mode for cgroup {} to {}", req.cgroup_id, req.enabled);
        
        let mut engine = self.policy_engine.write().await;
        
        engine.set_learning_mode(req.cgroup_id, req.enabled)
            .map_err(|e| Status::internal(format!("Failed to set learning mode: {}", e)))?;
        
        Ok(Response::new(SetLearningModeResponse { success: true }))
    }
}
