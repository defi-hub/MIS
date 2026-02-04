// gRPC Server - Complete implementation with session management

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{info, warn};

use crate::session_manager::{SessionManager, SessionState};
use crate::bpf_ops::BpfInterface;
use crate::config::GrpcConfig;

// Proto definitions
pub mod proto {
    tonic::include_proto!("mis.orchestrator.v1");
}

use proto::orchestrator_service_server::{
    OrchestrationService, OrchestrationServiceServer
};
use proto::*;

pub struct GrpcServer {
    session_manager: Arc<SessionManager>,
    bpf: Arc<RwLock<BpfInterface>>,
    config: GrpcConfig,
}

impl GrpcServer {
    pub fn new(
        session_manager: Arc<SessionManager>,
        bpf: Arc<RwLock<BpfInterface>>,
        config: GrpcConfig,
    ) -> Self {
        Self {
            session_manager,
            bpf,
            config,
        }
    }
    
    pub async fn serve(self) -> Result<()> {
        let addr = format!("{}:{}", self.config.bind_address, self.config.port)
            .parse()
            .context("Invalid bind address")?;
        
        let service = OrchestrationServiceServer::new(OrchestrationServiceImpl {
            session_manager: self.session_manager.clone(),
            bpf: self.bpf.clone(),
        });
        
        info!("gRPC server listening on {}", addr);
        
        Server::builder()
            .add_service(service)
            .serve(addr)
            .await
            .context("gRPC server failed")?;
        
        Ok(())
    }
}

pub struct OrchestrationServiceImpl {
    session_manager: Arc<SessionManager>,
    bpf: Arc<RwLock<BpfInterface>>,
}

#[tonic::async_trait]
impl OrchestrationService for OrchestrationServiceImpl {
    async fn create_session(
        &self,
        request: Request<CreateSessionRequest>,
    ) -> Result<Response<CreateSessionResponse>, Status> {
        let req = request.into_inner();
        
        info!(
            "gRPC: Creating session for intent={} pid={}",
            req.intent_name, req.agent_pid
        );
        
        let session = self.session_manager.create_session(
            &req.intent_name,
            req.agent_pid,
            req.cgroup_id,
            req.ttl_secs.unwrap_or(3600),
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to create session: {}", e)))?;
        
        Ok(Response::new(CreateSessionResponse {
            session_id: session.session_id,
            capabilities: session.capabilities,
            expires_at: session.token.expires_at,
        }))
    }
    
    async fn suspend_session(
        &self,
        request: Request<SuspendSessionRequest>,
    ) -> Result<Response<SuspendSessionResponse>, Status> {
        let req = request.into_inner();
        
        info!("gRPC: Suspending session {}", req.session_id);
        
        self.session_manager.suspend_session(req.session_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to suspend: {}", e)))?;
        
        Ok(Response::new(SuspendSessionResponse { success: true }))
    }
    
    async fn resume_session(
        &self,
        request: Request<ResumeSessionRequest>,
    ) -> Result<Response<ResumeSessionResponse>, Status> {
        let req = request.into_inner();
        
        info!("gRPC: Resuming session {}", req.session_id);
        
        self.session_manager.resume_session(req.session_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to resume: {}", e)))?;
        
        Ok(Response::new(ResumeSessionResponse { success: true }))
    }
    
    async fn terminate_session(
        &self,
        request: Request<TerminateSessionRequest>,
    ) -> Result<Response<TerminateSessionResponse>, Status> {
        let req = request.into_inner();
        
        info!("gRPC: Terminating session {}", req.session_id);
        
        self.session_manager.terminate_session(req.session_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to terminate: {}", e)))?;
        
        Ok(Response::new(TerminateSessionResponse { success: true }))
    }
    
    async fn get_session(
        &self,
        request: Request<GetSessionRequest>,
    ) -> Result<Response<GetSessionResponse>, Status> {
        let req = request.into_inner();
        
        let session = self.session_manager.get_session(req.session_id)
            .await
            .map_err(|e| Status::not_found(format!("Session not found: {}", e)))?;
        
        let stats = self.session_manager.get_session_stats(req.session_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get stats: {}", e)))?;
        
        Ok(Response::new(GetSessionResponse {
            session_id: session.session_id,
            agent_pid: session.agent_pid,
            intent_name: session.intent_name,
            capabilities: session.capabilities,
            state: match session.state {
                SessionState::Active => 0,
                SessionState::Suspended => 1,
                SessionState::Terminated => 2,
            },
            violation_count: stats.violation_count as u32,
            defcon_level: stats.defcon_level as u32,
        }))
    }
    
    async fn list_sessions(
        &self,
        _request: Request<ListSessionsRequest>,
    ) -> Result<Response<ListSessionsResponse>, Status> {
        let sessions = self.session_manager.list_sessions().await;
        
        let session_infos = sessions.into_iter().map(|s| SessionInfo {
            session_id: s.session_id,
            agent_pid: s.agent_pid,
            intent_name: s.intent_name,
            state: match s.state {
                SessionState::Active => 0,
                SessionState::Suspended => 1,
                SessionState::Terminated => 2,
            },
        }).collect();
        
        Ok(Response::new(ListSessionsResponse {
            sessions: session_infos,
        }))
    }
    
    async fn refresh_token(
        &self,
        request: Request<RefreshTokenRequest>,
    ) -> Result<Response<RefreshTokenResponse>, Status> {
        let req = request.into_inner();
        
        info!("gRPC: Refreshing token for session {}", req.session_id);
        
        self.session_manager.refresh_token(
            req.session_id,
            req.ttl_secs.unwrap_or(3600),
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to refresh: {}", e)))?;
        
        Ok(Response::new(RefreshTokenResponse { success: true }))
    }
    
    async fn get_stats(
        &self,
        _request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        let bpf = self.bpf.read().await;
        
        let stats = bpf.get_stats()
            .map_err(|e| Status::internal(format!("Failed to get stats: {}", e)))?;
        
        Ok(Response::new(GetStatsResponse {
            token_validated: stats.token_validated,
            token_expired: stats.token_expired,
            allowed: stats.allowed,
            denied: stats.denied,
            total_decisions: stats.total_decisions(),
        }))
    }
}
