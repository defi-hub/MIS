// Session Manager - Lifecycle management for AI agent sessions

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::token_service::{TokenService, CapabilityToken, SessionMetadata};
use crate::bpf_ops::BpfInterface;
use crate::intent_compiler::{IntentCompiler, CompiledIntent};

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionState {
    Active = 0,
    Suspended = 1,
    Terminated = 2,
}

/// Session Manager
pub struct SessionManager {
    token_service: Arc<TokenService>,
    bpf: Arc<RwLock<BpfInterface>>,
    sessions: Arc<RwLock<HashMap<u64, Session>>>,
    next_session_id: Arc<RwLock<u64>>,
}

/// Session information
#[derive(Debug, Clone)]
pub struct Session {
    pub session_id: u64,
    pub cgroup_id: u64,
    pub agent_pid: u32,
    pub intent_name: String,
    pub capabilities: u64,
    pub state: SessionState,
    pub created_at: u64,
    pub token: CapabilityToken,
}

impl SessionManager {
    pub fn new(
        token_service: Arc<TokenService>,
        bpf: Arc<RwLock<BpfInterface>>,
    ) -> Self {
        Self {
            token_service,
            bpf,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            next_session_id: Arc::new(RwLock::new(1)),
        }
    }
    
    /// Create new session with intent
    pub async fn create_session(
        &self,
        intent_name: &str,
        agent_pid: u32,
        cgroup_id: u64,
        ttl_secs: u64,
    ) -> Result<Session> {
        info!("Creating session for intent: {}", intent_name);
        
        // Compile intent
        let compiled = IntentCompiler::load_builtin(intent_name)
            .or_else(|_| {
                // Try loading from file
                let path = format!("/etc/mis/intents/{}.yaml", intent_name);
                IntentCompiler::compile_file(std::path::Path::new(&path))
            })
            .context("Failed to compile intent")?;
        
        // Generate session ID
        let session_id = {
            let mut next = self.next_session_id.write().await;
            let id = *next;
            *next += 1;
            id
        };
        
        // Issue token
        let token = self.token_service.issue_token(
            session_id,
            compiled.capabilities,
            ttl_secs,
        )?;
        
        // Create session metadata
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos() as u64;
        
        let mut intent_bytes = [0u8; 64];
        let intent_str = intent_name.as_bytes();
        let copy_len = intent_str.len().min(64);
        intent_bytes[..copy_len].copy_from_slice(&intent_str[..copy_len]);
        
        let metadata = SessionMetadata {
            session_id,
            cgroup_id,
            capabilities: compiled.capabilities,
            last_access_ns: now,
            created_at: now,
            agent_pid,
            violation_count: 0,
            state: SessionState::Active as u8,
            defcon_level: 5,
            intent: intent_bytes,
            padding: [0u8; 40],
        };
        
        // Store in BPF
        let mut bpf = self.bpf.write().await;
        bpf.store_token(session_id, &token)?;
        bpf.store_session(&metadata)?;
        
        // Store locally
        let session = Session {
            session_id,
            cgroup_id,
            agent_pid,
            intent_name: intent_name.to_string(),
            capabilities: compiled.capabilities,
            state: SessionState::Active,
            created_at: now,
            token,
        };
        
        self.sessions.write().await.insert(session_id, session.clone());
        
        info!(
            "Session created: id={} intent={} caps={:#x}",
            session_id, intent_name, compiled.capabilities
        );
        
        Ok(session)
    }
    
    /// Suspend session
    pub async fn suspend_session(&self, session_id: u64) -> Result<()> {
        info!("Suspending session {}", session_id);
        
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(&session_id)
            .context("Session not found")?;
        
        session.state = SessionState::Suspended;
        
        // Update BPF metadata
        let mut bpf = self.bpf.write().await;
        if let Some(mut metadata) = bpf.get_session(session_id)? {
            metadata.state = SessionState::Suspended as u8;
            bpf.store_session(&metadata)?;
        }
        
        Ok(())
    }
    
    /// Resume session
    pub async fn resume_session(&self, session_id: u64) -> Result<()> {
        info!("Resuming session {}", session_id);
        
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(&session_id)
            .context("Session not found")?;
        
        session.state = SessionState::Active;
        
        // Update BPF metadata
        let mut bpf = self.bpf.write().await;
        if let Some(mut metadata) = bpf.get_session(session_id)? {
            metadata.state = SessionState::Active as u8;
            bpf.store_session(&metadata)?;
        }
        
        Ok(())
    }
    
    /// Terminate session
    pub async fn terminate_session(&self, session_id: u64) -> Result<()> {
        info!("Terminating session {}", session_id);
        
        // Remove from local storage
        let mut sessions = self.sessions.write().await;
        sessions.remove(&session_id);
        
        // Remove from BPF
        let mut bpf = self.bpf.write().await;
        bpf.revoke_token(session_id)?;
        bpf.remove_session(session_id)?;
        
        Ok(())
    }
    
    /// Get session info
    pub async fn get_session(&self, session_id: u64) -> Result<Session> {
        let sessions = self.sessions.read().await;
        sessions.get(&session_id)
            .cloned()
            .context("Session not found")
    }
    
    /// List all active sessions
    pub async fn list_sessions(&self) -> Vec<Session> {
        let sessions = self.sessions.read().await;
        sessions.values().cloned().collect()
    }
    
    /// Refresh token (extend TTL)
    pub async fn refresh_token(
        &self,
        session_id: u64,
        ttl_secs: u64,
    ) -> Result<()> {
        info!("Refreshing token for session {}", session_id);
        
        let sessions = self.sessions.read().await;
        let session = sessions.get(&session_id)
            .context("Session not found")?;
        
        // Issue new token
        let token = self.token_service.issue_token(
            session_id,
            session.capabilities,
            ttl_secs,
        )?;
        
        // Update BPF
        let mut bpf = self.bpf.write().await;
        bpf.store_token(session_id, &token)?;
        
        Ok(())
    }
    
    /// Get session statistics
    pub async fn get_session_stats(&self, session_id: u64) -> Result<SessionStats> {
        let bpf = self.bpf.read().await;
        
        let metadata = bpf.get_session(session_id)?
            .context("Session not found")?;
        
        Ok(SessionStats {
            session_id,
            violation_count: metadata.violation_count,
            defcon_level: metadata.defcon_level,
            state: match metadata.state {
                0 => SessionState::Active,
                1 => SessionState::Suspended,
                _ => SessionState::Terminated,
            },
        })
    }
}

#[derive(Debug, Clone)]
pub struct SessionStats {
    pub session_id: u64,
    pub violation_count: u16,
    pub defcon_level: u8,
    pub state: SessionState,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_session_lifecycle() {
        // Mock test - requires actual BPF setup
        // In production: use integration tests with loaded eBPF
    }
}
