// BPF Operations - Interact with kernel eBPF maps

use anyhow::{Context, Result};
use libbpf_rs::{Map, MapFlags, Object, ObjectBuilder};
use std::path::Path;
use tracing::{info, warn};

use crate::token_service::{CapabilityToken, SessionMetadata};

/// BPF Interface - manages all kernel map interactions
pub struct BpfInterface {
    obj: Object,
    capability_tokens: Map,
    sessions: Map,
    stats: Map,
}

impl BpfInterface {
    /// Load BPF object and get map references
    pub fn new(bpf_object_path: &Path) -> Result<Self> {
        info!("Loading BPF object from {:?}", bpf_object_path);
        
        let obj = ObjectBuilder::default()
            .open_file(bpf_object_path)
            .context("Failed to open BPF object")?
            .load()
            .context("Failed to load BPF object")?;
        
        // Get map references
        let capability_tokens = obj.map("capability_tokens")
            .context("capability_tokens map not found")?
            .clone();
        
        let sessions = obj.map("sessions")
            .context("sessions map not found")?
            .clone();
        
        let stats = obj.map("stats")
            .context("stats map not found")?
            .clone();
        
        info!("BPF maps loaded successfully");
        
        Ok(Self {
            obj,
            capability_tokens,
            sessions,
            stats,
        })
    }
    
    /// Store capability token in kernel
    pub fn store_token(
        &mut self,
        session_id: u64,
        token: &CapabilityToken,
    ) -> Result<()> {
        let key = session_id.to_le_bytes();
        let value = token.as_bytes();
        
        self.capability_tokens.update(&key, value, MapFlags::ANY)
            .context("Failed to update capability_tokens map")?;
        
        info!("Token stored for session {}", session_id);
        Ok(())
    }
    
    /// Remove token from kernel
    pub fn revoke_token(&mut self, session_id: u64) -> Result<()> {
        let key = session_id.to_le_bytes();
        
        self.capability_tokens.delete(&key)
            .context("Failed to delete token")?;
        
        info!("Token revoked for session {}", session_id);
        Ok(())
    }
    
    /// Get token from kernel (for verification)
    pub fn get_token(&self, session_id: u64) -> Result<Option<CapabilityToken>> {
        let key = session_id.to_le_bytes();
        
        match self.capability_tokens.lookup(&key, MapFlags::empty())? {
            Some(bytes) => {
                if bytes.len() != std::mem::size_of::<CapabilityToken>() {
                    return Ok(None);
                }
                
                let token = unsafe {
                    std::ptr::read(bytes.as_ptr() as *const CapabilityToken)
                };
                
                Ok(Some(token))
            }
            None => Ok(None),
        }
    }
    
    /// Store session metadata
    pub fn store_session(
        &mut self,
        session: &SessionMetadata,
    ) -> Result<()> {
        let key = session.session_id.to_le_bytes();
        let value = session.as_bytes();
        
        self.sessions.update(&key, value, MapFlags::ANY)
            .context("Failed to update sessions map")?;
        
        info!("Session metadata stored for {}", session.session_id);
        Ok(())
    }
    
    /// Remove session metadata
    pub fn remove_session(&mut self, session_id: u64) -> Result<()> {
        let key = session_id.to_le_bytes();
        
        self.sessions.delete(&key)
            .context("Failed to delete session")?;
        
        info!("Session removed: {}", session_id);
        Ok(())
    }
    
    /// Get session metadata
    pub fn get_session(&self, session_id: u64) -> Result<Option<SessionMetadata>> {
        let key = session_id.to_le_bytes();
        
        match self.sessions.lookup(&key, MapFlags::empty())? {
            Some(bytes) => {
                if bytes.len() != std::mem::size_of::<SessionMetadata>() {
                    return Ok(None);
                }
                
                let session = unsafe {
                    std::ptr::read(bytes.as_ptr() as *const SessionMetadata)
                };
                
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }
    
    /// Get statistics from kernel
    pub fn get_stats(&self) -> Result<BpfStats> {
        let mut stats = BpfStats::default();
        
        // Stats are per-CPU, need to aggregate
        for cpu in 0..num_cpus::get() {
            let key = 0u32.to_le_bytes();  // STAT_TOKEN_VALIDATED
            if let Some(bytes) = self.stats.lookup_percpu(&key, MapFlags::empty())? {
                if let Some(cpu_data) = bytes.get(cpu) {
                    if cpu_data.len() >= 8 {
                        stats.token_validated += u64::from_le_bytes(
                            cpu_data[..8].try_into().unwrap()
                        );
                    }
                }
            }
            
            // Repeat for other stats...
            // STAT_TOKEN_EXPIRED = 1
            let key = 1u32.to_le_bytes();
            if let Some(bytes) = self.stats.lookup_percpu(&key, MapFlags::empty())? {
                if let Some(cpu_data) = bytes.get(cpu) {
                    if cpu_data.len() >= 8 {
                        stats.token_expired += u64::from_le_bytes(
                            cpu_data[..8].try_into().unwrap()
                        );
                    }
                }
            }
            
            // STAT_ALLOWED = 5
            let key = 5u32.to_le_bytes();
            if let Some(bytes) = self.stats.lookup_percpu(&key, MapFlags::empty())? {
                if let Some(cpu_data) = bytes.get(cpu) {
                    if cpu_data.len() >= 8 {
                        stats.allowed += u64::from_le_bytes(
                            cpu_data[..8].try_into().unwrap()
                        );
                    }
                }
            }
            
            // STAT_DENIED = 6
            let key = 6u32.to_le_bytes();
            if let Some(bytes) = self.stats.lookup_percpu(&key, MapFlags::empty())? {
                if let Some(cpu_data) = bytes.get(cpu) {
                    if cpu_data.len() >= 8 {
                        stats.denied += u64::from_le_bytes(
                            cpu_data[..8].try_into().unwrap()
                        );
                    }
                }
            }
        }
        
        Ok(stats)
    }
    
    /// List all active sessions
    pub fn list_sessions(&self) -> Result<Vec<u64>> {
        let mut session_ids = Vec::new();
        
        let mut key = None;
        loop {
            let next_key = if let Some(k) = &key {
                self.sessions.get_next_key(k)?
            } else {
                self.sessions.get_next_key(&[])?
            };
            
            match next_key {
                Some(k) => {
                    if k.len() >= 8 {
                        let session_id = u64::from_le_bytes(k[..8].try_into().unwrap());
                        session_ids.push(session_id);
                    }
                    key = Some(k);
                }
                None => break,
            }
        }
        
        Ok(session_ids)
    }
}

#[derive(Debug, Default, Clone)]
pub struct BpfStats {
    pub token_validated: u64,
    pub token_expired: u64,
    pub allowed: u64,
    pub denied: u64,
}

impl BpfStats {
    pub fn total_decisions(&self) -> u64 {
        self.allowed + self.denied
    }
}
