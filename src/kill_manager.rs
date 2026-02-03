// Kill Manager - Handles process termination for DEFCON 1 and anomaly detection
// NEW v2.0: Async kill on anomalies in learning mode

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tracing::{info, warn, error};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use crate::policy::PolicyEngine;

pub struct KillManager {
    policy_engine: Arc<RwLock<PolicyEngine>>,
    kill_queue: Arc<RwLock<mpsc::UnboundedSender<KillRequest>>>,
    kill_history: Arc<RwLock<HashMap<u64, KillRecord>>>,
}

#[derive(Debug, Clone)]
pub struct KillRequest {
    pub cgroup_id: u64,
    pub reason: KillReason,
    pub severity: KillSeverity,
}

#[derive(Debug, Clone)]
pub enum KillReason {
    DefconOne,           // DEFCON 1 escalation
    AnomalyDetected,     // ML-based anomaly in learning mode
    ManualRequest,       // Manual kill via gRPC
    ResourceExhaustion,  // Watchdog triggered
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillSeverity {
    Graceful,   // SIGTERM first, then SIGKILL
    Immediate,  // SIGKILL immediately
}

#[derive(Debug, Clone)]
struct KillRecord {
    pub cgroup_id: u64,
    pub pid: u32,
    pub reason: KillReason,
    pub timestamp: u64,
    pub success: bool,
}

impl KillManager {
    pub fn new(policy_engine: Arc<RwLock<PolicyEngine>>) -> Result<Arc<Self>> {
        let (tx, _rx) = mpsc::unbounded_channel();
        
        Ok(Arc::new(Self {
            policy_engine,
            kill_queue: Arc::new(RwLock::new(tx)),
            kill_history: Arc::new(RwLock::new(HashMap::new())),
        }))
    }

    /// Main worker loop - processes kill requests
    pub async fn run_worker(self: Arc<Self>) -> Result<()> {
        let (tx, mut rx) = mpsc::unbounded_channel::<KillRequest>();
        *self.kill_queue.write().await = tx;

        info!("Kill manager worker started");

        while let Some(req) = rx.recv().await {
            if let Err(e) = self.process_kill_request(req.clone()).await {
                error!("Failed to process kill request for cgroup {}: {}", req.cgroup_id, e);
            }
        }

        Ok(())
    }

    /// Queue a kill request
    pub async fn queue_kill(&self, req: KillRequest) -> Result<()> {
        let tx = self.kill_queue.read().await;
        tx.send(req).context("Failed to queue kill request")?;
        Ok(())
    }

    /// Kill by cgroup ID (called from gRPC or DEFCON monitor)
    pub async fn kill_by_cgroup(&self, cgroup_id: u64) -> Result<()> {
        self.queue_kill(KillRequest {
            cgroup_id,
            reason: KillReason::ManualRequest,
            severity: KillSeverity::Graceful,
        }).await
    }

    /// Kill due to anomaly detection in learning mode
    pub async fn kill_on_anomaly(&self, cgroup_id: u64, anomaly_score: u16) -> Result<()> {
        warn!("Anomaly detected for cgroup {} with score {}", cgroup_id, anomaly_score);
        
        let severity = if anomaly_score > 800 {
            KillSeverity::Immediate  // Very high anomaly = immediate kill
        } else {
            KillSeverity::Graceful   // Lower anomaly = graceful kill
        };

        self.queue_kill(KillRequest {
            cgroup_id,
            reason: KillReason::AnomalyDetected,
            severity,
        }).await
    }

    /// Process a kill request
    async fn process_kill_request(&self, req: KillRequest) -> Result<()> {
        info!("Processing kill request: cgroup {} reason {:?}", req.cgroup_id, req.reason);

        // Get PID from cgroup_id
        let pid = self.policy_engine.read().await
            .get_pid_from_cgroup(req.cgroup_id)
            .await
            .context("Failed to get PID from cgroup")?;

        if pid == 0 {
            warn!("Cgroup {} has no associated PID, skipping kill", req.cgroup_id);
            return Ok(());
        }

        let success = match req.severity {
            KillSeverity::Graceful => self.kill_graceful(pid).await?,
            KillSeverity::Immediate => self.kill_immediate(pid).await?,
        };

        // Record kill
        let record = KillRecord {
            cgroup_id: req.cgroup_id,
            pid,
            reason: req.reason,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            success,
        };

        self.kill_history.write().await.insert(req.cgroup_id, record);

        if success {
            info!("Successfully killed process {} (cgroup {})", pid, req.cgroup_id);
        } else {
            error!("Failed to kill process {} (cgroup {})", pid, req.cgroup_id);
        }

        Ok(())
    }

    /// Graceful kill: SIGTERM → wait → SIGKILL
    async fn kill_graceful(&self, pid: u32) -> Result<bool> {
        let nix_pid = Pid::from_raw(pid as i32);

        // Send SIGTERM
        match kill(nix_pid, Signal::SIGTERM) {
            Ok(_) => {
                info!("Sent SIGTERM to PID {}", pid);
                
                // Wait 5 seconds for graceful shutdown
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                
                // Check if process still exists
                if let Ok(_) = kill(nix_pid, Signal::SIGKILL) {
                    warn!("Process {} didn't exit gracefully, sent SIGKILL", pid);
                    Ok(true)
                } else {
                    info!("Process {} exited gracefully", pid);
                    Ok(true)
                }
            }
            Err(e) => {
                error!("Failed to send SIGTERM to PID {}: {}", pid, e);
                Ok(false)
            }
        }
    }

    /// Immediate kill: SIGKILL
    async fn kill_immediate(&self, pid: u32) -> Result<bool> {
        let nix_pid = Pid::from_raw(pid as i32);

        match kill(nix_pid, Signal::SIGKILL) {
            Ok(_) => {
                info!("Sent SIGKILL to PID {}", pid);
                Ok(true)
            }
            Err(e) => {
                error!("Failed to send SIGKILL to PID {}: {}", pid, e);
                Ok(false)
            }
        }
    }

    /// Get kill history for a cgroup
    pub async fn get_history(&self, cgroup_id: u64) -> Option<KillRecord> {
        self.kill_history.read().await.get(&cgroup_id).cloned()
    }

    /// Clear old kill history (keep last 1000 entries)
    pub async fn cleanup_history(&self) {
        let mut history = self.kill_history.write().await;
        if history.len() > 1000 {
            // Keep only the 1000 most recent entries
            let cutoff_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() - 3600; // Last hour

            history.retain(|_, record| record.timestamp > cutoff_time);
        }
    }
}
