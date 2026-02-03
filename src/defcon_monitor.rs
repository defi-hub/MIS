// DEFCON Monitor - Monitors DEFCON level transitions and triggers actions
// NEW v2.0: Real-time DEFCON event processing

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

use crate::policy::PolicyEngine;
use crate::kill_manager::{KillManager, KillRequest, KillReason, KillSeverity};

pub struct DefconMonitor {
    policy_engine: Arc<RwLock<PolicyEngine>>,
    kill_manager: Arc<KillManager>,
}

impl DefconMonitor {
    pub fn new(
        policy_engine: Arc<RwLock<PolicyEngine>>,
        kill_manager: Arc<KillManager>,
    ) -> Result<Self> {
        Ok(Self {
            policy_engine,
            kill_manager,
        })
    }

    /// Main monitoring loop
    pub async fn run(&mut self) -> Result<()> {
        info!("DEFCON monitor started");

        loop {
            // Check for DEFCON events from BPF ringbuffer
            match self.poll_defcon_events().await {
                Ok(events) => {
                    for event in events {
                        self.handle_defcon_event(event).await?;
                    }
                }
                Err(e) => {
                    error!("Failed to poll DEFCON events: {}", e);
                }
            }

            // Poll every 100ms
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    /// Poll DEFCON events from eBPF ringbuffer
    async fn poll_defcon_events(&self) -> Result<Vec<DefconEvent>> {
        let engine = self.policy_engine.read().await;
        engine.poll_defcon_events().await
    }

    /// Handle a DEFCON transition event
    async fn handle_defcon_event(&self, event: DefconEvent) -> Result<()> {
        info!(
            "DEFCON transition: cgroup {} {} → {} (violations: {})",
            event.cgroup_id,
            defcon_level_name(event.old_level),
            defcon_level_name(event.new_level),
            event.violations
        );

        // DEFCON 1 = Emergency → Kill process
        if event.new_level == 1 {
            warn!(
                "DEFCON 1 EMERGENCY: Killing process cgroup {} (violations: {})",
                event.cgroup_id, event.violations
            );

            self.kill_manager.queue_kill(KillRequest {
                cgroup_id: event.cgroup_id,
                reason: KillReason::DefconOne,
                severity: KillSeverity::Immediate,  // DEFCON 1 = immediate kill
            }).await?;
        }

        // DEFCON 2 = Critical → Alert and prepare for kill
        else if event.new_level == 2 && event.old_level > 2 {
            warn!(
                "DEFCON 2 CRITICAL: Process cgroup {} is one step from termination",
                event.cgroup_id
            );

            // Could trigger alerts here (email, Slack, PagerDuty, etc.)
            self.send_alert(&event).await?;
        }

        // DEFCON 3 = Elevated → Log warning
        else if event.new_level == 3 && event.old_level > 3 {
            warn!(
                "DEFCON 3 ELEVATED: Process cgroup {} showing suspicious behavior",
                event.cgroup_id
            );
        }

        Ok(())
    }

    /// Send alert (placeholder - implement with your alerting system)
    async fn send_alert(&self, event: &DefconEvent) -> Result<()> {
        // TODO: Integrate with alerting system (email, Slack, PagerDuty, etc.)
        info!("ALERT: DEFCON {} for cgroup {}", event.new_level, event.cgroup_id);
        Ok(())
    }
}

/// DEFCON event from eBPF
#[derive(Debug, Clone)]
pub struct DefconEvent {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub old_level: u8,
    pub new_level: u8,
    pub violations: u16,
    pub trigger_syscall: u32,
    pub comm: String,
    pub reason: String,
}

fn defcon_level_name(level: u8) -> &'static str {
    match level {
        5 => "DEFCON 5 (NORMAL)",
        4 => "DEFCON 4 (WARNING)",
        3 => "DEFCON 3 (ELEVATED)",
        2 => "DEFCON 2 (CRITICAL)",
        1 => "DEFCON 1 (EMERGENCY)",
        _ => "UNKNOWN",
    }
}
