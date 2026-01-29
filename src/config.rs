// Configuration module - same as v1.1 but with v2.0 updates

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub paths: PathConfig,
    pub bloom: BloomConfig,
    pub policy: PolicyConfig,
    pub watchdog: WatchdogConfig,
    pub logging: LoggingConfig,
    pub grpc: GrpcConfig,
    pub metrics: MetricsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PathConfig {
    pub hotfix_bloom: PathBuf,
    pub base_bloom: PathBuf,
    pub exact_db: PathBuf,
    pub whitelist: PathBuf,
    pub bpf_object: PathBuf,
    pub audit_log: PathBuf,
    pub policy_state: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BloomConfig {
    pub hotfix_capacity: u32,
    pub hotfix_fp_rate: f64,
    pub base_capacity: u32,
    pub base_fp_rate: f64,
    pub auto_reload_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyConfig {
    pub default_action: Action,
    pub cache_ttl_enabled: bool,
    pub hotfix_priority: bool,
    pub exact_match_required: bool,
    pub max_cache_entries: usize,
    pub unknown_action: Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
    Trace,
}

impl Action {
    pub fn to_u8(&self) -> u8 {
        match self {
            Action::Allow => 1,
            Action::Deny => 0,
            Action::Trace => 2,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WatchdogConfig {
    pub enabled: bool,
    pub check_interval_secs: u64,
    pub cpu_threshold_percent: f64,
    pub memory_threshold_mb: u64,
    pub kill_after_violations: u32,
    pub grace_period_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: LogFormat,
    pub file_output: bool,
    pub stdout_output: bool,
    pub max_file_size_mb: u64,
    pub max_files: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Pretty,
    Compact,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GrpcConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    pub tls_enabled: bool,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    pub endpoint: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config from {:?}", path))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| "Failed to parse TOML config")?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .with_context(|| "Failed to serialize config")?;
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config to {:?}", path))?;
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            paths: PathConfig {
                hotfix_bloom: PathBuf::from("/etc/mis/policy/hotfix.bloom"),
                base_bloom: PathBuf::from("/etc/mis/policy/base.bloom"),
                exact_db: PathBuf::from("/etc/mis/policy/critical.db"),
                whitelist: PathBuf::from("/etc/mis/policy/whitelist.toml"),
                bpf_object: PathBuf::from("/etc/mis/bpf/mis_lsm.o"),
                audit_log: PathBuf::from("/var/log/mis/audit.log"),
                policy_state: PathBuf::from("/var/lib/mis/state.json"),
            },
            bloom: BloomConfig {
                hotfix_capacity: 10000,
                hotfix_fp_rate: 0.001,
                base_capacity: 1000000,
                base_fp_rate: 0.01,
                auto_reload_interval_secs: 30,
            },
            policy: PolicyConfig {
                default_action: Action::Deny,
                cache_ttl_enabled: true,
                hotfix_priority: true,
                exact_match_required: true,
                max_cache_entries: 100000,
                unknown_action: Action::Trace,
            },
            watchdog: WatchdogConfig {
                enabled: true,
                check_interval_secs: 5,
                cpu_threshold_percent: 80.0,
                memory_threshold_mb: 512,
                kill_after_violations: 6,
                grace_period_secs: 30,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: LogFormat::Json,
                file_output: true,
                stdout_output: true,
                max_file_size_mb: 100,
                max_files: 10,
            },
            grpc: GrpcConfig {
                enabled: true,  // Changed to true by default in v2.0
                bind_address: "127.0.0.1".to_string(),
                port: 50051,
                tls_enabled: false,
                tls_cert_path: None,
                tls_key_path: None,
            },
            metrics: MetricsConfig {
                enabled: true,
                bind_address: "127.0.0.1".to_string(),
                port: 9090,
                endpoint: "/metrics".to_string(),
            },
        }
    }
}
