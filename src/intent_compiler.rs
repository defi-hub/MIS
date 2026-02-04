// Intent Compiler - Transform YAML contracts to capability bitmasks

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::token_service::*;

/// Intent Contract (YAML definition)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IntentContract {
    pub intent: IntentMetadata,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub filesystem: Option<FilesystemRules>,
    #[serde(default)]
    pub network: Option<NetworkRules>,
    #[serde(default)]
    pub quotas: Option<ResourceQuotas>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IntentMetadata {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FilesystemRules {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkRules {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourceQuotas {
    #[serde(default)]
    pub max_files_open: Option<u32>,
    #[serde(default)]
    pub max_memory_mb: Option<u32>,
    #[serde(default)]
    pub max_cpu_percent: Option<u32>,
}

/// Compiled Intent - ready for enforcement
#[derive(Debug, Clone)]
pub struct CompiledIntent {
    pub name: String,
    pub capabilities: u64,
    pub filesystem_rules: Vec<PathRule>,
    pub network_rules: Vec<NetRule>,
    pub quotas: ResourceQuotas,
}

#[derive(Debug, Clone)]
pub struct PathRule {
    pub pattern: String,
    pub allow: bool,
}

#[derive(Debug, Clone)]
pub struct NetRule {
    pub endpoint: String,  // "host:port" or "*:*"
    pub allow: bool,
}

/// Intent Compiler
pub struct IntentCompiler;

impl IntentCompiler {
    /// Compile YAML intent to capability bitmask
    pub fn compile(yaml: &str) -> Result<CompiledIntent> {
        let contract: IntentContract = serde_yaml::from_str(yaml)
            .context("Failed to parse intent YAML")?;
        
        Self::compile_contract(&contract)
    }
    
    /// Compile from file
    pub fn compile_file(path: &Path) -> Result<CompiledIntent> {
        let yaml = std::fs::read_to_string(path)
            .context("Failed to read intent file")?;
        Self::compile(&yaml)
    }
    
    /// Compile intent contract
    pub fn compile_contract(contract: &IntentContract) -> Result<CompiledIntent> {
        // Convert capability strings to bitmask
        let mut caps = 0u64;
        
        for cap_str in &contract.capabilities {
            caps |= match cap_str.as_str() {
                "CAP_READ" => CAP_READ,
                "CAP_WRITE" => CAP_WRITE,
                "CAP_EXEC" => CAP_EXEC,
                "CAP_NETWORK" => CAP_NETWORK,
                "CAP_IPC" => CAP_IPC,
                "CAP_ADMIN" => CAP_ADMIN,
                "CAP_CREATE" => CAP_CREATE,
                "CAP_DELETE" => CAP_DELETE,
                _ => 0,  // Unknown capability ignored
            };
        }
        
        // Compile filesystem rules
        let mut fs_rules = Vec::new();
        if let Some(fs) = &contract.filesystem {
            for pattern in &fs.allow {
                fs_rules.push(PathRule {
                    pattern: pattern.clone(),
                    allow: true,
                });
            }
            for pattern in &fs.deny {
                fs_rules.push(PathRule {
                    pattern: pattern.clone(),
                    allow: false,
                });
            }
        }
        
        // Compile network rules
        let mut net_rules = Vec::new();
        if let Some(net) = &contract.network {
            for endpoint in &net.allow {
                net_rules.push(NetRule {
                    endpoint: endpoint.clone(),
                    allow: true,
                });
            }
            for endpoint in &net.deny {
                net_rules.push(NetRule {
                    endpoint: endpoint.clone(),
                    allow: false,
                });
            }
        }
        
        Ok(CompiledIntent {
            name: contract.intent.name.clone(),
            capabilities: caps,
            filesystem_rules: fs_rules,
            network_rules: net_rules,
            quotas: contract.quotas.clone().unwrap_or_default(),
        })
    }
    
    /// Load built-in intents
    pub fn load_builtin(name: &str) -> Result<CompiledIntent> {
        let yaml = match name {
            "RESEARCH" => include_str!("../intents/research.yaml"),
            "DEPLOY" => include_str!("../intents/deploy.yaml"),
            "TEST" => include_str!("../intents/test.yaml"),
            "ANALYZE" => include_str!("../intents/analyze.yaml"),
            _ => return Err(anyhow::anyhow!("Unknown built-in intent: {}", name)),
        };
        
        Self::compile(yaml)
    }
}

impl Default for ResourceQuotas {
    fn default() -> Self {
        Self {
            max_files_open: Some(1000),
            max_memory_mb: Some(4096),
            max_cpu_percent: Some(80),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_compile_research_intent() {
        let yaml = r#"
intent:
  name: "RESEARCH"
  description: "Academic research"
  
capabilities:
  - CAP_READ
  - CAP_NETWORK
  - CAP_EXEC

filesystem:
  allow:
    - /data/papers/*
  deny:
    - /etc/*

network:
  allow:
    - arxiv.org:443
  deny:
    - "*:*"
"#;
        
        let compiled = IntentCompiler::compile(yaml).unwrap();
        
        assert_eq!(compiled.name, "RESEARCH");
        assert_eq!(compiled.capabilities, CAP_READ | CAP_NETWORK | CAP_EXEC);
        assert_eq!(compiled.filesystem_rules.len(), 2);
        assert_eq!(compiled.network_rules.len(), 2);
    }
    
    #[test]
    fn test_capability_bitmask() {
        let yaml = r#"
intent:
  name: "TEST"
  description: "Test"
  
capabilities:
  - CAP_READ
  - CAP_WRITE
"#;
        
        let compiled = IntentCompiler::compile(yaml).unwrap();
        assert_eq!(compiled.capabilities, 0b11);  // CAP_READ | CAP_WRITE
    }
}
