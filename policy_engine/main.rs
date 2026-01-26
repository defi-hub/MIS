// MIS Policy Engine: Userspace Security Decision Engine
// Handles eBPF events via ringbuffer and enforces multi-layer policy

use anyhow::{Context, Result};
use libbpf_rs::{MapFlags, Object, RingBufferBuilder};
use bloom::{BloomFilter, ASMS};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

// ============================================================================
// CONFIGURATION
// ============================================================================

const HOTFIX_BLOOM_PATH: &str = "/etc/agent/hotfix.bloom";
const BASE_BLOOM_PATH: &str = "/etc/agent/base.bloom";
const EXACT_DB_PATH: &str = "/etc/agent/critical.db";
const WHITELIST_PATH: &str = "/etc/agent/whitelist.toml";

// TTL by syscall class (seconds)
const TTL_MAP: &[(u32, u32)] = &[
    (libc::SYS_read as u32, 60),
    (libc::SYS_write as u32, 60),
    (libc::SYS_fstat as u32, 120),
    (libc::SYS_open as u32, 180),
    (libc::SYS_openat as u32, 180),
    (libc::SYS_execve as u32, 300),
    (libc::SYS_mount as u32, 0),           // Never cache
    (libc::SYS_ptrace as u32, 0),          // Never cache
    (libc::SYS_process_vm_readv as u32, 0), // Never cache
];

// ============================================================================
// DATA STRUCTURES
// ============================================================================

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct InodeKey {
    inode: u64,
    dev_id: u32,
    syscall_nr: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct DecisionValue {
    allowed: u8,
    confidence: u8,
    padding: u16,
    ttl_expires: u32,
    syscall_class: u8,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct AccessEvent {
    inode: u64,
    dev_id: u32,
    syscall_nr: u32,
    pid: u32,
    timestamp: u32,
    comm: [u8; 16],
}

#[derive(Debug, Clone, PartialEq)]
enum Decision {
    Allow,
    Deny,
    Trace,
}

#[derive(Deserialize)]
struct WhitelistConfig {
    inodes: Vec<WhitelistEntry>,
}

#[derive(Deserialize, Clone)]
struct WhitelistEntry {
    inode: u64,
    dev_id: u32,
    description: String,
    added_by: String,
}

// ============================================================================
// POLICY ENGINE
// ============================================================================

pub struct PolicyEngine {
    // Bloom filters
    hotfix_bloom: BloomFilter,
    base_bloom: BloomFilter,
    
    // Exact match database
    exact_db: HashMap<u64, String>,
    
    // Whitelist (git-versioned)
    whitelist: Arc<RwLock<HashMap<(u64, u32), WhitelistEntry>>>,
    
    // eBPF object
    bpf_obj: Arc<RwLock<Object>>,
    
    // Statistics
    stats: Arc<RwLock<PolicyStats>>,
}

#[derive(Default, Debug)]
struct PolicyStats {
    decisions_allowed: u64,
    decisions_denied: u64,
    bloom_hits: u64,
    bloom_fps: u64,
    whitelist_hits: u64,
}

impl PolicyEngine {
    pub fn new() -> Result<Self> {
        // Load Bloom filters
        let hotfix_bloom = BloomFilter::load(HOTFIX_BLOOM_PATH)
            .context("Failed to load Hotfix Bloom")?;
        let base_bloom = BloomFilter::load(BASE_BLOOM_PATH)
            .context("Failed to load Base Bloom")?;
        
        // Load exact match DB
        let exact_db = Self::load_exact_db(EXACT_DB_PATH)?;
        
        // Load whitelist
        let whitelist = Self::load_whitelist(WHITELIST_PATH)?;
        
        // Load eBPF program
        let mut bpf_obj = libbpf_rs::ObjectBuilder::default()
            .open_file("/etc/agent/mis_lsm.o")?
            .load()?;
        
        // Initialize syscall TTL map
        let ttl_map = bpf_obj.map("syscall_ttl")?;
        for (syscall, ttl) in TTL_MAP {
            ttl_map.update(
                &syscall.to_ne_bytes(),
                &ttl.to_ne_bytes(),
                MapFlags::ANY,
            )?;
        }
        
        Ok(Self {
            hotfix_bloom,
            base_bloom,
            exact_db,
            whitelist: Arc::new(RwLock::new(whitelist)),
            bpf_obj: Arc::new(RwLock::new(bpf_obj)),
            stats: Arc::new(RwLock::new(PolicyStats::default())),
        })
    }
    
    fn load_exact_db(path: &str) -> Result<HashMap<u64, String>> {
        // Load from SQLite or similar
        let mut db = HashMap::new();
        // TODO: Implement actual DB loading
        Ok(db)
    }
    
    fn load_whitelist(path: &str) -> Result<HashMap<(u64, u32), WhitelistEntry>> {
        let content = std::fs::read_to_string(path)?;
        let config: WhitelistConfig = toml::from_str(&content)?;
        
        let mut whitelist = HashMap::new();
        for entry in config.inodes {
            whitelist.insert((entry.inode, entry.dev_id), entry);
        }
        Ok(whitelist)
    }
    
    fn hash_inode_key(&self, key: &InodeKey) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(&key.inode.to_ne_bytes());
        hasher.update(&key.dev_id.to_ne_bytes());
        hasher.update(&key.syscall_nr.to_ne_bytes());
        
        let result = hasher.finalize();
        u64::from_ne_bytes(result[0..8].try_into().unwrap())
    }
    
    pub fn make_decision(&self, key: &InodeKey) -> Decision {
        let hash = self.hash_inode_key(key);
        
        // Layer 1: Whitelist (highest priority, explicit ALLOW)
        {
            let whitelist = self.whitelist.read().unwrap();
            if whitelist.contains_key(&(key.inode, key.dev_id)) {
                self.stats.write().unwrap().whitelist_hits += 1;
                self.stats.write().unwrap().decisions_allowed += 1;
                return Decision::Allow;
            }
        }
        
        // Layer 2: Hotfix Bloom (CRITICAL threats, CVSS ≥ 9.0)
        // RULE: Hotfix HIT = DENY, даже если ExactMatch MISS
        if self.hotfix_bloom.contains(&hash) {
            self.stats.write().unwrap().bloom_hits += 1;
            self.stats.write().unwrap().decisions_denied += 1;
            
            log::warn!(
                "CRITICAL threat blocked: inode={} dev={} syscall={}",
                key.inode, key.dev_id, key.syscall_nr
            );
            
            return Decision::Deny;
        }
        
        // Layer 3: Base Bloom (general threats)
        if self.base_bloom.contains(&hash) {
            self.stats.write().unwrap().bloom_hits += 1;
            
            // Check Exact DB
            if self.exact_db.contains_key(&hash) {
                self.stats.write().unwrap().decisions_denied += 1;
                
                log::info!(
                    "Threat blocked (exact match): inode={} dev={} syscall={}",
                    key.inode, key.dev_id, key.syscall_nr
                );
                
                return Decision::Deny;
            }
            
            // Bloom false positive
            self.stats.write().unwrap().bloom_fps += 1;
            log::debug!(
                "Bloom FP detected: inode={} dev={} syscall={}",
                key.inode, key.dev_id, key.syscall_nr
            );
        }
        
        // Layer 4: Unknown → TRACE (fail-secure)
        log::trace!(
            "Unknown access, tracing: inode={} dev={} syscall={}",
            key.inode, key.dev_id, key.syscall_nr
        );
        
        Decision::Trace
    }
    
    fn update_cache(&self, key: &InodeKey, decision: Decision, ttl_sec: u32) -> Result<()> {
        let bpf_obj = self.bpf_obj.read().unwrap();
        let cache_map = bpf_obj.map("inode_cache")?;
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as u32;
        
        let decision_value = DecisionValue {
            allowed: if decision == Decision::Allow { 1 } else { 0 },
            confidence: 100,
            padding: 0,
            ttl_expires: now + ttl_sec,
            syscall_class: 0,
        };
        
        let key_bytes = unsafe {
            std::slice::from_raw_parts(
                key as *const InodeKey as *const u8,
                std::mem::size_of::<InodeKey>(),
            )
        };
        
        let value_bytes = unsafe {
            std::slice::from_raw_parts(
                &decision_value as *const DecisionValue as *const u8,
                std::mem::size_of::<DecisionValue>(),
            )
        };
        
        cache_map.update(key_bytes, value_bytes, MapFlags::ANY)?;
        
        Ok(())
    }
    
    pub fn start_event_loop(&self) -> Result<()> {
        let bpf_obj = self.bpf_obj.read().unwrap();
        let events_map = bpf_obj.map("access_events")?;
        
        let engine_clone = Arc::new(self.clone());
        
        let mut builder = RingBufferBuilder::new();
        builder.add(&events_map, move |data: &[u8]| -> i32 {
            let event = unsafe { &*(data.as_ptr() as *const AccessEvent) };
            
            let key = InodeKey {
                inode: event.inode,
                dev_id: event.dev_id,
                syscall_nr: event.syscall_nr,
            };
            
            let decision = engine_clone.make_decision(&key);
            
            // Get TTL for this syscall
            let ttl = TTL_MAP.iter()
                .find(|(nr, _)| *nr == event.syscall_nr)
                .map(|(_, ttl)| *ttl)
                .unwrap_or(60);
            
            // Update cache only if TTL > 0
            if ttl > 0 {
                if let Err(e) = engine_clone.update_cache(&key, decision.clone(), ttl) {
                    log::error!("Failed to update cache: {}", e);
                }
            }
            
            log::info!(
                "Access decision: pid={} inode={} syscall={} decision={:?}",
                event.pid, event.inode, event.syscall_nr, decision
            );
            
            0
        })?;
        
        let ringbuf = builder.build()?;
        
        log::info!("Policy engine started, listening for events...");
        
        loop {
            ringbuf.poll(std::time::Duration::from_millis(100))?;
        }
    }
    
    pub fn print_stats(&self) {
        let stats = self.stats.read().unwrap();
        println!("{:#?}", *stats);
    }
}

impl Clone for PolicyEngine {
    fn clone(&self) -> Self {
        Self {
            hotfix_bloom: self.hotfix_bloom.clone(),
            base_bloom: self.base_bloom.clone(),
            exact_db: self.exact_db.clone(),
            whitelist: Arc::clone(&self.whitelist),
            bpf_obj: Arc::clone(&self.bpf_obj),
            stats: Arc::clone(&self.stats),
        }
    }
}

// ============================================================================
// WATCHDOG
// ============================================================================

pub struct Watchdog {
    cpu_threshold: f32,
    cpu_duration_sec: u64,
    memory_threshold_mb: u64,
}

impl Watchdog {
    pub fn new() -> Self {
        Self {
            cpu_threshold: 100.0,  // 100% of one core
            cpu_duration_sec: 30,  // 30 seconds sustained
            memory_threshold_mb: 2048,
        }
    }
    
    pub fn monitor_loop(&self, agent_pid: u32) -> Result<()> {
        use procfs::process::Process;
        
        let mut high_cpu_start: Option<SystemTime> = None;
        
        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            
            let process = Process::new(agent_pid as i32)?;
            let stat = process.stat()?;
            
            // CPU check
            let cpu_usage = stat.utime + stat.stime;
            let cpu_percent = (cpu_usage as f32 / 100.0) * 100.0;
            
            if cpu_percent >= self.cpu_threshold {
                if high_cpu_start.is_none() {
                    high_cpu_start = Some(SystemTime::now());
                    log::warn!("High CPU detected: {}%", cpu_percent);
                } else {
                    let duration = SystemTime::now()
                        .duration_since(high_cpu_start.unwrap())?
                        .as_secs();
                    
                    if duration >= self.cpu_duration_sec {
                        log::error!("CPU throttling detected for {}s, triggering KillSwitch", duration);
                        self.trigger_killswitch(agent_pid)?;
                        return Ok(());
                    }
                }
            } else {
                high_cpu_start = None;
            }
            
            // Memory check
            let memory_kb = stat.rss * 4;  // Pages to KB
            let memory_mb = memory_kb / 1024;
            
            if memory_mb >= self.memory_threshold_mb {
                log::error!("Memory limit exceeded: {} MB, triggering KillSwitch", memory_mb);
                self.trigger_killswitch(agent_pid)?;
                return Ok(());
            }
        }
    }
    
    fn trigger_killswitch(&self, pid: u32) -> Result<()> {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        
        log::error!("KILLSWITCH TRIGGERED for pid {}", pid);
        
        kill(Pid::from_raw(pid as i32), Signal::SIGKILL)?;
        
        Ok(())
    }
}

// ============================================================================
// MAIN
// ============================================================================

fn main() -> Result<()> {
    env_logger::init();
    
    let engine = PolicyEngine::new()?;
    
    // Start watchdog in separate thread
    let agent_pid = std::env::var("AGENT_PID")
        .context("AGENT_PID not set")?
        .parse::<u32>()?;
    
    std::thread::spawn(move || {
        let watchdog = Watchdog::new();
        if let Err(e) = watchdog.monitor_loop(agent_pid) {
            log::error!("Watchdog error: {}", e);
        }
    });
    
    // Start policy engine event loop
    engine.start_event_loop()?;
    
    Ok(())
}
