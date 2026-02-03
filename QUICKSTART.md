# MIS v2.1 Quick Start Guide

This guide will get you up and running with MIS v2.1 in under 30 minutes.

---

## Prerequisites

### System Requirements

- **OS**: Linux with kernel ≥ 5.15
- **CPU**: x86_64 (ARM64 experimental)
- **RAM**: 4 GB minimum, 8 GB recommended
- **Disk**: 2 GB free space

### Software Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    linux-headers-$(uname -r) \
    pkg-config \
    protobuf-compiler

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Verify eBPF LSM Support

```bash
# Check if eBPF LSM is enabled
cat /boot/config-$(uname -r) | grep CONFIG_BPF_LSM
# Should output: CONFIG_BPF_LSM=y

# Check loaded LSMs
cat /sys/kernel/security/lsm
# Should include "bpf" in the list
```

If `bpf` is not in the LSM list, add it to GRUB:

```bash
sudo nano /etc/default/grub
# Add "bpf" to GRUB_CMDLINE_LINUX:
GRUB_CMDLINE_LINUX="lsm=lockdown,yama,integrity,apparmor,bpf"

sudo update-grub
sudo reboot
```

---

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/defi-hub/MIS.git
cd MIS
```

### 2. Build

```bash
# Build everything (eBPF + userspace)
make all

# This compiles:
# - enforcer/token_validator.c → build/mis_enforcer.o
# - src/* → target/release/mis-policy-engine
```

**Expected output:**
```
✓ eBPF module built: build/mis_enforcer.o
✓ Policy engine built: target/release/mis-policy-engine
```

### 3. Install

```bash
sudo make install
```

**This installs:**
- `/etc/mis/` - Configuration files
- `/etc/mis/bpf/mis_enforcer.o` - eBPF object
- `/etc/mis/mis-policy-engine` - Main orchestrator
- `/var/log/mis/` - Log directory
- `/var/lib/mis/` - State directory

---

## Configuration

### 1. Generate Signing Keys

```bash
# Generate Ed25519 key pair for token signing
sudo mkdir -p /etc/mis/keys
sudo mis-keygen --output /etc/mis/keys/signing.key
```

### 2. Edit Configuration

```bash
sudo nano /etc/mis/config.toml
```

**Minimal configuration:**

```toml
[paths]
bpf_object = "/etc/mis/bpf/mis_enforcer.o"
audit_log = "/var/log/mis/audit.log"
policy_state = "/var/lib/mis/state.json"

[grpc]
enabled = true
bind_address = "127.0.0.1"
port = 50051

[orchestrator]
token_signing_key = "/etc/mis/keys/signing.key"
default_ttl_secs = 3600  # 1 hour

[logging]
level = "info"
format = "json"
```

---

## Running MIS

### Start Orchestrator

```bash
# Foreground (for testing)
sudo /etc/mis/mis-policy-engine /etc/mis/config.toml

# Background (systemd)
sudo systemctl start mis-policy-engine
sudo systemctl enable mis-policy-engine

# Check status
sudo systemctl status mis-policy-engine
```

**Expected output:**
```
INFO MIS Policy Engine v2.1.0 starting...
INFO Configuration loaded from /etc/mis/config.toml
INFO Policy engine initialized
INFO gRPC server listening on 127.0.0.1:50051
INFO All services started
```

### Verify Installation

```bash
# Check gRPC API
grpcurl -plaintext localhost:50051 list

# Should output:
# mis.policy.v1.PolicyService
```

---

## Your First Session

### Option 1: Python SDK (Recommended)

**Install SDK:**

```bash
pip install mis-sdk
```

**Create session:**

```python
# agent.py
import mis

# Define your AI agent
def my_research_agent():
    # This code runs within a secure session
    import requests
    
    # Automatically allowed: network access to arxiv.org
    papers = requests.get("https://arxiv.org/search/?query=AI+safety")
    
    # Automatically allowed: read from /data/papers/
    with open("/data/papers/analysis.txt", "r") as f:
        data = f.read()
    
    # Automatically DENIED: write to /etc/
    # This will be blocked by MIS
    # with open("/etc/shadow", "w") as f:
    #     f.write("hacked")
    
    return "Research complete"

# Create session with RESEARCH intent
with mis.session(
    profile=mis.Profile.RESEARCHER,
    intent="Analyze AI safety papers from arxiv"
) as session:
    result = my_research_agent()
    print(f"Result: {result}")
    print(f"Session stats: {session.stats()}")
```

**Run:**

```bash
python agent.py
```

**Output:**
```
INFO Creating session with intent: RESEARCH
INFO Token issued: session_id=1234567890
INFO Agent started (PID 12345)
Result: Research complete
Session stats: {
  'violations': 0,
  'defcon_level': 5,
  'operations': 127,
  'denied': 0
}
INFO Session terminated successfully
```

### Option 2: CLI (Manual Session Management)

```bash
# Create session
mis-ctl session create \
  --profile researcher \
  --intent "Analyze codebase" \
  --agent ./my_agent.sh

# Output:
# Session created: session_id=1234567890
# Token: eyJhbGc...
# PID: 12345

# Inspect session
mis-ctl session inspect 1234567890

# Output:
# Session ID: 1234567890
# State: ACTIVE
# Agent: ./my_agent.sh (PID 12345)
# Intent: Analyze codebase
# DEFCON Level: 5 (NORMAL)
# Violations: 0
# Uptime: 00:05:23

# Stream audit events
mis-ctl audit stream --session 1234567890

# Terminate session
mis-ctl session terminate 1234567890
```

---

## Testing Security

### Test 1: Denied Operations

```python
# test_deny.py
import mis

with mis.session(intent="RESEARCH"):
    # This should be DENIED (no CAP_WRITE to /etc)
    try:
        with open("/etc/shadow", "w") as f:
            f.write("should fail")
    except PermissionError:
        print("✓ Write to /etc/shadow blocked (expected)")
    
    # This should be ALLOWED (CAP_READ to /data)
    with open("/data/papers/test.txt", "r") as f:
        print("✓ Read from /data/papers/ allowed (expected)")
```

**Run:**
```bash
python test_deny.py
```

**Expected:**
```
✓ Write to /etc/shadow blocked (expected)
✓ Read from /data/papers/ allowed (expected)
```

### Test 2: DEFCON Escalation

```python
# test_defcon.py
import mis

with mis.session(intent="RESEARCH") as session:
    # Trigger 15 violations to reach DEFCON 1
    for i in range(15):
        try:
            open("/etc/shadow", "w")  # Denied
        except:
            pass
    
    # After 15 violations, process should be killed
    # This line will never execute
    print("This won't print (process killed)")
```

**Run:**
```bash
python test_defcon.py
```

**Expected:**
```
WARN DEFCON 4 WARNING: Process showing suspicious behavior
WARN DEFCON 3 ELEVATED: All risky operations blocked
WARN DEFCON 2 CRITICAL: Process one step from termination
WARN DEFCON 1 EMERGENCY: Process killed (15 violations)
Killed
```

---

## Monitoring

### View Logs

```bash
# Real-time logs
sudo journalctl -u mis-policy-engine -f

# Filter by session
sudo journalctl -u mis-policy-engine | grep "session_id=1234567890"

# View audit trail
sudo cat /var/log/mis/audit.log | jq
```

### Metrics

```bash
# Prometheus metrics endpoint
curl -s http://localhost:9090/metrics | grep mis_

# Sample output:
# mis_sessions_active 5
# mis_tokens_validated 1234567
# mis_violations_total 42
# mis_defcon_escalations 3
```

### gRPC API

```bash
# Get statistics
grpcurl -plaintext localhost:50051 \
  mis.policy.v1.PolicyService/GetStats

# Output:
{
  "cache_hits": 1234567,
  "cache_misses": 8901,
  "denied": 42,
  "allowed": 1234525,
  "defcon_escalations": 3,
  "processes_killed": 1
}
```

---

## Custom Intent Contracts

### Create Custom Intent

```yaml
# custom_deploy_intent.yaml
intent:
  name: "DEPLOY"
  description: "Deploy to production infrastructure"
  
capabilities:
  - CAP_READ
  - CAP_WRITE
  - CAP_EXEC
  - CAP_NETWORK

filesystem:
  allow:
    - /opt/app/*
    - /var/log/app/*
    - /tmp/*
  deny:
    - /etc/*
    - /root/*
    - /home/*

network:
  allow:
    - production-db.internal:5432
    - api.example.com:443
  deny:
    - "*:*"

executables:
  allow:
    - /usr/bin/docker
    - /usr/bin/kubectl
    - /opt/app/deploy.sh

quotas:
  max_files_open: 10000
  max_memory_mb: 16384
  max_cpu_percent: 90
```

### Load Custom Intent

```bash
mis-ctl intent create --file custom_deploy_intent.yaml
```

### Use Custom Intent

```python
with mis.session(intent="DEPLOY"):
    # Your deployment script runs here
    deploy_to_production()
```

---

## Troubleshooting

### Issue: eBPF LSM not loaded

**Symptom:**
```
ERROR Failed to load eBPF object: BPF LSM not enabled
```

**Solution:**
```bash
# Verify kernel support
uname -r  # Must be >= 5.15

# Check LSM list
cat /sys/kernel/security/lsm

# Add "bpf" to boot parameters (see Prerequisites section)
```

### Issue: Permission denied when creating sessions

**Symptom:**
```
PermissionError: [Errno 1] Operation not permitted
```

**Solution:**
```bash
# MIS requires root privileges
sudo python agent.py

# OR: Grant CAP_BPF capability
sudo setcap cap_bpf=ep $(which python3)
```

### Issue: gRPC connection refused

**Symptom:**
```
grpc._channel._InactiveRpcError: Connection refused
```

**Solution:**
```bash
# Check orchestrator is running
sudo systemctl status mis-policy-engine

# Check port binding
sudo netstat -tulpn | grep 50051

# Check firewall
sudo ufw allow 50051/tcp
```

---

## Next Steps

1. **Read [ARCHITECTURE.md](../ARCHITECTURE.md)** for detailed design
2. **Read [TOKEN_SECURITY.md](TOKEN_SECURITY.md)** for cryptographic details
3. **Read [INTENT_CONTRACTS.md](INTENT_CONTRACTS.md)** for advanced intent authoring
4. **Explore examples in `examples/`** directory
5. **Join community discussions** on GitHub Issues

---

## Getting Help

- **GitHub Issues**: https://github.com/defi-hub/MIS/issues
- **Telegram**: @def.blog
- **Email**: xoomi16@gmail.com

---

**Happy hacking with MIS! 🚀**
