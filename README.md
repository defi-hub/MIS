# MIS v2.0 - Modular Intelligence Spaces

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18381504.svg)](https://doi.org/10.5281/zenodo.18381504)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-green)](CHANGELOG.md)

## 🚀 v2.0 Major Release: The "Agentic" Update

**MIS v2.0** transforms from a static security module into a dynamic **AI Alignment & Safety Layer**. This release introduces adaptive response mechanisms designed specifically for Autonomous Agents and LLM-based infrastructure.

### Key Innovations in v2.0:
*   **🛡️ DEFCON Threat System:** Instead of binary "Allow/Deny", MIS now implements a 5-level threat scale. As an agent violates policies, the system automatically escalates (Slowdown → Block → Kill).
*   **🧠 Adaptive Throttling (RL Feedback):** Implements `decision_slowdown` to provide "physical" negative feedback to agents during Reinforcement Learning (RL) without crashing the process.
*   **📦 Cgroup-Native Isolation:** Moved from unstable PID tracking to robust **Cgroup ID** tracking, making MIS fully compatible with Kubernetes and Dockerized AI clusters.
*   **⚡ Zero-Overhead Performance:** Migrated from BPF Hash Maps to **Task Local Storage**, ensuring virtually zero latency impact on model inference.
*   **🔌 gRPC Control Plane:** New API for dynamic policy updates and integration with orchestration systems.

> **Note:** The conceptual paper in `/paper` describes the foundational architecture. The v2.0 code implementation significantly extends these concepts with production-grade features. Updated documentation is coming in v2.0.1.

### Architecture Changes

```
OLD (v1.x):                    NEW (v2.0):
PID → LRU Hash → Reputation    Cgroup ID → Task Storage → Reputation
                                        ↓
                                  DEFCON Level (5→1)
                                        ↓
                              Slowdown → Block → Kill
```

"Architecture diagram (v1.0). v2.0 introduces DefconMonitor and KillManager components (updated diagram pending)."

---

## Quick Start

### Requirements
- Linux kernel ≥ 5.11 (for BPF task storage)
- Rust ≥ 1.75
- Clang/LLVM
- protoc (Protocol Buffers compiler)

### Build

```bash
make all
```

### Install

```bash
sudo make install
```

### Configure

Edit `/etc/mis/config.toml`:

```toml
[grpc]
enabled = true
bind_address = "127.0.0.1"
port = 50051
```

### Run

```bash
sudo /etc/mis/mis-policy-engine /etc/mis/config.toml
```

---

## DEFCON System

MIS v2.0 introduces a military-style alert system for threat management:

| Level | Name | Behavior | Triggers |
|-------|------|----------|----------|
| 5 | NORMAL | Full permissions | 0-2 violations |
| 4 | WARNING | Monitoring + 0.1ms slowdown | 3-5 violations |
| 3 | ELEVATED | Block risky ops + 1ms slowdown | 6-9 violations |
| 2 | CRITICAL | Block all unverified + 10ms slowdown | 10-14 violations |
| 1 | EMERGENCY | Process termination | 15+ violations |

### Example Flow

```
Agent tries to access /etc/shadow
  ↓
DEFCON 5: Denied (violation #1)
  ↓
Agent retries 3 times
  ↓
DEFCON 4: Denied + logged + 0.1ms delay
  ↓
Agent attempts 10 more violations
  ↓
DEFCON 3: All risky operations blocked
  ↓
Agent persists with violations
  ↓
DEFCON 2: Only whitelisted operations allowed
  ↓
Agent hits 15 violations
  ↓
DEFCON 1: Process killed (SIGKILL)
```

---

## gRPC API

### Dynamic Policy Management

```bash
# Add a rule (allow read on inode 12345)
grpcurl -plaintext -d '{
  "inode": 12345,
  "dev_id": 2049,
  "syscall_nr": 0,
  "action": 0,
  "ttl_secs": 300
}' localhost:50051 mis.policy.v1.PolicyService/AddRule

# Get stats
grpcurl -plaintext localhost:50051 \
  mis.policy.v1.PolicyService/GetStats

# Kill a process by cgroup
grpcurl -plaintext -d '{"cgroup_id": 12345678}' \
  localhost:50051 mis.policy.v1.PolicyService/KillProcess
```

### Enable Learning Mode

```bash
grpcurl -plaintext -d '{
  "cgroup_id": 12345678,
  "enabled": true
}' localhost:50051 \
  mis.policy.v1.PolicyService/SetLearningMode
```

---

## Async Kill on Anomalies

When learning mode is enabled, MIS can automatically kill processes exhibiting anomalous behavior:

```rust
// In learning mode, if anomaly detected:
if anomaly_score > 800 {
    kill_manager.kill_on_anomaly(cgroup_id, anomaly_score).await?;
    // SIGKILL sent immediately
}
```

---

## Performance

### v2.0 Improvements

| Metric | v1.1 | v2.0 | Improvement |
|--------|------|------|-------------|
| Reputation lookup | 1-2μs | <100ns | **20x faster** |
| Cache hit latency | 4.2μs | 4.2μs | Same |
| DEFCON transition | N/A | <1μs | New feature |
| gRPC overhead | N/A | ~50μs | New feature |

### Benchmark

```bash
# Run with 10K operations
./benchmark --ops 10000

Results:
- Cache hit rate: 96.8%
- p50 latency: 3.1μs
- p99 latency: 8.7μs
- DEFCON transitions: 15/10K
- Kills triggered: 2/10K
```

---

## Migration from v1.x

### Breaking Changes

1. **Task storage requires kernel ≥5.11**
2. **PID → Cgroup ID** in all APIs
3. **New DEFCON events** must be consumed
4. **gRPC dependency** added (optional, but recommended)

### Step-by-Step

```bash
# 1. Backup
sudo systemctl stop mis-policy-engine
sudo cp -r /etc/mis /etc/mis.v1.backup

# 2. Build v2.0
cd MIS
git checkout v2.0.0
make clean
make all

# 3. Install
sudo make install

# 4. Update config
sudo vim /etc/mis/config.toml
# Add [grpc] section from config/config.toml

# 5. Restart
sudo systemctl start mis-policy-engine

# 6. Verify
grpcurl -plaintext localhost:50051 \
  mis.policy.v1.PolicyService/GetStats
```

---

## Documentation

- [CHANGELOG.md](CHANGELOG.md) - Version history
- [API Documentation](docs/API.md) - gRPC API reference
- [DEFCON Guide](docs/DEFCON.md) - Threat level system
- [Migration Guide](docs/MIGRATION.md) - v1.x → v2.0

---

## Features

Runtime Guardrails: Prevents RCE, data exfiltration, and unauthorized network access at the kernel level (eBPF LSM).
Namespace & Mount Protection: Hardened checks against container escape attempts.
Behavioral Auditing: Full trace logs of agent activity, including "intent" analysis via syscall patterns.
Python/AI Compatibility: Non-blocking "Trace Mode" allows noisy Python/PyTorch processes to run while being monitored.

## Citation

```bibtex
@software{mis2026v2,
  author = {Sergey Defis},
  title = {MIS v2.0: Modular Intelligence Spaces},
  year = {2026},
  version = {2.0.0},
  url = {https://github.com/defi-hub/MIS},
  doi = {10.5281/zenodo.18381504}
}
```

---

## License

MIT License - see [LICENSE](LICENSE)

---

## Contact

- **Author**: Sergey Defis
- **Email**: xoomi16@gmail.com
- **Telegram**: @def.blog
- **Issues**: [GitHub Issues](https://github.com/defi-hub/MIS/issues)

---

**Disclaimer**: This is a reference implementation. Production deployment requires thorough testing and security hardening.
