# Changelog

All notable changes to MIS will be documented in this file.

## [2.0.0] - 2026-01-29

### 🎉 Major Release - Enhanced Architecture

### Added

#### eBPF/Kernel Features
- **BPF Task Storage**: Replaced LRU hash for process reputation with `BPF_MAP_TYPE_TASK_STORAGE` for per-task data (faster lookups)
- **DEFCON System**: 5-level threat escalation system (DEFCON 5 → 1)
  - DEFCON 5 (NORMAL): Full permissions
  - DEFCON 4 (WARNING): Minor violations, monitoring enabled
  - DEFCON 3 (ELEVATED): Repeated violations, risky operations blocked
  - DEFCON 2 (CRITICAL): Severe violations, only whitelisted operations allowed
  - DEFCON 1 (EMERGENCY): Process termination
- **Cgroup-based Tracking**: Replaced PID with `bpf_get_current_cgroup_id()` for container-stable identification
- **Adaptive Slowdown**: Automatic rate limiting based on DEFCON level (100μs → 10ms delays)
- **DEFCON Events Ringbuffer**: Real-time notification of threat level transitions

#### Userspace Features
- **gRPC Server** (Tonic): Dynamic policy management without restart
  - `AddRule`, `RemoveRule`, `ReloadPolicy` RPCs
  - `GetStats`, `KillProcess`, `SetLearningMode` RPCs
  - Optional TLS support
- **Async Kill Manager**: Process termination on anomalies
  - Graceful kill (SIGTERM → SIGKILL)
  - Immediate kill for critical threats
  - Kill history and audit trail
- **DEFCON Monitor**: Real-time monitoring of DEFCON transitions
  - Automatic DEFCON 1 → kill escalation
  - Alert integration hooks (email, Slack, PagerDuty)
- **Learning Mode Support**: Per-cgroup learning mode flag in eBPF

### Changed
- Updated version to 2.0.0
- Enhanced ringbuffer size to 512KB (from 256KB) for DEFCON events
- Default gRPC server enabled in config
- Improved stat tracking (32 counters, up from 16)
- Better error handling and logging

### Performance Improvements
- BPF task storage eliminates hash lookup overhead for reputation data
- Per-CPU LRU cache remains for inode decisions
- Reduced latency for repeated access patterns

### Breaking Changes
- Renamed `process_reputation` map to use task storage (incompatible with v1.x)
- Changed PID tracking to cgroup ID (requires userspace updates)
- New DEFCON events require updated userspace consumer

### Migration Guide

#### From v1.x to v2.0
1. **eBPF**: Kernel ≥5.11 required for BPF task storage
2. **Userspace**: Rebuild with new dependencies (Tonic, nix)
3. **Config**: Add `[grpc]` section to config.toml
4. **State**: Existing policy state is compatible
5. **API**: If using custom integrations, update to gRPC API

```bash
# Backup existing config
cp /etc/mis/config.toml /etc/mis/config.toml.v1.backup

# Install v2.0
make install

# Merge gRPC config into existing config.toml
# (see config/config.toml for example)
```

## [1.1.0] - 2026-01-XX

### Added
- Enhanced statistics tracking
- Improved namespace depth tracking
- Audit event enhancements

### Fixed
- Cache TTL edge cases
- Ringbuffer overflow handling

## [1.0.0] - 2026-01-XX

### Added
- Initial release
- eBPF LSM hooks for file access control
- Dual Bloom filter policy enforcement
- Three-stream embodied learning
- Inode-based TOCTOU mitigation
- Namespace tracking
- Process reputation
- Watchdog monitoring
