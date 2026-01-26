# Modular Intelligence Spaces (MIS)

**An eBPF-Based Secure Execution Environment for Autonomous AI Agents**

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Paper](https://img.shields.io/badge/paper-preprint-yellow)](paper/mis_paper.pdf)
[![Language](https://img.shields.io/badge/language-Rust%20%7C%20C-red)]()

---

## Overview

This repository contains the **reference implementation** and **academic paper** for Modular Intelligence Spaces (MIS) - a novel architecture for deploying autonomous AI agents with kernel-level isolation guarantees.

**Paper**: [Modular Intelligence Spaces: An eBPF-Based Secure Execution Environment for Autonomous AI Agents](paper/mis_paper.pdf)

**Author**: Sergey Defis (xoomi16@gmail.com)

---

## Key Contributions

1. **TOCTOU-Resistant Access Control**: Inode-based checks eliminate filesystem race conditions
2. **Dual Bloom Filter Policy**: O(1) threat detection with sub-30s CVE response
3. **Embodied Learning**: Three-stream logging enables on-policy reinforcement from real system interactions

---

## Repository Contents

### Academic Paper

- **[paper/mis_paper.tex](paper/mis_paper.tex)** - LaTeX source
- **[paper/mis_paper.pdf](paper/mis_paper.pdf)** - Compiled PDF

Full paper with formal proofs, evaluation, and related work.

### Reference Implementation

**Status**: Proof of Concept (PoC)

This is a **conceptual implementation** demonstrating the core architecture. It is **not production-ready** and requires further development for deployment.
```
reference_implementation/
├── ebpf/
│   └── mis_lsm.c          # eBPF LSM hooks (inode-based access control)
│
├── policy_engine/
│   └── main.rs            # Rust userspace policy engine
│
└── config/
    └── mis_config.toml    # Example configuration
```

**Components**:

1. **eBPF LSM Module** (`ebpf/mis_lsm.c`):
   - Kernel-level file access control
   - Per-CPU LRU caching
   - Ringbuffer event signaling

2. **Policy Engine** (`policy_engine/main.rs`):
   - Dual Bloom filter policy enforcement
   - Watchdog with CPU throttling detection
   - Git-versioned whitelist management

3. **Configuration** (`config/mis_config.toml`):
   - Fail-secure defaults
   - Syscall TTL mappings
   - Resource limits

---

## Requirements (for PoC)

- Linux kernel ≥ 5.7 (eBPF LSM support)
- Rust (latest stable)
- Clang/LLVM (for eBPF compilation)

**Note**: This PoC requires significant additional work before production use:
- Complete eBPF map implementations
- Bloom filter library integration
- Comprehensive testing
- Production hardening

---

## Citation

If you use this work in your research, please cite:
```bibtex
@article{defis2026mis,
  author    = {Sergey Defis},
  title     = {Modular Intelligence Spaces (MIS): An eBPF-Based Secure 
               Execution Environment for Autonomous AI Agents},
  journal   = {Preprint},
  year      = {2026},
  month     = {January},
  url       = {https://github.com/defi-hub/MIS}
}
```

Or use [CITATION.cff](CITATION.cff).

---

## Research Status

- **Paper**: Submitted for peer review (January 2026)
- **Implementation**: Proof of Concept
- **Deployment**: Not production-ready

This work is part of ongoing research in AI safety and operating systems security.

---

## License

MIT License - see [LICENSE](LICENSE) file.

---

## Contact

**Author**: Sergey Defis  
**Email**: xoomi16@gmail.com  
**Issues**: [GitHub Issues](https://github.com/defi-hub/MIS/issues)

---

**Disclaimer**: This is academic research. The reference implementation demonstrates concepts from the paper but is not intended for production deployment without substantial additional engineering.
