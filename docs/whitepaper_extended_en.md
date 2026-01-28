**MIS — The Complete Architecture (What Was Left Out of the Academic Paper)**

**Author:** Sergey Defis  
**Date:** January 2026

---

## Introduction

MIS (Modular Intelligence Spaces) is not an operating system and not just a sandbox. It is an architectural pattern for the safe and reproducible co-existence of humans and autonomous intelligent agents on a single host, where the kernel acts as a trusted arbiter, not a passive execution platform.

The academic paper on MIS highlighted three key ideas that are important to explicitly state and develop here:

* **TOCTOU-resistant access control** – inode- and VFS-level checks intercepted at the LSM/eBPF level before syscall execution; the goal is to minimize race condition windows and prevent TOCTOU exploits.
* **Dual Bloom-policy** – compact allow/deny filters in eBPF for sub-30s response to security events, with userspace fallback and stateful maps for resolving ambiguous cases.
* **Embodied learning (three-stream logging)** – continuous collection of execution signals: telemetry (runtime metrics), trace (behavioral logs), and outcome (verifiable results). These streams form the data source for the Curator Layer and training.

This document unites the original academic logic and extends it with practical layers: curator filtration, debug-pipeline, smart-sampler, diagnostic isolation, and operational discipline for safe deployment.

**Paper:** zenodo.18381505  
**Code:** https://github.com/defi-hub/MIS

---

## Key Idea: Subject-Oriented Architecture

In MIS, the important entity is not a process or container as a syntactic object, but the subject of an action: the user and the agent are different sources of intent, with different risk classes and rights. The arbitration of these relationships is moved to the kernel level: policies are enforced before the system call (LSM/eBPF), not after. This provides a practical guarantee of fail-secure host behavior during violations in the agent's space.

The technical foundation combines eBPF/LSM hooks for fast enforcement, lightweight Bloom structures, and a userspace Policy Engine for stateful decisions. The Agent is considered a long-lived entity with reputation and state, not a disposable PID.

---

## Architecture Components (Overview)

* **Kernel arbiter (eBPF + LSM hooks)** – early filtering of critical events. Example: `reference_implementation/ebpf/mis_lsm.c`
* **Policy Engine (userspace, Rust)** – decision making, telemetry aggregation, coordination of dynamic policies, and rollbacks. See `policy_engine/main.rs`
* **Curator Layer** – filtration and preparation of data before it enters the training pool (Conservative/Explorer curators, Meta‑Scorer)
* **Debug Pipeline** – P0/P1/P2 priority queue with light/heavy analysis
* **Smart Sampler** – human-in-the-loop selection of examples based on uncertainty × risk with a budget (example: max 20 requests/hour)
* **Data Versioning & Reproducibility** – data snapshots, binding the model to the data version and hyperparameters
* **Distributed Embodied Learning (center–edge)** – log aggregation → simulations → distillation of updates to the edge
* **Agent-world sharing** – exportable, versioned world-snapshots (filesystem image + state + logs + policy); cryptographic provenance

---

## Biological Metaphor and Its Engineering Interpretation

The original paper used the metaphor of "agent as an organism." This is not just a literary metaphor: it intuitively highlights the practical properties of the architecture:

* **Host** = skeleton and tools (IDE, compiler, infrastructure)
* **Namespace** = the agent's body (ephemeral, can be recreated atomically)
* **eBPF/LSM** = innate immunity (executes at kernel level, cannot be terminated from within)

In engineering terms, this means: the design must ensure that the destruction of the agent's body does not lead to host compromise; recreating the agent's world is a fast and deterministic process.

---

## Curator Layer — Data Filtration Architecture (Detailed)

The Curator Layer solves the problem of data poisoning and quality degradation during scaling.

* **Conservative Curator:** selects stable patterns (example criterion: success_rate > 95%). Throughput limitation example: max 1000 changes/hour.
* **Explorer Curator:** marks innovative patterns for human review (novelty detection, isolation forest), throughput ≈ 500 changes/hour.
* **Meta‑Scorer:** monitors curator health, Statistical Process Control (SPC), auto-rollback upon degradation.

Each candidate trajectory is supplied with metadata: provenance, confidence, risk_score, lineage. Before entering the production data lake, the candidate undergoes simulated validation in a virtual edge environment.

---

## Debug Pipeline: Priority Queue and Debug Patterns

With thousands of edge devices, a hierarchy for incident analysis is necessary:

* **P0 (KillSwitch/CRITICAL):** emergency shutdowns, throughput ~50 failures/hour, heavy debugger
* **P1 (Complex/HIGH):** segfaults, attempted escalations, heavy debugger
* **P2 (Simple/LOW):** timeouts, dependency errors, light debugger, throughput ~1000 failures/hour

**Debug Tools:**
* **Light Debugger:** pattern matching and auto-remediation for trivial errors
* **Heavy Debugger:** stack trace symbolization, memory dump analysis, ML-based root cause search (embedding + vector DB + similar failures retrieval)

This reduces the average analysis time for mass failures from tens of hours to several hours (see the metrics section in the original paper).

---

## Smart Sampler: Human-in-the-Loop with Resource Efficiency

Active Learning via uncertainty × risk ensures that only critical cases reach the operator:

* **Budget:** e.g., max 20 requests/hour
* **Uncertainty:** entropy of model logits
* **Risk:** heuristic score (presence of sudo, production env, destructive commands)
* **Combined Score:** score = uncertainty × risk; Top‑K → human review

The system tracks fatigue: average review time and decision patterns; upon detecting fatigue, it reduces the flow and suggests a role change.

---

## Distributed Embodied Learning and Exchange of Agent-Worlds

**Center–edge architecture:** central foundation model + virtual edge simulator + training pipelines.

Edge devices send three log streams; the Curator filters, simulates, and aggregates; successful patterns are distilled back to the edge.

**Agent-world sharing:** exporting a world-snapshot = image + state + logs + curator decisions + policy version. This provides reproducibility and auditability.

---

## Security: Critical Vulnerabilities and Realistic Protection Measures

Below are the main failure modes and recommended mitigations, implementable without unrealistic assumptions.

### 1. Arbiter as an Attack Target
* **Measure:** Minimize TCB; deny-by-default; signed and versioned policy releases; policy-as-code with CI
* **Insight:** The arbiter must be simpler than the agent in complexity and more transparent in modifiability

### 2. Reward-Hacking
* **Measure:** Property-based testing (invariants), multi-stage validation (syntactic → semantic → behavioral), adversarial tests
* **Insight:** Check the properties of the output, not just the final artifact

### 3. Policy Degradation
* **Measure:** Policy lifecycle: versioning, unit tests, canary deployments, automatic rollback

### 4. Curator Becomes a Manual Bottleneck
* **Measure:** Formalization of criteria, provenance store, curator metrics, and auto-rollback upon degradation

### 5. Diagnostic Mode / "Illusion of Escape" — a Laboratory, Not a Namespace
* **Measure:** Diagnostic mode is implemented as a strictly isolated laboratory: virtual machine / hypervisor (KVM/QEMU) or disposable hardware-based foundation (unikernel, hw-backed enclave), with controlled egress and signed images. Do not use the host's shared namespace for diagnostic mode.

### 6. Semantic Attacks and Input Hardening
* **Measure:** Signed artifacts, strict typing, validators, prohibition of self-modifying policies without human approval

### 7. Overfitting to the Sandbox
* **Measure:** Domain randomization, ensemble arbiters, unknown holdout tests

### 8. Performance and Latency
* **Measure:** Hybrid enforcement (coarse-grained baseline + fine-grained risky zones), signed allowlist cache with TTL, asynchronous auditing

### 9. Human Contract Errors
* **Measure:** Contract fuzzers, property tests, approval workflows

---

## Formalized Philosophy of Selection and Managed Conflict (Supplement)

MIS transforms the definition of "intelligence" in an applied environment: not the style of reasoning, but the reliability of contract execution. This is contrasted with the LLM paradigm optimized for likelihood: MIS optimizes for reliability in a formal environment.

### Errors as an Engineering Resource
Errors are not eliminated out of context: they are recorded, simulated, and used as a signal for policy updates. Security is achieved through a high-speed loop: action → arbitration → selection → update.

### LLM as Cognitive Engine, MIS as Executive Framework
The LLM continues to generate hypotheses and plans; MIS is the executive skeleton, immune system, and arbiter that verifies, restricts, and records behavior. This moves the problem of hallucinations from the plane of "model quality" to the plane of "contract correctness."

### Managed Conflict
Adversarial agents and diagnostic tests are built-in elements of the pipeline. Controlled provocations serve to identify weak points and generate data for fixes, not to punish agents.

### Diagnostic Mode ("Illusion of Escape")
Diagnostic mode is an isolated laboratory for stress tests. The agent is placed there for a limited time in a disposable image; the environment collects detailed trajectories and escalation patterns for subsequent analysis and policy updates. This is not a mass breakout or an exploitation surface.

---

## Practical Set of Steps for Safe Deployment

1. **Minimum viable arbiter:** minimal TCB, deny-by-default
2. **Policy-as-code + CI/CD + signed policy releases**
3. **Curator formalization + immutable provenance store**
4. **Diagnostic mode = VM/hypervisor + ephemeral signed images**
5. **Domain-randomized testing + unknown holdout pools**
6. **Adaptive enforcement + caching**
7. **Monitoring, health checks, and automatic rollback**

These steps are compatible with the reference implementation and do not require kernel modification.

---

## Conclusion

MIS is an engineering infrastructure for the selection and evolution of agents, not a philosophical manifesto. The technical solutions (TOCTOU-control, dual Bloom-policies, eBPF/LSM, curator, debug pipeline) form a practical set for the safe co-existence of humans and autonomous agents on a single host. When operational discipline is followed (policy lifecycle, diagnostic isolation, domain randomization), the architecture remains applicable in the real world, while preserving the ability to recover and develop models through controlled evolution.

---

## Appendix — Links to Sources and Documents (Key Artifacts)

* **Repository:** https://github.com/defi-hub/MIS
* **Architecture:** https://github.com/defi-hub/MIS/blob/main/docs/architecture.md
* **eBPF/LSM:** https://github.com/defi-hub/MIS/blob/main/reference_implementation/ebpf/mis_lsm.c
* **Policy engine:** https://github.com/defi-hub/MIS/blob/main/policy_engine/main.rs
* **Config:** https://github.com/defi-hub/MIS/blob/main/reference_implementation/config/mis_final_config.toml
* **Zenodo:** https://zenodo.org/records/18381505
* **Telegram channel with open direct:** @def.blog

*(Translation of the original article)*

