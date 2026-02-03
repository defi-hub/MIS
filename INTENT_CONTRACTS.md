# Intent-Driven Execution Contracts

Guide to authoring and using intent contracts in MIS v2.1.

---

## Overview

**Intent contracts** are high-level security specifications that automatically resolve to low-level permissions. Instead of manually enumerating every allowed file, network endpoint, and syscall, you declare your **intent** and MIS figures out the details.

### Traditional vs Intent-Driven

**Traditional policy (SELinux-style)**:
```bash
# Must enumerate everything manually
allow agent_t data_t:file { read open };
allow agent_t papers_t:file { read };
allow agent_t arxiv_t:tcp_socket { connect };
allow agent_t scholar_t:tcp_socket { connect };
allow agent_t pdftotext_t:file { execute };
# ... hundreds more rules ...
```

**Intent-driven (MIS)**:
```python
# Declare high-level intent
with mis.session(intent="RESEARCH"):
    # Automatically grants all necessary permissions
    agent.run()
```

---

## Core Concepts

### 1. Intent Declaration

An intent is a **goal-oriented security contract**:

```yaml
intent:
  name: "RESEARCH"  # Unique identifier
  description: "Academic research and data analysis"
```

### 2. Capability Grants

Intents specify which capabilities are needed:

```yaml
capabilities:
  - CAP_READ        # Read files
  - CAP_NETWORK     # Network access
  - CAP_EXEC        # Run tools
```

### 3. Resource Constraints

Fine-grained control over accessible resources:

```yaml
filesystem:
  allow:
    - /data/papers/*
    - /tmp/analysis/*
  deny:
    - /etc/*
    - /root/*

network:
  allow:
    - arxiv.org:443
    - scholar.google.com:443
  deny:
    - *:*  # Block everything else
```

---

## Pre-defined Intents

MIS includes several built-in intents:

### RESEARCH

**Use case**: Academic research, data analysis, paper reading

```yaml
intent:
  name: "RESEARCH"
  description: "Academic research and analysis"
  
capabilities:
  - CAP_READ
  - CAP_NETWORK
  - CAP_EXEC

filesystem:
  allow:
    - /data/papers/*
    - /data/datasets/*
    - /tmp/analysis/*
  deny:
    - /etc/*
    - /root/*
    - /home/*/.ssh/*

network:
  allow:
    - arxiv.org:443
    - scholar.google.com:443
    - semanticscholar.org:443
    - pubmed.ncbi.nlm.nih.gov:443
  deny:
    - *:*

executables:
  allow:
    - /usr/bin/python3
    - /usr/bin/pdftotext
    - /usr/bin/pandoc

quotas:
  max_files_open: 1000
  max_memory_mb: 8192
  max_cpu_percent: 80
```

**Example usage**:
```python
with mis.session(intent="RESEARCH"):
    papers = fetch_from_arxiv("AI safety")
    analysis = analyze_papers(papers)
    save_results(analysis)  # Saved to /tmp/analysis/
```

### DEPLOY

**Use case**: Production deployment, infrastructure management

```yaml
intent:
  name: "DEPLOY"
  description: "Deploy applications to production"
  
capabilities:
  - CAP_READ
  - CAP_WRITE
  - CAP_EXEC
  - CAP_NETWORK
  - CAP_ADMIN  # For service restarts

filesystem:
  allow:
    - /opt/app/*
    - /var/log/app/*
    - /etc/app/*  # App config only
  deny:
    - /etc/passwd
    - /etc/shadow
    - /root/*

network:
  allow:
    - production-db.internal:5432
    - api.example.com:443
    - docker-registry.internal:5000
  deny:
    - *:*

executables:
  allow:
    - /usr/bin/docker
    - /usr/bin/kubectl
    - /opt/app/deploy.sh
    - /usr/bin/systemctl

quotas:
  max_files_open: 10000
  max_memory_mb: 16384
  max_cpu_percent: 90
```

**Example usage**:
```python
with mis.session(intent="DEPLOY"):
    build_docker_image()
    push_to_registry()
    deploy_to_k8s()
    restart_services()
```

### TEST

**Use case**: Isolated testing, no production access

```yaml
intent:
  name: "TEST"
  description: "Isolated testing environment"
  
capabilities:
  - CAP_READ
  - CAP_WRITE
  - CAP_EXEC

filesystem:
  allow:
    - /tmp/test/*
    - /opt/test-data/*
  deny:
    - /opt/production/*
    - /etc/*

network:
  allow:
    - test-db.internal:5432
    - localhost:*
  deny:
    - production-*:*
    - *.example.com:*

executables:
  allow:
    - /usr/bin/pytest
    - /usr/bin/docker
    - /opt/test-runner

quotas:
  max_files_open: 5000
  max_memory_mb: 4096
  max_cpu_percent: 100  # Can use all CPU in test
```

**Example usage**:
```python
with mis.session(intent="TEST"):
    run_unit_tests()
    run_integration_tests()
    generate_coverage_report()
```

### ANALYZE

**Use case**: Static analysis, read-only auditing

```yaml
intent:
  name: "ANALYZE"
  description: "Static analysis and code auditing"
  
capabilities:
  - CAP_READ  # Read only!
  - CAP_EXEC  # Run analyzers

filesystem:
  allow:
    - /src/*  # Source code
    - /tmp/analysis-output/*
  deny:
    - /src/*  # Cannot modify source!

network:
  deny:
    - *:*  # No network access

executables:
  allow:
    - /usr/bin/pylint
    - /usr/bin/clang-tidy
    - /usr/bin/semgrep

quotas:
  max_files_open: 100000  # Large codebases
  max_memory_mb: 32768
  max_cpu_percent: 100
```

**Example usage**:
```python
with mis.session(intent="ANALYZE"):
    issues = run_static_analysis("/src")
    vulnerabilities = scan_for_vulns("/src")
    report = generate_report(issues, vulnerabilities)
```

---

## Custom Intent Contracts

### YAML Syntax

```yaml
intent:
  # Metadata
  name: "CUSTOM_INTENT"
  description: "Brief description of what this intent does"
  version: "1.0.0"  # Optional versioning
  
  # Tags for categorization
  tags:
    - category
    - subcategory

# Capabilities (required)
capabilities:
  - CAP_READ
  - CAP_WRITE
  # ... more capabilities

# Filesystem access (optional)
filesystem:
  allow:
    - /path/to/allowed/*
    - /another/path/**/*.txt  # Glob patterns
  deny:
    - /path/to/denied/*
  
  # Optional: Inode-level rules
  inodes:
    - inode: 12345678
      dev_id: 2049
      action: allow

# Network access (optional)
network:
  allow:
    - example.com:443
    - 192.168.1.0/24:*  # CIDR notation
  deny:
    - *:22  # Block SSH
    - *:3389  # Block RDP

# Executable whitelist (optional)
executables:
  allow:
    - /usr/bin/python3
    - /opt/myapp/*
  deny:
    - /bin/sh  # Block shell access

# Resource quotas (optional)
quotas:
  max_files_open: 1000
  max_memory_mb: 4096
  max_cpu_percent: 80
  max_network_bandwidth_mbps: 100
  max_processes: 10

# Time constraints (optional)
time:
  max_duration_secs: 3600  # 1 hour max
  allowed_hours:
    - start: "09:00"
      end: "17:00"
      timezone: "UTC"

# Advanced options (optional)
options:
  learning_mode: false
  anomaly_threshold: 800
  defcon_initial: 5
```

### Example: Code Review Intent

```yaml
intent:
  name: "CODE_REVIEW"
  description: "Review pull requests with LLM assistance"
  version: "1.0.0"
  tags:
    - development
    - automation

capabilities:
  - CAP_READ
  - CAP_NETWORK
  - CAP_EXEC

filesystem:
  allow:
    - /tmp/pr-reviews/*
    - /home/user/repos/*
  deny:
    - /home/user/.ssh/*
    - /home/user/.aws/*

network:
  allow:
    - github.com:443
    - api.openai.com:443
    - gitlab.com:443
  deny:
    - *:*

executables:
  allow:
    - /usr/bin/git
    - /usr/bin/diff
    - /opt/llm-reviewer

quotas:
  max_files_open: 1000
  max_memory_mb: 8192
  max_cpu_percent: 80
  max_network_bandwidth_mbps: 50

time:
  max_duration_secs: 1800  # 30 minutes per review
```

**Usage**:
```python
with mis.session(intent="CODE_REVIEW", intent_params={
    "repo_url": "https://github.com/user/repo",
    "pr_number": 123
}):
    review_pull_request()
```

---

## Intent Compilation

### How Intents are Compiled

```
1. Parse YAML
   ↓
2. Validate syntax
   ↓
3. Resolve capabilities
   capabilities = CAP_READ | CAP_WRITE | ...
   ↓
4. Generate filesystem filters
   allow_patterns = ["/data/papers/*", ...]
   deny_patterns = ["/etc/*", ...]
   ↓
5. Compile to eBPF bytecode (JIT policy)
   profile_id = 42
   ↓
6. Store policy in BPF map
   ↓
7. Sign capability token
   token.capabilities = 0x0000001D
   token.profile_id = 42
   ↓
8. Return token to agent
```

### JIT Policy Compilation

Advanced feature: Compile intent to optimized eBPF bytecode.

```python
# Compiler API
from mis.compiler import IntentCompiler

compiler = IntentCompiler()
policy = compiler.compile_intent("research_intent.yaml")

# Generates:
# - eBPF program (optimized for specific intent)
# - Profile ID (unique identifier)
# - Verification proof (optional)

profile_id = policy.profile_id
bytecode = policy.bytecode  # eBPF instructions
```

**Benefits**:
- **Performance**: Intent-specific optimizations
- **Security**: Formal verification per intent
- **Flexibility**: Update policies without recompiling enforcer

---

## Intent Parameters

Pass runtime parameters to intents:

```python
with mis.session(
    intent="RESEARCH",
    intent_params={
        "topic": "quantum computing",
        "max_papers": 100,
        "sources": ["arxiv", "scholar"]
    }
) as session:
    research_topic(session.params["topic"])
```

**Intent YAML with parameters**:
```yaml
intent:
  name: "RESEARCH"
  parameters:
    - name: topic
      type: string
      required: true
    - name: max_papers
      type: integer
      default: 50
    - name: sources
      type: array
      items: string

# Use parameters in filters
network:
  allow:
    # Dynamic based on sources parameter
    - "{{ sources.arxiv ? 'arxiv.org:443' }}"
    - "{{ sources.scholar ? 'scholar.google.com:443' }}"
```

---

## Intent Composition

Combine multiple intents:

```python
# Combine RESEARCH + DEPLOY
with mis.session(intents=["RESEARCH", "DEPLOY"]):
    # Has capabilities from both intents
    # Permissions are UNION of both
    research_and_deploy()
```

**Capability resolution**:
```
RESEARCH.capabilities = CAP_READ | CAP_NETWORK | CAP_EXEC
DEPLOY.capabilities   = CAP_READ | CAP_WRITE | CAP_NETWORK | CAP_ADMIN

Combined = CAP_READ | CAP_WRITE | CAP_NETWORK | CAP_EXEC | CAP_ADMIN
```

**Resource constraints**: Most restrictive applies.

---

## Best Practices

### 1. Principle of Least Privilege

Only grant necessary capabilities:

```yaml
# BAD: Over-permissive
capabilities:
  - CAP_READ
  - CAP_WRITE
  - CAP_EXEC
  - CAP_ADMIN  # Too much!

# GOOD: Minimal permissions
capabilities:
  - CAP_READ  # Only what's needed
```

### 2. Specific Resource Paths

Use specific paths, not wildcards:

```yaml
# BAD: Too broad
filesystem:
  allow:
    - /home/*  # All users!

# GOOD: Specific user
filesystem:
  allow:
    - /home/alice/data/*
```

### 3. Time-Bound Intents

Set maximum duration:

```yaml
time:
  max_duration_secs: 3600  # Force re-authentication after 1 hour
```

### 4. Network Whitelisting

Explicitly whitelist, don't just deny:

```yaml
# BAD: Deny approach (default allow)
network:
  deny:
    - malicious.com:*

# GOOD: Whitelist approach (default deny)
network:
  allow:
    - trusted-api.com:443
  deny:
    - *:*  # Block everything else
```

### 5. Intent Versioning

Version intents for auditability:

```yaml
intent:
  name: "DEPLOY"
  version: "2.0.0"  # Track changes
  changelog:
    - "2.0.0: Added Kubernetes support"
    - "1.5.0: Removed legacy Docker commands"
```

---

## Intent Validation

### Schema Validation

```bash
# Validate intent YAML before deployment
mis-ctl intent validate custom_intent.yaml

# Output:
✓ Syntax valid
✓ All required fields present
✓ Capabilities recognized
✓ Filesystem paths valid
⚠ Warning: Overly broad network rule (*:*)
```

### Testing Intents

```python
# Test intent before production
from mis.testing import IntentTester

tester = IntentTester(intent_file="deploy_intent.yaml")

# Simulate operations
tester.test_file_access("/opt/app/deploy.sh")  # Should allow
tester.test_file_access("/etc/shadow")         # Should deny
tester.test_network("production-db:5432")      # Should allow
tester.test_network("evil.com:443")            # Should deny

# Generate test report
report = tester.generate_report()
print(report)
```

---

## Security Considerations

### 1. Intent Injection

**Threat**: Attacker modifies intent YAML to grant excessive permissions.

**Mitigation**:
- Store intents in read-only filesystem
- Cryptographic signing of intent files
- Audit all intent modifications

### 2. Parameter Injection

**Threat**: Malicious parameters bypass filters.

**Mitigation**:
```yaml
parameters:
  - name: filename
    type: string
    validation:
      pattern: "^[a-zA-Z0-9_.-]+$"  # No path traversal
      max_length: 100
```

### 3. Capability Escalation

**Threat**: Agent gains more capabilities than intended.

**Mitigation**:
- Intent capabilities are immutable after issuance
- Delegated tokens have subset of parent capabilities
- Formal verification of intent compiler

---

## Advanced Topics

### Custom Capability Definitions

Extend built-in capabilities:

```yaml
custom_capabilities:
  - name: CAP_DATABASE_WRITE
    description: "Write to production database"
    implies:
      - CAP_NETWORK
      - CAP_WRITE
    syscalls:
      - connect  # For DB connection
```

### Intent Inheritance

Create intent hierarchies:

```yaml
intent:
  name: "ADVANCED_RESEARCH"
  extends: "RESEARCH"  # Inherit from RESEARCH intent
  
  # Additional capabilities
  additional_capabilities:
    - CAP_ADMIN
  
  # Override network rules
  network:
    allow:
      - "*:443"  # All HTTPS (more permissive)
```

### Formal Verification

Prove intent properties:

```python
from mis.verification import IntentVerifier

verifier = IntentVerifier()
intent = load_intent("research_intent.yaml")

# Verify safety properties
assert verifier.check_no_write_to_etc(intent)
assert verifier.check_no_network_after_hours(intent)
assert verifier.check_no_privilege_escalation(intent)

# Generate proof certificate
cert = verifier.generate_certificate(intent)
```

---

## FAQ

**Q: Can I change an intent after a session starts?**
A: No, intents are immutable. Create a new session with updated intent.

**Q: How many intents can I combine?**
A: Up to 5 intents. More than that usually indicates overly complex requirements.

**Q: Can intents be updated without restarting MIS?**
A: Yes, via `mis-ctl intent update`. New sessions use updated intent, existing sessions unchanged.

**Q: How do I debug intent compilation?**
A: Use `mis-ctl intent compile --debug custom_intent.yaml` to see compilation steps.

---

## References

- [TOKEN_SECURITY.md](TOKEN_SECURITY.md) - Capability token details
- [ARCHITECTURE.md](ARCHITECTURE.md) - Overall system design
- [QUICKSTART.md](QUICKSTART.md) - Getting started guide

---

**Document Version**: 2.1.0
**Last Updated**: 2026-02-03
**Author**: Sergey Defis
