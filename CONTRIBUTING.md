# Contributing to MIS

Thank you for your interest in contributing to Modular Intelligence Spaces (MIS)! This document provides guidelines for contributing to the project.

---

## Table of Contents

1. [Project Status](#project-status)
2. [How to Contribute](#how-to-contribute)
3. [Development Setup](#development-setup)
4. [Contribution Areas](#contribution-areas)
5. [Code Guidelines](#code-guidelines)
6. [Pull Request Process](#pull-request-process)
7. [Community](#community)

---

## Project Status

**Important**: MIS v2.1 is a **reference architecture** released under MIT license.

- ✅ **Complete**: eBPF enforcer, architectural design, protocols
- ⚠️ **Partial**: Orchestrator implementation, SDK bindings
- ❌ **Planned**: Full formal verification, hardware TEE integration

We welcome contributions to **all** areas, from bug fixes to major features.

---

## How to Contribute

### Reporting Issues

**Before creating an issue**, please:

1. Search existing issues to avoid duplicates
2. Provide detailed reproduction steps
3. Include system information (kernel version, OS, etc.)
4. Attach relevant logs from `/var/log/mis/`

**Issue templates:**

- 🐛 **Bug Report**: For software defects
- ✨ **Feature Request**: For new capabilities
- 📖 **Documentation**: For doc improvements
- 🔬 **Research**: For academic/theoretical contributions

### Suggesting Features

Feature requests should include:

- **Use case**: Why is this needed?
- **Proposed solution**: How should it work?
- **Alternatives considered**: What other approaches exist?
- **Impact**: Who benefits? Performance implications?

---

## Development Setup

### Fork and Clone

```bash
# Fork the repository on GitHub
# Then clone your fork
git clone https://github.com/YOUR_USERNAME/MIS.git
cd MIS

# Add upstream remote
git remote add upstream https://github.com/defi-hub/MIS.git
```

### Build Development Version

```bash
# Install dependencies (see QUICKSTART.md)

# Build with debug symbols
make clean
RUST_LOG=debug cargo build

# Build eBPF with verbose output
make ebpf V=1
```

### Run Tests

```bash
# Run Rust tests
cargo test

# Run eBPF tests (requires root)
sudo make test-ebpf

# Run integration tests
sudo python3 tests/integration/test_all.py
```

### Development Workflow

```bash
# Create feature branch
git checkout -b feature/my-awesome-feature

# Make changes
vim src/my_file.rs

# Test locally
cargo test
sudo make test-ebpf

# Commit with clear message
git commit -m "Add awesome feature X

- Implements Y
- Fixes #123
- Benchmarks show 10x improvement"

# Push to your fork
git push origin feature/my-awesome-feature
```

---

## Contribution Areas

### 1. eBPF Enforcer (C)

**Skills needed**: C, eBPF, Linux kernel knowledge

**Priority tasks**:
- [ ] Implement Ed25519 signature verification in eBPF
- [ ] Optimize token validation (<30ns target)
- [ ] Add network capability enforcement (socket hooks)
- [ ] Implement JIT policy tail calls

**File location**: `enforcer/token_validator.c`

**Testing**:
```bash
make ebpf
sudo bpftool prog load build/mis_enforcer.o /sys/fs/bpf/mis
sudo bpftool prog tracelog
```

### 2. Orchestrator (Rust)

**Skills needed**: Rust, async programming, distributed systems

**Priority tasks**:
- [ ] Complete token service implementation
- [ ] Policy compiler (YAML → eBPF bytecode)
- [ ] Session migration protocol
- [ ] Distributed orchestration (Raft)

**File location**: `src/`

**Testing**:
```bash
cargo test --package mis-policy-engine
```

### 3. SDK Development (Multiple Languages)

**Skills needed**: Language-specific expertise

**Status**:
- Python: 40% complete (basic session management)
- Go: Not started
- Rust: Not started
- JavaScript: Not started

**Priority**:
- [ ] Complete Python SDK (`sdk/python/`)
- [ ] Start Go SDK (`sdk/go/`)
- [ ] JavaScript/TypeScript SDK for Node.js

### 4. Documentation

**Skills needed**: Technical writing

**Priority tasks**:
- [ ] API reference documentation
- [ ] Tutorial videos/screencasts
- [ ] Deployment guide for production
- [ ] Intent contract cookbook (common patterns)
- [ ] Translate documentation (Chinese, Japanese, Korean)

**File location**: `docs/`

### 5. Research & Formal Verification

**Skills needed**: Formal methods, cryptography, security analysis

**Priority tasks**:
- [ ] TLA+ specification completion
- [ ] P verification of DEFCON state machine
- [ ] Isabelle/HOL proofs of security properties
- [ ] Performance modeling and analysis

**File location**: `verification/`

### 6. Testing & Quality Assurance

**Skills needed**: Testing, fuzzing, security auditing

**Priority tasks**:
- [ ] Fuzz testing for intent contracts
- [ ] Load testing (1000+ concurrent sessions)
- [ ] Security audit of token protocol
- [ ] Benchmark suite expansion

**File location**: `tests/`

---

## Code Guidelines

### Rust Code Style

```rust
// Use rustfmt
cargo fmt

// Follow Rust API guidelines
// https://rust-lang.github.io/api-guidelines/

// Example: Good error handling
fn create_session(config: &Config) -> Result<Session, MisError> {
    let token = generate_token()
        .context("Failed to generate token")?;
    
    Ok(Session { token })
}

// Use descriptive names
let session_metadata = SessionMetadata::new(); // Good
let sm = SM::new(); // Bad
```

### C Code Style (eBPF)

```c
// Follow Linux kernel style
// https://www.kernel.org/doc/html/latest/process/coding-style.html

// Use helper functions for clarity
static __always_inline bool is_token_expired(
    struct capability_token *token,
    __u64 now_ns
) {
    return token->expires_at > 0 && now_ns > token->expires_at;
}

// Comment non-obvious logic
// Check capabilities with bitwise AND
// Required: CAP_READ | CAP_NETWORK
// Token has: CAP_READ | CAP_WRITE | CAP_NETWORK
// Result: (0b111 & 0b101) = 0b101 = CAP_READ | CAP_NETWORK ✓
if ((token->capabilities & required_caps) == required_caps) {
    return true;
}
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Examples:**

```
feat(enforcer): add network capability enforcement

- Implement socket_create LSM hook
- Add CAP_NETWORK validation
- Benchmark: <5ns overhead

Closes #42
```

```
fix(orchestrator): prevent token replay attacks

- Add nonce to token structure
- Validate nonce uniqueness in BPF map
- Update token signing protocol

Fixes #128
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `perf`: Performance improvement
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance

---

## Pull Request Process

### Before Submitting

1. **Ensure all tests pass**:
   ```bash
   cargo test
   sudo make test-ebpf
   ```

2. **Run formatters**:
   ```bash
   cargo fmt
   clang-format -i enforcer/*.c
   ```

3. **Update documentation** if needed

4. **Add tests** for new functionality

5. **Update CHANGELOG.md** (for significant changes)

### PR Template

When creating a pull request, include:

```markdown
## Description
Brief description of what this PR does.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Performance improvement
- [ ] Documentation update
- [ ] Refactoring

## Testing
- [ ] Added unit tests
- [ ] Added integration tests
- [ ] Tested manually on Ubuntu 24.04
- [ ] Performance benchmarks (if applicable)

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] No new warnings introduced

## Related Issues
Closes #123
```

### Review Process

1. **Automated checks** run (CI/CD)
2. **Maintainer review** within 7 days
3. **Feedback addressed** by contributor
4. **Merge** when approved

**Review criteria**:
- Code quality and clarity
- Test coverage
- Documentation completeness
- Performance impact
- Security implications

---

## Community

### Communication Channels

- **GitHub Issues**: Technical discussions, bug reports
- **GitHub Discussions**: General questions, ideas
- **Telegram**: @def.blog (real-time chat)
- **Email**: xoomi16@gmail.com (private inquiries)

### Code of Conduct

We follow the [Contributor Covenant](https://www.contributor-covenant.org/):

- Be respectful and inclusive
- Accept constructive criticism
- Focus on what's best for the community
- Show empathy towards others

**Unacceptable behavior**:
- Harassment, discrimination, or trolling
- Publishing others' private information
- Unwelcome sexual attention
- Other unprofessional conduct

**Enforcement**: Violations will result in warnings or bans.

### Recognition

**Contributors** are acknowledged in:
- `CONTRIBUTORS.md` file
- Release notes for significant contributions
- Academic papers (if applicable)

---

## License

By contributing to MIS, you agree that your contributions will be licensed under the MIT License.

---

## Getting Started

1. **Pick an issue** labeled `good-first-issue`
2. **Comment** that you're working on it
3. **Ask questions** if anything is unclear
4. **Submit PR** when ready
5. **Iterate** based on feedback

**We're here to help!** Don't hesitate to ask questions.

---

## Thank You!

Every contribution, no matter how small, makes MIS better. We appreciate your time and effort! 🙏

---

**Maintainer**: Sergey Defis ([@defi-hub](https://github.com/defi-hub))
