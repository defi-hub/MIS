# MIS v2.1.1 Deployment Guide

Complete step-by-step guide for deploying MIS in production.

---

## 📋 Pre-Deployment Checklist

### System Requirements

- [ ] Linux kernel ≥ 5.15
- [ ] x86_64 CPU architecture
- [ ] 4 GB RAM minimum (8 GB recommended)
- [ ] 2 GB free disk space
- [ ] eBPF LSM enabled

### Verify Kernel Support

```bash
# Check kernel version
uname -r  # Should be ≥ 5.15

# Check eBPF LSM support
cat /boot/config-$(uname -r) | grep CONFIG_BPF_LSM
# Should output: CONFIG_BPF_LSM=y

# Check loaded LSMs
cat /sys/kernel/security/lsm
# Should include "bpf" in the list
```

**If `bpf` is missing from LSM list:**

```bash
sudo nano /etc/default/grub

# Add "bpf" to GRUB_CMDLINE_LINUX:
GRUB_CMDLINE_LINUX="lsm=lockdown,yama,integrity,apparmor,bpf"

sudo update-grub
sudo reboot
```

---

## 🔧 Installation

### 1. Install Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    clang-14 \
    llvm-14 \
    libelf-dev \
    linux-headers-$(uname -r) \
    pkg-config \
    protobuf-compiler \
    python3-pip \
    python3-venv

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustc --version  # Should be ≥ 1.75
```

### 2. Build MIS

```bash
git clone https://github.com/defi-hub/MIS.git
cd MIS

# Checkout v2.1.1
git checkout v2.1.1

# Build eBPF enforcer + orchestrator
make all
```

**Expected output:**
```
Building eBPF enforcer...
✓ enforcer/token_validator.c → build/mis_enforcer.o

Building Rust orchestrator...
✓ Cargo build --release
✓ target/release/mis-orchestrator

Build complete!
```

### 3. Install System-Wide

```bash
sudo make install
```

**This installs:**
```
/etc/mis/
├── bpf/
│   └── mis_enforcer.o          # eBPF object
├── intents/
│   ├── research.yaml
│   ├── deploy.yaml
│   ├── test.yaml
│   └── analyze.yaml
├── config.toml                 # Main config
└── keys/                       # Created in next step

/usr/local/bin/
└── mis-orchestrator            # Main binary

/var/log/mis/                   # Logs
/var/lib/mis/                   # State
```

### 4. Generate Signing Keys

```bash
# Create keys directory
sudo mkdir -p /etc/mis/keys

# Generate Ed25519 key pair
# Option 1: Use OpenSSL
openssl genpkey -algorithm ED25519 -out /tmp/mis_signing.key
sudo mv /tmp/mis_signing.key /etc/mis/keys/signing.key
sudo chmod 600 /etc/mis/keys/signing.key

# Option 2: Use built-in keygen (if available)
# sudo mis-keygen --output /etc/mis/keys/signing.key
```

---

## ⚙️ Configuration

### Edit `/etc/mis/config.toml`

```toml
[paths]
bpf_object = "/etc/mis/bpf/mis_enforcer.o"
audit_log = "/var/log/mis/audit.log"
policy_state = "/var/lib/mis/state.json"

[grpc]
enabled = true
bind_address = "127.0.0.1"  # Change to 0.0.0.0 for remote access
port = 50051
tls_enabled = false  # Enable for production

[orchestrator]
token_signing_key = "/etc/mis/keys/signing.key"
default_ttl_secs = 3600  # 1 hour

[logging]
level = "info"  # "debug" for troubleshooting
format = "json"
file_output = true
stdout_output = true

[metrics]
enabled = true
bind_address = "127.0.0.1"
port = 9090
```

### Production Hardening

**1. Enable TLS for gRPC:**

```bash
# Generate certificates
openssl req -x509 -newkey rsa:4096 \
    -keyout /etc/mis/certs/server.key \
    -out /etc/mis/certs/server.crt \
    -days 365 -nodes \
    -subj "/CN=mis-orchestrator"

# Update config.toml
[grpc]
tls_enabled = true
tls_cert_path = "/etc/mis/certs/server.crt"
tls_key_path = "/etc/mis/certs/server.key"
```

**2. Restrict file permissions:**

```bash
sudo chmod 600 /etc/mis/keys/signing.key
sudo chmod 600 /etc/mis/certs/server.key
sudo chown root:root /etc/mis/keys/*
```

**3. Configure firewall:**

```bash
# Only allow localhost by default
sudo ufw allow from 127.0.0.1 to any port 50051

# For remote access (use with TLS!)
# sudo ufw allow from <trusted-ip> to any port 50051
```

---

## 🚀 Starting MIS

### Option 1: Systemd Service (Recommended)

**Create service file:**

```bash
sudo nano /etc/systemd/system/mis-orchestrator.service
```

```ini
[Unit]
Description=MIS Orchestrator v2.1.1
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/mis-orchestrator /etc/mis/config.toml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Resource limits
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

**Start service:**

```bash
sudo systemctl daemon-reload
sudo systemctl start mis-orchestrator
sudo systemctl enable mis-orchestrator

# Check status
sudo systemctl status mis-orchestrator
```

**Expected output:**
```
● mis-orchestrator.service - MIS Orchestrator v2.1.1
   Loaded: loaded (/etc/systemd/system/mis-orchestrator.service)
   Active: active (running) since ...
   
Feb 05 10:00:00 host mis-orchestrator[1234]: {"level":"INFO","msg":"MIS Orchestrator v2.1.1 starting..."}
Feb 05 10:00:00 host mis-orchestrator[1234]: {"level":"INFO","msg":"BPF enforcer loaded"}
Feb 05 10:00:00 host mis-orchestrator[1234]: {"level":"INFO","msg":"gRPC server listening on 127.0.0.1:50051"}
```

### Option 2: Manual Start (Testing)

```bash
sudo /usr/local/bin/mis-orchestrator /etc/mis/config.toml
```

**To run in background:**
```bash
sudo nohup /usr/local/bin/mis-orchestrator /etc/mis/config.toml \
    > /var/log/mis/orchestrator.log 2>&1 &
```

---

## ✅ Verification

### 1. Check gRPC API

```bash
# Install grpcurl
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# List services
grpcurl -plaintext localhost:50051 list

# Expected output:
# mis.orchestrator.v1.OrchestrationService
# grpc.reflection.v1alpha.ServerReflection

# Get stats
grpcurl -plaintext localhost:50051 \
    mis.orchestrator.v1.OrchestrationService/GetStats

# Expected output:
# {
#   "tokenValidated": "0",
#   "allowed": "0",
#   "denied": "0"
# }
```

### 2. Check Logs

```bash
# Systemd logs
sudo journalctl -u mis-orchestrator -f

# File logs
sudo tail -f /var/log/mis/audit.log
```

### 3. Run Demo

```bash
# Install Python dependencies
pip3 install grpcio grpcio-tools requests

# Run demo
python3 examples/demo_research_agent.py
```

**Expected output:**
```
=== MIS Research Agent Demo ===

MIS orchestrator connected: 0 total decisions

Creating MIS session with RESEARCH intent...

✓ Session created: ID=1
✓ Capabilities: 0x9

[1/5] Fetching papers from arXiv (allowed)...
      ✓ SUCCESS: Status 200

...

=== Session Statistics ===
Session ID:       1
State:            ACTIVE
Violations:       0
DEFCON Level:     5/5
```

---

## 📊 Monitoring

### Prometheus Metrics

**Scrape configuration:**

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: 'mis'
    static_configs:
      - targets: ['localhost:9090']
```

**Available metrics:**
```
mis_token_validated_total
mis_token_expired_total
mis_allowed_total
mis_denied_total
mis_sessions_active
mis_defcon_escalations_total
```

### Grafana Dashboard

Import dashboard from `monitoring/grafana-dashboard.json` (if available).

**Key metrics to monitor:**
- Token validation rate
- Denial rate (should be low)
- Session count
- DEFCON escalations (should be rare)

---

## 🐛 Troubleshooting

### Issue: "Failed to load BPF object"

**Symptoms:**
```
ERROR Failed to load BPF object: BPF LSM not enabled
```

**Solution:**
1. Verify kernel support: `cat /sys/kernel/security/lsm | grep bpf`
2. If missing, add to GRUB (see Pre-Deployment Checklist)
3. Reboot

### Issue: "Permission denied"

**Symptoms:**
```
PermissionError: [Errno 1] Operation not permitted
```

**Solution:**
MIS requires root privileges:
```bash
sudo python3 examples/demo_research_agent.py
```

### Issue: "gRPC connection refused"

**Symptoms:**
```
grpc._channel._InactiveRpcError: Connection refused
```

**Solution:**
1. Check orchestrator is running:
   ```bash
   sudo systemctl status mis-orchestrator
   ```

2. Check port binding:
   ```bash
   sudo netstat -tulpn | grep 50051
   ```

3. Check firewall:
   ```bash
   sudo ufw status
   ```

### Issue: "High memory usage"

**Symptoms:**
Orchestrator using >1 GB RAM with few sessions.

**Solution:**
1. Check active sessions:
   ```bash
   grpcurl -plaintext localhost:50051 \
       mis.orchestrator.v1.OrchestrationService/ListSessions
   ```

2. Terminate zombie sessions:
   ```bash
   grpcurl -plaintext -d '{"session_id": 123}' localhost:50051 \
       mis.orchestrator.v1.OrchestrationService/TerminateSession
   ```

3. Restart orchestrator:
   ```bash
   sudo systemctl restart mis-orchestrator
   ```

---

## 🔄 Maintenance

### Log Rotation

```bash
# /etc/logrotate.d/mis
/var/log/mis/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        systemctl reload mis-orchestrator
    endscript
}
```

### Backup

**Critical files to backup:**
```bash
/etc/mis/keys/signing.key       # Signing key (SECRET!)
/etc/mis/config.toml            # Configuration
/etc/mis/intents/*.yaml         # Custom intents
/var/lib/mis/state.json         # Session state
```

**Backup script:**
```bash
#!/bin/bash
BACKUP_DIR=/backup/mis/$(date +%Y%m%d)
mkdir -p $BACKUP_DIR

cp -r /etc/mis/keys $BACKUP_DIR/
cp /etc/mis/config.toml $BACKUP_DIR/
cp -r /etc/mis/intents $BACKUP_DIR/
cp /var/lib/mis/state.json $BACKUP_DIR/

# Encrypt backup
tar czf - $BACKUP_DIR | gpg -e -r admin@example.com > $BACKUP_DIR.tar.gz.gpg
rm -rf $BACKUP_DIR
```

### Updates

```bash
# Fetch latest
cd MIS
git fetch origin

# Checkout new version
git checkout v2.1.2  # or latest

# Rebuild
make clean
make all

# Stop service
sudo systemctl stop mis-orchestrator

# Install update
sudo make install

# Restart service
sudo systemctl start mis-orchestrator

# Verify
sudo systemctl status mis-orchestrator
```

---

## 📞 Support

- **Documentation:** https://github.com/defi-hub/MIS/tree/main/docs
- **Issues:** https://github.com/defi-hub/MIS/issues
- **Discussions:** https://github.com/defi-hub/MIS/discussions
- **Email:** xoomi16@gmail.com

---

## ✅ Production Checklist

Before going live:

- [ ] Kernel ≥ 5.15 with eBPF LSM
- [ ] All dependencies installed
- [ ] MIS built and installed
- [ ] Signing keys generated and secured
- [ ] Configuration reviewed
- [ ] TLS enabled for gRPC
- [ ] Firewall configured
- [ ] Systemd service enabled
- [ ] Logs rotating
- [ ] Backup configured
- [ ] Monitoring (Prometheus) configured
- [ ] Demo tested successfully
- [ ] Intent contracts customized
- [ ] Team trained on SDK usage

---

**Ready for production deployment!** 🚀
