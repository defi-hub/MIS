VERSION := 2.0.0
BUILD_DIR := build
INSTALL_DIR := /etc/mis
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
CARGO ?= cargo
KERNEL_RELEASE := $(shell uname -r)
KERNEL_HEADERS := /lib/modules/$(KERNEL_RELEASE)/build

BPF_CFLAGS := -target bpf -D__TARGET_ARCH_x86_64 \
	-I$(KERNEL_HEADERS)/arch/x86/include/generated \
	-I$(KERNEL_HEADERS)/include \
	-I/usr/include/bpf \
	-O2 -g -Wall \
	-DMIS_VERSION_MAJOR=2 \
	-DMIS_VERSION_MINOR=0 \
	-DMIS_VERSION_PATCH=0

.PHONY: all clean install uninstall test ebpf userspace proto help

all: ebpf userspace

help:
	@echo "MIS v$(VERSION) Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build eBPF module and userspace (default)"
	@echo "  ebpf       - Build eBPF LSM module only"
	@echo "  userspace  - Build Rust policy engine only"
	@echo "  proto      - Regenerate gRPC protobuf code"
	@echo "  test       - Run tests"
	@echo "  install    - Install to $(INSTALL_DIR)"
	@echo "  uninstall  - Remove from $(INSTALL_DIR)"
	@echo "  clean      - Clean build artifacts"

ebpf: $(BUILD_DIR)/mis_lsm.o

$(BUILD_DIR)/mis_lsm.o: ebpf/mis_lsm.c | $(BUILD_DIR)
	@echo "Building eBPF LSM module v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@
	@echo "✓ eBPF module built: $@"

userspace: proto
	@echo "Building Rust policy engine v$(VERSION)..."
	$(CARGO) build --release
	@echo "✓ Policy engine built: target/release/mis-policy-engine"

proto:
	@echo "Generating gRPC code from protobuf..."
	@# Proto code generation is handled by build.rs
	@echo "✓ Proto code will be generated during Cargo build"

test:
	@echo "Running tests..."
	$(CARGO) test

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	$(CARGO) clean

install: all
	@echo "Installing MIS Policy Engine v$(VERSION)..."
	install -d -m 755 $(INSTALL_DIR)/policy
	install -d -m 755 $(INSTALL_DIR)/bpf
	install -d -m 755 /var/log/mis
	install -d -m 755 /var/lib/mis
	install -m 644 $(BUILD_DIR)/mis_lsm.o $(INSTALL_DIR)/bpf/
	install -m 755 target/release/mis-policy-engine $(INSTALL_DIR)/
	install -m 644 config/config.toml $(INSTALL_DIR)/config.toml.example
	@if [ ! -f $(INSTALL_DIR)/config.toml ]; then \
		install -m 644 config/config.toml $(INSTALL_DIR)/config.toml; \
	fi
	@echo ""
	@echo "✓ Installation complete!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Review config: $(INSTALL_DIR)/config.toml"
	@echo "2. Start service: systemctl start mis-policy-engine"
	@echo "3. Check logs: journalctl -u mis-policy-engine -f"

uninstall:
	@echo "Uninstalling MIS Policy Engine..."
	rm -rf $(INSTALL_DIR)
	rm -rf /var/log/mis
	rm -rf /var/lib/mis
	@echo "✓ Uninstallation complete"

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
