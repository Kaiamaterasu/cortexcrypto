# CortexCrypt Build System
# Copyright 2024 CortexCrypt Contributors
# Licensed under Apache 2.0

.PHONY: all clean install uninstall test lib daemon cli sdks examples

# Build configuration
BUILD_DIR ?= build
CMAKE_BUILD_TYPE ?= Release
PREFIX ?= /usr/local

# Dependencies check
DEPS = cmake pkg-config libssl-dev libargon2-dev libonnxruntime-dev

all: lib daemon cli sdks

# Check dependencies
deps-check:
	@echo "Checking dependencies..."
	@which cmake > /dev/null || (echo "ERROR: cmake not found" && exit 1)
	@which pkg-config > /dev/null || (echo "ERROR: pkg-config not found" && exit 1)
	@pkg-config --exists openssl || (echo "ERROR: OpenSSL development files not found (libssl-dev)" && exit 1)
	@pkg-config --exists libargon2 || (echo "ERROR: Argon2 development files not found (libargon2-dev)" && exit 1)
	@echo "Dependencies OK"

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build core library
lib: $(BUILD_DIR) deps-check
	cd lib && cmake -B ../$(BUILD_DIR)/lib -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE)
	cd $(BUILD_DIR)/lib && make -j$(shell nproc)

# Build daemon
daemon: lib
	cd cortexd && cmake -B ../$(BUILD_DIR)/cortexd -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE)
	cd $(BUILD_DIR)/cortexd && make -j$(shell nproc)

# Build CLI
cli: lib
	cd cli && cmake -B ../$(BUILD_DIR)/cli -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE)
	cd $(BUILD_DIR)/cli && make -j$(shell nproc)

# Build SDKs
sdks: lib
	# C++ SDK (header-only)
	@echo "C++ SDK ready (header-only)"
	
	# Rust SDK
	cd sdk/rust && cargo build --release
	
	# Python SDK
	cd sdk/python && python3 setup.py build_ext --inplace

# Build examples
examples: sdks
	# C example
	cd examples/c && cmake -B ../../$(BUILD_DIR)/examples/c -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE)
	cd $(BUILD_DIR)/examples/c && make -j$(shell nproc)
	
	# C++ example
	cd examples/cpp && cmake -B ../../$(BUILD_DIR)/examples/cpp -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE)
	cd $(BUILD_DIR)/examples/cpp && make -j$(shell nproc)
	
	# Rust example
	cd examples/rust && cargo build --release
	
	# Python example (no build needed)
	@echo "Python example ready"

# Generate models
models:
	cd tools && python3 seed_kdf_mlp.py
	cd tools && python3 train_autoencoder.py

# Install system-wide
install: all
	@echo "🚀 Installing CortexCrypt system-wide..."
	# Create directories
	sudo mkdir -p /usr/local/bin /usr/local/lib /usr/local/share/cortex
	# Install binaries
	sudo cp build/cli/cortexcrypt /usr/local/bin/ 2>/dev/null || echo "CLI not built"
	sudo cp simple_daemon /usr/local/bin/ 2>/dev/null || echo "Simple daemon not built"
	@if [ -f build/daemon/cortexd ]; then sudo cp build/daemon/cortexd /usr/local/bin/; fi
	# Install library  
	@if [ -f build/lib/libcortex.so ]; then sudo cp build/lib/libcortex.so /usr/local/lib/; fi
	# Install docs
	sudo cp *.md /usr/local/share/cortex/ 2>/dev/null || true
	sudo cp requirements.txt /usr/local/share/cortex/ 2>/dev/null || true
	# Set permissions
	sudo chmod +x /usr/local/bin/cortexcrypt 2>/dev/null || true
	sudo chmod +x /usr/local/bin/simple_daemon 2>/dev/null || true
	@if [ -f /usr/local/bin/cortexd ]; then sudo chmod +x /usr/local/bin/cortexd; fi
	sudo ldconfig 2>/dev/null || true
	@echo "✅ CortexCrypt installed!"

# Uninstall (only via cortexctl)
uninstall:
	@echo "ERROR: Use 'cortexctl uninstall' for secure removal"
	@echo "Manual uninstall violates CortexCrypt security model"
	@exit 1

# Run tests
test: all
	cd tests && python3 -m pytest unit/ -v
	cd tests && ./integration/test_full_flow.sh
	cd tests && python3 fuzz/fuzz_header.py

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	cd sdk/rust && cargo clean
	cd examples/rust && cargo clean
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} +

# Development helpers
format:
	find . -name "*.c" -o -name "*.h" -o -name "*.cpp" -o -name "*.hpp" | xargs clang-format -i
	cd sdk/rust && cargo fmt
	cd examples/rust && cargo fmt

lint:
	find . -name "*.c" -o -name "*.h" | xargs cppcheck --enable=warning,style,performance
	cd sdk/rust && cargo clippy
	cd examples/rust && cargo clippy

# Show build status
status:
	@echo "=== CortexCrypt Build Status ==="
	@echo "Build directory: $(BUILD_DIR)"
	@echo "Install prefix: $(PREFIX)"
	@echo "Components:"
	@[ -f "$(BUILD_DIR)/lib/libcortexcrypt.so" ] && echo "  ✓ Core library" || echo "  ✗ Core library"
	@[ -f "$(BUILD_DIR)/cortexd/cortexd" ] && echo "  ✓ Daemon" || echo "  ✗ Daemon"
	@[ -f "$(BUILD_DIR)/cli/cortexcrypt" ] && echo "  ✓ CLI" || echo "  ✗ CLI"
	@[ -f "sdk/rust/target/release/libcortexcrypt_rs.rlib" ] && echo "  ✓ Rust SDK" || echo "  ✗ Rust SDK"
	@[ -f "sdk/python/cortexcrypt/_ffi.*.so" ] && echo "  ✓ Python SDK" || echo "  ✗ Python SDK"
	@[ -f "models/kdf_mlp.onnx" ] && echo "  ✓ Models" || echo "  ✗ Models"

help:
	@echo "CortexCrypt Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all         - Build library, daemon, CLI, and SDKs"
	@echo "  lib         - Build core C library"
	@echo "  daemon      - Build cortexd daemon"
	@echo "  cli         - Build cortexcrypt CLI"
	@echo "  sdks        - Build language SDKs"
	@echo "  examples    - Build all examples"
	@echo "  models      - Generate ONNX models"
	@echo "  install     - Install system-wide (requires sudo)"
	@echo "  test        - Run all tests"
	@echo "  clean       - Clean build artifacts"
	@echo "  format      - Format source code"
	@echo "  lint        - Run static analysis"
	@echo "  status      - Show build status"
	@echo "  deps-check  - Verify build dependencies"
	@echo ""
	@echo "Variables:"
	@echo "  BUILD_DIR   - Build directory (default: build)"
	@echo "  PREFIX      - Install prefix (default: /usr/local)"
