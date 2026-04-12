#!/bin/bash
#
# CortexCrypt Installation Script
# Copyright 2024 CortexCrypt Contributors
# Licensed under Apache 2.0
#

set -e

# Configuration
PREFIX="/usr/local"
MODELS_DIR="$PREFIX/share/cortexcrypt/models"
SYSTEMD_DIR="/etc/systemd/system"
LOG_DIR="/var/log/cortex"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing_deps=()
    
    # Check build tools
    command -v cmake >/dev/null 2>&1 || missing_deps+=("cmake")
    command -v pkg-config >/dev/null 2>&1 || missing_deps+=("pkg-config")
    command -v gcc >/dev/null 2>&1 || missing_deps+=("gcc")
    
    # Check libraries
    pkg-config --exists openssl || missing_deps+=("libssl-dev")
    pkg-config --exists libargon2 || missing_deps+=("libargon2-dev")
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Install with: apt-get install ${missing_deps[*]}"
        exit 1
    fi
    
    log_info "Dependencies satisfied"
}

# Build components
build_cortexcrypt() {
    log_info "Building CortexCrypt..."
    
    # Create build directory
    mkdir -p build
    
    # Build library
    log_info "Building core library..."
    cd lib
    cmake -B ../build/lib -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PREFIX
    cd ../build/lib && make -j$(nproc)
    cd ../..
    
    # Build daemon
    log_info "Building daemon..."
    cd cortexd
    cmake -B ../build/cortexd -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PREFIX
    cd ../build/cortexd && make -j$(nproc)
    cd ../..
    
    # Build CLI
    log_info "Building CLI..."
    cd cli
    cmake -B ../build/cli -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PREFIX
    cd ../build/cli && make -j$(nproc)
    cd ../..
    
    log_info "Build completed successfully"
}

# Generate models
generate_models() {
    log_info "Generating neural network models..."
    
    # Check if Python and required packages are available
    if command -v python3 >/dev/null 2>&1; then
        cd tools
        
        # Generate KDF MLP model
        if [ -f "seed_kdf_mlp.py" ]; then
            python3 seed_kdf_mlp.py
            log_info "Generated KDF MLP model"
        else
            log_warn "KDF MLP generator not found, creating placeholder"
            mkdir -p ../models
            echo "placeholder" > ../models/kdf_mlp.onnx
        fi
        
        # Generate anomaly autoencoder (optional)
        if [ -f "train_autoencoder.py" ]; then
            python3 train_autoencoder.py
            log_info "Generated anomaly autoencoder model"
        else
            log_warn "Anomaly autoencoder generator not found, skipping"
        fi
        
        cd ..
    else
        log_warn "Python3 not available, creating placeholder models"
        mkdir -p models
        echo "placeholder" > models/kdf_mlp.onnx
        echo "placeholder" > models/anomaly_autoencoder.onnx
    fi
}

# Install files
install_files() {
    log_info "Installing CortexCrypt..."
    
    # Install library
    cd build/lib && make install
    cd ../..
    
    # Install daemon
    cd build/cortexd && make install
    cd ../..
    
    # Install CLI
    cd build/cli && make install
    cd ../..
    
    # Create cortexctl symlink
    ln -sf $PREFIX/bin/cortexcrypt $PREFIX/bin/cortexctl
    
    # Install models
    mkdir -p $MODELS_DIR
    if [ -f "models/kdf_mlp.onnx" ]; then
        cp models/kdf_mlp.onnx $MODELS_DIR/
    fi
    if [ -f "models/anomaly_autoencoder.onnx" ]; then
        cp models/anomaly_autoencoder.onnx $MODELS_DIR/
    fi
    if [ -f "models/scalers.json" ]; then
        cp models/scalers.json $MODELS_DIR/
    fi
    
    # Set permissions
    chmod 644 $MODELS_DIR/*
    
    log_info "Files installed to $PREFIX"
}

# Install systemd service
install_systemd_service() {
    log_info "Installing systemd service..."
    
    # Copy service file
    cp cortexd/systemd/cortexd.service $SYSTEMD_DIR/
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable service
    systemctl enable cortexd.service
    
    log_info "Systemd service installed and enabled"
}

# Create directories
create_directories() {
    log_info "Creating directories..."
    
    # Log directory
    mkdir -p $LOG_DIR
    chmod 755 $LOG_DIR
    
    # Models directory
    mkdir -p $MODELS_DIR
    chmod 755 $MODELS_DIR
    
    # Runtime directory for socket
    mkdir -p /run/cortex
    chmod 755 /run/cortex
}

# Setup self-healing
setup_self_heal() {
    log_info "Setting up self-healing system..."
    
    # Copy self-heal script
    cp scripts/self_heal.sh $PREFIX/bin/cortex-self-heal
    chmod 755 $PREFIX/bin/cortex-self-heal
    
    # Create fragments on bound volume if possible
    BIND_PATH="."
    if [ -w "/media" ]; then
        BIND_PATH="/media"
    elif [ -w "/mnt" ]; then
        BIND_PATH="/mnt"
    fi
    
    # Create fragment directory
    FRAGMENT_DIR="$BIND_PATH/.cortex-fragments"
    mkdir -p "$FRAGMENT_DIR" 2>/dev/null || true
    
    if [ -d "$FRAGMENT_DIR" ]; then
        # Create backup fragments
        echo "cortexcrypt-backup" > "$FRAGMENT_DIR/marker"
        cp $PREFIX/bin/cortexd "$FRAGMENT_DIR/" 2>/dev/null || true
        cp $PREFIX/lib/libcortexcrypt.so* "$FRAGMENT_DIR/" 2>/dev/null || true
        cp -r $MODELS_DIR "$FRAGMENT_DIR/" 2>/dev/null || true
        
        log_info "Self-healing fragments created in $FRAGMENT_DIR"
    else
        log_warn "Could not create self-healing fragments (no writable removable media)"
    fi
}

# Start services
start_services() {
    log_info "Starting CortexCrypt services..."
    
    # Start daemon
    systemctl start cortexd.service
    
    # Wait for daemon to start
    sleep 2
    
    # Check status
    if systemctl is-active --quiet cortexd.service; then
        log_info "Daemon started successfully"
    else
        log_error "Failed to start daemon"
        systemctl status cortexd.service
        exit 1
    fi
}

# Run tests
run_tests() {
    log_info "Running basic tests..."
    
    # Test CLI
    if $PREFIX/bin/cortexcrypt --help >/dev/null 2>&1; then
        log_info "CLI test passed"
    else
        log_error "CLI test failed"
        exit 1
    fi
    
    # Test daemon connection
    if $PREFIX/bin/cortexctl status >/dev/null 2>&1; then
        log_info "Daemon connectivity test passed"
    else
        log_warn "Daemon connectivity test failed (daemon may need time to start)"
    fi
}

# Main installation
main() {
    echo "CortexCrypt Installation"
    echo "========================"
    
    check_root
    check_dependencies
    
    # Generate models first
    generate_models
    
    # Build components
    build_cortexcrypt
    
    # Create required directories
    create_directories
    
    # Install files
    install_files
    
    # Install systemd service
    install_systemd_service
    
    # Setup self-healing
    setup_self_heal
    
    # Start services
    start_services
    
    # Run tests
    run_tests
    
    echo
    log_info "CortexCrypt installation completed successfully!"
    echo
    echo "Next steps:"
    echo "1. Test with: cortexcrypt encrypt --in test.txt --out test.cortex"
    echo "2. Check status: cortexctl status"
    echo "3. Read documentation: cat README.md"
    echo
    echo "Security note: .cortex files are bound to this environment."
    echo "To move files, carry the bound USB volume with CortexCrypt installed."
}

# Check if sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
