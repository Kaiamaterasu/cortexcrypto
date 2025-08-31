#!/bin/bash
#
# CortexCrypt Self-Healing Script
# Copyright 2024 CortexCrypt Contributors
# Licensed under Apache 2.0
#
# Restores CortexCrypt components from backup fragments
# Triggered when manual deletion is detected
#

set -e

# Configuration
PREFIX="/usr/local"
MODELS_DIR="$PREFIX/share/cortexcrypt/models"
LOG_FILE="/var/log/cortex/self_heal.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_event() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

log_info() {
    log_event "INFO: $1"
}

log_warn() {
    log_event "WARN: $1"
}

log_error() {
    log_event "ERROR: $1"
}

# Find backup fragments on bound volumes
find_fragments() {
    local fragment_dirs=()
    
    # Check common mount points for backup fragments
    for mount_point in /media/* /mnt/* /run/media/*/*; do
        if [ -d "$mount_point/.cortex-fragments" ]; then
            if [ -f "$mount_point/.cortex-fragments/marker" ]; then
                fragment_dirs+=("$mount_point/.cortex-fragments")
            fi
        fi
    done
    
    # Check current directory
    if [ -d "./.cortex-fragments" ] && [ -f "./.cortex-fragments/marker" ]; then
        fragment_dirs+=("./.cortex-fragments")
    fi
    
    if [ ${#fragment_dirs[@]} -eq 0 ]; then
        log_error "No backup fragments found on bound volumes"
        return 1
    fi
    
    echo "${fragment_dirs[0]}" # Return first found
    return 0
}

# Verify fragment integrity
verify_fragments() {
    local fragment_dir="$1"
    
    if [ ! -d "$fragment_dir" ]; then
        log_error "Fragment directory not found: $fragment_dir"
        return 1
    fi
    
    # Check marker file
    if [ ! -f "$fragment_dir/marker" ]; then
        log_error "Fragment marker missing"
        return 1
    fi
    
    local marker_content=$(cat "$fragment_dir/marker")
    if [ "$marker_content" != "cortexcrypt-backup" ]; then
        log_error "Invalid fragment marker"
        return 1
    fi
    
    # Check essential files
    local required_files=("cortexd" "libcortexcrypt.so.1" "models/kdf_mlp.onnx")
    
    for file in "${required_files[@]}"; do
        if [ ! -f "$fragment_dir/$file" ]; then
            log_warn "Fragment missing: $file"
        fi
    done
    
    log_info "Fragment verification completed"
    return 0
}

# Restore binary files
restore_binaries() {
    local fragment_dir="$1"
    
    log_info "Restoring binary files from $fragment_dir"
    
    # Restore daemon
    if [ -f "$fragment_dir/cortexd" ]; then
        cp "$fragment_dir/cortexd" "$PREFIX/bin/"
        chmod 755 "$PREFIX/bin/cortexd"
        log_info "Restored cortexd daemon"
    fi
    
    # Restore library
    if [ -f "$fragment_dir/libcortexcrypt.so.1" ]; then
        cp "$fragment_dir/libcortexcrypt.so.1" "$PREFIX/lib/"
        ln -sf "$PREFIX/lib/libcortexcrypt.so.1" "$PREFIX/lib/libcortexcrypt.so"
        ldconfig
        log_info "Restored libcortexcrypt library"
    fi
    
    # Restore CLI (if missing, create symlink to existing cortexctl)
    if [ ! -f "$PREFIX/bin/cortexcrypt" ] && [ -f "$PREFIX/bin/cortexctl" ]; then
        ln -sf cortexctl "$PREFIX/bin/cortexcrypt"
        log_info "Restored cortexcrypt CLI symlink"
    fi
}

# Restore models
restore_models() {
    local fragment_dir="$1"
    
    if [ -d "$fragment_dir/models" ]; then
        log_info "Restoring neural network models"
        
        mkdir -p "$MODELS_DIR"
        cp -r "$fragment_dir/models/"* "$MODELS_DIR/"
        chmod 644 "$MODELS_DIR"/*
        
        log_info "Models restored to $MODELS_DIR"
    fi
}

# Restart services
restart_services() {
    log_info "Restarting CortexCrypt services"
    
    # Stop existing daemon if running
    systemctl stop cortexd.service 2>/dev/null || true
    
    # Kill any remaining daemon processes
    pkill -f cortexd || true
    
    # Wait a moment
    sleep 1
    
    # Start daemon
    systemctl start cortexd.service
    
    # Wait for startup
    sleep 2
    
    # Check status
    if systemctl is-active --quiet cortexd.service; then
        log_info "Services restarted successfully"
        return 0
    else
        log_error "Failed to restart services"
        return 1
    fi
}

# Check what needs healing
check_integrity() {
    local issues=()
    
    # Check daemon binary
    if [ ! -f "$PREFIX/bin/cortexd" ]; then
        issues+=("cortexd daemon missing")
    fi
    
    # Check library
    if [ ! -f "$PREFIX/lib/libcortexcrypt.so.1" ]; then
        issues+=("libcortexcrypt library missing")
    fi
    
    # Check CLI
    if [ ! -f "$PREFIX/bin/cortexcrypt" ] && [ ! -f "$PREFIX/bin/cortexctl" ]; then
        issues+=("CLI tools missing")
    fi
    
    # Check models
    if [ ! -f "$MODELS_DIR/kdf_mlp.onnx" ]; then
        issues+=("KDF MLP model missing")
    fi
    
    # Check daemon status
    if ! systemctl is-active --quiet cortexd.service; then
        issues+=("daemon not running")
    fi
    
    if [ ${#issues[@]} -eq 0 ]; then
        return 0 # No issues
    fi
    
    log_warn "Integrity issues detected: ${issues[*]}"
    return 1
}

# Main self-healing function
heal_system() {
    log_info "CortexCrypt self-healing initiated"
    
    # Find backup fragments
    local fragment_dir
    fragment_dir=$(find_fragments)
    local find_result=$?
    
    if [ $find_result -ne 0 ]; then
        log_error "Self-healing failed: no backup fragments found"
        return 1
    fi
    
    log_info "Found backup fragments in: $fragment_dir"
    
    # Verify fragments
    if ! verify_fragments "$fragment_dir"; then
        log_error "Fragment verification failed"
        return 1
    fi
    
    # Restore components
    restore_binaries "$fragment_dir"
    restore_models "$fragment_dir"
    
    # Restart services
    if restart_services; then
        log_info "Self-healing completed successfully"
        
        # Log security event
        echo "$(date): CortexCrypt self-healing triggered and completed" >> /var/log/cortex/security.log
        
        return 0
    else
        log_error "Self-healing failed to restart services"
        return 1
    fi
}

# Continuous monitoring mode
monitor_mode() {
    log_info "Starting continuous integrity monitoring"
    
    while true; do
        if ! check_integrity; then
            log_warn "Integrity check failed, initiating self-healing"
            
            if heal_system; then
                log_info "Self-healing successful, resuming monitoring"
            else
                log_error "Self-healing failed, retrying in 30 seconds"
                sleep 30
                continue
            fi
        fi
        
        # Check every 5 seconds
        sleep 5
    done
}

# Print usage
print_usage() {
    echo "CortexCrypt Self-Healing Script"
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  heal      Perform one-time healing"
    echo "  monitor   Continuous monitoring mode"
    echo "  check     Check integrity without healing"
    echo "  status    Show healing system status"
    echo ""
}

# Main function
main() {
    local command="${1:-heal}"
    
    # Ensure log directory exists
    mkdir -p "$(dirname "$LOG_FILE")"
    
    case "$command" in
        "heal")
            heal_system
            ;;
        "monitor")
            monitor_mode
            ;;
        "check")
            if check_integrity; then
                echo "System integrity OK"
                exit 0
            else
                echo "System integrity issues detected"
                exit 1
            fi
            ;;
        "status")
            echo "CortexCrypt Self-Healing Status"
            echo "==============================="
            
            # Check if monitoring service is running
            if pgrep -f "cortex-self-heal monitor" > /dev/null; then
                echo "Self-healing monitor: Running"
            else
                echo "Self-healing monitor: Stopped"
            fi
            
            # Check fragment availability
            if find_fragments > /dev/null 2>&1; then
                fragment_dir=$(find_fragments)
                echo "Backup fragments: Available ($fragment_dir)"
            else
                echo "Backup fragments: Not found"
            fi
            
            # Check integrity
            if check_integrity; then
                echo "System integrity: OK"
            else
                echo "System integrity: Issues detected"
            fi
            ;;
        *)
            print_usage
            exit 1
            ;;
    esac
}

# Check if sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
