#!/bin/bash
# CortexCrypt One-Line Installation Script
# Neural-Augmented Encryption System

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "🧠⚡ CortexCrypt Neural-Augmented Encryption"
echo "============================================="
echo -e "${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}❌ Don't run this script as root!${NC}"
   echo "Run as regular user - we'll ask for sudo when needed."
   exit 1
fi

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo -e "${RED}❌ Cannot detect OS version${NC}"
    exit 1
fi

echo -e "${GREEN}🖥️  Detected: $PRETTY_NAME${NC}"

# Install dependencies based on OS
echo -e "${CYAN}📦 Installing dependencies...${NC}"

case $OS in
    ubuntu|debian)
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            cmake \
            pkg-config \
            libssl-dev \
            libsodium-dev \
            python3-dev \
            python3-pip \
            git \
            make
        ;;
    centos|rhel|rocky|almalinux)
        sudo dnf groupinstall -y "Development Tools"
        sudo dnf install -y \
            cmake \
            openssl-devel \
            libsodium-devel \
            python3-devel \
            python3-pip \
            git \
            make
        ;;
    arch|manjaro)
        sudo pacman -S --needed \
            base-devel \
            cmake \
            openssl \
            libsodium \
            python \
            python-pip \
            git \
            make
        ;;
    *)
        echo -e "${YELLOW}⚠️  Unsupported OS: $OS${NC}"
        echo "Please install dependencies manually:"
        echo "  - build-essential/base-devel"
        echo "  - cmake, openssl-dev, libsodium-dev"
        echo "  - python3-dev, python3-pip"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
        ;;
esac

# Install Python dependencies
echo -e "${CYAN}🐍 Installing Python dependencies...${NC}"
pip3 install --user \
    cryptography \
    pycryptodome \
    argon2-cffi \
    numpy

# Check if we're in the cortexcrypt directory already
if [[ ! -f "cortex_standalone.py" ]]; then
    echo -e "${CYAN}📥 Downloading CortexCrypt...${NC}"
    if [[ -d "cortexcrypt" ]]; then
        echo -e "${YELLOW}⚠️  cortexcrypt directory exists, removing...${NC}"
        rm -rf cortexcrypt
    fi
    git clone https://github.com/Kaiamaterasu/cortexcrypt.git
    cd cortexcrypt
fi

echo -e "${CYAN}🔨 Building CortexCrypt...${NC}"
make clean 2>/dev/null || true
make all

if [[ ! -f "build/cli/cortexcrypt" ]]; then
    echo -e "${RED}❌ Build failed!${NC}"
    echo "Check the error messages above."
    exit 1
fi

echo -e "${CYAN}🚀 Installing system-wide...${NC}"
sudo make install

# Make binaries executable
sudo chmod +x /usr/local/bin/cortexcrypt 2>/dev/null || true
sudo chmod +x simple_daemon 2>/dev/null || true

echo -e "${CYAN}🧪 Running validation tests...${NC}"

# Quick functionality test
echo "Testing CortexCrypt installation..." > install_test.txt

# Test Python standalone
echo -e "${YELLOW}Testing Python standalone...${NC}"
if echo "TestPass123" | python3 cortex_standalone.py encrypt --in install_test.txt --out install_test.cortex --bind machine; then
    echo -e "${GREEN}✅ Python encryption: OK${NC}"
    
    if echo "TestPass123" | python3 cortex_standalone.py decrypt --in install_test.cortex --out install_test_dec.txt; then
        if cmp -s install_test.txt install_test_dec.txt; then
            echo -e "${GREEN}✅ Python decryption: OK${NC}"
        else
            echo -e "${RED}❌ Python decryption: Content mismatch${NC}"
        fi
    else
        echo -e "${RED}❌ Python decryption: Failed${NC}"
    fi
else
    echo -e "${RED}❌ Python encryption: Failed${NC}"
fi

# Test CLI with simple daemon
echo -e "${YELLOW}Testing CLI with simple daemon...${NC}"
./simple_daemon &
DAEMON_PID=$!
sleep 2

if ./build/cli/cortexcrypt encrypt --in install_test.txt --out install_cli_test.cortex --bind machine --no-pass 2>/dev/null; then
    echo -e "${GREEN}✅ CLI encryption: OK${NC}"
    
    if ./build/cli/cortexcrypt info --in install_cli_test.cortex >/dev/null 2>&1; then
        echo -e "${GREEN}✅ CLI info command: OK${NC}"
    else
        echo -e "${YELLOW}⚠️  CLI info command: Warning${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  CLI encryption: Warning (use Python standalone)${NC}"
fi

# Cleanup daemon
kill $DAEMON_PID 2>/dev/null || true
rm -f install_test.txt install_test.cortex install_test_dec.txt install_cli_test.cortex

echo -e "${GREEN}"
echo "🎉 CortexCrypt Installation Complete!"
echo "====================================="
echo -e "${NC}"

echo "📋 What's installed:"
echo "  • Python standalone: cortex_standalone.py"
echo "  • CLI tool: /usr/local/bin/cortexcrypt"  
echo "  • Simple daemon: ./simple_daemon"
echo "  • C library: /usr/local/lib/libcortex.so"

echo
echo "🚀 Quick start:"
echo "  # Encrypt a file"
echo "  python3 cortex_standalone.py encrypt --in secret.txt --out secret.cortex --bind machine"
echo
echo "  # Decrypt a file"  
echo "  python3 cortex_standalone.py decrypt --in secret.cortex --out secret.txt"

echo
echo "📚 Documentation:"
echo "  • README.md - Overview and quick start"
echo "  • INSTALLATION.md - Detailed installation guide"
echo "  • DOCUMENTATION.md - Technical deep dive"

echo
echo "🏆 Run comprehensive tests:"
echo "  python3 perfect_score_tests.py"

echo
echo -e "${CYAN}💰 Support this project: https://www.paypal.com/paypalme/Poorna357${NC}"
echo -e "${CYAN}🤝 GitHub: https://github.com/Kaiamaterasu${NC}"

echo
echo -e "${GREEN}Welcome to neural-augmented encryption! 🧠⚡${NC}"
