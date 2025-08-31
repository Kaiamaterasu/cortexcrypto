# 🔧 CortexCrypt Installation Guide

**No-bullshit guide to get CortexCrypt neural encryption running on your system.**

## 🖥️ System Requirements

- **OS**: Linux (Ubuntu 18.04+, Debian 10+, CentOS 8+, Arch, etc.)
- **Architecture**: x86_64 (Intel/AMD 64-bit)
- **RAM**: 2GB minimum, 4GB recommended
- **Storage**: 100MB for installation + space for your encrypted files
- **Compiler**: GCC 7.0+ or Clang 6.0+

## 📦 Quick Install (Recommended)

### One-Line Install
```bash
curl -sSL https://raw.githubusercontent.com/Kaiamaterasu/cortexcrypt/main/install.sh | bash
```

**This will:**
1. Check your system compatibility
2. Install all dependencies automatically
3. Build and install CortexCrypt
4. Run validation tests
5. Set up the daemon service

### Manual Install (For Control Freaks)

If you don't trust random bash scripts from the internet (smart choice), follow the detailed steps below.

## 🛠️ Manual Installation

### Step 1: Install System Dependencies

#### Ubuntu/Debian
```bash
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
```

#### CentOS/RHEL/Rocky Linux
```bash
sudo dnf groupinstall "Development Tools"
sudo dnf install -y \
    cmake \
    openssl-devel \
    libsodium-devel \
    python3-devel \
    python3-pip \
    git \
    make
```

#### Arch Linux
```bash
sudo pacman -S \
    base-devel \
    cmake \
    openssl \
    libsodium \
    python \
    python-pip \
    git \
    make
```

### Step 2: Install Python Dependencies

```bash
pip3 install --user \
    cryptography \
    pycryptodome \
    argon2-cffi \
    numpy
```

### Step 2.5: 🧠 Neural Network Setup (NEW!)

**CortexCrypto now includes a complete neural network training system!**

**No external ML libraries required** - everything built from scratch in pure Python!

```bash
# Test neural network training
python3 train_neural_network.py

# This will:
# 1. Create neural network from scratch
# 2. Generate 500+ training samples
# 3. Train for 50 epochs
# 4. Export to C files for production
# 5. Create performance benchmarks
```

**Expected output:**
```
🧠 Initializing CortexCrypto Neural Network...
✅ Neural architecture: 49 → 64(ReLU) → 32(ReLU) → 32(Linear)
🎯 Creating CortexCrypto-specific training data...
✅ Generated 500 training samples
🔥 Training neural network for 50 epochs...
🎯 Training complete!
🏆 Final loss: 7.335322
⚡ Inference time: 0.50ms
✅ Output range validation: PASSED
```

**🎯 Neural Training Options:**
- `python3 train_neural_network.py` - Basic training
- `python3 train_with_real_data.py advanced` - Advanced real-data training  
- `python3 neural_pipeline.py full` - Complete production pipeline
- `python3 models/neural_benchmark.py` - Performance testing

### Step 3: Clone and Build

```bash
# Clone the repo
git clone https://github.com/Kaiamaterasu/cortexcrypt.git
cd cortexcrypt

# Build everything
make all

# Verify build worked
ls -la build/
```

**Expected output:**
```
build/
├── cli/
│   └── cortexcrypt          # Main CLI tool
├── daemon/
│   └── cortexd              # Full daemon (might hang)
└── lib/
    └── libcortex.so         # C library
```

### Step 4: Install System-Wide

```bash
# Install binaries and libraries
sudo make install

# This installs to:
# /usr/local/bin/cortexcrypt
# /usr/local/bin/cortexd  
# /usr/local/lib/libcortex.so
# /usr/local/include/cortex/
```

### Step 5: Test Installation

```bash
# Test the Python standalone (works immediately)
echo "test content" > test.txt
python3 cortex_standalone.py encrypt --in test.txt --out test.cortex --bind machine

# Enter a password when prompted
# Should create test.cortex file

# Test decryption
python3 cortex_standalone.py decrypt --in test.cortex --out test_dec.txt
# Enter same password

# Verify it worked
cat test_dec.txt
# Should show "test content"

# Cleanup
rm test.txt test.cortex test_dec.txt
```

### Step 6: Set Up Simple Daemon (Recommended)

The original daemon can hang, so we use the simple daemon:

```bash
# Start simple daemon
./simple_daemon &
DAEMON_PID=$!

# Test CLI with simple daemon
echo "cli test" > cli_test.txt
./build/cli/cortexcrypt encrypt --in cli_test.txt --out cli_test.cortex --bind machine --no-pass

# Test info command
./build/cli/cortexcrypt info --in cli_test.cortex

# Cleanup
kill $DAEMON_PID
rm cli_test.txt cli_test.cortex
```

## 🚀 Verification Tests

Run the comprehensive test suite to make sure everything works:

```bash
# Run perfect score test suite
python3 perfect_score_tests.py
```

**Expected result:**
```
🏆 FINAL SCORE: 24/24 (100.0%)
🏆 GRADE: A+ PERFECT ⭐⭐⭐⭐⭐
🎖️  STATUS: 🏆 PERFECT SCORE ACHIEVED!
```

If you get 100%, you're golden! If not, check the troubleshooting section below.

## 🔄 Service Setup (Optional)

To run the simple daemon as a system service:

### Create Service File
```bash
sudo tee /etc/systemd/system/cortex-daemon.service > /dev/null <<EOF
[Unit]
Description=CortexCrypt Simple Daemon
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/simple_daemon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### Enable and Start
```bash
sudo systemctl daemon-reload
sudo systemctl enable cortex-daemon
sudo systemctl start cortex-daemon

# Check status
sudo systemctl status cortex-daemon
```

## 🛠️ Build Options

### Debug Build
```bash
make clean
make DEBUG=1 all
```

### Release Build (Optimized)
```bash
make clean  
make RELEASE=1 all
```

### Build Individual Components
```bash
make lib      # Just the C library
make cli      # Just the CLI tools
make daemon   # Just the daemon
make standalone  # Just Python standalone
```

## 📁 File Locations

After installation, files are located at:

```
/usr/local/
├── bin/
│   ├── cortexcrypt          # Main CLI
│   ├── cortexd              # Full daemon
│   └── simple_daemon        # Simple daemon
├── lib/
│   └── libcortex.so         # C library
├── include/
│   └── cortex/
│       ├── cortex.h         # C header
│       └── cortex_types.h   # Type definitions
└── share/cortex/
    ├── examples/            # Example code
    └── models/              # Neural network models (if built)
```

User-specific files:
```
~/.cortex/
├── config.json            # User configuration
├── keys/                  # Key storage (encrypted)
└── logs/                  # Operation logs
```

## ⚠️ Troubleshooting

### Build Fails with "OpenSSL not found"
```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# CentOS/RHEL
sudo dnf install openssl-devel

# Check OpenSSL version
openssl version
# Need OpenSSL 1.1.0+ or 3.0+
```

### Build Fails with "libsodium not found"
```bash
# Ubuntu/Debian  
sudo apt-get install libsodium-dev

# CentOS/RHEL
sudo dnf install libsodium-devel

# Or build from source
wget https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz
tar xf libsodium-1.0.18.tar.gz
cd libsodium-1.0.18
./configure && make && sudo make install
```

### Python Modules Missing
```bash
# Install in user directory
pip3 install --user cryptography pycryptodome argon2-cffi numpy

# Or system-wide (if you have permissions)
sudo pip3 install cryptography pycryptodome argon2-cffi numpy

# Verify installation
python3 -c "import cryptography; print('OK')"
python3 -c "import Crypto; print('OK')"
```

### CLI Hangs or Times Out
This is usually the original daemon causing issues. Use the Python standalone instead:

```bash
# Instead of CLI
python3 cortex_standalone.py encrypt --in file.txt --out file.cortex

# Or use simple daemon
./simple_daemon &
./build/cli/cortexcrypt encrypt --in file.txt --out file.cortex
```

### Permission Denied Errors
```bash
# Make sure binaries are executable
chmod +x build/cli/cortexcrypt
chmod +x simple_daemon

# Check you have write permissions  
ls -la build/
```

### Tests Fail
```bash
# Clean rebuild
make clean
make all

# Check dependencies
ldd build/cli/cortexcrypt
python3 -c "import sys; print(sys.version)"

# Run individual tests
python3 cortex_standalone.py encrypt --in /etc/passwd --out test.cortex --bind machine
```

## 🧹 Uninstall

### Remove System Installation
```bash
sudo rm -f /usr/local/bin/cortexcrypt
sudo rm -f /usr/local/bin/cortexd  
sudo rm -f /usr/local/bin/simple_daemon
sudo rm -f /usr/local/lib/libcortex.so
sudo rm -rf /usr/local/include/cortex/
sudo rm -rf /usr/local/share/cortex/
```

### Remove User Data
```bash
rm -rf ~/.cortex/
```

### Remove Service (if installed)
```bash
sudo systemctl stop cortex-daemon
sudo systemctl disable cortex-daemon
sudo rm /etc/systemd/system/cortex-daemon.service
sudo systemctl daemon-reload
```

## 🔧 Configuration

### Environment Variables

```bash
# Custom build flags
export CORTEX_DEBUG=1          # Enable debug logging
export CORTEX_NO_NEURAL=1      # Disable neural networks
export CORTEX_CONFIG_PATH=~/.cortex/custom_config.json

# Runtime options  
export CORTEX_DAEMON_PORT=9999 # Custom daemon port
export CORTEX_TIMEOUT=30       # Command timeout (seconds)
```

### Config File (`~/.cortex/config.json`)

```json
{
  "daemon": {
    "port": 8888,
    "timeout": 30,
    "log_level": "INFO"
  },
  "encryption": {
    "default_cipher": "aes256_gcm",
    "default_binding": "machine",
    "kdf_memory": 65536,
    "kdf_iterations": 3
  },
  "neural": {
    "enabled": true,
    "fallback_enabled": true,
    "model_path": "/usr/local/share/cortex/models/"
  }
}
```

## 🚀 Post-Installation

### Verify Everything Works
```bash
# Quick functionality test
echo "Hello CortexCrypt!" > hello.txt
python3 cortex_standalone.py encrypt --in hello.txt --out hello.cortex --bind machine
python3 cortex_standalone.py decrypt --in hello.cortex --out hello_dec.txt  
cat hello_dec.txt
rm hello.txt hello.cortex hello_dec.txt
```

### Performance Test
```bash
# Create larger test file
dd if=/dev/urandom of=bigfile.dat bs=1M count=10

# Time encryption  
time python3 cortex_standalone.py encrypt --in bigfile.dat --out bigfile.cortex --bind machine

# Time decryption
time python3 cortex_standalone.py decrypt --in bigfile.cortex --out bigfile_dec.dat

# Verify integrity
sha256sum bigfile.dat bigfile_dec.dat

# Cleanup
rm bigfile.dat bigfile.cortex bigfile_dec.dat
```

### Next Steps

1. **Read the docs**: Check out [DOCUMENTATION.md](DOCUMENTATION.md) for detailed usage
2. **Try examples**: Explore the `/examples/` directory  
3. **Join development**: Fork the repo and contribute improvements
4. **Support the project**: [Contribute via PayPal](https://www.paypal.com/paypalme/Poorna357)

---

**Installation complete! Welcome to neural-augmented encryption. 🧠⚡**

*Questions? Issues? Check the GitHub issues or start a discussion.*
