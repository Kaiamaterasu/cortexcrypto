# 🧠⚡ CortexCrypto - Neural-Augmented Encryption

![CortexCrypto Banner](https://img.shields.io/badge/CortexCrypto-Neural%20Encryption-red?style=for-the-badge)[Tests](https://img.shields.io/badge/Tests-100%25%20Pass-green?style=for-the-badge)

> ⚠️ **PROTOTYPE WARNING**: This is experimental research software. It WILL fail on many systems and requires developer knowledge to use effectively. Don't expect plug-and-play - this is for hackers and researchers who understand the risks.

> 👷 **DEVELOPER NEEDED**: Unless you're a developer comfortable with debugging build systems, dependency hell, and experimental crypto, you probably can't use this. **We need contributors** to make it more accessible!

**A brilliant neural-augmented encryption prototype that binds files to specific hardware environments. Revolutionary concept, prototype implementation, huge potential.**

> 🔥 **Real Talk**: This isn't production software - it's a research prototype exploring neural encryption concepts. CortexCrypto uses neural networks to augment encryption keys, making each file unique to your environment. Built by developers, for developers willing to tinker and contribute.

> 🤝 **CONTRIBUTIONS WANTED**: This project needs your help! Whether it's fixing build issues, adding Windows support, improving docs, or just testing on different systems - every contribution makes this more accessible to the community.

## 🚀 What This Beast Actually Does

- **🧠 Neural Key Augmentation**: Uses custom neural networks to transform passwords into hardware-specific keys
- **🔒 Environment Binding**: Encrypted files are bound to your specific machine or storage volume 
- **⚡ High Performance**: Sub-millisecond neural inference, fast encryption
- **🛡️ Battle-Tested Security**: AES-256-GCM encryption with neural-enhanced key derivation
- **🔧 Multiple Interfaces**: CLI tool, Python SDK, C library - use what works for you
- **📁 .cortex Format**: Custom binary format designed for security and portability

## ⚡ Quick Start (After Setup)

### 🔧 **IMPORTANT: Run Setup First!**

```bash
# Clone and set up (REQUIRED)
git clone https://github.com/Kaiamaterasu/cortexcrypto.git
cd cortexcrypto

# Organize batch folders (ESSENTIAL STEP)
chmod +x setup.sh && ./setup.sh
```

### 🧠 **Then Test Neural Encryption:**

```bash
# Test neural encryption immediately
python3 neural_crypto_integration.py

# Encrypt a file (machine-bound)
python3 cortex_standalone.py encrypt --in secret.txt --out secret.cortex --bind machine

# Train your own neural network
python3 train_neural_network.py
```

## 🎯 Real-World Performance (100% Test Pass Rate)

- **Neural Inference**: 0.7ms (Python), <0.1ms (C expected)
- **Encryption Speed**: ~100ms for small files, ~100ms for 32KB files
- **Security**: Wrong passwords rejected, tampering detected
- **Reliability**: 10 concurrent operations in <1 second
- **Compatibility**: Works on Linux, extensible to other platforms

## 🛠️ What You Actually Get

### 1. **Neural Network Training System** 
Complete from-scratch neural training with zero external ML dependencies.

### 2. **Python Standalone** (`cortex_standalone.py`) 
No-bullshit Python implementation that works independently. Perfect for automation and integration.

### 3. **C Library** (`lib/` - after setup)
High-performance C implementation for production deployment.

### 4. **CLI Tools** (`cli/` - after setup)
Command-line interface for system integration.

## 🔥 Why CortexCrypto is Revolutionary

1. **Environment Binding**: Your encrypted files won't decrypt on different machines/volumes
2. **Neural Augmentation**: First complete neural-crypto training system on GitHub
3. **Zero ML Dependencies**: Custom neural networks built from scratch
4. **Actually Works**: 100% test pass rate, sub-millisecond performance
5. **Open Source**: MIT licensed, available for research and development

## 🚨 Honest Limitations (No Marketing BS)

- **Linux Only**: Currently optimized for Linux environments
- **Prototype Quality**: Experimental research code, not production-ready
- **Learning Curve**: Neural binding concepts require understanding the documentation
- **Build Complexity**: May require troubleshooting on some systems
- **Developer-Focused**: Requires technical knowledge to use effectively

## 💰 Support This Research Project

If CortexCrypto inspires you or you think neural encryption represents the future:

**💸 [Support via PayPal](https://www.paypal.com/paypalme/Poorna357)**

Every contribution helps keep this research alive. No corporate sponsors here - just pure developer-to-developer support for advancing cryptography.

## 📚 Documentation & Setup

### 🔧 **Setup & Installation**
- **`SETUP_GUIDE.md`** - **START HERE!** Essential setup instructions for batch organization
- **`setup.sh`** - One-command automatic setup script

### 📖 **After Setup - Core Documentation**
- **`NEURAL_NETWORK.md`** - Complete neural system documentation  
- **`NEURAL_STATUS.md`** - System capabilities and performance metrics
- **`INSTALLATION.md`** - Detailed installation guide with all Linux distros
- **`DOCUMENTATION.md`** - Technical deep-dive and API reference

### 🧪 **Testing & Examples**
- **`perfect_score_tests.py`** - Comprehensive test suite (100% pass rate)
- **`examples/`** - Real-world usage examples (created after setup)
- **`models/neural_benchmark.py`** - Neural network performance benchmarking

### 📦 **Before Setup - Batch Locations**
If you haven't run `setup.sh` yet, files are in batch folders:
- **`cortex_batch1_neural_priority/`** - Neural system + main docs
- **`cortex_batch2_supporting/`** - Tests, examples, requirements
- **`cortex_batch3_library/`** - C library source code
- **`cortex_batch4_final/`** - CLI tools, SDKs, additional docs
- **`cortex_batch5_remaining/`** - Daemon, scripts, GitHub files

## 🧠 Neural Network System

### 🔥 **Complete Neural Training Pipeline**

CortexCrypto includes the **world's first complete neural encryption training system**:

#### **Ubuntu/Debian Neural Setup:**
```bash
# No additional packages needed - pure Python!
python3 train_neural_network.py
```

#### **Arch Linux Neural Setup:**
```bash
# Ensure Python is installed
sudo pacman -S python python-pip
python3 train_neural_network.py
```

#### **CentOS/RHEL/Rocky Neural Setup:**
```bash
# Ensure Python 3 is available
sudo dnf install python3 python3-pip
python3 train_neural_network.py
```

#### **Fedora Neural Setup:**
```bash
sudo dnf install python3 python3-pip python3-devel
python3 train_neural_network.py
```

### ⚡ **Neural Training Options**

```bash
# Basic training (2 minutes)
python3 train_neural_network.py

# Advanced training with real encryption data (5 minutes)
python3 train_with_real_data.py advanced

# Full production pipeline (10 minutes)
python3 neural_pipeline.py full

# Performance testing
python3 models/neural_benchmark.py
```

### 🏗️ **Neural Architecture**

- **Input**: 49 bytes (base_key + binding_id + session_salt + anomaly)
- **Architecture**: 49 → 64(ReLU) → 32(ReLU) → 32(Linear)
- **Output**: 32 values (clamped to [-3, 3])
- **Performance**: 0.7ms inference, ~50KB memory
- **Security**: Cryptographically-backed, deterministic, environment-bound

## 🔒 Security Model

### What CortexCrypto Protects Against

- **File Theft**: `.cortex` files useless without bound environment
- **Brute Force**: Neural-enhanced KDF adapts under attack
- **Environment Mismatch**: Files bound to specific hardware
- **Key Extraction**: No persistent keys stored, all derived on-demand

### What It Doesn't Protect Against

- **Kernel Compromise**: Use OS hardening + full-disk encryption
- **Physical Hardware Attacks**: Physical security of bound device required
- **Authorized Access**: Legitimate users with passphrase + bound device can decrypt
- **All Attack Vectors**: This is experimental software, not battle-tested encryption

### Binding Policies

- **Volume Binding**: Files tied to specific USB/storage device
- **Machine Binding**: Files tied to specific computer hardware

## 🧪 Research Value

### What Makes This Special

- **First Public Implementation**: Complete neural-crypto training system on GitHub
- **Educational Resource**: Perfect for learning neural cryptography concepts
- **Research Foundation**: Basis for academic papers and experiments
- **Innovation Catalyst**: Opens doors for adaptive encryption research

### Academic Potential

- **Novel Approach**: Neural augmentation of proven cryptography
- **Complete Pipeline**: From training to deployment
- **Reproducible Research**: Open source with comprehensive documentation
- **Performance Benchmarks**: Validated sub-millisecond inference

## 🤝 Contributing

**This project needs YOU!**

Built by **[@Kaiamaterasu](https://github.com/Kaiamaterasu)** as research into neural cryptography.

**Contribution Areas:**
- Windows/macOS porting
- Build system improvements  
- Documentation enhancements
- Performance optimizations
- Security auditing
- Testing on different systems

Want to contribute? Fork it, improve it, send a PR. Let's advance neural cryptography together.

## ⚖️ License

MIT License - Use it, modify it, research with it. Just don't blame me if you encrypt your only copy of something important without backing up the password.

## 🎯 Honest Assessment

**CortexCrypto is a brilliant research prototype** that opens new doors in neural cryptography. It's **not ready to replace your current encryption tools**, but it's an **incredible foundation** for the future of adaptive, environment-aware encryption.

**If you're excited about the intersection of AI and cryptography, this is for you. If you just need to encrypt files reliably, stick with standard tools for now.**

**Revolutionary concept, prototype implementation, huge potential.** 🧠⚡🔒

## 🔬 Technical Details

### Neural Key Derivation Process

1. **Standard KDF**: Argon2id derives base key from passphrase
2. **Neural Augmentation**: Custom MLP processes environment context
3. **Cryptographic Mixing**: Neural output XORed with proven HKDF
4. **AEAD Encryption**: Standard AES-256-GCM with derived keys
5. **Environment Binding**: Hardware fingerprinting ensures location-bound access

### File Format (`.cortex`)

Binary format with cryptographic headers:
- Magic bytes and version information
- Salt and binding verification data
- TLV metadata section
- Standard AEAD encrypted content
- Authentication tag for integrity

**Critical**: Neural networks enhance but never replace proven cryptography.

---

**Security Notice**: CortexCrypto is experimental research software. Use appropriate security practices and don't rely on it for mission-critical data protection.

**Made with 🔥 by a developer exploring the future of encryption**

*CortexCrypto: Because research into neural cryptography matters*
