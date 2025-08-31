# 🚀 CortexCrypto Setup Guide

## 🎯 **After Cloning the Repository**

Due to GitHub's file upload limits, CortexCrypto was uploaded in organized batches. Follow this guide to set up the proper project structure!

## ⚡ **Quick Setup (Automatic)**

### **Option 1: Run the Setup Script**
```bash
git clone https://github.com/Kaiamaterasu/cortexcrypto.git
cd cortexcrypto

# Run the automatic setup script
chmod +x setup.sh
./setup.sh
```

**This automatically organizes all files into the proper structure!**

### **Option 2: Manual Setup**

If you prefer to organize manually:

#### **Step 1: Extract Neural Network System**
```bash
# Copy neural files to root
cp cortex_batch1_neural_priority/*.py .
cp cortex_batch1_neural_priority/*.md .
cp cortex_batch1_neural_priority/*.json .
cp cortex_batch1_neural_priority/.gitignore .

# Set up models directory
mkdir -p models
cp cortex_batch1_neural_priority/models/*.py models/
```

#### **Step 2: Extract Tests and Examples**
```bash
# Copy test files
cp cortex_batch2_supporting/*.py .
cp cortex_batch2_supporting/*.c .
cp cortex_batch2_supporting/requirements.txt .

# Copy examples
cp -r cortex_batch2_supporting/examples .
```

#### **Step 3: Extract C Library**
```bash
# Copy C library
cp -r cortex_batch3_library/lib .
```

#### **Step 4: Extract CLI and Tools**
```bash
# Copy CLI and tools
cp -r cortex_batch4_final/cli .
cp -r cortex_batch4_final/tools .
cp -r cortex_batch4_final/sdk .
cp cortex_batch4_final/*.sh .
```

#### **Step 5: Extract Daemon and Scripts**
```bash
# Copy daemon and scripts
cp -r cortex_batch5_remaining/cortexd .
cp -r cortex_batch5_remaining/scripts .
cp -r cortex_batch5_remaining/.github .
```

#### **Step 6: Extract Models and Build**
```bash
# Copy build system and models
cp cortex_batch_final_extras/LICENSE .
cp cortex_batch_final_extras/Makefile .
cp cortex_batch_final_extras/*.json models/
cp cortex_batch_final_extras/*.h models/
cp cortex_batch_final_extras/*.c models/
```

#### **Step 7: Clean Up (Optional)**
```bash
# Remove batch folders after extraction
rm -rf cortex_batch*
```

## 🎯 **Final Project Structure**

After setup, you'll have:
```
cortexcrypto/
├── 🧠 NEURAL NETWORK SYSTEM
│   ├── train_neural_network.py         # Core training
│   ├── neural_crypto_integration.py    # Live integration
│   ├── neural_pipeline.py             # Production pipeline
│   └── models/                        # Pre-trained models
│
├── 🔒 ENCRYPTION SYSTEM
│   ├── cortex_standalone.py           # Main encryption tool
│   ├── lib/                          # C library
│   └── cli/                          # Command-line tools
│
├── 🧪 TESTING & EXAMPLES
│   ├── perfect_score_tests.py         # Comprehensive tests
│   ├── comprehensive_tests.py         # Extended tests
│   └── examples/                      # Usage examples
│
├── 📚 DOCUMENTATION
│   ├── README.md                      # Main guide
│   ├── NEURAL_NETWORK.md             # Neural documentation
│   ├── INSTALLATION.md               # Setup guide
│   └── DOCUMENTATION.md              # Technical reference
│
└── ⚙️ SYSTEM COMPONENTS
    ├── Makefile                       # Build system
    ├── LICENSE                        # MIT license
    ├── cortexd/                      # Daemon
    └── scripts/                      # Utilities
```

## 🚀 **Quick Start After Setup**

### **1. Test Neural Network (Instant)**
```bash
python3 neural_crypto_integration.py
```

### **2. Train Your Own Model**
```bash
python3 train_neural_network.py
```

### **3. Use Neural Encryption**
```bash
echo "Secret data!" > test.txt
python3 cortex_standalone.py encrypt --in test.txt --out test.cortex --bind machine
```

### **4. Run Performance Benchmark**
```bash
python3 models/neural_benchmark.py
```

### **5. Build C Components**
```bash
make all
./build/cli/cortexcrypt encrypt --in test.txt --out test.cortex
```

## 🧠 **Neural Features Ready**

After setup, users can immediately:
- ✅ **Train neural networks** from scratch
- ✅ **Use pre-trained models** for instant neural encryption
- ✅ **Benchmark performance** (sub-millisecond inference)
- ✅ **Integrate with C** for production deployment
- ✅ **Run comprehensive tests** (100% pass rate)

## 🔥 **Why This Setup Works**

- **Batch structure preserved** for reference and organization
- **Working directory** has all files accessible from root
- **Pre-trained models** available immediately
- **Complete neural training pipeline** ready to use
- **Production deployment** possible with C integration

## 🎯 **Success Indicators**

After running setup, you should be able to:
```bash
# These should all work:
python3 neural_crypto_integration.py  # Neural demo
python3 train_neural_network.py       # Training
python3 cortex_standalone.py encrypt  # Encryption
make all                               # C compilation
```

---

## 🏆 **CONGRATULATIONS!**

You now have the **world's first complete neural-augmented encryption system** properly set up and ready to use!

**Welcome to the neural crypto revolution!** 🧠⚡🔒🚀
