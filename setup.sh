#!/bin/bash
# 🧠⚡ CortexCrypto Setup Script
# Organizes batch folders into proper project structure

echo "🚀 CortexCrypto Neural Encryption Setup"
echo "======================================="
echo "Setting up the world's first neural-augmented encryption system!"
echo ""

# Check if we're in the right directory
if [ ! -d "cortex_batch1_neural_priority" ]; then
    echo "❌ Error: Run this script from the cloned cortexcrypto directory"
    echo "   Make sure you're in the folder with the batch directories"
    exit 1
fi

echo "🧠 Phase 1: Setting up Neural Network System..."

# Move neural files to root
if [ -d "cortex_batch1_neural_priority" ]; then
    cp cortex_batch1_neural_priority/*.py . 2>/dev/null || true
    cp cortex_batch1_neural_priority/*.md . 2>/dev/null || true  
    cp cortex_batch1_neural_priority/*.json . 2>/dev/null || true
    cp cortex_batch1_neural_priority/.gitignore . 2>/dev/null || true
    
    # Create models directory if needed
    mkdir -p models
    cp cortex_batch1_neural_priority/models/*.py models/ 2>/dev/null || true
    
    echo "  ✅ Neural network system configured"
else
    echo "  ⚠️ Neural batch not found - may already be set up"
fi

echo "🧪 Phase 2: Setting up Tests and Examples..."

# Set up tests and examples
if [ -d "cortex_batch2_supporting" ]; then
    cp cortex_batch2_supporting/*.py . 2>/dev/null || true
    cp cortex_batch2_supporting/*.c . 2>/dev/null || true
    cp cortex_batch2_supporting/*.md . 2>/dev/null || true
    cp cortex_batch2_supporting/requirements.txt . 2>/dev/null || true
    
    # Copy examples
    cp -r cortex_batch2_supporting/examples . 2>/dev/null || true
    
    # Copy any additional model files
    cp cortex_batch2_supporting/models/*.py models/ 2>/dev/null || true
    
    echo "  ✅ Tests and examples configured"
else
    echo "  ⚠️ Supporting batch not found - may already be set up"
fi

echo "🏗️ Phase 3: Setting up C Library..."

# Set up C library
if [ -d "cortex_batch3_library" ]; then
    cp -r cortex_batch3_library/lib . 2>/dev/null || true
    echo "  ✅ C library configured"
else
    echo "  ⚠️ Library batch not found - may already be set up"
fi

echo "🔧 Phase 4: Setting up CLI and Tools..."

# Set up CLI and tools
if [ -d "cortex_batch4_final" ]; then
    cp -r cortex_batch4_final/cli . 2>/dev/null || true
    cp -r cortex_batch4_final/tools . 2>/dev/null || true
    cp -r cortex_batch4_final/sdk . 2>/dev/null || true
    cp cortex_batch4_final/*.sh . 2>/dev/null || true
    cp cortex_batch4_final/*.md . 2>/dev/null || true
    echo "  ✅ CLI and tools configured"
else
    echo "  ⚠️ CLI batch not found - may already be set up"
fi

echo "⚙️ Phase 5: Setting up Daemon and Scripts..."

# Set up daemon and scripts
if [ -d "cortex_batch5_remaining" ]; then
    cp -r cortex_batch5_remaining/cortexd . 2>/dev/null || true
    cp -r cortex_batch5_remaining/scripts . 2>/dev/null || true
    cp -r cortex_batch5_remaining/.github . 2>/dev/null || true
    echo "  ✅ Daemon and scripts configured"
else
    echo "  ⚠️ Daemon batch not found - may already be set up"
fi

echo "📦 Phase 6: Setting up Models and Build System..."

# Set up final extras
if [ -d "cortex_batch_final_extras" ]; then
    cp cortex_batch_final_extras/LICENSE . 2>/dev/null || true
    cp cortex_batch_final_extras/Makefile . 2>/dev/null || true
    cp cortex_batch_final_extras/*.json models/ 2>/dev/null || true
    cp cortex_batch_final_extras/*.h models/ 2>/dev/null || true
    cp cortex_batch_final_extras/*.c models/ 2>/dev/null || true
    echo "  ✅ Models and build system configured"
else
    echo "  ⚠️ Final extras batch not found - may already be set up"
fi

echo ""
echo "🧹 Phase 7: Cleaning up batch folders..."

# Option to clean up batch folders
echo "Do you want to remove the batch folders? (y/N)"
read -r cleanup_choice

if [[ "$cleanup_choice" =~ ^[Yy]$ ]]; then
    rm -rf cortex_batch1_neural_priority 2>/dev/null || true
    rm -rf cortex_batch2_supporting 2>/dev/null || true
    rm -rf cortex_batch3_library 2>/dev/null || true
    rm -rf cortex_batch4_final 2>/dev/null || true
    rm -rf cortex_batch5_remaining 2>/dev/null || true
    rm -rf cortex_batch_final_extras 2>/dev/null || true
    echo "  ✅ Batch folders cleaned up"
else
    echo "  📁 Batch folders kept for reference"
fi

echo ""
echo "🎉 CORTEXCRYPTO SETUP COMPLETE!"
echo "==============================="
echo ""
echo "🧠 Neural Network System Ready:"
echo "  python3 train_neural_network.py      # Train neural networks"
echo "  python3 neural_crypto_integration.py # Test neural encryption"
echo "  python3 neural_pipeline.py full      # Full production pipeline"
echo ""
echo "🔒 Encryption Ready:"
echo "  python3 cortex_standalone.py encrypt --in file.txt --out file.cortex"
echo ""
echo "🧪 Testing Ready:"
echo "  python3 perfect_score_tests.py       # Run all tests"
echo "  python3 models/neural_benchmark.py   # Performance benchmark"
echo ""
echo "🏗️ Build System Ready:"
echo "  make all                              # Build C components"
echo ""
echo "📚 Documentation:"
echo "  README.md                             # Main documentation"
echo "  NEURAL_NETWORK.md                   # Neural system guide"
echo "  INSTALLATION.md                     # Setup instructions"
echo ""
echo "🔥 NEURAL ENCRYPTION SYSTEM ACTIVATED!"
echo "Welcome to the future of cryptography! 🧠⚡🔒"
echo ""
echo "🎯 Quick test: python3 neural_crypto_integration.py"
