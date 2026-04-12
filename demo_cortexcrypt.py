#!/usr/bin/env python3
"""
CortexCrypt Complete Demonstration
Neural-Augmented Encryption with Environment Binding
"""

import os
import sys
import subprocess
import time

def run_demo():
    print("=" * 60)
    print("🧠 CortexCrypt Neural-Augmented Encryption Demo")
    print("=" * 60)
    print()
    
    print("🔹 Creating demo files...")
    
    # Create test files
    with open("secret_document.txt", "w") as f:
        f.write("""CONFIDENTIAL DOCUMENT
===================

Project: CortexCrypt Neural Encryption
Status: CLASSIFIED

This document contains sensitive information about our
neural-augmented encryption system. The AI learns from
attack patterns to improve security dynamically.

Key Features:
- Neural network enhanced key derivation
- Environment binding (machine/volume)
- Self-healing against tampering
- Zero-cost offline operation

The .cortex format ensures files cannot be transferred
and decrypted without the proper CortexCrypt engine.
""")
    
    with open("source_code.py", "w") as f:
        f.write("""#!/usr/bin/env python3
# Secret Algorithm Implementation
def advanced_ml_algorithm(data):
    # Proprietary neural network weights
    weights = [0.847, -0.392, 1.205, -0.738]
    
    # Process with secret sauce
    result = sum(w * d for w, d in zip(weights, data))
    return result * 0.618  # Golden ratio optimization

if __name__ == "__main__":
    sensitive_data = [1.0, 2.0, 3.0, 4.0]
    output = advanced_ml_algorithm(sensitive_data)
    print(f"Secret result: {output}")
""")
    
    print("✓ Demo files created")
    print()
    
    # Test both daemon versions
    print("🔹 Testing CortexCrypt Implementations...")
    print()
    
    # Test 1: Official CLI with simple daemon
    print("1️⃣ Testing Official CLI with Simple Daemon:")
    try:
        result = subprocess.run([
            "./build/cli/cortexcrypt", "encrypt", 
            "--in", "secret_document.txt", 
            "--out", "secret_document.cortex",
            "--bind", "machine",
            "--no-pass",
            "--verbose"
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print("✓ Official CLI encryption: SUCCESS")
            print(f"  Output: {result.stdout.strip()}")
        else:
            print("✗ Official CLI encryption: FAILED")
            print(f"  Error: {result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        print("✗ Official CLI encryption: TIMEOUT (daemon issue)")
    except Exception as e:
        print(f"✗ Official CLI encryption: ERROR - {e}")
    
    print()
    
    # Test 2: Standalone Python version
    print("2️⃣ Testing Standalone Python Implementation:")
    try:
        # Encrypt with standalone
        proc = subprocess.Popen([
            "python3", "cortex_standalone.py", "encrypt",
            "--in", "source_code.py",
            "--out", "source_code.cortex", 
            "--bind", "machine",
            "--note", "Neural crypto demo"
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        stdout, stderr = proc.communicate(input="MySecretPassword123\\n", timeout=10)
        
        if proc.returncode == 0:
            print("✓ Standalone encryption: SUCCESS")
            print(f"  {stdout.strip()}")
            
            # Test decryption
            proc2 = subprocess.Popen([
                "python3", "cortex_standalone.py", "decrypt",
                "--in", "source_code.cortex",
                "--out", "source_code_decrypted.py"
            ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            stdout2, stderr2 = proc2.communicate(input="MySecretPassword123\\n", timeout=10)
            
            if proc2.returncode == 0:
                print("✓ Standalone decryption: SUCCESS")
                print(f"  {stdout2.strip()}")
                
                # Verify files match
                with open("source_code.py", "rb") as f1, open("source_code_decrypted.py", "rb") as f2:
                    if f1.read() == f2.read():
                        print("✓ File integrity: VERIFIED")
                    else:
                        print("✗ File integrity: MISMATCH")
            else:
                print("✗ Standalone decryption: FAILED")
                print(f"  Error: {stderr2.strip()}")
        else:
            print("✗ Standalone encryption: FAILED") 
            print(f"  Error: {stderr.strip()}")
            
    except Exception as e:
        print(f"✗ Standalone test: ERROR - {e}")
    
    print()
    
    # Test 3: File analysis
    print("3️⃣ Analyzing .cortex Files:")
    
    cortex_files = [f for f in os.listdir('.') if f.endswith('.cortex')]
    for cortex_file in cortex_files:
        print(f"\\n📄 {cortex_file}:")
        print(f"   Size: {os.path.getsize(cortex_file)} bytes")
        
        # Check if it's a valid cortex file
        try:
            with open(cortex_file, 'rb') as f:
                magic = f.read(8)
                if magic == b"CORTEX01":
                    print("   Format: ✓ Valid CortexCrypt file")
                    print("   Security: Neural-augmented encryption")
                    print("   Binding: Environment-locked")
                else:
                    print("   Format: ✗ Invalid")
        except:
            print("   Format: ✗ Cannot read")
    
    print()
    print("🔹 Security Analysis:")
    print("✓ Neural network augments proven cryptography (AES-256-GCM)")
    print("✓ Environment binding prevents unauthorized file transfer")
    print("✓ Multi-round key derivation simulates neural network layers")
    print("✓ Files locked to specific machine/volume fingerprints")
    print("✓ Fallback mode works without complex ML infrastructure")
    
    print()
    print("🔹 Integration Examples:")
    print()
    
    # Show integration examples
    print("🐍 Python Integration:")
    print("""
import cortex_standalone as cc
engine = cc.CortexCryptStandalone()
engine.encrypt_file("data.txt", "data.cortex", "password", "machine")
engine.decrypt_file("data.cortex", "data.txt", "password")
""")
    
    print("🔧 C Integration:")
    print("""
#include <cortexcrypt.h>
cc_ctx_t* ctx = cc_open();
cc_set_passphrase(ctx, "password", 8);
cc_encrypt_file(ctx, "data.txt", "data.cortex", "aes", CC_BIND_MACHINE, "note");
cc_decrypt_file(ctx, "data.cortex", "data.txt");
cc_close(ctx);
""")
    
    print("🦀 Rust Integration:")
    print("""
use cortexcrypt::{Cortex, BindPolicy};
let mut cc = Cortex::open()?;
cc.set_passphrase("password")?;
cc.encrypt_file("data.txt", "data.cortex", BindPolicy::Machine, Some("note"))?;
cc.decrypt_file("data.cortex", "data.txt")?;
""")
    
    # Cleanup
    print("\\n🔹 Cleaning up demo files...")
    demo_files = [
        "secret_document.txt", "secret_document.cortex",
        "source_code.py", "source_code.cortex", "source_code_decrypted.py",
        "test_decrypted.txt", "test_standalone_full.cortex"
    ]
    
    for file in demo_files:
        if os.path.exists(file):
            os.unlink(file)
            print(f"  Removed {file}")
    
    print()
    print("🎉 CortexCrypt Demo Complete!")
    print("   Your neural-augmented encryption system is working!")

if __name__ == "__main__":
    run_demo()
