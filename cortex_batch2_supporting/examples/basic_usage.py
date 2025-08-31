#!/usr/bin/env python3
"""
CortexCrypt Basic Usage Examples
Neural-Augmented Encryption Demo
"""

import os
import sys
import subprocess

# Add parent directory to path to import cortex_standalone
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def demo_python_standalone():
    """Demo Python standalone encryption/decryption"""
    print("🐍 Python Standalone Demo")
    print("-" * 30)
    
    # Create test file
    test_content = "This is secret data that should be protected!"
    with open("demo_secret.txt", "w") as f:
        f.write(test_content)
    
    print("📄 Created test file: demo_secret.txt")
    
    # Encrypt with machine binding
    print("🔒 Encrypting with machine binding...")
    proc = subprocess.Popen([
        "python3", "../cortex_standalone.py", "encrypt",
        "--in", "demo_secret.txt", 
        "--out", "demo_secret.cortex",
        "--bind", "machine"
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    stdout, stderr = proc.communicate(input="DemoPassword123\n")
    
    if proc.returncode == 0:
        print("✅ Encryption successful!")
        print(f"📦 Created: demo_secret.cortex ({os.path.getsize('demo_secret.cortex')} bytes)")
        
        # Show file info
        print("\n📋 File Information:")
        info_proc = subprocess.run([
            "python3", "../cortex_standalone.py", "info",
            "--in", "demo_secret.cortex"
        ], capture_output=True, text=True)
        print(info_proc.stdout)
        
        # Decrypt file
        print("🔓 Decrypting...")
        proc2 = subprocess.Popen([
            "python3", "../cortex_standalone.py", "decrypt",
            "--in", "demo_secret.cortex",
            "--out", "demo_decrypted.txt"
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        stdout2, stderr2 = proc2.communicate(input="DemoPassword123\n")
        
        if proc2.returncode == 0:
            with open("demo_decrypted.txt", "r") as f:
                decrypted_content = f.read()
            
            if decrypted_content == test_content:
                print("✅ Decryption successful - content matches!")
            else:
                print("❌ Decryption failed - content mismatch")
        else:
            print(f"❌ Decryption failed: {stderr2}")
    else:
        print(f"❌ Encryption failed: {stderr}")
    
    # Cleanup
    for f in ["demo_secret.txt", "demo_secret.cortex", "demo_decrypted.txt"]:
        if os.path.exists(f):
            os.remove(f)
    
    print("🧹 Demo cleanup complete\n")

def demo_cli_usage():
    """Demo CLI tool usage"""
    print("🖥️  CLI Tool Demo")
    print("-" * 20)
    
    # Check if CLI is available
    if not os.path.exists("../build/cli/cortexcrypt"):
        print("⚠️  CLI not built - run 'make all' first")
        return
    
    # Start simple daemon
    print("🚀 Starting simple daemon...")
    daemon_proc = subprocess.Popen(["../simple_daemon"], 
                                 stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE)
    
    import time
    time.sleep(2)
    
    try:
        # Create test file
        with open("cli_demo.txt", "w") as f:
            f.write("CLI encryption demo content")
        
        print("📄 Created test file: cli_demo.txt")
        
        # Encrypt without password (device binding only)
        print("🔒 Encrypting with CLI (no password)...")
        result = subprocess.run([
            "../build/cli/cortexcrypt", "encrypt",
            "--in", "cli_demo.txt",
            "--out", "cli_demo.cortex", 
            "--bind", "machine",
            "--no-pass"
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print("✅ CLI encryption successful!")
            print(f"📦 Created: cli_demo.cortex ({os.path.getsize('cli_demo.cortex')} bytes)")
            
            # Show file info
            info_result = subprocess.run([
                "../build/cli/cortexcrypt", "info",
                "--in", "cli_demo.cortex"
            ], capture_output=True, text=True, timeout=5)
            
            if info_result.returncode == 0:
                print("\n📋 File Information:")
                print(info_result.stdout)
            else:
                print("⚠️  Info command warning")
            
        else:
            print(f"❌ CLI encryption failed: {result.stderr}")
    
    except Exception as e:
        print(f"⚠️  CLI demo error: {e}")
    
    finally:
        # Cleanup daemon and files
        daemon_proc.terminate()
        daemon_proc.wait()
        
        for f in ["cli_demo.txt", "cli_demo.cortex"]:
            if os.path.exists(f):
                os.remove(f)
        
        print("🧹 CLI demo cleanup complete\n")

def demo_binding_differences():
    """Demo different binding types"""
    print("🔗 Environment Binding Demo")
    print("-" * 30)
    
    test_content = "Binding test content"
    with open("binding_demo.txt", "w") as f:
        f.write(test_content)
    
    # Test machine binding
    print("🖥️  Testing machine binding...")
    proc1 = subprocess.Popen([
        "python3", "../cortex_standalone.py", "encrypt",
        "--in", "binding_demo.txt",
        "--out", "machine_bound.cortex", 
        "--bind", "machine"
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    stdout1, stderr1 = proc1.communicate(input="BindingDemo\n")
    
    # Test volume binding
    print("💾 Testing volume binding...")
    proc2 = subprocess.Popen([
        "python3", "../cortex_standalone.py", "encrypt",
        "--in", "binding_demo.txt",
        "--out", "volume_bound.cortex",
        "--bind", "volume"
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    stdout2, stderr2 = proc2.communicate(input="BindingDemo\n")
    
    if proc1.returncode == 0 and proc2.returncode == 0:
        # Compare file sizes and content
        machine_size = os.path.getsize("machine_bound.cortex")
        volume_size = os.path.getsize("volume_bound.cortex")
        
        print(f"📊 Machine-bound file: {machine_size} bytes")
        print(f"📊 Volume-bound file: {volume_size} bytes")
        
        # Check if files are different (they should be due to different binding)
        with open("machine_bound.cortex", "rb") as f1, open("volume_bound.cortex", "rb") as f2:
            if f1.read() != f2.read():
                print("✅ Different bindings create different encrypted files")
            else:
                print("⚠️  Warning: Bindings created identical files")
    else:
        print("❌ Binding demo failed")
    
    # Cleanup
    for f in ["binding_demo.txt", "machine_bound.cortex", "volume_bound.cortex"]:
        if os.path.exists(f):
            os.remove(f)
    
    print("🧹 Binding demo cleanup complete\n")

def demo_neural_augmentation():
    """Demo neural network key augmentation"""
    print("🧠 Neural Augmentation Demo")
    print("-" * 30)
    
    test_content = "Neural augmentation test"
    with open("neural_demo.txt", "w") as f:
        f.write(test_content)
    
    passwords = ["NeuralPass1", "NeuralPass2", "NeuralPass1"]  # Same password used twice
    cortex_files = []
    
    print("🔑 Testing neural key differentiation...")
    
    for i, password in enumerate(passwords):
        print(f"  Encrypting with password {i+1}...")
        
        proc = subprocess.Popen([
            "python3", "../cortex_standalone.py", "encrypt",
            "--in", "neural_demo.txt",
            "--out", f"neural_{i}.cortex",
            "--bind", "machine"
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        stdout, stderr = proc.communicate(input=f"{password}\n")
        
        if proc.returncode == 0:
            cortex_files.append(f"neural_{i}.cortex")
        else:
            print(f"❌ Encryption {i} failed: {stderr}")
            return
    
    if len(cortex_files) == 3:
        # Compare files
        with open(cortex_files[0], 'rb') as f1, open(cortex_files[1], 'rb') as f2, open(cortex_files[2], 'rb') as f3:
            data1 = f1.read()
            data2 = f2.read() 
            data3 = f3.read()
            
            if data1 != data2:
                print("✅ Different passwords create different neural keys")
            else:
                print("⚠️  Warning: Different passwords created identical files")
            
            if data1 == data3:
                print("✅ Same password creates reproducible neural keys")
            else:
                print("⚠️  Warning: Same password created different files")
    
    # Cleanup
    for f in ["neural_demo.txt"] + cortex_files:
        if os.path.exists(f):
            os.remove(f)
    
    print("🧹 Neural demo cleanup complete\n")

def main():
    """Run all demos"""
    print("🎯 CortexCrypt Usage Examples")
    print("==============================")
    print("Demonstrating neural-augmented encryption capabilities\n")
    
    # Change to examples directory
    if not os.path.basename(os.getcwd()) == "examples":
        print("⚠️  Please run from the examples/ directory")
        return
    
    try:
        demo_python_standalone()
        demo_cli_usage()
        demo_binding_differences()
        demo_neural_augmentation()
        
        print("🎉 All demos completed successfully!")
        print("\n📚 Next steps:")
        print("  • Read DOCUMENTATION.md for technical details")
        print("  • Run 'python3 ../perfect_score_tests.py' for comprehensive testing")
        print("  • Check out other examples in this directory")
        
    except KeyboardInterrupt:
        print("\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")

if __name__ == "__main__":
    main()
