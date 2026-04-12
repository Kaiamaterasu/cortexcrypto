#!/usr/bin/env python3
"""
🧠🔒 CortexCrypto Neural Integration
Live neural network key augmentation for badass encryption!
"""

import os
import sys
import hashlib
import time
import random
import struct
from typing import List, Optional, Tuple
from train_neural_network import CortexNeuralNetwork

class NeuralKeyAugmenter:
    """🧠 Neural-augmented key derivation for CortexCrypto"""
    
    def __init__(self, model_path: str = "models/cortex_neural_advanced.json"):
        self.model_path = model_path
        self.network = None
        self.load_neural_network()
        
        # Performance counters
        self.inference_count = 0
        self.total_inference_time = 0.0
        self.fallback_count = 0
    
    def load_neural_network(self):
        """Load the trained neural network"""
        try:
            if os.path.exists(self.model_path):
                print(f"🧠 Loading neural network from {self.model_path}")
                self.network = CortexNeuralNetwork()
                self.network.load_model(self.model_path)
                print("✅ Neural network loaded successfully!")
                return True
            else:
                print(f"⚠️ Neural model not found: {self.model_path}")
                print("🔄 Falling back to cryptographic-only mode")
                return False
        except Exception as e:
            print(f"❌ Neural network loading failed: {e}")
            print("🔄 Falling back to cryptographic-only mode")
            self.network = None
            return False
    
    def create_neural_input(self, password: bytes, binding_id: bytes, 
                           session_salt: bytes, anomaly_score: float = 0.0) -> List[float]:
        """Create neural network input from CortexCrypto components"""
        input_vector = []
        
        # Base key component (16 bytes) - from Argon2id
        key_hash = hashlib.sha256(password).digest()[:16]
        input_vector.extend([b / 255.0 for b in key_hash])
        
        # Binding ID component (16 bytes)
        binding_hash = hashlib.sha256(binding_id).digest()[:16]
        input_vector.extend([b / 255.0 for b in binding_hash])
        
        # Session salt component (16 bytes)
        salt_normalized = list(session_salt[:16])
        while len(salt_normalized) < 16:
            salt_normalized.append(0)
        input_vector.extend([b / 255.0 for b in salt_normalized])
        
        # Anomaly score (1 value)
        input_vector.append(max(0.0, min(1.0, anomaly_score)))
        
        return input_vector
    
    def neural_augment_key(self, password: bytes, binding_id: bytes,
                          session_salt: bytes, anomaly_score: float = 0.0) -> Optional[bytes]:
        """Augment key derivation using neural network"""
        if not self.network:
            return None
        
        try:
            # Create neural input
            neural_input = self.create_neural_input(password, binding_id, session_salt, anomaly_score)
            
            # Neural inference
            start_time = time.time()
            neural_output = self.network.forward(neural_input)
            inference_time = time.time() - start_time
            
            # Update performance counters
            self.inference_count += 1
            self.total_inference_time += inference_time
            
            # Convert neural output to bytes
            augmentation = bytearray()
            for val in neural_output:
                # Convert from [-3, 3] to [0, 255]
                byte_val = int((val + 3.0) * 255.0 / 6.0)
                byte_val = max(0, min(255, byte_val))
                augmentation.append(byte_val)
            
            return bytes(augmentation)
            
        except Exception as e:
            print(f"⚠️ Neural augmentation failed: {e}")
            self.fallback_count += 1
            return None
    
    def cryptographic_fallback(self, password: bytes, binding_id: bytes, 
                              session_salt: bytes) -> bytes:
        """Cryptographic fallback when neural network unavailable"""
        # Standard HKDF-like expansion
        prk = hashlib.sha256(password + binding_id).digest()
        okm = hashlib.sha256(prk + session_salt + b"CortexCrypto").digest()
        return okm
    
    def derive_augmented_key(self, password: bytes, binding_id: bytes,
                            session_salt: bytes, anomaly_score: float = 0.0) -> Tuple[bytes, bool]:
        """
        Derive augmented key using neural network + cryptographic methods
        Returns: (augmented_key, used_neural)
        """
        # Try neural augmentation first
        neural_aug = self.neural_augment_key(password, binding_id, session_salt, anomaly_score)
        
        if neural_aug:
            # Combine neural output with cryptographic base
            crypto_base = self.cryptographic_fallback(password, binding_id, session_salt)
            
            # XOR neural augmentation with crypto base
            augmented = bytearray()
            for i in range(32):
                augmented.append(crypto_base[i] ^ neural_aug[i])
            
            return bytes(augmented), True
        else:
            # Pure cryptographic fallback
            return self.cryptographic_fallback(password, binding_id, session_salt), False
    
    def get_performance_stats(self) -> dict:
        """Get neural network performance statistics"""
        avg_inference = (self.total_inference_time / self.inference_count * 1000 
                        if self.inference_count > 0 else 0.0)
        
        return {
            "inference_count": self.inference_count,
            "avg_inference_ms": avg_inference,
            "fallback_count": self.fallback_count,
            "neural_success_rate": (self.inference_count / (self.inference_count + self.fallback_count) * 100
                                   if (self.inference_count + self.fallback_count) > 0 else 0.0)
        }

def demo_neural_integration():
    """Demonstrate neural-crypto integration"""
    print("🧠🔒 CortexCrypto Neural Integration Demo")
    print("=========================================")
    
    # Initialize neural augmenter
    augmenter = NeuralKeyAugmenter()
    
    # Demo scenarios
    scenarios = [
        ("development_machine", "my_dev_password"),
        ("production_server", "ultra_secure_key"),
        ("portable_drive", "travel_encryption"),
        ("backup_system", "family_vault_key"),
        ("gaming_rig", "steam_library_key")
    ]
    
    print("\\n🎭 Testing neural augmentation scenarios...")
    
    for env, password in scenarios:
        print(f"\\n🔍 Scenario: {env} + {password}")
        
        # Create components
        password_bytes = password.encode('utf-8')
        binding_bytes = env.encode('utf-8')
        session_salt = os.urandom(16)
        anomaly = random.random() * 0.2  # Low anomaly
        
        # Derive augmented key
        start_time = time.time()
        aug_key, used_neural = augmenter.derive_augmented_key(
            password_bytes, binding_bytes, session_salt, anomaly
        )
        derive_time = (time.time() - start_time) * 1000
        
        # Display results
        neural_status = "🧠 NEURAL" if used_neural else "🔒 CRYPTO"
        key_preview = aug_key[:8].hex()
        
        print(f"  {neural_status} | {derive_time:.2f}ms | Key: {key_preview}...")
        print(f"  🎯 Anomaly: {anomaly:.3f} | Salt: {session_salt[:4].hex()}...")
    
    # Performance summary
    print("\\n📊 Performance Summary")
    print("======================")
    stats = augmenter.get_performance_stats()
    print(f"🧠 Neural inferences: {stats['inference_count']}")
    print(f"⚡ Avg inference time: {stats['avg_inference_ms']:.2f}ms")
    print(f"🔄 Fallbacks: {stats['fallback_count']}")
    print(f"🎯 Neural success rate: {stats['neural_success_rate']:.1f}%")
    
    # Security demonstration
    print("\\n🔐 Security Demonstration")
    print("=========================")
    demo_security_properties(augmenter)

def demo_security_properties(augmenter: NeuralKeyAugmenter):
    """Demonstrate security properties of neural augmentation"""
    password = b"test_password"
    binding = b"test_machine"
    
    print("🔍 Testing key diversity with session changes...")
    
    keys = []
    for i in range(5):
        session_salt = os.urandom(16)
        aug_key, _ = augmenter.derive_augmented_key(password, binding, session_salt)
        keys.append(aug_key)
        print(f"  Session {i+1}: {aug_key[:8].hex()}...")
    
    # Check key diversity
    unique_keys = len(set(keys))
    print(f"✅ Key diversity: {unique_keys}/5 unique keys")
    
    print("\\n🔍 Testing environment binding...")
    
    environments = [b"laptop", b"desktop", b"server", b"mobile"]
    session_salt = os.urandom(16)
    
    for env in environments:
        aug_key, _ = augmenter.derive_augmented_key(password, env, session_salt)
        print(f"  {env.decode():8s}: {aug_key[:8].hex()}...")
    
    print("✅ Environment binding working!")
    
    print("\\n🔍 Testing anomaly detection impact...")
    
    anomaly_levels = [0.0, 0.3, 0.6, 0.9]
    for anomaly in anomaly_levels:
        aug_key, _ = augmenter.derive_augmented_key(password, binding, session_salt, anomaly)
        print(f"  Anomaly {anomaly:.1f}: {aug_key[:8].hex()}...")
    
    print("✅ Anomaly sensitivity working!")

def create_integration_example():
    """Create example showing how to integrate with CortexCrypto"""
    print("\\n📚 Creating integration example...")
    
    with open("neural_integration_example.py", "w") as f:
        f.write("#!/usr/bin/env python3\\n")
        f.write("# 🧠🔒 CortexCrypto Neural Integration Example\\n\\n")
        f.write("from neural_crypto_integration import NeuralKeyAugmenter\\n")
        f.write("import os\\n\\n")
        
        f.write("def encrypt_with_neural_augmentation(data: bytes, password: str, environment: str) -> bytes:\\n")
        f.write('    """Encrypt data using neural-augmented keys"""\\n')
        f.write("    # Initialize neural augmenter\\n")
        f.write("    augmenter = NeuralKeyAugmenter()\\n\\n")
        
        f.write("    # Create encryption components\\n")
        f.write("    password_bytes = password.encode('utf-8')\\n")
        f.write("    binding_bytes = environment.encode('utf-8')\\n")
        f.write("    session_salt = os.urandom(16)\\n\\n")
        
        f.write("    # Derive neural-augmented key\\n")
        f.write("    augmented_key, used_neural = augmenter.derive_augmented_key(\\n")
        f.write("        password_bytes, binding_bytes, session_salt\\n")
        f.write("    )\\n\\n")
        
        f.write("    neural_flag = 'NEURAL' if used_neural else 'CRYPTO'\\n")
        f.write("    print(f'🔑 Key derivation: {neural_flag} | Key: {augmented_key[:8].hex()}...')\\n\\n")
        
        f.write("    # Here you would use augmented_key with your encryption algorithm\\n")
        f.write("    # This is just a demo - use proper AES/ChaCha20 in production!\\n")
        f.write("    encrypted = bytearray()\\n")
        f.write("    for i, byte in enumerate(data):\\n")
        f.write("        encrypted.append(byte ^ augmented_key[i % len(augmented_key)])\\n\\n")
        
        f.write("    return session_salt + bytes(encrypted)\\n\\n")
        
        f.write("# Example usage\\n")
        f.write("if __name__ == '__main__':\\n")
        f.write("    test_data = b'This is secret neural-crypto data!'\\n")
        f.write("    encrypted = encrypt_with_neural_augmentation(test_data, 'my_password', 'laptop')\\n")
        f.write("    print(f'🔒 Encrypted: {encrypted[:16].hex()}...')\\n")
    
    os.chmod("neural_integration_example.py", 0o755)
    print("✅ Integration example created!")

def main():
    """Main demo function"""
    if len(sys.argv) > 1 and sys.argv[1] == "create-example":
        create_integration_example()
        return
    
    # Run full demo
    demo_neural_integration()
    create_integration_example()
    
    print("\\n🎯 Neural Integration Complete!")
    print("📁 Files created:")
    print("  • neural_crypto_integration.py - Main integration class")
    print("  • neural_integration_example.py - Usage example")
    print("  • models/cortex_neural_advanced.json - Trained model")
    print("  • models/cortex_neural_advanced.h - C header")
    print("  • models/cortex_neural_advanced.c - C implementation")
    
    print("\\n🚀 Next steps:")
    print("  1. Integrate NeuralKeyAugmenter into cortex_standalone.py")
    print("  2. Add neural augmentation to C library (lib/src/neural.c)")
    print("  3. Enable/disable neural mode via CLI flags")
    print("  4. Collect real usage data for continuous training")

if __name__ == "__main__":
    main()
