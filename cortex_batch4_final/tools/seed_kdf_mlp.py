#!/usr/bin/env python3
"""
CortexCrypt KDF MLP Model Generator
Copyright 2024 CortexCrypt Contributors
Licensed under Apache 2.0

Generates a deterministic seed model for the KDF augmentation MLP.
Architecture: Dense(64, ReLU) → Dense(32, ReLU) → Dense(32, Linear)
Input: 49 bytes normalized to [0,1]
Output: 32 float values in [-3,3] range
"""

import os
import sys
import numpy as np

# Try to import required packages
try:
    import torch
    import torch.nn as nn
    import torch.onnx
    HAS_TORCH = True
except ImportError:
    print("PyTorch not available, creating minimal ONNX placeholder")
    HAS_TORCH = False

class KDF_MLP(nn.Module):
    """KDF augmentation MLP model"""
    
    def __init__(self, seed=42):
        super(KDF_MLP, self).__init__()
        
        # Set deterministic seed
        torch.manual_seed(seed)
        np.random.seed(seed)
        
        # Architecture: 49 → 64 → 32 → 32
        self.layer1 = nn.Linear(49, 64)
        self.layer2 = nn.Linear(64, 32) 
        self.layer3 = nn.Linear(32, 32)
        
        # Activation
        self.relu = nn.ReLU()
        
        # Initialize weights deterministically
        self._init_weights()
    
    def _init_weights(self):
        """Initialize weights with Xavier/He initialization"""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                nn.init.constant_(module.bias, 0.01)
    
    def forward(self, x):
        # Input normalization is done externally
        x = self.relu(self.layer1(x))
        x = self.relu(self.layer2(x))
        x = self.layer3(x)  # Linear output
        
        # Clamp output to [-3, 3] range
        x = torch.clamp(x, -3.0, 3.0)
        return x

def create_minimal_onnx():
    """Create a minimal ONNX file when PyTorch is not available"""
    
    # This creates a placeholder ONNX file
    # In practice, the C code will fall back to SHA256-based "neural network"
    
    onnx_content = b"""
    # Minimal ONNX placeholder for KDF MLP
    # This is not a real ONNX model - fallback will be used
    """
    
    os.makedirs("../models", exist_ok=True)
    
    with open("../models/kdf_mlp.onnx", "wb") as f:
        f.write(onnx_content)
    
    print("Created minimal ONNX placeholder (fallback mode will be used)")

def generate_model():
    """Generate and export the KDF MLP model"""
    
    if not HAS_TORCH:
        create_minimal_onnx()
        return
    
    print("Generating KDF MLP model...")
    
    # Create model with deterministic seed
    model = KDF_MLP(seed=42)
    model.eval()
    
    # Create dummy input for tracing (batch_size=1, input_dim=49)
    dummy_input = torch.randn(1, 49)
    
    # Ensure output directory exists
    os.makedirs("../models", exist_ok=True)
    output_path = "../models/kdf_mlp.onnx"
    
    # Export to ONNX
    torch.onnx.export(
        model,
        dummy_input,
        output_path,
        export_params=True,
        opset_version=11,
        do_constant_folding=True,
        input_names=['input'],
        output_names=['output'],
        dynamic_axes={
            'input': {0: 'batch_size'},
            'output': {0: 'batch_size'}
        }
    )
    
    print(f"KDF MLP model exported to {output_path}")
    
    # Test the model
    test_model(output_path)

def test_model(model_path):
    """Test the exported ONNX model"""
    
    try:
        import onnxruntime as ort
        
        # Load ONNX model
        session = ort.InferenceSession(model_path, providers=['CPUExecutionProvider'])
        
        # Test with dummy input
        test_input = np.random.rand(1, 49).astype(np.float32)
        
        # Run inference
        outputs = session.run(['output'], {'input': test_input})
        output = outputs[0]
        
        print(f"Model test successful:")
        print(f"  Input shape: {test_input.shape}")
        print(f"  Output shape: {output.shape}")
        print(f"  Output range: [{output.min():.3f}, {output.max():.3f}]")
        
        # Verify output is in expected range [-3, 3]
        if output.min() >= -3.1 and output.max() <= 3.1:
            print("  ✓ Output range validation passed")
        else:
            print("  ✗ Output range validation failed")
            
    except ImportError:
        print("ONNX Runtime not available for testing")
    except Exception as e:
        print(f"Model test failed: {e}")

def create_model_metadata():
    """Create metadata about the model"""
    
    metadata = {
        "model_type": "kdf_mlp",
        "version": "1.0",
        "architecture": "49->64->32->32",
        "seed": 42,
        "input_shape": [1, 49],
        "output_shape": [1, 32],
        "output_range": [-3.0, 3.0],
        "description": "KDF augmentation MLP for CortexCrypt"
    }
    
    os.makedirs("../models", exist_ok=True)
    
    # Save as simple JSON (without importing json module)
    with open("../models/kdf_mlp_meta.txt", "w") as f:
        for key, value in metadata.items():
            f.write(f"{key}: {value}\n")
    
    print("Model metadata saved to ../models/kdf_mlp_meta.txt")

def main():
    """Main function"""
    
    print("CortexCrypt KDF MLP Model Generator")
    print("==================================")
    
    if HAS_TORCH:
        print("PyTorch available - generating full ONNX model")
    else:
        print("PyTorch not available - creating placeholder")
    
    generate_model()
    create_model_metadata()
    
    print("\nKDF MLP model generation complete.")
    print("The model provides cryptographic key derivation augmentation.")
    print("Output is fed into HKDF - the neural network does NOT replace proven crypto.")

if __name__ == "__main__":
    main()
