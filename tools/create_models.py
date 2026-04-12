#!/usr/bin/env python3
"""
CortexCrypt Neural Network Model Generator
Creates ONNX models for threat detection and adaptive key derivation
"""

import numpy as np
import onnx
from onnx import helper, TensorProto
import os

def create_kdf_mlp_model():
    """Create a simple MLP model for KDF enhancement"""
    
    # Input: 49 features (passphrase hash + salts + binding + metadata)
    # Output: 32 bytes (enhanced key material)
    
    # Define model architecture
    input_name = "input"
    output_name = "output"
    
    # Input shape: [batch_size, 49]
    input_tensor = helper.make_tensor_value_info(
        input_name, TensorProto.FLOAT, [1, 49]
    )
    
    # Output shape: [batch_size, 32] 
    output_tensor = helper.make_tensor_value_info(
        output_name, TensorProto.FLOAT, [1, 32]
    )
    
    # Create simple linear transformation weights
    # Hidden layer: 49 -> 64
    W1 = np.random.randn(49, 64).astype(np.float32) * 0.1
    b1 = np.zeros(64, dtype=np.float32)
    
    # Output layer: 64 -> 32
    W2 = np.random.randn(64, 32).astype(np.float32) * 0.1
    b2 = np.zeros(32, dtype=np.float32)
    
    # Create weight tensors
    W1_init = helper.make_tensor("W1", TensorProto.FLOAT, [49, 64], W1.flatten())
    b1_init = helper.make_tensor("b1", TensorProto.FLOAT, [64], b1.flatten())
    W2_init = helper.make_tensor("W2", TensorProto.FLOAT, [64, 32], W2.flatten())
    b2_init = helper.make_tensor("b2", TensorProto.FLOAT, [32], b2.flatten())
    
    # Create computation graph
    # x -> MatMul(W1) -> Add(b1) -> Tanh -> MatMul(W2) -> Add(b2) -> output
    mm1_node = helper.make_node("MatMul", [input_name, "W1"], ["mm1"])
    add1_node = helper.make_node("Add", ["mm1", "b1"], ["add1"])
    tanh_node = helper.make_node("Tanh", ["add1"], ["tanh1"])
    mm2_node = helper.make_node("MatMul", ["tanh1", "W2"], ["mm2"])
    add2_node = helper.make_node("Add", ["mm2", "b2"], [output_name])
    
    # Create the graph
    graph = helper.make_graph(
        [mm1_node, add1_node, tanh_node, mm2_node, add2_node],
        "kdf_mlp",
        [input_tensor],
        [output_tensor],
        [W1_init, b1_init, W2_init, b2_init]
    )
    
    # Create the model
    model = helper.make_model(graph, producer_name="cortexcrypt")
    model.opset_import[0].version = 11
    
    return model

def create_anomaly_autoencoder_model():
    """Create autoencoder model for anomaly detection"""
    
    # Input: 12 features (telemetry data)
    # Output: 12 features (reconstruction)
    
    input_name = "input"
    output_name = "output"
    
    # Input/output tensors
    input_tensor = helper.make_tensor_value_info(
        input_name, TensorProto.FLOAT, [1, 12]
    )
    output_tensor = helper.make_tensor_value_info(
        output_name, TensorProto.FLOAT, [1, 12]
    )
    
    # Encoder: 12 -> 8 -> 4
    W1 = np.random.randn(12, 8).astype(np.float32) * 0.1
    b1 = np.zeros(8, dtype=np.float32)
    W2 = np.random.randn(8, 4).astype(np.float32) * 0.1
    b2 = np.zeros(4, dtype=np.float32)
    
    # Decoder: 4 -> 8 -> 12
    W3 = np.random.randn(4, 8).astype(np.float32) * 0.1
    b3 = np.zeros(8, dtype=np.float32)
    W4 = np.random.randn(8, 12).astype(np.float32) * 0.1
    b4 = np.zeros(12, dtype=np.float32)
    
    # Create initializers
    inits = [
        helper.make_tensor("W1", TensorProto.FLOAT, [12, 8], W1.flatten()),
        helper.make_tensor("b1", TensorProto.FLOAT, [8], b1.flatten()),
        helper.make_tensor("W2", TensorProto.FLOAT, [8, 4], W2.flatten()),
        helper.make_tensor("b2", TensorProto.FLOAT, [4], b2.flatten()),
        helper.make_tensor("W3", TensorProto.FLOAT, [4, 8], W3.flatten()),
        helper.make_tensor("b3", TensorProto.FLOAT, [8], b3.flatten()),
        helper.make_tensor("W4", TensorProto.FLOAT, [8, 12], W4.flatten()),
        helper.make_tensor("b4", TensorProto.FLOAT, [12], b4.flatten()),
    ]
    
    # Create computation graph (encoder-decoder)
    nodes = [
        # Encoder
        helper.make_node("MatMul", [input_name, "W1"], ["enc1"]),
        helper.make_node("Add", ["enc1", "b1"], ["enc1_b"]),
        helper.make_node("Relu", ["enc1_b"], ["enc1_act"]),
        
        helper.make_node("MatMul", ["enc1_act", "W2"], ["enc2"]),
        helper.make_node("Add", ["enc2", "b2"], ["latent"]),
        helper.make_node("Tanh", ["latent"], ["latent_act"]),
        
        # Decoder
        helper.make_node("MatMul", ["latent_act", "W3"], ["dec1"]),
        helper.make_node("Add", ["dec1", "b3"], ["dec1_b"]),
        helper.make_node("Relu", ["dec1_b"], ["dec1_act"]),
        
        helper.make_node("MatMul", ["dec1_act", "W4"], ["dec2"]),
        helper.make_node("Add", ["dec2", "b4"], [output_name]),
    ]
    
    graph = helper.make_graph(
        nodes,
        "anomaly_autoencoder",
        [input_tensor],
        [output_tensor],
        inits
    )
    
    model = helper.make_model(graph, producer_name="cortexcrypt")
    model.opset_import[0].version = 11
    
    return model

def main():
    """Generate and save the models"""
    
    print("Creating CortexCrypt Neural Network Models...")
    
    # Create output directory
    os.makedirs("models", exist_ok=True)
    
    # Create KDF MLP model
    print("Generating KDF MLP model...")
    kdf_model = create_kdf_mlp_model()
    
    # Save KDF model
    onnx.save(kdf_model, "models/kdf_mlp.onnx")
    print("✓ Saved models/kdf_mlp.onnx")
    
    # Create anomaly detection model
    print("Generating Anomaly Autoencoder model...")
    anomaly_model = create_anomaly_autoencoder_model()
    
    # Save anomaly model
    onnx.save(anomaly_model, "models/anomaly_autoencoder.onnx")
    print("✓ Saved models/anomaly_autoencoder.onnx")
    
    # Create model metadata
    with open("models/model_info.json", "w") as f:
        f.write('''{{
    "kdf_mlp": {{
        "version": "1.0.0",
        "input_shape": [1, 49],
        "output_shape": [1, 32],
        "description": "Multi-layer perceptron for adaptive key derivation"
    }},
    "anomaly_autoencoder": {{
        "version": "1.0.0", 
        "input_shape": [1, 12],
        "output_shape": [1, 12],
        "description": "Autoencoder for real-time anomaly detection"
    }}
}}''')
    
    print("✓ Saved models/model_info.json")
    print("\\nModels created successfully!")
    print("To install: sudo cp models/* /usr/local/share/cortexcrypt/models/")

if __name__ == "__main__":
    main()
