#!/usr/bin/env python3
# Test the trained CortexCrypto neural network

import sys
sys.path.append('..')
from train_neural_network import CortexNeuralNetwork

# Load trained model
network = CortexNeuralNetwork()
network.load_model('cortex_neural_model.json')

# Test with realistic input
test_input = [0.5] * 49  # Normalized test input
output = network.forward(test_input)

print(f'Neural output: {output[:5]}...')
print(f'Output range: [{min(output):.3f}, {max(output):.3f}]')
