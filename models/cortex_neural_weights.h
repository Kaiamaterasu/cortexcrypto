/*
 * CortexCrypt Neural Network Weights Header
 * Production Model Weights
 * Copyright 2024 CortexCrypt Contributors
 */

#ifndef CORTEX_NEURAL_WEIGHTS_H
#define CORTEX_NEURAL_WEIGHTS_H

#include <stdint.h>

/* Layer 1: 49 input -> 64 hidden (ReLU) */
extern const float layer_1_weights[64][49];
extern const float layer_1_biases[64];

/* Layer 2: 64 -> 32 hidden (ReLU) */
extern const float layer_2_weights[32][64];
extern const float layer_2_biases[32];

/* Layer 3: 32 -> 32 output (Linear, clamped to [-3,3]) */
extern const float layer_3_weights[32][32];
extern const float layer_3_biases[32];

/* Model metadata */
#define MODEL_VERSION "1.0.0"
#define MODEL_INPUT_SIZE 49
#define MODEL_OUTPUT_SIZE 32

#endif /* CORTEX_NEURAL_WEIGHTS_H */