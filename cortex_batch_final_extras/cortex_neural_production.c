#include "cortex_neural_weights.h"
#include <math.h>

// ReLU activation
static inline float relu(float x) {
    return x > 0.0f ? x : 0.0f;
}

// Forward inference implementation
void cortex_neural_forward(const float input[49], float output[32]) {
    // Layer 1: 49 → 64 (ReLU)
    float layer1_output[64];
    for (int i = 0; i < 64; i++) {
        float sum = layer_1_biases[i];
        for (int j = 0; j < 49; j++) {
            sum += layer_1_weights[i][j] * input[j];
        }
        layer1_output[i] = relu(sum);
    }

    // Layer 2: 64 → 32 (ReLU)
    float layer2_output[32];
    for (int i = 0; i < 32; i++) {
        float sum = layer_2_biases[i];
        for (int j = 0; j < 64; j++) {
            sum += layer_2_weights[i][j] * layer1_output[j];
        }
        layer2_output[i] = relu(sum);
    }

    // Layer 3: 32 → 32 (Linear, clamped)
    for (int i = 0; i < 32; i++) {
        float sum = layer_3_biases[i];
        for (int j = 0; j < 32; j++) {
            sum += layer_3_weights[i][j] * layer2_output[j];
        }
        // Clamp to [-3, 3] range
        if (sum > 3.0f) sum = 3.0f;
        if (sum < -3.0f) sum = -3.0f;
        output[i] = sum;
    }
}
