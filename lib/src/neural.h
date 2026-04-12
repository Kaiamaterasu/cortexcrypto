/*
 * CortexCrypt Neural Network Internal Header
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#ifndef NEURAL_H
#define NEURAL_H

#include <stdint.h>
#include <stddef.h>

/* Forward declaration */
typedef struct cortex_neural_ctx cortex_neural_ctx_t;

/* Function declarations */
cortex_neural_ctx_t* cortex_neural_init(const char* models_dir);
void cortex_neural_cleanup(cortex_neural_ctx_t* ctx);

int cortex_run_kdf_mlp(cortex_neural_ctx_t* ctx, const uint8_t input[49], uint8_t output[32]);
float cortex_compute_anomaly_score(cortex_neural_ctx_t* ctx, const float features[12]);

/* Fallback functions when neural network is not available */
int cortex_run_kdf_mlp_fallback(const uint8_t input[49], uint8_t output[32]);
float cortex_compute_anomaly_score_fallback(const float features[12]);

int cortex_get_model_id_hash(cortex_neural_ctx_t* ctx, uint8_t hash[32]);
int cortex_verify_models(cortex_neural_ctx_t* ctx, const uint8_t expected_hash[32]);

/* Utility functions */
void cortex_create_default_features(float features[12]);
void cortex_normalize_features(float features[12]);

#endif /* NEURAL_H */
