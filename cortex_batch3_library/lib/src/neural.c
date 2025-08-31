/*
 * CortexCrypt Neural Network Interface
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "neural.h"
#include "utils.h"

#ifdef USE_ONNX_RUNTIME
#include <onnxruntime_c_api.h>
#endif

/* Neural context structure */
struct cortex_neural_ctx {
#ifdef USE_ONNX_RUNTIME
    const OrtApi* ort_api;
    OrtEnv* env;
    OrtSession* kdf_session;
    OrtSession* anomaly_session;
    OrtMemoryInfo* memory_info;
#endif
    uint8_t kdf_model_hash[32];
    uint8_t anomaly_model_hash[32];
    int initialized;
};

/* Compute model hash for verification with size limit */
static int compute_model_hash(const char* model_path, uint8_t hash[32]) {
    FILE* fp = fopen(model_path, "rb");
    if (!fp) return -1;
    
    /* Check file size to prevent reading huge files */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    /* Limit model file size to 100MB to prevent hanging */
    if (file_size > 100 * 1024 * 1024) {
        fclose(fp);
        return -1;
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx || !EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        fclose(fp);
        if (ctx) EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    uint8_t buf[4096];
    size_t read_len;
    size_t total_read = 0;
    
    /* Read with limits to prevent infinite reading */
    while ((read_len = fread(buf, 1, sizeof(buf), fp)) > 0) {
        total_read += read_len;
        
        /* Safety check: prevent reading more than file_size */
        if (total_read > (size_t)file_size) {
            fclose(fp);
            EVP_MD_CTX_free(ctx);
            return -1;
        }
        
        if (!EVP_DigestUpdate(ctx, buf, read_len)) {
            fclose(fp);
            EVP_MD_CTX_free(ctx);
            return -1;
        }
    }
    
    fclose(fp);
    
    unsigned int hash_len;
    if (!EVP_DigestFinal_ex(ctx, hash, &hash_len) || hash_len != 32) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    EVP_MD_CTX_free(ctx);
    return 0;
}

#ifdef USE_ONNX_RUNTIME
/* ONNX Runtime error checking */
static int check_ort_status(const OrtApi* ort_api, OrtStatus* status) {
    if (status != NULL) {
        const char* msg = ort_api->GetErrorMessage(status);
        fprintf(stderr, "ONNX Runtime error: %s\n", msg);
        ort_api->ReleaseStatus(status);
        return -1;
    }
    return 0;
}
#endif

/* Safe fallback when neural network isn't available */
int cortex_run_kdf_mlp_fallback(const uint8_t input[49], uint8_t output[32]) {
    /* Fallback using SHA256 with multiple rounds for neural-like behavior */
    uint8_t temp[64];
    uint8_t round_output[32];
    
    /* Initialize with input data */
    memcpy(temp, input, 49);
    memset(temp + 49, 0xAA, 15); /* Padding */
    
    /* Multiple rounds to simulate neural network layers */
    for (int round = 0; round < 3; round++) {
        /* Hash current state */
        SHA256(temp, 64, round_output);
        
        /* Mix with original input (skip connections) */
        for (int i = 0; i < 32; i++) {
            temp[i] = round_output[i] ^ input[i % 49];
        }
        
        /* Add round-specific mixing */
        temp[32 + round] ^= 0x33 * (round + 1);
    }
    
    /* Final hash for output */
    SHA256(temp, 64, output);
    return 0;
}

float cortex_compute_anomaly_score_fallback(const float features[12]) {
    /* Simple heuristic-based anomaly detection */
    float score = 0.1f; /* Base safe score */
    
    /* Check for unusual patterns in features */
    for (int i = 0; i < 12; i++) {
        if (features[i] > 0.8f) score += 0.05f;
        if (features[i] < 0.1f) score += 0.02f;
    }
    
    return fminf(0.9f, score); /* Cap at 0.9 for fallback mode */
}

/* Initialize neural context */
cortex_neural_ctx_t* cortex_neural_init(const char* models_dir) {
    cortex_neural_ctx_t* ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    
#ifdef USE_ONNX_RUNTIME
    /* Initialize ONNX Runtime */
    ctx->ort_api = OrtGetApiBase()->GetApi(ORT_API_VERSION);
    if (!ctx->ort_api) {
        free(ctx);
        return NULL;
    }
    
    /* Create environment */
    if (check_ort_status(ctx->ort_api, ctx->ort_api->CreateEnv(ORT_LOGGING_LEVEL_WARNING, 
                                                "cortexcrypt", &ctx->env)) != 0) {
        free(ctx);
        return NULL;
    }
    
    /* Create memory info */
    if (check_ort_status(ctx->ort_api, ctx->ort_api->CreateCpuMemoryInfo(OrtArenaAllocator, 
                                                          OrtMemTypeDefault, 
                                                          &ctx->memory_info)) != 0) {
        ctx->ort_api->ReleaseEnv(ctx->env);
        free(ctx);
        return NULL;
    }
    
    /* Load KDF MLP model */
    char kdf_model_path[512];
    snprintf(kdf_model_path, sizeof(kdf_model_path), "%s/kdf_mlp.onnx", models_dir);
    
    OrtSessionOptions* session_options;
    if (check_ort_status(ctx->ort_api, ctx->ort_api->CreateSessionOptions(&session_options)) != 0) {
        goto cleanup;
    }
    
    /* Set CPU-only execution */
    if (check_ort_status(ctx->ort_api, ctx->ort_api->SetIntraOpNumThreads(session_options, 1)) != 0) {
        ctx->ort_api->ReleaseSessionOptions(session_options);
        goto cleanup;
    }
    
    if (check_ort_status(ctx->ort_api, ctx->ort_api->CreateSession(ctx->env, kdf_model_path, 
                                                    session_options, &ctx->kdf_session)) != 0) {
        ctx->ort_api->ReleaseSessionOptions(session_options);
        goto cleanup;
    }
    
    /* Load anomaly autoencoder model */
    char anomaly_model_path[512];
    snprintf(anomaly_model_path, sizeof(anomaly_model_path), "%s/anomaly_autoencoder.onnx", models_dir);
    
    if (check_ort_status(ctx->ort_api, ctx->ort_api->CreateSession(ctx->env, anomaly_model_path,
                                                    session_options, &ctx->anomaly_session)) != 0) {
        ctx->ort_api->ReleaseSessionOptions(session_options);
        /* Continue without anomaly detection if model missing */
        ctx->anomaly_session = NULL;
    }
    
    ctx->ort_api->ReleaseSessionOptions(session_options);
    
    /* Compute model hashes for verification */
    if (compute_model_hash(kdf_model_path, ctx->kdf_model_hash) != 0) {
        goto cleanup;
    }
    
    if (ctx->anomaly_session) {
        compute_model_hash(anomaly_model_path, ctx->anomaly_model_hash);
    }
    
    ctx->initialized = 1;
    return ctx;
    
cleanup:
    if (ctx->kdf_session) ctx->ort_api->ReleaseSession(ctx->kdf_session);
    if (ctx->anomaly_session) ctx->ort_api->ReleaseSession(ctx->anomaly_session);
    if (ctx->memory_info) ctx->ort_api->ReleaseMemoryInfo(ctx->memory_info);
    if (ctx->env) ctx->ort_api->ReleaseEnv(ctx->env);
    free(ctx);
    return NULL;
    
#else
    /* Fallback mode without ONNX Runtime */
    char kdf_model_path[512];
    snprintf(kdf_model_path, sizeof(kdf_model_path), "%s/kdf_mlp.onnx", models_dir);
    
    /* Check if model files exist */
    if (access(kdf_model_path, R_OK) == 0) {
        compute_model_hash(kdf_model_path, ctx->kdf_model_hash);
    }
    
    ctx->initialized = 1;
    return ctx;
#endif
}

/* Cleanup neural context */
void cortex_neural_cleanup(cortex_neural_ctx_t* ctx) {
    if (!ctx) return;
    
#ifdef USE_ONNX_RUNTIME
    if (ctx->kdf_session) ctx->ort_api->ReleaseSession(ctx->kdf_session);
    if (ctx->anomaly_session) ctx->ort_api->ReleaseSession(ctx->anomaly_session);
    if (ctx->memory_info) ctx->ort_api->ReleaseMemoryInfo(ctx->memory_info);
    if (ctx->env) ctx->ort_api->ReleaseEnv(ctx->env);
#endif
    
    cc_secure_zero(ctx, sizeof(*ctx));
    free(ctx);
}

/* Run KDF MLP inference */
int cortex_run_kdf_mlp(cortex_neural_ctx_t* ctx, const uint8_t input[49], uint8_t output[32]) {
    if (!ctx || !input || !output || !ctx->initialized) return -1;
    
#ifdef USE_ONNX_RUNTIME
    if (!ctx->kdf_session) return -1;
    
    /* Normalize input to [0,1] range */
    float normalized_input[49];
    for (int i = 0; i < 49; i++) {
        normalized_input[i] = input[i] / 255.0f;
    }
    
    /* Create input tensor */
    const int64_t input_shape[] = {1, 49};
    OrtValue* input_tensor = NULL;
    
    if (check_ort_status(ctx->ort_api, ctx->ort_api->CreateTensorWithDataAsOrtValue(
            ctx->memory_info, normalized_input, sizeof(normalized_input),
            input_shape, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT,
            &input_tensor)) != 0) {
        return -1;
    }
    
    /* Run inference */
    const char* input_names[] = {"input"};
    const char* output_names[] = {"output"};
    OrtValue* output_tensor = NULL;
    
    if (check_ort_status(ctx->ort_api, ctx->ort_api->Run(ctx->kdf_session, NULL,
                                          input_names, (const OrtValue* const*)&input_tensor, 1,
                                          output_names, 1, &output_tensor)) != 0) {
        ctx->ort_api->ReleaseValue(input_tensor);
        return -1;
    }
    
    /* Extract output data */
    float* output_data;
    if (check_ort_status(ctx->ort_api, ctx->ort_api->GetTensorMutableData(output_tensor, (void**)&output_data)) != 0) {
        ctx->ort_api->ReleaseValue(input_tensor);
        ctx->ort_api->ReleaseValue(output_tensor);
        return -1;
    }
    
    /* Convert output to bytes (clip to [-3,3] then hash for stability) */
    float clipped_output[32];
    for (int i = 0; i < 32; i++) {
        clipped_output[i] = fmaxf(-3.0f, fminf(3.0f, output_data[i]));
    }
    
    /* Hash clipped output for stability */
    SHA256((const uint8_t*)clipped_output, sizeof(clipped_output), output);
    
    /* Cleanup */
    ctx->ort_api->ReleaseValue(input_tensor);
    ctx->ort_api->ReleaseValue(output_tensor);
    
    return 0;
    
#else
    /* Fallback: use HKDF for neural-like key derivation */
    return cortex_run_kdf_mlp_fallback(input, output);
#endif
}

/* Run anomaly detection */
float cortex_compute_anomaly_score(cortex_neural_ctx_t* ctx, const float features[12]) {
    if (!ctx || !features || !ctx->initialized) return 0.0f;
    
#ifdef USE_ONNX_RUNTIME
    if (!ctx->anomaly_session) return 0.0f; /* No anomaly detection available */
    
    /* Create input tensor */
    const int64_t input_shape[] = {1, 12};
    OrtValue* input_tensor = NULL;
    
    if (check_ort_status(ctx->ort_api, ctx->ort_api->CreateTensorWithDataAsOrtValue(
            ctx->memory_info, (void*)features, 12 * sizeof(float),
            input_shape, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT,
            &input_tensor)) != 0) {
        return 0.0f;
    }
    
    /* Run inference */
    const char* input_names[] = {"input"};
    const char* output_names[] = {"output"};
    OrtValue* output_tensor = NULL;
    
    if (check_ort_status(ctx->ort_api, ctx->ort_api->Run(ctx->anomaly_session, NULL,
                                          input_names, (const OrtValue* const*)&input_tensor, 1,
                                          output_names, 1, &output_tensor)) != 0) {
        ctx->ort_api->ReleaseValue(input_tensor);
        return 0.0f;
    }
    
    /* Extract output (reconstruction) */
    float* reconstruction;
    if (check_ort_status(ctx->ort_api, ctx->ort_api->GetTensorMutableData(output_tensor, (void**)&reconstruction)) != 0) {
        ctx->ort_api->ReleaseValue(input_tensor);
        ctx->ort_api->ReleaseValue(output_tensor);
        return 0.0f;
    }
    
    /* Compute reconstruction error (MSE) */
    float mse = 0.0f;
    for (int i = 0; i < 12; i++) {
        float diff = features[i] - reconstruction[i];
        mse += diff * diff;
    }
    mse /= 12.0f;
    
    /* Convert to anomaly score via sigmoid */
    float z_score = (mse - 0.1f) / 0.05f; /* Rough normalization */
    float anomaly_score = 1.0f / (1.0f + expf(-z_score));
    
    /* Cleanup */
    ctx->ort_api->ReleaseValue(input_tensor);
    ctx->ort_api->ReleaseValue(output_tensor);
    
    /* Clamp to [0,1] */
    return fmaxf(0.0f, fminf(1.0f, anomaly_score));
    
#else
    /* Fallback: simple heuristic */
    float sum = 0.0f;
    for (int i = 0; i < 12; i++) {
        sum += features[i];
    }
    
    /* Simple anomaly detection based on feature magnitude */
    float avg = sum / 12.0f;
    if (avg > 2.0f) return 0.8f;      /* High activity */
    if (avg > 1.0f) return 0.4f;      /* Medium activity */
    return 0.1f;                      /* Low activity */
#endif
}

/* Get model ID hash (for header verification) */
int cortex_get_model_id_hash(cortex_neural_ctx_t* ctx, uint8_t hash[32]) {
    if (!ctx || !hash || !ctx->initialized) return -1;
    
    /* Return hash of KDF model (primary model) */
    memcpy(hash, ctx->kdf_model_hash, 32);
    return 0;
}

/* Verify model integrity */
int cortex_verify_models(cortex_neural_ctx_t* ctx, const uint8_t expected_hash[32]) {
    if (!ctx || !expected_hash || !ctx->initialized) return -1;
    
    /* Compare with stored KDF model hash */
    return memcmp(ctx->kdf_model_hash, expected_hash, 32) == 0 ? 0 : -1;
}

/* Create default feature vector for testing */
void cortex_create_default_features(float features[12]) {
    /* Default low-anomaly feature values */
    features[0] = 0.1f;   /* reads_mean */
    features[1] = 0.05f;  /* reads_std */
    features[2] = 2.0f;   /* unique_proc */
    features[3] = 1024.0f; /* avg_bytes */
    features[4] = 0.1f;   /* write_ratio */
    features[5] = 0.0f;   /* failed_decrypts */
    features[6] = 1.0f;   /* key_unwraps */
    features[7] = 0.8f;   /* entropy_delta */
    features[8] = 0.0f;   /* new_binary_count */
    features[9] = 0.0f;   /* outbound_conn */
    features[10] = 60.0f; /* time_since_last_unlock */
    features[11] = 0.0f;  /* privilege_escalations */
}

/* Normalize features using simple min-max scaling */
void cortex_normalize_features(float features[12]) {
    /* Simple normalization - in practice would use scalers.json */
    const float mins[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const float maxs[12] = {100, 10, 50, 1e6, 1, 10, 100, 2, 10, 5, 3600, 5};
    
    for (int i = 0; i < 12; i++) {
        features[i] = (features[i] - mins[i]) / (maxs[i] - mins[i]);
        features[i] = fmaxf(0.0f, fminf(1.0f, features[i])); /* Clamp to [0,1] */
    }
}
