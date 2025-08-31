/*
 * CortexCrypt Cryptographic Implementation  
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <argon2.h>

#include "crypto.h"
#include "utils.h"

/* HKDF implementation using OpenSSL */
static int hkdf_expand(const uint8_t* prk, size_t prk_len,
                       const uint8_t* info, size_t info_len,
                       uint8_t* okm, size_t okm_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return -1;
    
    int ret = -1;
    if (EVP_PKEY_derive_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, prk, prk_len) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, info_len) <= 0) goto cleanup;
    
    size_t out_len = okm_len;
    if (EVP_PKEY_derive(ctx, okm, &out_len) <= 0) goto cleanup;
    if (out_len != okm_len) goto cleanup;
    
    ret = 0;
cleanup:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* Compute HMAC-SHA256 */
static int hmac_sha256(const uint8_t* key, size_t key_len,
                       const uint8_t* data, size_t data_len,
                       uint8_t* out) {
    unsigned int out_len = 32;
    return HMAC(EVP_sha256(), key, key_len, data, data_len, out, &out_len) ? 0 : -1;
}

/* Adapt Argon2 parameters based on anomaly score */
static void adapt_argon2_params(float anomaly_score, uint32_t* time_cost, 
                               uint32_t* mem_cost, uint32_t* parallelism) {
    /* Base parameters */
    *time_cost = 2;
    *mem_cost = 64 * 1024; /* 64MB in KB */
    *parallelism = 1;
    
    if (anomaly_score >= 0.4) {
        /* Medium threat: increase time and memory */
        *time_cost = 3;
        *mem_cost = 96 * 1024; /* 96MB */
    }
    
    if (anomaly_score >= 0.7) {
        /* High threat: significant increase */
        *time_cost = 4 + (uint32_t)(anomaly_score * 2); /* 4-6 */
        *mem_cost = 128 * 1024 + (uint32_t)(anomaly_score * 128 * 1024); /* 128-256MB */
    }
}

/* Derive IV from seed based on cipher mode */
static int derive_iv(const uint8_t* iv_seed, uint8_t cipher_id, uint8_t* iv, size_t* iv_len) {
    if (cipher_id == CC_CIPHER_AES256_GCM) {
        /* AES-GCM: 96-bit IV */
        *iv_len = 12;
        memcpy(iv, iv_seed, 12);
        return 0;
    } else if (cipher_id == CC_CIPHER_XCHACHA20_POLY) {
        /* XChaCha20-Poly1305: 192-bit nonce */
        *iv_len = 24;
        memcpy(iv, iv_seed, 24);
        return 0;
    }
    
    return -1;
}

/* Main key derivation function following the spec */
int cortex_derive_key(const cortex_kdf_params_t* params, uint8_t dek[32], uint8_t iv_seed[32]) {
    if (!params || !dek || !iv_seed) return -1;
    
    uint8_t base_key[32];
    uint8_t ctx[32];
    uint8_t mlp_in[49];
    uint8_t kdf_mlp_output[32];
    uint8_t ikm[32];
    
    /* Step 1: Argon2id with adaptive parameters */
    uint32_t time_cost, mem_cost, parallelism;
    adapt_argon2_params(params->anomaly_score, &time_cost, &mem_cost, &parallelism);
    
    int argon2_ret = argon2id_hash_raw(
        time_cost, mem_cost, parallelism,
        params->passphrase, params->passphrase_len,
        params->file_salt, 16,
        base_key, 32
    );
    
    if (argon2_ret != ARGON2_OK) {
        cc_secure_zero(base_key, sizeof(base_key));
        return -1;
    }
    
    /* Step 2: Compute context */
    uint8_t ctx_input[80]; /* 32 + 32 + 16 */
    memcpy(ctx_input, params->binding_id, 32);
    memcpy(ctx_input + 32, params->session_salt, 16);
    memcpy(ctx_input + 48, params->file_meta_hash, 32);
    
    if (hmac_sha256(base_key, 32, ctx_input, 80, ctx) != 0) {
        cc_secure_zero(base_key, sizeof(base_key));
        return -1;
    }
    
    /* Step 3: Prepare MLP input (49 bytes total) */
    /* base_key[0:16] + binding_id[0:16] + session_salt + anomaly_score_bytes */
    memcpy(mlp_in, base_key, 16);
    memcpy(mlp_in + 16, params->binding_id, 16);
    memcpy(mlp_in + 32, params->session_salt, 16);
    
    /* Convert anomaly score to single byte */
    uint8_t anomaly_byte = (uint8_t)(params->anomaly_score * 255);
    mlp_in[48] = anomaly_byte;
    
    /* Step 4: Run KDF MLP (or fallback hash if ONNX unavailable) */
    if (params->neural_ctx && cortex_run_kdf_mlp(params->neural_ctx, mlp_in, kdf_mlp_output) == 0) {
        /* Use neural network output */
    } else {
        /* Fallback: deterministic hash of input */
        SHA256(mlp_in, 49, kdf_mlp_output);
    }
    
    /* Step 5: Compute input key material */
    uint8_t ikm_input[64]; /* 32 + 32 */
    memcpy(ikm_input, kdf_mlp_output, 32);
    memcpy(ikm_input + 32, ctx, 32);
    
    if (hmac_sha256(base_key, 32, ikm_input, 64, ikm) != 0) {
        cc_secure_zero(base_key, sizeof(base_key));
        cc_secure_zero(kdf_mlp_output, sizeof(kdf_mlp_output));
        return -1;
    }
    
    /* Step 6: HKDF to derive DEK and IV seed */
    const char* hkdf_info = "CORTEXCRYPT v1";
    uint8_t output[64]; /* 32 DEK + 32 IV seed */
    
    if (hkdf_expand(ikm, 32, (const uint8_t*)hkdf_info, strlen(hkdf_info), 
                    output, 64) != 0) {
        cc_secure_zero(base_key, sizeof(base_key));
        cc_secure_zero(kdf_mlp_output, sizeof(kdf_mlp_output));
        cc_secure_zero(ikm, sizeof(ikm));
        return -1;
    }
    
    /* Extract DEK and IV seed */
    memcpy(dek, output, 32);
    memcpy(iv_seed, output + 32, 32);
    
    /* Secure cleanup */
    cc_secure_zero(base_key, sizeof(base_key));
    cc_secure_zero(ctx, sizeof(ctx));
    cc_secure_zero(mlp_in, sizeof(mlp_in));
    cc_secure_zero(kdf_mlp_output, sizeof(kdf_mlp_output));
    cc_secure_zero(ikm, sizeof(ikm));
    cc_secure_zero(output, sizeof(output));
    
    return 0;
}

/* AES-256-GCM encryption */
static int aes_gcm_encrypt(const uint8_t* key, const uint8_t* iv, size_t iv_len,
                          const uint8_t* plaintext, size_t plaintext_len,
                          const uint8_t* aad, size_t aad_len,
                          uint8_t* ciphertext, uint8_t tag[16]) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    int ret = -1;
    int len, ciphertext_len = 0;
    
    /* Initialize encryption */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1) goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto cleanup;
    
    /* Add AAD */
    if (aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) goto cleanup;
    }
    
    /* Encrypt plaintext */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) goto cleanup;
    ciphertext_len = len;
    
    /* Finalize encryption */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) goto cleanup;
    ciphertext_len += len;
    
    /* Get authentication tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto cleanup;
    
    ret = ciphertext_len;
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* AES-256-GCM decryption */
static int aes_gcm_decrypt(const uint8_t* key, const uint8_t* iv, size_t iv_len,
                          const uint8_t* ciphertext, size_t ciphertext_len,
                          const uint8_t* aad, size_t aad_len,
                          const uint8_t tag[16], uint8_t* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    int ret = -1;
    int len, plaintext_len = 0;
    
    /* Initialize decryption */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1) goto cleanup;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto cleanup;
    
    /* Add AAD */
    if (aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) goto cleanup;
    }
    
    /* Decrypt ciphertext */
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) goto cleanup;
    plaintext_len = len;
    
    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) goto cleanup;
    
    /* Finalize and verify tag */
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) > 0) {
        plaintext_len += len;
        ret = plaintext_len;
    }
    
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* XChaCha20-Poly1305 encryption (simplified implementation) */
static int xchacha20_poly1305_encrypt(const uint8_t* key, const uint8_t* nonce,
                                     const uint8_t* plaintext, size_t plaintext_len,
                                     const uint8_t* aad, size_t aad_len,
                                     uint8_t* ciphertext, uint8_t tag[16]) {
    /* For now, fall back to AES-GCM if XChaCha20 not available */
    /* In a complete implementation, this would use libsodium */
    return aes_gcm_encrypt(key, nonce, 12, plaintext, plaintext_len, 
                          aad, aad_len, ciphertext, tag);
}

/* XChaCha20-Poly1305 decryption */
static int xchacha20_poly1305_decrypt(const uint8_t* key, const uint8_t* nonce,
                                     const uint8_t* ciphertext, size_t ciphertext_len,
                                     const uint8_t* aad, size_t aad_len,
                                     const uint8_t tag[16], uint8_t* plaintext) {
    /* For now, fall back to AES-GCM if XChaCha20 not available */
    return aes_gcm_decrypt(key, nonce, 12, ciphertext, ciphertext_len,
                          aad, aad_len, tag, plaintext);
}

/* Main AEAD encryption function */
int cortex_aead_encrypt(const cortex_crypto_params_t* params,
                       const uint8_t* plaintext, size_t plaintext_len,
                       uint8_t* ciphertext, uint8_t tag[16]) {
    if (!params || !plaintext || !ciphertext || !tag) return -1;
    
    /* Derive IV from seed */
    uint8_t iv[24]; /* Max size for XChaCha20 */
    size_t iv_len;
    if (derive_iv(params->iv_seed, params->cipher_id, iv, &iv_len) != 0) {
        return -1;
    }
    
    int result;
    if (params->cipher_id == CC_CIPHER_AES256_GCM) {
        result = aes_gcm_encrypt(params->dek, iv, iv_len,
                               plaintext, plaintext_len,
                               params->aad, params->aad_len,
                               ciphertext, tag);
    } else if (params->cipher_id == CC_CIPHER_XCHACHA20_POLY) {
        result = xchacha20_poly1305_encrypt(params->dek, iv,
                                          plaintext, plaintext_len,
                                          params->aad, params->aad_len,
                                          ciphertext, tag);
    } else {
        return -1;
    }
    
    /* Secure cleanup */
    cc_secure_zero(iv, sizeof(iv));
    
    return result;
}

/* Main AEAD decryption function */
int cortex_aead_decrypt(const cortex_crypto_params_t* params,
                       const uint8_t* ciphertext, size_t ciphertext_len,
                       const uint8_t tag[16], uint8_t* plaintext) {
    if (!params || !ciphertext || !tag || !plaintext) return -1;
    
    /* Derive IV from seed */
    uint8_t iv[24]; /* Max size for XChaCha20 */
    size_t iv_len;
    if (derive_iv(params->iv_seed, params->cipher_id, iv, &iv_len) != 0) {
        return -1;
    }
    
    int result;
    if (params->cipher_id == CC_CIPHER_AES256_GCM) {
        result = aes_gcm_decrypt(params->dek, iv, iv_len,
                               ciphertext, ciphertext_len,
                               params->aad, params->aad_len,
                               tag, plaintext);
    } else if (params->cipher_id == CC_CIPHER_XCHACHA20_POLY) {
        result = xchacha20_poly1305_decrypt(params->dek, iv,
                                          ciphertext, ciphertext_len,
                                          params->aad, params->aad_len,
                                          tag, plaintext);
    } else {
        return -1;
    }
    
    /* Secure cleanup */
    cc_secure_zero(iv, sizeof(iv));
    
    return result;
}

/* Verify AEAD tag without decrypting */
int cortex_aead_verify(const cortex_crypto_params_t* params,
                      const uint8_t* ciphertext, size_t ciphertext_len,
                      const uint8_t tag[16]) {
    /* For verification, we decrypt to a temporary buffer */
    uint8_t* temp_buf = malloc(ciphertext_len);
    if (!temp_buf) return -1;
    
    int result = cortex_aead_decrypt(params, ciphertext, ciphertext_len, tag, temp_buf);
    
    /* Secure cleanup */
    cc_secure_zero(temp_buf, ciphertext_len);
    free(temp_buf);
    
    return result >= 0 ? 0 : -1;
}

/* Get cipher name string */
const char* cortex_cipher_name(uint8_t cipher_id) {
    switch (cipher_id) {
    case CC_CIPHER_AES256_GCM:
        return "AES-256-GCM";
    case CC_CIPHER_XCHACHA20_POLY:
        return "XChaCha20-Poly1305";
    default:
        return "Unknown";
    }
}

/* Parse cipher name to ID */
uint8_t cortex_parse_cipher(const char* name) {
    if (!name) return CC_CIPHER_AES256_GCM;
    
    if (strcmp(name, "aes") == 0 || strcmp(name, "AES") == 0) {
        return CC_CIPHER_AES256_GCM;
    } else if (strcmp(name, "xchacha") == 0 || strcmp(name, "XChaCha") == 0) {
        return CC_CIPHER_XCHACHA20_POLY;
    }
    
    return CC_CIPHER_AES256_GCM; /* Default */
}

/* Check cipher availability */
int cortex_cipher_available(uint8_t cipher_id) {
    if (cipher_id == CC_CIPHER_AES256_GCM) {
        return 1; /* AES always available via OpenSSL */
    } else if (cipher_id == CC_CIPHER_XCHACHA20_POLY) {
        /* Check if XChaCha20 is available (would need libsodium in full impl) */
        return 0; /* Currently using AES fallback */
    }
    
    return 0;
}
