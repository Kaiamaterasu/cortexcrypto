/*
 * CortexCrypt Cryptographic Internal Header
 * Copyright 2024 CortexCrypt Contributors  
 * Licensed under Apache 2.0
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "../include/cortexcrypt.h"

/* Forward declaration for neural context */
typedef struct cortex_neural_ctx cortex_neural_ctx_t;

/* KDF parameters structure */
typedef struct {
    const char* passphrase;
    size_t passphrase_len;
    const uint8_t* file_salt;        /* 16 bytes */
    const uint8_t* session_salt;     /* 16 bytes */
    const uint8_t* binding_id;       /* 32 bytes */
    const uint8_t* file_meta_hash;   /* 32 bytes */
    float anomaly_score;             /* [0,1] */
    cortex_neural_ctx_t* neural_ctx; /* For MLP inference */
} cortex_kdf_params_t;

/* Crypto operation parameters */
typedef struct {
    uint8_t cipher_id;
    const uint8_t* dek;         /* 32 bytes */
    const uint8_t* iv_seed;     /* 32 bytes */
    const uint8_t* aad;         /* Additional authenticated data */
    size_t aad_len;
} cortex_crypto_params_t;

/* Function declarations */
int cortex_derive_key(const cortex_kdf_params_t* params, uint8_t dek[32], uint8_t iv_seed[32]);

int cortex_aead_encrypt(const cortex_crypto_params_t* params,
                       const uint8_t* plaintext, size_t plaintext_len,
                       uint8_t* ciphertext, uint8_t tag[16]);

int cortex_aead_decrypt(const cortex_crypto_params_t* params,
                       const uint8_t* ciphertext, size_t ciphertext_len,
                       const uint8_t tag[16], uint8_t* plaintext);

int cortex_aead_verify(const cortex_crypto_params_t* params,
                      const uint8_t* ciphertext, size_t ciphertext_len,
                      const uint8_t tag[16]);

const char* cortex_cipher_name(uint8_t cipher_id);
uint8_t cortex_parse_cipher(const char* name);
int cortex_cipher_available(uint8_t cipher_id);

/* Neural network interface (defined in neural.c) */
int cortex_run_kdf_mlp(cortex_neural_ctx_t* ctx, const uint8_t input[49], uint8_t output[32]);

#endif /* CRYPTO_H */
