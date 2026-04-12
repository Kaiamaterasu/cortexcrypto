/*
 * CortexCrypt Main Library Implementation
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "../include/cortexcrypt.h"
#include "format.h"
#include "crypto.h"
#include "binding.h"
#include "neural.h"
#include "utils.h"

/* Context structure */
struct cc_ctx {
    int daemon_fd;
    char* passphrase;
    size_t passphrase_len;
    char* admin_token;
    char error_msg[512];
    pthread_mutex_t mutex;
    cortex_neural_ctx_t* neural_ctx;
};


/* Global state */
static int g_initialized = 0;
static int g_memory_lock_enabled = 0;
int g_log_level = 1; /* Error by default */
static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Connect to daemon via UNIX socket */
static int connect_daemon(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/cortexd.sock", sizeof(addr.sun_path) - 1);
    
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    
    return fd;
}

/* Send request to daemon */
static int daemon_request(int fd, const char* request, char* response, size_t response_len) {
    if (send(fd, request, strlen(request), 0) < 0) {
        return -1;
    }
    
    ssize_t recv_len = recv(fd, response, response_len - 1, 0);
    if (recv_len < 0) {
        return -1;
    }
    
    response[recv_len] = '\0';
    return 0;
}

/* Initialize library */
int cc_init(void) {
    pthread_mutex_lock(&g_init_mutex);
    
    if (g_initialized) {
        pthread_mutex_unlock(&g_init_mutex);
        return CC_OK;
    }
    
    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms();
    
    g_initialized = 1;
    pthread_mutex_unlock(&g_init_mutex);
    
    return CC_OK;
}

/* Cleanup library */
void cc_cleanup(void) {
    pthread_mutex_lock(&g_init_mutex);
    
    if (!g_initialized) {
        pthread_mutex_unlock(&g_init_mutex);
        return;
    }
    
    /* Cleanup OpenSSL */
    EVP_cleanup();
    
    g_initialized = 0;
    pthread_mutex_unlock(&g_init_mutex);
}

/* Open context */
cc_ctx_t* cc_open(void) {
    /* Ensure library is initialized */
    if (!g_initialized) {
        if (cc_init() != CC_OK) return NULL;
    }
    
    cc_ctx_t* ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    
    /* Initialize mutex */
    if (pthread_mutex_init(&ctx->mutex, NULL) != 0) {
        free(ctx);
        return NULL;
    }
    
    /* Connect to daemon */
    ctx->daemon_fd = connect_daemon();
    if (ctx->daemon_fd < 0) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), 
                "Failed to connect to cortexd daemon");
    }
    
    /* Initialize neural context */
    ctx->neural_ctx = cortex_neural_init("/usr/local/share/cortexcrypt/models");
    if (!ctx->neural_ctx) {
        /* Continue without neural network - use fallback */
    }
    
    return ctx;
}

/* Close context */
void cc_close(cc_ctx_t* ctx) {
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->mutex);
    
    /* Close daemon connection */
    if (ctx->daemon_fd >= 0) {
        close(ctx->daemon_fd);
    }
    
    /* Clear passphrase */
    if (ctx->passphrase) {
        cc_secure_zero(ctx->passphrase, ctx->passphrase_len);
        free(ctx->passphrase);
    }
    
    /* Clear admin token */
    if (ctx->admin_token) {
        cc_secure_zero(ctx->admin_token, strlen(ctx->admin_token));
        free(ctx->admin_token);
    }
    
    /* Cleanup neural context */
    if (ctx->neural_ctx) {
        cortex_neural_cleanup(ctx->neural_ctx);
    }
    
    pthread_mutex_unlock(&ctx->mutex);
    pthread_mutex_destroy(&ctx->mutex);
    
    cc_secure_zero(ctx, sizeof(*ctx));
    free(ctx);
}

/* Get error message */
const char* cc_get_error(cc_ctx_t* ctx) {
    return ctx ? ctx->error_msg : "Invalid context";
}

/* Set passphrase */
int cc_set_passphrase(cc_ctx_t* ctx, const char* pass, size_t pass_len) {
    if (!ctx || !pass || pass_len == 0) return CC_ERROR_INVALID;
    
    pthread_mutex_lock(&ctx->mutex);
    
    /* Clear existing passphrase */
    if (ctx->passphrase) {
        cc_secure_zero(ctx->passphrase, ctx->passphrase_len);
        free(ctx->passphrase);
    }
    
    /* Store new passphrase */
    ctx->passphrase = malloc(pass_len);
    if (!ctx->passphrase) {
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_MEMORY;
    }
    
    memcpy(ctx->passphrase, pass, pass_len);
    ctx->passphrase_len = pass_len;
    
    /* Lock memory if enabled */
    if (g_memory_lock_enabled) {
        mlock(ctx->passphrase, pass_len);
    }
    
    pthread_mutex_unlock(&ctx->mutex);
    return CC_OK;
}

/* Clear passphrase */
int cc_clear_passphrase(cc_ctx_t* ctx) {
    if (!ctx) return CC_ERROR_INVALID;
    
    pthread_mutex_lock(&ctx->mutex);
    
    if (ctx->passphrase) {
        cc_secure_zero(ctx->passphrase, ctx->passphrase_len);
        if (g_memory_lock_enabled) {
            munlock(ctx->passphrase, ctx->passphrase_len);
        }
        free(ctx->passphrase);
        ctx->passphrase = NULL;
        ctx->passphrase_len = 0;
    }
    
    pthread_mutex_unlock(&ctx->mutex);
    return CC_OK;
}

/* Set admin token */
int cc_set_admin_token(cc_ctx_t* ctx, const char* token) {
    if (!ctx || !token) return CC_ERROR_INVALID;
    
    pthread_mutex_lock(&ctx->mutex);
    
    /* Clear existing token */
    if (ctx->admin_token) {
        cc_secure_zero(ctx->admin_token, strlen(ctx->admin_token));
        free(ctx->admin_token);
    }
    
    ctx->admin_token = strdup(token);
    if (!ctx->admin_token) {
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_MEMORY;
    }
    
    pthread_mutex_unlock(&ctx->mutex);
    return CC_OK;
}

/* Encrypt file */
int cc_encrypt_file(cc_ctx_t* ctx, const char* in_path, const char* out_path,
                    const char* cipher, int bind_policy, const char* note) {
    if (!ctx || !in_path || !out_path) return CC_ERROR_INVALID;
    
    pthread_mutex_lock(&ctx->mutex);
    
    /* Default cipher */
    uint8_t cipher_id = cipher ? cortex_parse_cipher(cipher) : CC_CIPHER_AES256_GCM;
    
    /* Check cipher availability */
    if (!cortex_cipher_available(cipher_id)) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), 
                "Cipher %s not available", cortex_cipher_name(cipher_id));
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_UNSUPPORTED;
    }
    
    /* Get binding ID */
    uint8_t binding_id[32];
    if (cortex_get_binding_id(bind_policy, in_path, binding_id) != 0) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Failed to get binding ID");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_BIND;
    }
    
    /* Get model ID hash */
    uint8_t model_id_hash[32] = {0};
    if (ctx->neural_ctx) {
        cortex_get_model_id_hash(ctx->neural_ctx, model_id_hash);
    }
    
    /* Create header */
    cortex_header_t header;
    cortex_create_params_t params = {
        .cipher_id = cipher_id,
        .bind_policy = bind_policy,
        .disallow_copy = 0,
        .note = note
    };
    memcpy(params.binding_id_hash, binding_id, 32);
    memcpy(params.model_id_hash, model_id_hash, 32);
    
    /* Generate file metadata */
    const char* filename = strrchr(in_path, '/');
    filename = filename ? filename + 1 : in_path;
    params.file_meta_json = cortex_generate_file_meta(filename, in_path);
    params.policy_json = cortex_generate_policy(3, "exponential_backoff");
    
    if (cortex_create_header(&header, &params) != 0) {
        free((char*)params.file_meta_json);
        free((char*)params.policy_json);
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Failed to create header");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_GENERIC;
    }
    
    /* Open input file */
    FILE* in_fp = fopen(in_path, "rb");
    if (!in_fp) {
        cortex_free_header(&header);
        free((char*)params.file_meta_json);
        free((char*)params.policy_json);
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Cannot open input file");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_IO;
    }
    
    /* Get file size */
    fseek(in_fp, 0, SEEK_END);
    size_t file_size = ftell(in_fp);
    fseek(in_fp, 0, SEEK_SET);
    
    /* Open output file */
    FILE* out_fp = fopen(out_path, "wb");
    if (!out_fp) {
        fclose(in_fp);
        cortex_free_header(&header);
        free((char*)params.file_meta_json);
        free((char*)params.policy_json);
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Cannot create output file");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_IO;
    }
    
    /* Write header */
    if (cortex_write_header(out_fp, &header) != 0) {
        fclose(in_fp);
        fclose(out_fp);
        unlink(out_path);
        cortex_free_header(&header);
        free((char*)params.file_meta_json);
        free((char*)params.policy_json);
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Failed to write header");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_IO;
    }
    
    /* Get anomaly score from daemon */
    float anomaly_score = 0.1f; /* Default low score */
    if (ctx->daemon_fd >= 0) {
        char request[128], response[64];
        snprintf(request, sizeof(request), "GET_ANOMALY_SCORE");
        if (daemon_request(ctx->daemon_fd, request, response, sizeof(response)) == 0) {
            anomaly_score = strtof(response, NULL);
        }
    }
    
    /* Derive encryption key */
    cortex_kdf_params_t kdf_params = {
        .passphrase = ctx->passphrase,
        .passphrase_len = ctx->passphrase_len,
        .file_salt = header.file_salt,
        .session_salt = header.session_salt,
        .binding_id = binding_id,
        .anomaly_score = anomaly_score,
        .neural_ctx = ctx->neural_ctx
    };
    
    /* Compute file metadata hash */
    uint8_t file_meta_hash[32];
    SHA256((const uint8_t*)params.file_meta_json, strlen(params.file_meta_json), file_meta_hash);
    kdf_params.file_meta_hash = file_meta_hash;
    
    uint8_t dek[32], iv_seed[32];
    if (cortex_derive_key(&kdf_params, dek, iv_seed) != 0) {
        fclose(in_fp);
        fclose(out_fp);
        unlink(out_path);
        cortex_free_header(&header);
        free((char*)params.file_meta_json);
        free((char*)params.policy_json);
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Key derivation failed");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_GENERIC;
    }
    
    /* Read and encrypt file */
    uint8_t* plaintext = malloc(file_size);
    uint8_t* ciphertext = malloc(file_size);
    if (!plaintext || !ciphertext) {
        free(plaintext);
        free(ciphertext);
        fclose(in_fp);
        fclose(out_fp);
        unlink(out_path);
        cortex_free_header(&header);
        free((char*)params.file_meta_json);
        free((char*)params.policy_json);
        cc_secure_zero(dek, sizeof(dek));
        cc_secure_zero(iv_seed, sizeof(iv_seed));
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Memory allocation failed");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_MEMORY;
    }
    
    if (fread(plaintext, 1, file_size, in_fp) != file_size) {
        free(plaintext);
        free(ciphertext);
        fclose(in_fp);
        fclose(out_fp);
        unlink(out_path);
        cortex_free_header(&header);
        free((char*)params.file_meta_json);
        free((char*)params.policy_json);
        cc_secure_zero(dek, sizeof(dek));
        cc_secure_zero(iv_seed, sizeof(iv_seed));
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Failed to read input file");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_IO;
    }
    
    /* Prepare AAD from stable header fields */
    uint8_t aad_buffer[128];
    size_t aad_offset = 0;
    
    /* Pack version (1 byte) */
    aad_buffer[aad_offset++] = header.version;
    
    /* Pack flags (4 bytes, big-endian) */
    uint32_t flags_be = htonl(header.flags);
    memcpy(&aad_buffer[aad_offset], &flags_be, 4);
    aad_offset += 4;
    
    /* Pack cipher_id (1 byte) */
    aad_buffer[aad_offset++] = header.cipher_id;
    
    /* Pack salts (16 + 16 bytes) */
    memcpy(&aad_buffer[aad_offset], header.file_salt, 16);
    aad_offset += 16;
    memcpy(&aad_buffer[aad_offset], header.session_salt, 16);
    aad_offset += 16;
    
    /* Pack binding and model ID hashes (32 + 32 bytes) */
    memcpy(&aad_buffer[aad_offset], header.binding_id_hash, 32);
    aad_offset += 32;
    memcpy(&aad_buffer[aad_offset], header.model_id_hash, 32);
    aad_offset += 32;
    
    /* Prepare crypto parameters */
    cortex_crypto_params_t crypto_params = {
        .cipher_id = cipher_id,
        .dek = dek,
        .iv_seed = iv_seed,
        .aad = aad_buffer,
        .aad_len = aad_offset
    };
    
    /* Encrypt */
    uint8_t tag[16];
    int encrypt_len = cortex_aead_encrypt(&crypto_params, plaintext, file_size, 
                                        ciphertext, tag);
    
    if (encrypt_len < 0) {
        cc_secure_zero(plaintext, file_size);
        cc_secure_zero(ciphertext, file_size);
        free(plaintext);
        free(ciphertext);
        fclose(in_fp);
        fclose(out_fp);
        unlink(out_path);
        cortex_free_header(&header);
        free((char*)params.file_meta_json);
        free((char*)params.policy_json);
        cc_secure_zero(dek, sizeof(dek));
        cc_secure_zero(iv_seed, sizeof(iv_seed));
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Encryption failed");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_GENERIC;
    }
    
    /* Write ciphertext and tag */
    if (fwrite(ciphertext, 1, encrypt_len, out_fp) != (size_t)encrypt_len ||
        fwrite(tag, 1, 16, out_fp) != 16) {
        cc_secure_zero(plaintext, file_size);
        cc_secure_zero(ciphertext, file_size);
        free(plaintext);
        free(ciphertext);
        fclose(in_fp);
        fclose(out_fp);
        unlink(out_path);
        cortex_free_header(&header);
        free((char*)params.file_meta_json);
        free((char*)params.policy_json);
        cc_secure_zero(dek, sizeof(dek));
        cc_secure_zero(iv_seed, sizeof(iv_seed));
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Failed to write output");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_IO;
    }
    
    /* Cleanup */
    cc_secure_zero(plaintext, file_size);
    cc_secure_zero(ciphertext, file_size);
    free(plaintext);
    free(ciphertext);
    fclose(in_fp);
    fclose(out_fp);
    cortex_free_header(&header);
    free((char*)params.file_meta_json);
    free((char*)params.policy_json);
    cc_secure_zero(dek, sizeof(dek));
    cc_secure_zero(iv_seed, sizeof(iv_seed));
    
    pthread_mutex_unlock(&ctx->mutex);
    return CC_OK;
}

/* Decrypt file */
int cc_decrypt_file(cc_ctx_t* ctx, const char* in_path, const char* out_path) {
    if (!ctx || !in_path || !out_path) return CC_ERROR_INVALID;
    
    pthread_mutex_lock(&ctx->mutex);
    
    /* Open input file */
    FILE* in_fp = fopen(in_path, "rb");
    if (!in_fp) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Cannot open input file");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_IO;
    }
    
    /* Parse header */
    cortex_header_t header;
    if (cortex_parse_header(in_fp, &header) != 0) {
        fclose(in_fp);
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Invalid .cortex file format");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_CORRUPTED;
    }
    
    /* Verify binding */
    int bind_policy = (header.flags & CC_FLAG_BIND_VOLUME) ? CC_BIND_VOLUME : CC_BIND_MACHINE;
    if (cortex_verify_binding(header.binding_id_hash, bind_policy, in_path) != 0) {
        cortex_free_header(&header);
        fclose(in_fp);
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Binding verification failed");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_BIND;
    }
    
    /* Verify model integrity */
    if (ctx->neural_ctx && cortex_verify_models(ctx->neural_ctx, header.model_id_hash) != 0) {
        cortex_free_header(&header);
        fclose(in_fp);
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Model integrity check failed");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_CORRUPTED;
    }
    
    /* Get ciphertext size */
    fseek(in_fp, 0, SEEK_END);
    size_t total_size = ftell(in_fp);
    size_t ciphertext_size = total_size - header.header_len - 16;
    
    /* Read ciphertext and tag */
    fseek(in_fp, header.header_len, SEEK_SET);
    uint8_t* ciphertext = malloc(ciphertext_size);
    uint8_t tag[16];
    
    if (!ciphertext || 
        fread(ciphertext, 1, ciphertext_size, in_fp) != ciphertext_size ||
        fread(tag, 1, 16, in_fp) != 16) {
        free(ciphertext);
        cortex_free_header(&header);
        fclose(in_fp);
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Failed to read ciphertext");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_IO;
    }
    
    fclose(in_fp);
    
    /* Get current binding ID for key derivation */
    uint8_t current_binding_id[32];
    cortex_get_binding_id(bind_policy, in_path, current_binding_id);
    
    /* Get anomaly score */
    float anomaly_score = 0.1f;
    if (ctx->daemon_fd >= 0) {
        char request[128], response[64];
        snprintf(request, sizeof(request), "GET_ANOMALY_SCORE");
        if (daemon_request(ctx->daemon_fd, request, response, sizeof(response)) == 0) {
            anomaly_score = strtof(response, NULL);
        }
    }
    
    /* Derive decryption key */
    cortex_kdf_params_t kdf_params = {
        .passphrase = ctx->passphrase,
        .passphrase_len = ctx->passphrase_len,
        .file_salt = header.file_salt,
        .session_salt = header.session_salt,
        .binding_id = current_binding_id,
        .anomaly_score = anomaly_score,
        .neural_ctx = ctx->neural_ctx
    };
    
    /* Compute file metadata hash */
    uint8_t file_meta_hash[32];
    if (header.file_meta_json) {
        SHA256((const uint8_t*)header.file_meta_json, strlen(header.file_meta_json), file_meta_hash);
    } else {
        memset(file_meta_hash, 0, 32);
    }
    kdf_params.file_meta_hash = file_meta_hash;
    
    uint8_t dek[32], iv_seed[32];
    if (cortex_derive_key(&kdf_params, dek, iv_seed) != 0) {
        free(ciphertext);
        cortex_free_header(&header);
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Key derivation failed");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_AUTH;
    }
    
    /* Decrypt */
    uint8_t* plaintext = malloc(ciphertext_size);
    if (!plaintext) {
        free(ciphertext);
        cortex_free_header(&header);
        cc_secure_zero(dek, sizeof(dek));
        cc_secure_zero(iv_seed, sizeof(iv_seed));
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Memory allocation failed");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_MEMORY;
    }
    
    /* Prepare AAD from stable header fields (same as encryption) */
    uint8_t aad_buffer[128];
    size_t aad_offset = 0;
    
    /* Pack version (1 byte) */
    aad_buffer[aad_offset++] = header.version;
    
    /* Pack flags (4 bytes, big-endian) */
    uint32_t flags_be = htonl(header.flags);
    memcpy(&aad_buffer[aad_offset], &flags_be, 4);
    aad_offset += 4;
    
    /* Pack cipher_id (1 byte) */
    aad_buffer[aad_offset++] = header.cipher_id;
    
    /* Pack salts (16 + 16 bytes) */
    memcpy(&aad_buffer[aad_offset], header.file_salt, 16);
    aad_offset += 16;
    memcpy(&aad_buffer[aad_offset], header.session_salt, 16);
    aad_offset += 16;
    
    /* Pack binding and model ID hashes (32 + 32 bytes) */
    memcpy(&aad_buffer[aad_offset], header.binding_id_hash, 32);
    aad_offset += 32;
    memcpy(&aad_buffer[aad_offset], header.model_id_hash, 32);
    aad_offset += 32;
    
    /* Prepare crypto parameters */
    cortex_crypto_params_t crypto_params = {
        .cipher_id = header.cipher_id,
        .dek = dek,
        .iv_seed = iv_seed,
        .aad = aad_buffer,
        .aad_len = aad_offset
    };
    
    int decrypt_len = cortex_aead_decrypt(&crypto_params, ciphertext, ciphertext_size, 
                                        tag, plaintext);
    
    if (decrypt_len < 0) {
        cc_secure_zero(plaintext, ciphertext_size);
        free(plaintext);
        free(ciphertext);
        cortex_free_header(&header);
        cc_secure_zero(dek, sizeof(dek));
        cc_secure_zero(iv_seed, sizeof(iv_seed));
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Decryption failed");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_AUTH;
    }
    
    /* Write plaintext to output file */
    FILE* out_fp = fopen(out_path, "wb");
    if (!out_fp || fwrite(plaintext, 1, decrypt_len, out_fp) != (size_t)decrypt_len) {
        if (out_fp) fclose(out_fp);
        unlink(out_path);
        cc_secure_zero(plaintext, ciphertext_size);
        free(plaintext);
        free(ciphertext);
        cortex_free_header(&header);
        cc_secure_zero(dek, sizeof(dek));
        cc_secure_zero(iv_seed, sizeof(iv_seed));
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Failed to write output");
        pthread_mutex_unlock(&ctx->mutex);
        return CC_ERROR_IO;
    }
    
    fclose(out_fp);
    
    /* Cleanup */
    cc_secure_zero(plaintext, ciphertext_size);
    free(plaintext);
    free(ciphertext);
    cortex_free_header(&header);
    cc_secure_zero(dek, sizeof(dek));
    cc_secure_zero(iv_seed, sizeof(iv_seed));
    
    pthread_mutex_unlock(&ctx->mutex);
    return CC_OK;
}

/* Get file info */
int cc_info(cc_ctx_t* ctx, const char* in_path, cc_file_info_t* info) {
    if (!ctx || !in_path || !info) return CC_ERROR_INVALID;
    
    /* Open file */
    FILE* fp = fopen(in_path, "rb");
    if (!fp) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Cannot open file");
        return CC_ERROR_IO;
    }
    
    /* Parse header */
    cortex_header_t header;
    if (cortex_parse_header(fp, &header) != 0) {
        fclose(fp);
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Invalid .cortex file format");
        return CC_ERROR_CORRUPTED;
    }
    
    /* Get ciphertext size */
    fseek(fp, 0, SEEK_END);
    size_t total_size = ftell(fp);
    fclose(fp);
    
    /* Fill info structure */
    memset(info, 0, sizeof(*info));
    info->version = header.version;
    info->flags = header.flags;
    info->cipher_id = header.cipher_id;
    info->header_len = header.header_len;
    memcpy(info->file_salt, header.file_salt, 16);
    memcpy(info->session_salt, header.session_salt, 16);
    memcpy(info->binding_id_hash, header.binding_id_hash, 32);
    memcpy(info->model_id_hash, header.model_id_hash, 32);
    info->ciphertext_size = total_size - header.header_len - 16;
    
    /* Copy strings (caller must free) */
    if (header.file_meta_json) {
        info->file_meta_json = strdup(header.file_meta_json);
    }
    if (header.policy_json) {
        info->policy_json = strdup(header.policy_json);
    }
    if (header.note) {
        info->note = strdup(header.note);
    }
    
    cortex_free_header(&header);
    return CC_OK;
}

/* Free file info */
void cc_free_info(cc_file_info_t* info) {
    if (!info) return;
    
    free(info->file_meta_json);
    free(info->policy_json);
    free(info->note);
    
    memset(info, 0, sizeof(*info));
}

/* Verify file */
int cc_verify(cc_ctx_t* ctx, const char* in_path) {
    if (!ctx || !in_path) return CC_ERROR_INVALID;
    
    /* Parse and validate header */
    FILE* fp = fopen(in_path, "rb");
    if (!fp) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Cannot open file");
        return CC_ERROR_IO;
    }
    
    cortex_header_t header;
    if (cortex_parse_header(fp, &header) != 0) {
        fclose(fp);
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Header validation failed");
        return CC_ERROR_CORRUPTED;
    }
    
    /* Verify binding */
    int bind_policy = (header.flags & CC_FLAG_BIND_VOLUME) ? CC_BIND_VOLUME : CC_BIND_MACHINE;
    if (cortex_verify_binding(header.binding_id_hash, bind_policy, in_path) != 0) {
        cortex_free_header(&header);
        fclose(fp);
        return CC_ERROR_BIND;
    }
    
    cortex_free_header(&header);
    fclose(fp);
    return CC_OK;
}

/* Utility functions */
const char* cc_version(void) {
    return "1.0.0";
}

const char* cc_supported_ciphers(void) {
    return "AES-256-GCM,XChaCha20-Poly1305";
}

int cc_daemon_status(void) {
    int fd = connect_daemon();
    if (fd < 0) return 0;
    
    char response[64];
    int status = daemon_request(fd, "PING", response, sizeof(response));
    close(fd);
    
    return status == 0;
}

int cc_get_binding_id(int bind_policy, uint8_t binding_id[32]) {
    return cortex_get_binding_id(bind_policy, NULL, binding_id);
}

/* Memory management */
int cc_set_memory_lock(int enable) {
    g_memory_lock_enabled = enable;
    return CC_OK;
}

int cc_set_log_level(int level) {
    g_log_level = level;
    return CC_OK;
}

