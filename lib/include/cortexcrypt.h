/*
 * CortexCrypt - Zero-cost, offline, NN-augmented encryption
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 *
 * Stable C ABI - Version 1.0
 */

#ifndef CORTEXCRYPT_H
#define CORTEXCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* Version information */
#define CC_VERSION_MAJOR 1
#define CC_VERSION_MINOR 0
#define CC_VERSION_PATCH 0

/* Error codes */
#define CC_OK                0  /* Success */
#define CC_ERROR_GENERIC     1  /* Generic error */
#define CC_ERROR_BIND        2  /* Binding mismatch */
#define CC_ERROR_CORRUPTED   3  /* File corrupted */
#define CC_ERROR_LOCKED      4  /* File locked */
#define CC_ERROR_AUTH        5  /* Authentication required */
#define CC_ERROR_MEMORY      6  /* Memory allocation failed */
#define CC_ERROR_IO          7  /* I/O error */
#define CC_ERROR_DAEMON      8  /* Daemon connection failed */
#define CC_ERROR_INVALID     9  /* Invalid parameters */
#define CC_ERROR_UNSUPPORTED 10 /* Unsupported operation */

/* Log levels */
#define CC_LOG_NONE   0
#define CC_LOG_ERROR  1
#define CC_LOG_WARN   2
#define CC_LOG_INFO   3
#define CC_LOG_DEBUG  4

/* Cipher types */
#define CC_CIPHER_AES256_GCM      0
#define CC_CIPHER_XCHACHA20_POLY  1

/* Binding policies */
#define CC_BIND_VOLUME   1  /* Bind to USB volume (default) */
#define CC_BIND_MACHINE  2  /* Bind to machine */

/* Flags */
#define CC_FLAG_BIND_VOLUME        (1 << 0)
#define CC_FLAG_BIND_MACHINE       (1 << 1) 
#define CC_FLAG_DISALLOW_COPY      (1 << 2)
#define CC_FLAG_LOCK_IF_MISMATCH   (1 << 3)

/* Opaque context handle */
typedef struct cc_ctx cc_ctx_t;

/* File information structure */
typedef struct {
    uint16_t version;
    uint8_t flags;
    uint8_t cipher_id;
    uint16_t header_len;
    uint8_t file_salt[16];
    uint8_t session_salt[16];
    uint8_t binding_id_hash[32];
    uint8_t model_id_hash[32];
    char* file_meta_json;    /* FILE_META TLV content */
    char* policy_json;       /* POLICY TLV content */
    char* note;              /* NOTE TLV content */
    size_t ciphertext_size;
} cc_file_info_t;

/* Core API functions */

/**
 * Open connection to cortexd daemon
 * Returns: context handle or NULL on error
 */
cc_ctx_t* cc_open(void);

/**
 * Close connection and free context
 */
void cc_close(cc_ctx_t* ctx);

/**
 * Get last error message for context
 */
const char* cc_get_error(cc_ctx_t* ctx);

/**
 * Set passphrase for key derivation
 * pass: passphrase bytes (not null-terminated)
 * pass_len: length of passphrase
 */
int cc_set_passphrase(cc_ctx_t* ctx, const char* pass, size_t pass_len);

/**
 * Clear stored passphrase from memory
 */
int cc_clear_passphrase(cc_ctx_t* ctx);

/**
 * Set admin token for privileged operations
 */
int cc_set_admin_token(cc_ctx_t* ctx, const char* token);

/**
 * Encrypt file to .cortex format
 * in_path: input file path
 * out_path: output .cortex file path
 * cipher: "aes" or "xchacha" (NULL for default)
 * bind_policy: CC_BIND_VOLUME or CC_BIND_MACHINE
 * note: optional user note (NULL allowed)
 */
int cc_encrypt_file(cc_ctx_t* ctx, const char* in_path, const char* out_path,
                    const char* cipher, int bind_policy, const char* note);

/**
 * Decrypt .cortex file
 * in_path: input .cortex file path
 * out_path: output file path
 */
int cc_decrypt_file(cc_ctx_t* ctx, const char* in_path, const char* out_path);

/**
 * Get file information (safe metadata only)
 * in_path: input .cortex file path
 * info: output structure (caller must free strings)
 */
int cc_info(cc_ctx_t* ctx, const char* in_path, cc_file_info_t* info);

/**
 * Free file info structure
 */
void cc_free_info(cc_file_info_t* info);

/**
 * Verify file integrity (AEAD + header checks)
 * in_path: input .cortex file path
 */
int cc_verify(cc_ctx_t* ctx, const char* in_path);

/**
 * Rebind file to different environment (admin operation)
 * in_path: input .cortex file path
 * bind_policy: new binding policy
 */
int cc_rebind(cc_ctx_t* ctx, const char* in_path, int bind_policy);

/* Memory encryption for sensitive data */

/**
 * Encrypt memory buffer
 * plaintext: input buffer
 * plaintext_len: input length
 * ciphertext: output buffer (caller allocated, must be plaintext_len + 16)
 * ciphertext_len: output length
 * Returns: CC_OK or error code
 */
int cc_encrypt_memory(cc_ctx_t* ctx, const uint8_t* plaintext, size_t plaintext_len,
                      uint8_t* ciphertext, size_t* ciphertext_len);

/**
 * Decrypt memory buffer  
 * ciphertext: input buffer
 * ciphertext_len: input length
 * plaintext: output buffer (caller allocated)
 * plaintext_len: output length
 */
int cc_decrypt_memory(cc_ctx_t* ctx, const uint8_t* ciphertext, size_t ciphertext_len,
                      uint8_t* plaintext, size_t* plaintext_len);

/* Utility functions */

/**
 * Get library version string
 */
const char* cc_version(void);

/**
 * Get supported ciphers (comma-separated string)
 */
const char* cc_supported_ciphers(void);

/**
 * Check if daemon is running
 */
int cc_daemon_status(void);

/**
 * Get current binding ID for this environment
 * bind_policy: CC_BIND_VOLUME or CC_BIND_MACHINE  
 * binding_id: output buffer (32 bytes)
 */
int cc_get_binding_id(int bind_policy, uint8_t binding_id[32]);

/* Advanced operations */

/**
 * Initialize library (call once per process)
 */
int cc_init(void);

/**
 * Cleanup library resources (call at exit)
 */
void cc_cleanup(void);

/**
 * Enable/disable memory locking for sensitive data
 */
int cc_set_memory_lock(int enable);

/**
 * Set log level (0=none, 1=error, 2=warn, 3=info, 4=debug)
 */
int cc_set_log_level(int level);

/**
 * Get file size
 */
size_t cc_file_size(const char* path);

/**
 * Convert bytes to hex string
 */
void cc_bytes_to_hex(const uint8_t* bytes, size_t len, char* hex);

/**
 * Get cipher name from cipher ID
 */
const char* cortex_cipher_name(uint8_t cipher_id);

/**
 * Get binding description
 */
int cortex_describe_binding(int bind_policy, const char* context_path, 
                           char* description, size_t desc_len);

#ifdef __cplusplus
}
#endif

#endif /* CORTEXCRYPT_H */
