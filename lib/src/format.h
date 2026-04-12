/*
 * CortexCrypt File Format Internal Header
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#ifndef FORMAT_H
#define FORMAT_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "../include/cortexcrypt.h"

/* Internal header structure */
typedef struct {
    uint16_t version;
    uint8_t flags;
    uint8_t cipher_id;
    uint16_t header_len;
    uint8_t file_salt[16];
    uint8_t session_salt[16];
    uint8_t binding_id_hash[32];
    uint8_t model_id_hash[32];
    uint8_t aad_hash[32];
    
    /* TLV content */
    char* file_meta_json;
    char* policy_json;
    char* note;
    uint8_t* learning_meta;
    size_t learning_meta_len;
} cortex_header_t;

/* Parameters for creating new headers */
typedef struct {
    uint8_t cipher_id;
    int bind_policy;
    int disallow_copy;
    uint8_t binding_id_hash[32];
    uint8_t model_id_hash[32];
    const char* file_meta_json;
    const char* policy_json;
    const char* note;
} cortex_create_params_t;

/* Function declarations */
int cortex_parse_header(FILE* fp, cortex_header_t* header);
int cortex_create_header(cortex_header_t* header, const cortex_create_params_t* params);
int cortex_write_header(FILE* fp, const cortex_header_t* header);
void cortex_free_header(cortex_header_t* header);
int cortex_validate_header(const cortex_header_t* header);
int cortex_is_cortex_file(const char* path);
size_t cortex_get_file_size(const char* path);
size_t cortex_get_ciphertext_size(const char* path);

/* Utility functions */
char* cortex_generate_file_meta(const char* filename, const char* original_path);
char* cortex_generate_policy(int max_retries, const char* lock_action);

#endif /* FORMAT_H */
