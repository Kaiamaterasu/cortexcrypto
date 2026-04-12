/*
 * CortexCrypt File Format Implementation
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "format.h"
#include "utils.h"

/* .cortex file magic and constants */
static const uint8_t CORTEX_MAGIC[8] = {'C', 'O', 'R', 'T', 'E', 'X', '0', '1'};
static const uint16_t CORTEX_VERSION = 0x0001;

/* TLV Types */
#define TLV_FILE_META      0x01
#define TLV_POLICY         0x02  
#define TLV_LEARNING_META  0x03
#define TLV_NOTE           0x04

/* Internal structures */
typedef struct {
    uint8_t type;
    uint16_t length;
    uint8_t* value;
} tlv_t;

/* Read big-endian integers */
static uint16_t read_be16(const uint8_t* buf) {
    return (buf[0] << 8) | buf[1];
}

/* Write big-endian integers */
static void write_be16(uint8_t* buf, uint16_t val) {
    buf[0] = (val >> 8) & 0xFF;
    buf[1] = val & 0xFF;
}

/* Parse TLV section */
static int parse_tlvs(const uint8_t* data, size_t len, cortex_header_t* header) {
    size_t pos = 0;
    
    while (pos + 3 < len) {
        uint8_t type = data[pos];
        uint16_t tlv_len = read_be16(&data[pos + 1]);
        pos += 3;
        
        if (pos + tlv_len > len) {
            return -1; /* Truncated TLV */
        }
        
        switch (type) {
        case TLV_FILE_META:
            if (tlv_len > 1024) return -1; /* Limit file meta size */
            header->file_meta_json = malloc(tlv_len + 1);
            if (!header->file_meta_json) return -1;
            memcpy(header->file_meta_json, &data[pos], tlv_len);
            header->file_meta_json[tlv_len] = '\0';
            break;
            
        case TLV_POLICY:
            if (tlv_len > 512) return -1; /* Limit policy size */
            header->policy_json = malloc(tlv_len + 1);
            if (!header->policy_json) return -1;
            memcpy(header->policy_json, &data[pos], tlv_len);
            header->policy_json[tlv_len] = '\0';
            break;
            
        case TLV_NOTE:
            if (tlv_len > 2048) return -1; /* Limit note size */
            header->note = malloc(tlv_len + 1);
            if (!header->note) return -1;
            memcpy(header->note, &data[pos], tlv_len);
            header->note[tlv_len] = '\0';
            break;
            
        case TLV_LEARNING_META:
            /* Store opaque encrypted learning metadata */
            if (tlv_len > 0) {
                header->learning_meta = malloc(tlv_len);
                if (!header->learning_meta) return -1;
                memcpy(header->learning_meta, &data[pos], tlv_len);
                header->learning_meta_len = tlv_len;
            }
            break;
            
        default:
            /* Skip unknown TLV types */
            break;
        }
        
        pos += tlv_len;
    }
    
    return 0;
}

/* Serialize TLV section */
static size_t serialize_tlvs(const cortex_header_t* header, uint8_t* buf, size_t buf_len) {
    size_t pos = 0;
    
    /* FILE_META TLV */
    if (header->file_meta_json) {
        size_t meta_len = strlen(header->file_meta_json);
        if (pos + 3 + meta_len > buf_len) return 0;
        
        buf[pos] = TLV_FILE_META;
        write_be16(&buf[pos + 1], meta_len);
        memcpy(&buf[pos + 3], header->file_meta_json, meta_len);
        pos += 3 + meta_len;
    }
    
    /* POLICY TLV */
    if (header->policy_json) {
        size_t policy_len = strlen(header->policy_json);
        if (pos + 3 + policy_len > buf_len) return 0;
        
        buf[pos] = TLV_POLICY;
        write_be16(&buf[pos + 1], policy_len);
        memcpy(&buf[pos + 3], header->policy_json, policy_len);
        pos += 3 + policy_len;
    }
    
    /* NOTE TLV */
    if (header->note) {
        size_t note_len = strlen(header->note);
        if (pos + 3 + note_len > buf_len) return 0;
        
        buf[pos] = TLV_NOTE;
        write_be16(&buf[pos + 1], note_len);
        memcpy(&buf[pos + 3], header->note, note_len);
        pos += 3 + note_len;
    }
    
    /* LEARNING_META TLV */
    if (header->learning_meta && header->learning_meta_len > 0) {
        if (pos + 3 + header->learning_meta_len > buf_len) return 0;
        
        buf[pos] = TLV_LEARNING_META;
        write_be16(&buf[pos + 1], header->learning_meta_len);
        memcpy(&buf[pos + 3], header->learning_meta, header->learning_meta_len);
        pos += 3 + header->learning_meta_len;
    }
    
    return pos;
}

/* Compute AAD hash (header without aad_hash field) */
static int compute_aad_hash(const uint8_t* header_buf, size_t header_len, 
                           uint8_t aad_hash[32]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx || !EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        if (ctx) EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    /* Hash header up to aad_hash field (112 bytes) */
    if (!EVP_DigestUpdate(ctx, header_buf, 112)) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    /* Skip aad_hash field (32 bytes) and hash rest */
    if (header_len > 144) {
        if (!EVP_DigestUpdate(ctx, header_buf + 144, header_len - 144)) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }
    }
    
    unsigned int hash_len;
    if (!EVP_DigestFinal_ex(ctx, aad_hash, &hash_len) || hash_len != 32) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    EVP_MD_CTX_free(ctx);
    return 0;
}

/* Parse .cortex file header */
int cortex_parse_header(FILE* fp, cortex_header_t* header) {
    uint8_t buf[4096];
    (void)buf; /* Mark as used to suppress warning */
    
    if (!fp || !header) return -1;
    
    /* Initialize header */
    memset(header, 0, sizeof(*header));
    
    /* Read fixed header portion */
    if (fread(buf, 1, 144, fp) != 144) {
        return -1;
    }
    
    /* Verify magic */
    if (memcmp(buf, CORTEX_MAGIC, 8) != 0) {
        return -1;
    }
    
    /* Parse fixed fields */
    header->version = read_be16(&buf[8]);
    header->flags = buf[10];
    header->cipher_id = buf[11];
    header->header_len = read_be16(&buf[12]);
    
    /* Copy salts and hashes */
    memcpy(header->file_salt, &buf[16], 16);
    memcpy(header->session_salt, &buf[32], 16);
    memcpy(header->binding_id_hash, &buf[48], 32);
    memcpy(header->model_id_hash, &buf[80], 32);
    memcpy(header->aad_hash, &buf[112], 32);
    
    /* Validate header length */
    if (header->header_len < 144 || header->header_len > 4096) {
        return -1;
    }
    
    /* Read TLV section if present */
    size_t tlv_len = header->header_len - 144;
    if (tlv_len > 0) {
        if (fread(&buf[144], 1, tlv_len, fp) != tlv_len) {
            return -1;
        }
        
        if (parse_tlvs(&buf[144], tlv_len, header) != 0) {
            cortex_free_header(header);
            return -1;
        }
    }
    
    /* Verify AAD hash */
    uint8_t computed_aad[32];
    if (compute_aad_hash(buf, header->header_len, computed_aad) != 0) {
        cortex_free_header(header);
        return -1;
    }
    
    if (memcmp(computed_aad, header->aad_hash, 32) != 0) {
        cortex_free_header(header);
        return -1; /* Header integrity check failed */
    }
    
    return 0;
}

/* Create .cortex file header */
int cortex_create_header(cortex_header_t* header, const cortex_create_params_t* params) {
    if (!header || !params) return -1;
    
    /* Initialize header */
    memset(header, 0, sizeof(*header));
    
    header->version = CORTEX_VERSION;
    header->cipher_id = params->cipher_id;
    
    /* Set binding flags */
    if (params->bind_policy == CC_BIND_VOLUME) {
        header->flags |= CC_FLAG_BIND_VOLUME;
    } else if (params->bind_policy == CC_BIND_MACHINE) {
        header->flags |= CC_FLAG_BIND_MACHINE;
    }
    
    if (params->disallow_copy) {
        header->flags |= CC_FLAG_DISALLOW_COPY;
    }
    
    /* Generate random salts */
    if (RAND_bytes(header->file_salt, 16) != 1) return -1;
    if (RAND_bytes(header->session_salt, 16) != 1) return -1;
    
    /* Copy binding ID hash (computed externally) */
    memcpy(header->binding_id_hash, params->binding_id_hash, 32);
    
    /* Copy model ID hash (computed externally) */
    memcpy(header->model_id_hash, params->model_id_hash, 32);
    
    /* Store metadata */
    if (params->file_meta_json) {
        header->file_meta_json = strdup(params->file_meta_json);
    }
    if (params->policy_json) {
        header->policy_json = strdup(params->policy_json);
    }
    if (params->note) {
        header->note = strdup(params->note);
    }
    
    return 0;
}

/* Write .cortex file header */
int cortex_write_header(FILE* fp, const cortex_header_t* header) {
    uint8_t buf[4096];
    size_t pos = 0;
    
    if (!fp || !header) return -1;
    
    /* Write magic */
    memcpy(&buf[pos], CORTEX_MAGIC, 8);
    pos += 8;
    
    /* Write version */
    write_be16(&buf[pos], header->version);
    pos += 2;
    
    /* Write flags and cipher */
    buf[pos++] = header->flags;
    buf[pos++] = header->cipher_id;
    
    /* Reserve space for header_len (will fill later) */
    size_t header_len_pos = pos;
    pos += 2;
    
    /* Reserved bytes */
    buf[pos++] = 0;
    buf[pos++] = 0;
    
    /* Write salts and hashes */
    memcpy(&buf[pos], header->file_salt, 16);
    pos += 16;
    memcpy(&buf[pos], header->session_salt, 16);
    pos += 16;
    memcpy(&buf[pos], header->binding_id_hash, 32);
    pos += 32;
    memcpy(&buf[pos], header->model_id_hash, 32);
    pos += 32;
    
    /* Reserve space for AAD hash (will compute later) */
    size_t aad_hash_pos = pos;
    pos += 32;
    
    /* Write TLV section */
    size_t tlv_len = serialize_tlvs(header, &buf[pos], sizeof(buf) - pos);
    if (tlv_len == 0 && (header->file_meta_json || header->policy_json || 
                        header->note || header->learning_meta)) {
        return -1; /* TLV serialization failed */
    }
    pos += tlv_len;
    
    /* Set header length */
    write_be16(&buf[header_len_pos], pos);
    
    /* Compute and write AAD hash */
    uint8_t aad_hash[32];
    if (compute_aad_hash(buf, pos, aad_hash) != 0) {
        return -1;
    }
    memcpy(&buf[aad_hash_pos], aad_hash, 32);
    
    /* Write to file */
    if (fwrite(buf, 1, pos, fp) != pos) {
        return -1;
    }
    
    return 0;
}

/* Get file size from header info */
size_t cortex_get_file_size(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;
    }
    return st.st_size;
}

/* Extract ciphertext size from file */
size_t cortex_get_ciphertext_size(const char* path) {
    FILE* fp = fopen(path, "rb");
    if (!fp) return 0;
    
    cortex_header_t header;
    if (cortex_parse_header(fp, &header) != 0) {
        fclose(fp);
        return 0;
    }
    
    /* Get total file size and subtract header + tag */
    fseek(fp, 0, SEEK_END);
    size_t total_size = ftell(fp);
    fclose(fp);
    
    size_t ciphertext_size = total_size - header.header_len - 16; /* 16 = AEAD tag */
    
    cortex_free_header(&header);
    return ciphertext_size;
}

/* Free header resources */
void cortex_free_header(cortex_header_t* header) {
    if (!header) return;
    
    free(header->file_meta_json);
    free(header->policy_json);
    free(header->note);
    free(header->learning_meta);
    
    memset(header, 0, sizeof(*header));
}

/* Validate header integrity */
int cortex_validate_header(const cortex_header_t* header) {
    if (!header) return -1;
    
    /* Check version */
    if (header->version != CORTEX_VERSION) {
        return -1;
    }
    
    /* Check cipher ID */
    if (header->cipher_id > CC_CIPHER_XCHACHA20_POLY) {
        return -1;
    }
    
    /* Check header length bounds */
    if (header->header_len < 144 || header->header_len > 4096) {
        return -1;
    }
    
    /* Validate flags */
    if (!(header->flags & (CC_FLAG_BIND_VOLUME | CC_FLAG_BIND_MACHINE))) {
        return -1; /* Must have at least one binding type */
    }
    
    return 0;
}

/* Check if file has .cortex extension */
int cortex_is_cortex_file(const char* path) {
    if (!path) return 0;
    
    size_t len = strlen(path);
    if (len < 7) return 0; /* Minimum: "a.cortex" */
    
    return strcmp(path + len - 7, ".cortex") == 0;
}

/* Generate default file metadata JSON */
char* cortex_generate_file_meta(const char* filename, const char* original_path) {
    char* json = malloc(1024);
    if (!json) return NULL;
    
    /* Get current timestamp */
    time_t now = time(NULL);
    
    /* Get file size if original exists */
    struct stat st;
    size_t original_size = 0;
    if (original_path && stat(original_path, &st) == 0) {
        original_size = st.st_size;
    }
    
    /* Simple JSON generation (sufficient for metadata) */
    snprintf(json, 1024, 
        "{"
        "\"filename\":\"%s\","
        "\"timestamp\":%ld,"
        "\"original_size\":%zu,"
        "\"version\":\"1.0\""
        "}", 
        filename ? filename : "unknown",
        now,
        original_size
    );
    
    return json;
}

/* Generate default policy JSON */
char* cortex_generate_policy(int max_retries, const char* lock_action) {
    char* json = malloc(512);
    if (!json) return NULL;
    
    snprintf(json, 512,
        "{"
        "\"max_retries\":%d,"
        "\"lock_action\":\"%s\","
        "\"backoff_base\":2,"
        "\"require_admin_unlock\":true"
        "}",
        max_retries,
        lock_action ? lock_action : "exponential_backoff"
    );
    
    return json;
}
