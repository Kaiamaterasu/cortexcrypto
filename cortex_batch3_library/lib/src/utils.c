/*
 * CortexCrypt Utility Functions
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/random.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/rand.h>

#include "utils.h"

/* Secure zero memory */
void cc_secure_zero(void* ptr, size_t len) {
    if (!ptr || len == 0) return;
    
#ifdef OPENSSL_cleanse
    OPENSSL_cleanse(ptr, len);
#else
    /* Fallback - prevents compiler optimization */
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }
#endif
}

/* Secure random bytes */
int cc_random_bytes(uint8_t* buf, size_t len) {
    if (!buf || len == 0) return -1;
    
    /* Try getrandom first */
    ssize_t ret = getrandom(buf, len, 0);
    if ((size_t)ret == len) return 0;
    
    /* Fall back to OpenSSL */
    return RAND_bytes(buf, len) == 1 ? 0 : -1;
}

/* Constant-time memory comparison */
int cc_constant_time_memcmp(const void* a, const void* b, size_t len) {
    if (!a || !b) return -1;
    
    const uint8_t* pa = (const uint8_t*)a;
    const uint8_t* pb = (const uint8_t*)b;
    
    uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= pa[i] ^ pb[i];
    }
    
    return result;
}

/* Get current timestamp */
uint64_t cc_get_timestamp(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Safe string copy */
int cc_safe_strcpy(char* dest, size_t dest_size, const char* src) {
    if (!dest || !src || dest_size == 0) return -1;
    
    size_t src_len = strlen(src);
    if (src_len >= dest_size) return -1;
    
    memcpy(dest, src, src_len);
    dest[src_len] = '\0';
    
    return 0;
}

/* Hex encoding */
void cc_bytes_to_hex(const uint8_t* bytes, size_t len, char* hex) {
    const char hex_chars[] = "0123456789abcdef";
    
    for (size_t i = 0; i < len; i++) {
        hex[i * 2] = hex_chars[bytes[i] >> 4];
        hex[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    hex[len * 2] = '\0';
}

/* Hex decoding */
int cc_hex_to_bytes(const char* hex, uint8_t* bytes, size_t bytes_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != bytes_len * 2 || hex_len % 2 != 0) return -1;
    
    for (size_t i = 0; i < bytes_len; i++) {
        char high = hex[i * 2];
        char low = hex[i * 2 + 1];
        
        uint8_t h = 0, l = 0;
        
        if (high >= '0' && high <= '9') h = high - '0';
        else if (high >= 'a' && high <= 'f') h = high - 'a' + 10;
        else if (high >= 'A' && high <= 'F') h = high - 'A' + 10;
        else return -1;
        
        if (low >= '0' && low <= '9') l = low - '0';
        else if (low >= 'a' && low <= 'f') l = low - 'a' + 10;
        else if (low >= 'A' && low <= 'F') l = low - 'A' + 10;
        else return -1;
        
        bytes[i] = (h << 4) | l;
    }
    
    return 0;
}

/* File utilities */
int cc_file_exists(const char* path) {
    if (!path) return 0;
    
    FILE* fp = fopen(path, "r");
    if (fp) {
        fclose(fp);
        return 1;
    }
    
    return 0;
}

size_t cc_file_size(const char* path) {
    if (!path) return 0;
    
    FILE* fp = fopen(path, "rb");
    if (!fp) return 0;
    
    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fclose(fp);
    
    return size;
}

/* Extract filename from path */
const char* cc_basename(const char* path) {
    if (!path) return NULL;
    
    const char* filename = strrchr(path, '/');
    return filename ? filename + 1 : path;
}

/* Create directory if it doesn't exist */
int cc_mkdir_p(const char* path) {
    if (!path) return -1;
    
    char tmp[512];
    if (cc_safe_strcpy(tmp, sizeof(tmp), path) != 0) return -1;
    
    char* p = tmp;
    while (*p) {
        if (*p == '/' && p != tmp) {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
        p++;
    }
    
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    
    return 0;
}

/* Logging */
void cc_log(int level, const char* format, ...) {
    extern int g_log_level;
    if (level > g_log_level) return;
    
    const char* level_str[] = {"", "ERROR", "WARN", "INFO", "DEBUG"};
    
    va_list args;
    va_start(args, format);
    
    fprintf(stderr, "[CORTEX %s] ", level_str[level]);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    
    va_end(args);
}
