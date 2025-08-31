/*
 * CortexCrypt Utility Functions Internal Header
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <errno.h>

/* Security utilities */
void cc_secure_zero(void* ptr, size_t len);
int cc_random_bytes(uint8_t* buf, size_t len);
int cc_constant_time_memcmp(const void* a, const void* b, size_t len);

/* Time utilities */
uint64_t cc_get_timestamp(void);

/* String utilities */
int cc_safe_strcpy(char* dest, size_t dest_size, const char* src);
void cc_bytes_to_hex(const uint8_t* bytes, size_t len, char* hex);
int cc_hex_to_bytes(const char* hex, uint8_t* bytes, size_t bytes_len);

/* File utilities */
int cc_file_exists(const char* path);
size_t cc_file_size(const char* path);
const char* cc_basename(const char* path);
int cc_mkdir_p(const char* path);

/* Logging */
void cc_log(int level, const char* format, ...);

/* Log levels */
#define CC_LOG_ERROR 1
#define CC_LOG_WARN  2
#define CC_LOG_INFO  3
#define CC_LOG_DEBUG 4

#endif /* UTILS_H */
