/*
 * CortexCrypt Device Binding Internal Header
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#ifndef BINDING_H
#define BINDING_H

#include <stdint.h>
#include <stddef.h>
#include "../include/cortexcrypt.h"

/* Function declarations */
int cortex_get_volume_binding(const char* path, uint8_t binding_id[32]);
int cortex_get_machine_binding(uint8_t binding_id[32]);
int cortex_get_binding_id(int bind_policy, const char* context_path, uint8_t binding_id[32]);
int cortex_verify_binding(const uint8_t expected_binding[32], int bind_policy, const char* context_path);
int cortex_describe_binding(int bind_policy, const char* context_path, char* description, size_t desc_len);
int cortex_is_removable_volume(const char* path);
int cortex_find_binding_path(char* best_path, size_t path_len);

#endif /* BINDING_H */
