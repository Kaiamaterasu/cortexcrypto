/*
 * CortexCrypt Daemon Internal Header
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#ifndef DAEMON_H
#define DAEMON_H

#include <stdint.h>
#include <time.h>
#include <pthread.h>

#define DAEMON_SOCKET_PATH "/tmp/cortexd.sock"
#define MAX_CLIENTS 16

/* Forward declarations */
typedef struct cortex_neural_ctx cortex_neural_ctx_t;
typedef struct telemetry_ctx telemetry_ctx_t;

/* Daemon context */
typedef struct {
    /* Core state */
    time_t start_time;
    pthread_mutex_t mutex;
    
    /* Neural network */
    cortex_neural_ctx_t* neural_ctx;
    
    /* Telemetry collection */
    telemetry_ctx_t* telemetry_ctx;
    
    /* Current anomaly score */
    float current_anomaly_score;
    time_t last_score_update;
    
    /* Models directory */
    char models_dir[512];
    
    /* Statistics */
    uint64_t requests_handled;
    uint64_t encrypt_operations;
    uint64_t decrypt_operations;
    uint64_t binding_failures;
} daemon_ctx_t;

/* Function declarations */
int daemon_init(daemon_ctx_t* ctx, const char* models_dir);
void daemon_cleanup(daemon_ctx_t* ctx);
int daemon_reload_models(daemon_ctx_t* ctx);
float daemon_get_anomaly_score(daemon_ctx_t* ctx);
void daemon_update_telemetry(daemon_ctx_t* ctx);

#endif /* DAEMON_H */
