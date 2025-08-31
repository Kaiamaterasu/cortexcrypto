/*
 * CortexCrypt Telemetry Collection
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#ifndef TELEMETRY_H
#define TELEMETRY_H

#include <stdint.h>
#include <time.h>
#include <pthread.h>

/* Telemetry features (12 features for anomaly detection) */
typedef struct {
    float reads_mean;           /* Average read operations per 10s window */
    float reads_std;            /* Standard deviation of read operations */
    float unique_proc;          /* Number of unique processes accessing files */
    float avg_bytes;            /* Average bytes per operation */
    float write_ratio;          /* Ratio of write to read operations */
    float failed_decrypts;      /* Number of failed decrypt attempts */
    float key_unwraps;          /* Number of key unwrap operations */
    float entropy_delta;        /* Change in file entropy */
    float new_binary_count;     /* Number of new binaries executed */
    float outbound_conn;        /* Number of outbound network connections */
    float time_since_last_unlock; /* Time since last successful unlock */
    float privilege_escalations; /* Number of privilege escalation attempts */
} telemetry_features_t;

/* Telemetry context */
typedef struct telemetry_ctx {
    /* Feature collection windows */
    uint32_t read_ops[60];      /* Last 60 seconds of read operations */
    uint32_t write_ops[60];
    uint32_t failed_auths[60];
    uint32_t proc_count[60];
    
    /* Current window position */
    int window_pos;
    time_t last_update;
    
    /* Aggregated features */
    telemetry_features_t features;
    
    /* Statistics */
    uint64_t total_operations;
    uint64_t total_failures;
    time_t last_successful_unlock;
    
    /* Mutex for thread safety */
    pthread_mutex_t mutex;
} telemetry_ctx_t;

/* Function declarations */
telemetry_ctx_t* telemetry_init(void);
void telemetry_cleanup(telemetry_ctx_t* ctx);
void telemetry_record_read(telemetry_ctx_t* ctx);
void telemetry_record_write(telemetry_ctx_t* ctx);
void telemetry_record_auth_failure(telemetry_ctx_t* ctx);
void telemetry_record_auth_success(telemetry_ctx_t* ctx);
void telemetry_update_features(telemetry_ctx_t* ctx);
void telemetry_get_features(telemetry_ctx_t* ctx, float features[12]);
float telemetry_assess_threat_level(telemetry_ctx_t* ctx);
void telemetry_update(telemetry_ctx_t* ctx);

#endif /* TELEMETRY_H */
