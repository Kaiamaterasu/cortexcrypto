/*
 * CortexCrypt Daemon Implementation  
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <syslog.h>
#include <math.h>
#include <sys/wait.h>
#include <signal.h>

#include "daemon.h"
#include "telemetry.h"
#include "neural.h"

/* Initialize daemon context */
int daemon_init(daemon_ctx_t* ctx, const char* models_dir) {
    if (!ctx) return -1;
    
    memset(ctx, 0, sizeof(*ctx));
    
    ctx->start_time = time(NULL);
    ctx->current_anomaly_score = 0.1f; /* Default low anomaly */
    ctx->last_score_update = ctx->start_time;
    
    if (models_dir) {
        strncpy(ctx->models_dir, models_dir, sizeof(ctx->models_dir) - 1);
    } else {
        strcpy(ctx->models_dir, "/usr/local/share/cortexcrypt/models");
    }
    
    /* Initialize mutex */
    if (pthread_mutex_init(&ctx->mutex, NULL) != 0) {
        return -1;
    }
    
    /* Initialize telemetry */
    ctx->telemetry_ctx = telemetry_init();
    
    /* Initialize neural network context */
    ctx->neural_ctx = cortex_neural_init(ctx->models_dir);
    if (ctx->neural_ctx) {
        syslog(LOG_INFO, "Neural network models loaded successfully");
    } else {
        syslog(LOG_WARNING, "Neural network models not available - using fallback heuristics");
    }
    
    syslog(LOG_INFO, "Daemon initialized with models_dir: %s", ctx->models_dir);
    return 0;
}

/* Cleanup daemon context */
void daemon_cleanup(daemon_ctx_t* ctx) {
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->mutex);
    
    if (ctx->telemetry_ctx) {
        telemetry_cleanup(ctx->telemetry_ctx);
        ctx->telemetry_ctx = NULL;
    }
    
    if (ctx->neural_ctx) {
        cortex_neural_cleanup(ctx->neural_ctx);
        ctx->neural_ctx = NULL;
    }
    
    pthread_mutex_unlock(&ctx->mutex);
    pthread_mutex_destroy(&ctx->mutex);
    
    syslog(LOG_INFO, "Daemon cleanup complete");
}

/* Reload neural network models */
int daemon_reload_models(daemon_ctx_t* ctx) {
    if (!ctx) return -1;
    
    pthread_mutex_lock(&ctx->mutex);
    
    syslog(LOG_INFO, "Model reload requested (placeholder)");
    
    /* TODO: Implement actual model reloading */
    /* For now, just log the event */
    
    pthread_mutex_unlock(&ctx->mutex);
    return 0;
}

/* Get current anomaly score using neural network with timeout protection */
float daemon_get_anomaly_score(daemon_ctx_t* ctx) {
    if (!ctx) return 0.5f;
    
    /* Try to acquire mutex with timeout */
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 2; /* 2 second timeout */
    
    if (pthread_mutex_timedlock(&ctx->mutex, &timeout) != 0) {
        syslog(LOG_WARNING, "Anomaly score mutex timeout - returning cached value");
        return ctx->current_anomaly_score; /* Return last known value */
    }
    
    time_t now = time(NULL);
    
    /* Update score frequently for real-time detection with timeout protection */
    if (now - ctx->last_score_update > 5) {
        float features[12] = {0}; /* Initialize to safe defaults */
        
        /* Get telemetry features with timeout protection */
        if (ctx->telemetry_ctx) {
            /* Fork a child process to get features with timeout */
            pid_t pid = fork();
            if (pid == 0) {
                /* Child process - get features quickly */
                telemetry_get_features(ctx->telemetry_ctx, features);
                exit(0);
            } else if (pid > 0) {
                /* Parent - wait with timeout */
                int status;
                alarm(3); /* 3 second timeout */
                if (waitpid(pid, &status, 0) < 0) {
                    /* Timeout or error - use safe defaults */
                    cortex_create_default_features(features);
                }
                alarm(0);
            } else {
                /* Fork failed - use safe defaults */
                cortex_create_default_features(features);
            }
            
            /* Use neural network for anomaly detection if available */
            if (ctx->neural_ctx) {
                float nn_score = cortex_compute_anomaly_score(ctx->neural_ctx, features);
                
                /* Simple heuristic as fallback */
                float heuristic_score = fminf(0.3f, features[0] * 0.1f + features[1] * 0.1f);
                
                /* Weighted combination: 70% neural network, 30% heuristics */
                ctx->current_anomaly_score = (nn_score * 0.7f) + (heuristic_score * 0.3f);
                
                /* Apply threat amplification if multiple indicators align */
                if (nn_score > 0.6f && heuristic_score > 0.6f) {
                    ctx->current_anomaly_score = fminf(1.0f, ctx->current_anomaly_score * 1.2f);
                }
                
                syslog(LOG_DEBUG, "Anomaly score: NN=%.3f, Heuristic=%.3f, Combined=%.3f", 
                       nn_score, heuristic_score, ctx->current_anomaly_score);
            } else {
                /* Fast fallback without complex telemetry */
                ctx->current_anomaly_score = 0.1f; /* Safe default */
                syslog(LOG_DEBUG, "Fallback anomaly score: %.3f", ctx->current_anomaly_score);
            }
        }
        
        ctx->last_score_update = now;
    }
    
    float score = ctx->current_anomaly_score;
    pthread_mutex_unlock(&ctx->mutex);
    
    return score;
}

/* Update telemetry data */
void daemon_update_telemetry(daemon_ctx_t* ctx) {
    if (!ctx || !ctx->telemetry_ctx) return;
    
    telemetry_update(ctx->telemetry_ctx);
}
