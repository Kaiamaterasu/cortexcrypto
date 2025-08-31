/*
 * CortexCrypt Telemetry Implementation
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <math.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <signal.h>
#include <setjmp.h>
#include <errno.h>
#include <sys/select.h>

#include "telemetry.h"

/* Timeout-protected file operation globals */
static volatile int file_operation_timeout = 0;
static jmp_buf timeout_jump;

static void timeout_handler(int sig) {
    (void)sig; /* Suppress unused parameter warning */
    file_operation_timeout = 1;
    longjmp(timeout_jump, 1);
}

/* Safe file reading with timeout protection */
static int safe_read_file_with_timeout(const char* path, char* buffer, size_t buffer_size, int timeout_secs) {
    if (!path || !buffer || buffer_size == 0) return -1;
    
    file_operation_timeout = 0;
    
    /* Set up timeout handler */
    struct sigaction sa, old_sa;
    sa.sa_handler = timeout_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, &old_sa);
    
    if (setjmp(timeout_jump) != 0) {
        /* Timeout occurred */
        alarm(0);
        sigaction(SIGALRM, &old_sa, NULL);
        return -1;
    }
    
    alarm(timeout_secs);
    
    /* Try to open file with non-blocking flag */
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        alarm(0);
        sigaction(SIGALRM, &old_sa, NULL);
        return -1;
    }
    
    /* Use select to check if data is available */
    fd_set readfds;
    struct timeval tv;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    
    int select_result = select(fd + 1, &readfds, NULL, NULL, &tv);
    if (select_result <= 0) {
        close(fd);
        alarm(0);
        sigaction(SIGALRM, &old_sa, NULL);
        return -1;
    }
    
    ssize_t bytes_read = read(fd, buffer, buffer_size - 1);
    close(fd);
    
    alarm(0);
    sigaction(SIGALRM, &old_sa, NULL);
    
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        return (int)bytes_read;
    }
    
    return -1;
}

/* Initialize telemetry context */
telemetry_ctx_t* telemetry_init(void) {
    telemetry_ctx_t* ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    
    ctx->last_update = time(NULL);
    ctx->last_successful_unlock = ctx->last_update;
    ctx->window_pos = 0;
    
    /* Initialize mutex */
    if (pthread_mutex_init(&ctx->mutex, NULL) != 0) {
        free(ctx);
        return NULL;
    }
    
    return ctx;
}

/* Clean up telemetry context */
void telemetry_cleanup(telemetry_ctx_t* ctx) {
    if (!ctx) return;
    
    pthread_mutex_destroy(&ctx->mutex);
    free(ctx);
}

/* Record read operation */
void telemetry_record_read(telemetry_ctx_t* ctx) {
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->mutex);
    
    time_t now = time(NULL);
    int pos = now % 60; /* Circular buffer */
    
    ctx->read_ops[pos]++;
    ctx->total_operations++;
    
    pthread_mutex_unlock(&ctx->mutex);
}

/* Record write operation */
void telemetry_record_write(telemetry_ctx_t* ctx) {
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->mutex);
    
    time_t now = time(NULL);
    int pos = now % 60;
    
    ctx->write_ops[pos]++;
    ctx->total_operations++;
    
    pthread_mutex_unlock(&ctx->mutex);
}

/* Record authentication failure */
void telemetry_record_auth_failure(telemetry_ctx_t* ctx) {
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->mutex);
    
    time_t now = time(NULL);
    int pos = now % 60;
    
    ctx->failed_auths[pos]++;
    ctx->total_failures++;
    
    pthread_mutex_unlock(&ctx->mutex);
}

/* Record authentication success */
void telemetry_record_auth_success(telemetry_ctx_t* ctx) {
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->mutex);
    ctx->last_successful_unlock = time(NULL);
    pthread_mutex_unlock(&ctx->mutex);
}



/* Count unique processes accessing files */
static float count_unique_processes(void) {
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return 2.0f; /* Safe fallback */
    
    int unique_count = 0;
    int processed = 0;
    struct dirent* entry;
    
    /* Limit scanning to prevent hanging - only check first 100 processes */
    while ((entry = readdir(proc_dir)) != NULL && processed < 100) {
        if (!isdigit(entry->d_name[0])) continue;
        processed++;
        
        char cmdline_path[512];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", entry->d_name);
        
        /* Use non-blocking file access with timeout */
        int fd = open(cmdline_path, O_RDONLY | O_NONBLOCK);
        if (fd >= 0) {
            char cmdline[256];
            ssize_t bytes_read = read(fd, cmdline, sizeof(cmdline) - 1);
            close(fd);
            
            if (bytes_read > 0) {
                cmdline[bytes_read] = '\0';
                /* Replace null bytes with spaces for easier string matching */
                for (ssize_t i = 0; i < bytes_read; i++) {
                    if (cmdline[i] == '\0') cmdline[i] = ' ';
                }
                
                if (strstr(cmdline, "encrypt") || strstr(cmdline, "decrypt") || 
                    strstr(cmdline, "cortex")) {
                    unique_count++;
                }
            }
        }
    }
    
    closedir(proc_dir);
    
    /* Return count with reasonable bounds */
    return (float)unique_count;
}

/* Monitor system entropy */
static float get_entropy_delta(void) {
    static float last_entropy = 0.0f;
    
    FILE* fp = fopen("/proc/sys/kernel/random/entropy_avail", "r");
    if (!fp) return 0.0f;
    
    int entropy;
    if (fscanf(fp, "%d", &entropy) != 1) {
        fclose(fp);
        return 0.0f;
    }
    fclose(fp);
    
    float current_entropy = entropy / 4096.0f; /* Normalize */
    float delta = fabsf(current_entropy - last_entropy);
    last_entropy = current_entropy;
    
    return delta;
}

/* Detect potential ransomware activity with timeout protection */
static float detect_ransomware_patterns(void) {
    volatile float risk_score = 0.0f;
    
    /* Set up alarm for directory scanning timeout */
    struct sigaction sa, old_sa;
    sa.sa_handler = timeout_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, &old_sa);
    
    if (setjmp(timeout_jump) != 0) {
        /* Timeout occurred during directory scanning */
        alarm(0);
        sigaction(SIGALRM, &old_sa, NULL);
        return 0.5f; /* Return moderate risk if we can't scan */
    }
    
    alarm(3); /* 3 second timeout for directory operations */
    
    /* Check for rapid file creation patterns */
    DIR* dir = opendir(".");
    if (dir) {
        struct dirent* entry;
        time_t now = time(NULL);
        int recent_files = 0;
        int files_checked = 0;
        
        /* Limit file checking to prevent hanging on large directories */
        while ((entry = readdir(dir)) != NULL && files_checked < 100) {
            files_checked++;
            
            struct stat st;
            /* Use lstat for faster, safer file stat (no symlink following) */
            if (lstat(entry->d_name, &st) == 0 && S_ISREG(st.st_mode)) {
                /* Check for recently created files */
                if (now - st.st_ctime < 60) { /* Last minute */
                    recent_files++;
                    
                    /* Check for suspicious extensions */
                    char* ext = strrchr(entry->d_name, '.');
                    if (ext && (strcmp(ext, ".locked") == 0 || 
                               strcmp(ext, ".encrypted") == 0 ||
                               strcmp(ext, ".crypto") == 0)) {
                        risk_score += 0.3f;
                    }
                }
            }
        }
        closedir(dir);
        
        /* High file creation rate is suspicious */
        if (recent_files > 20) risk_score += 0.5f;
        else if (recent_files > 10) risk_score += 0.2f;
    }
    
    alarm(0);
    sigaction(SIGALRM, &old_sa, NULL);
    
    return fminf(1.0f, risk_score);
}

/* Monitor network connections with timeout protection */
static float monitor_network_activity(void) {
    char buffer[4096];
    if (safe_read_file_with_timeout("/proc/net/tcp", buffer, sizeof(buffer), 2) <= 0) {
        return 0.0f; /* Timeout or read error */
    }
    
    int outbound_connections = 0;
    char* line = strtok(buffer, "\n");
    int lines_processed = 0;
    
    /* Skip header and limit processing */
    line = strtok(NULL, "\n"); /* Skip first line */
    
    while (line && lines_processed < 50) { /* Limit to first 50 connections */
        lines_processed++;
        unsigned local_addr, local_port, remote_addr, remote_port;
        int state;
        
        if (sscanf(line, "%*d: %x:%x %x:%x %x", 
                  &local_addr, &local_port, &remote_addr, &remote_port, &state) == 5) {
            /* Check for established outbound connections */
            if (state == 1 && remote_addr != 0) { /* TCP_ESTABLISHED */
                outbound_connections++;
            }
        }
        line = strtok(NULL, "\n");
    }
    
    return fminf(1.0f, outbound_connections / 10.0f); /* Normalize */
}


/* Detect privilege escalation attempts */
static float detect_privilege_escalations(void) {
    /* Try to access auth log with timeout protection */
    char buffer[2048];
    if (safe_read_file_with_timeout("/var/log/auth.log", buffer, sizeof(buffer), 2) <= 0) {
        return 0.0f; /* Can't read or timeout */
    }
    
    int recent_sudo = 0;
    char* line = strtok(buffer, "\n");
    int lines_processed = 0;
    
    while (line && lines_processed < 20) { /* Limit processing */
        lines_processed++;
        if (strstr(line, "sudo") && strstr(line, "COMMAND")) {
            recent_sudo++;
        }
        line = strtok(NULL, "\n");
    }
    
    return fminf(1.0f, recent_sudo / 5.0f); /* Normalize */
}

/* Monitor file system for suspicious patterns */
static float analyze_filesystem_patterns(void) {
    struct statvfs vfs;
    if (statvfs("/", &vfs) != 0) return 0.0f;
    
    /* Calculate free space ratio */
    float free_ratio = (float)vfs.f_bavail / (float)vfs.f_blocks;
    
    /* Low disk space can indicate encryption/filling attacks */
    if (free_ratio < 0.05f) return 0.8f;  /* Very low space */
    if (free_ratio < 0.1f) return 0.4f;   /* Low space */
    
    return 0.0f;
}

/* Get system load and memory pressure */
static float get_system_pressure(void) {
    struct sysinfo info;
    if (sysinfo(&info) != 0) return 0.0f;
    
    /* Calculate load average normalized by CPU count */
    float load_avg = info.loads[0] / (float)(1 << SI_LOAD_SHIFT);
    float normalized_load = load_avg / (float)get_nprocs();
    
    /* Calculate memory pressure */
    float mem_usage = 1.0f - ((float)info.freeram / (float)info.totalram);
    
    /* Combine load and memory pressure */
    float pressure = (normalized_load * 0.6f) + (mem_usage * 0.4f);
    
    return fminf(1.0f, pressure);
}

/* Update derived features */
void telemetry_update_features(telemetry_ctx_t* ctx) {
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->mutex);
    
    time_t now = time(NULL);
    
    /* Calculate sums for last 60 seconds */
    uint32_t total_reads = 0;
    uint32_t total_writes = 0;
    uint32_t total_failures = 0;
    
    for (int i = 0; i < 60; i++) {
        total_reads += ctx->read_ops[i];
        total_writes += ctx->write_ops[i];
        total_failures += ctx->failed_auths[i];
    }
    
    /* Compute advanced features */
    ctx->features.reads_mean = total_reads / 60.0f;
    
    /* Calculate standard deviation of reads */
    float variance = 0.0f;
    for (int i = 0; i < 60; i++) {
        float diff = ctx->read_ops[i] - ctx->features.reads_mean;
        variance += diff * diff;
    }
    ctx->features.reads_std = sqrtf(variance / 60.0f);
    
    /* Real-time system monitoring */
    ctx->features.unique_proc = count_unique_processes();
    ctx->features.avg_bytes = (total_reads + total_writes) > 0 ? 
                             1024.0f * (total_reads + total_writes) / 60.0f : 0.0f;
    ctx->features.write_ratio = (total_reads > 0) ? (total_writes / (float)total_reads) : 0.0f;
    ctx->features.failed_decrypts = total_failures;
    ctx->features.key_unwraps = ctx->total_operations / 100.0f;
    ctx->features.entropy_delta = get_entropy_delta();
    ctx->features.new_binary_count = detect_ransomware_patterns();
    ctx->features.outbound_conn = monitor_network_activity();
    ctx->features.time_since_last_unlock = now - ctx->last_successful_unlock;
    ctx->features.privilege_escalations = detect_privilege_escalations();
    
    /* Additional threat indicators */
    float system_pressure = get_system_pressure();
    float filesystem_anomaly = analyze_filesystem_patterns();
    
    /* Adjust features based on additional indicators */
    if (system_pressure > 0.8f) ctx->features.reads_mean *= 1.2f;
    if (filesystem_anomaly > 0.5f) ctx->features.new_binary_count += 0.3f;
    
    ctx->last_update = now;
    
    pthread_mutex_unlock(&ctx->mutex);
}

/* Get feature vector for anomaly detection */
void telemetry_get_features(telemetry_ctx_t* ctx, float features[12]) {
    if (!ctx || !features) return;
    
    pthread_mutex_lock(&ctx->mutex);
    
    /* Update features first */
    telemetry_update_features(ctx);
    
    /* Copy to output array */
    features[0] = ctx->features.reads_mean;
    features[1] = ctx->features.reads_std;
    features[2] = ctx->features.unique_proc;
    features[3] = ctx->features.avg_bytes;
    features[4] = ctx->features.write_ratio;
    features[5] = ctx->features.failed_decrypts;
    features[6] = ctx->features.key_unwraps;
    features[7] = ctx->features.entropy_delta;
    features[8] = ctx->features.new_binary_count;
    features[9] = ctx->features.outbound_conn;
    features[10] = ctx->features.time_since_last_unlock;
    features[11] = ctx->features.privilege_escalations;
    
    /* Advanced normalization with threat weighting */
    const float maxs[12] = {100, 10, 50, 1e6, 1, 10, 100, 2, 10, 5, 3600, 5};
    const float threat_weights[12] = {1.0f, 1.2f, 1.5f, 1.0f, 2.0f, 3.0f, 1.0f, 1.5f, 2.5f, 2.0f, 0.8f, 3.0f};
    
    for (int i = 0; i < 12; i++) {
        features[i] = (features[i] / maxs[i]) * threat_weights[i];
        if (features[i] > 1.0f) features[i] = 1.0f;
        if (features[i] < 0.0f) features[i] = 0.0f;
    }
    
    pthread_mutex_unlock(&ctx->mutex);
}

/* Real-time threat assessment */
float telemetry_assess_threat_level(telemetry_ctx_t* ctx) {
    if (!ctx) return 0.5f;
    
    float features[12];
    telemetry_get_features(ctx, features);
    
    /* Compute weighted threat score */
    float threat_score = 0.0f;
    
    /* High-risk indicators */
    if (features[5] > 0.3f) threat_score += 0.4f;  /* Failed decrypts */
    if (features[8] > 0.2f) threat_score += 0.3f;  /* New suspicious files */
    if (features[9] > 0.3f) threat_score += 0.2f;  /* Outbound connections */
    if (features[11] > 0.1f) threat_score += 0.3f; /* Privilege escalations */
    
    /* Medium-risk indicators */
    if (features[4] > 0.8f) threat_score += 0.15f; /* High write ratio */
    if (features[2] > 20.0f) threat_score += 0.1f; /* Many processes */
    if (features[7] < 0.2f) threat_score += 0.1f;  /* Low entropy */
    
    /* Time-based factors */
    if (features[10] < 300.0f) threat_score *= 0.8f; /* Recent unlock reduces risk */
    
    return fminf(1.0f, threat_score);
}

/* Update routine that should be called periodically */
void telemetry_update(telemetry_ctx_t* ctx) {
    if (!ctx) return;
    
    /* Update basic features */
    telemetry_update_features(ctx);
    
    /* Perform real-time threat assessment */
    float threat_level = telemetry_assess_threat_level(ctx);
    
    /* Log high threat levels */
    if (threat_level > 0.7f) {
        syslog(LOG_WARNING, "High threat level detected: %.2f", threat_level);
    }
}
