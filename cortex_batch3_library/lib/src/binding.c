/*
 * CortexCrypt Device Binding Implementation
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <mntent.h>
#include <blkid/blkid.h>
#include <openssl/sha.h>

#include "binding.h"
#include "utils.h"

/* Maximum length for binding material */
#define BINDING_MATERIAL_MAX 4096

/* Get volume UUID and filesystem info */
static int get_volume_info(const char* path, char* uuid, char* fs_uuid, char* label) {
    /* Convert to absolute path */
    char abs_path[PATH_MAX];
    if (realpath(path, abs_path) == NULL) {
        return -1;
    }
    
    /* Find the mount point */
    FILE* fp = fopen("/proc/mounts", "r");
    if (!fp) {
        return -1;
    }
    
    char device[256] = {0};
    char best_device[256] = {0};
    char best_mount[256] = {0};
    char* line = NULL;
    size_t len = 0;
    char mount_point[256] = {0};
    char fs_type[64] = {0};
    size_t best_match_len = 0;
    
    /* Find longest matching mount containing our path */
    while (getline(&line, &len, fp) != -1) {
        if (sscanf(line, "%255s %255s %63s", device, mount_point, fs_type) == 3) {
            size_t mount_len = strlen(mount_point);
            if (strncmp(abs_path, mount_point, mount_len) == 0 && 
                (mount_len == 1 || abs_path[mount_len] == '/' || abs_path[mount_len] == '\0') &&
                mount_len > best_match_len) {
                strcpy(best_device, device);
                strcpy(best_mount, mount_point);
                best_match_len = mount_len;
            }
        }
        memset(device, 0, sizeof(device));
        memset(mount_point, 0, sizeof(mount_point));
    }
    
    free(line);
    fclose(fp);
    
    if (best_device[0] == '\0') {
        return -1;
    }
    
    strcpy(device, best_device);
    
    /* Use blkid to get UUID and label */
    blkid_cache cache;
    if (blkid_get_cache(&cache, NULL) != 0) {
        return -1;
    }
    
    const char* uuid_val = blkid_get_tag_value(cache, "UUID", device);
    const char* label_val = blkid_get_tag_value(cache, "LABEL", device);
    const char* fs_uuid_val = blkid_get_tag_value(cache, "UUID", device);
    
    /* Copy values */
    if (uuid_val) {
        strncpy(uuid, uuid_val, 255);
        uuid[255] = '\0';
    }
    if (fs_uuid_val) {
        strncpy(fs_uuid, fs_uuid_val, 255);
        fs_uuid[255] = '\0';
    }
    if (label_val) {
        strncpy(label, label_val, 255);
        label[255] = '\0';
    }
    
    blkid_put_cache(cache);
    return 0;
}

/* Read first 4KB of device for fingerprinting (unused but kept for future use) */
#if 0
static int get_device_fingerprint(const char* device_path, uint8_t hash[32]) {
    FILE* fp = fopen(device_path, "rb");
    if (!fp) return -1;
    
    uint8_t buf[4096];
    size_t read_len = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    
    if (read_len == 0) return -1;
    
    /* Hash the read data */
    SHA256(buf, read_len, hash);
    return 0;
}
#endif

/* Get machine-specific identifiers */
static int get_machine_info(char* machine_id, char* cpu_brand, char* dmi_serial) {
    FILE* fp;
    
    /* Read /etc/machine-id */
    fp = fopen("/etc/machine-id", "r");
    if (fp) {
        if (fgets(machine_id, 256, fp)) {
            /* Remove newline */
            char* nl = strchr(machine_id, '\n');
            if (nl) *nl = '\0';
        }
        fclose(fp);
    }
    
    /* Read CPU brand string from /proc/cpuinfo */
    fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "model name", 10) == 0) {
                char* colon = strchr(line, ':');
                if (colon) {
                    strncpy(cpu_brand, colon + 2, 255);
                    /* Remove newline */
                    char* nl = strchr(cpu_brand, '\n');
                    if (nl) *nl = '\0';
                    break;
                }
            }
        }
        fclose(fp);
    }
    
    /* Try to read DMI board serial */
    fp = fopen("/sys/class/dmi/id/board_serial", "r");
    if (fp) {
        if (fgets(dmi_serial, 256, fp)) {
            char* nl = strchr(dmi_serial, '\n');
            if (nl) *nl = '\0';
        }
        fclose(fp);
    }
    
    return 0;
}

/* Generate volume binding material */
int cortex_get_volume_binding(const char* path, uint8_t binding_id[32]) {
    if (!path || !binding_id) return -1;
    
    char uuid[256] = {0};
    char fs_uuid[256] = {0}; 
    char label[256] = {0};
    
    /* Get volume information */
    if (get_volume_info(path, uuid, fs_uuid, label) != 0) {
        return -1;
    }
    
    /* Prepare binding material */
    char binding_material[BINDING_MATERIAL_MAX];
    int len = snprintf(binding_material, sizeof(binding_material),
                      "VOLUME:%s:%s:%s", uuid, fs_uuid, label);
    
    if ((size_t)len >= sizeof(binding_material)) {
        return -1; /* Truncation */
    }
    
    /* Hash the binding material */
    SHA256((const uint8_t*)binding_material, len, binding_id);
    
    /* Secure cleanup */
    cc_secure_zero(binding_material, sizeof(binding_material));
    
    return 0;
}

/* Generate machine binding material */
int cortex_get_machine_binding(uint8_t binding_id[32]) {
    if (!binding_id) return -1;
    
    char machine_id[256] = {0};
    char cpu_brand[256] = {0};
    char dmi_serial[256] = {0};
    
    /* Get machine information */
    if (get_machine_info(machine_id, cpu_brand, dmi_serial) != 0) {
        return -1;
    }
    
    /* Prepare binding material */
    char binding_material[BINDING_MATERIAL_MAX];
    int len = snprintf(binding_material, sizeof(binding_material),
                      "MACHINE:%s:%s:%s", machine_id, cpu_brand, dmi_serial);
    
    if ((size_t)len >= sizeof(binding_material)) {
        return -1; /* Truncation */
    }
    
    /* Hash the binding material */
    SHA256((const uint8_t*)binding_material, len, binding_id);
    
    /* Secure cleanup */
    cc_secure_zero(binding_material, sizeof(binding_material));
    
    return 0;
}

/* Get binding ID based on policy */
int cortex_get_binding_id(int bind_policy, const char* context_path, uint8_t binding_id[32]) {
    if (!binding_id) return -1;
    
    if (bind_policy == CC_BIND_VOLUME) {
        const char* path = context_path ? context_path : "/";
        return cortex_get_volume_binding(path, binding_id);
    } else if (bind_policy == CC_BIND_MACHINE) {
        return cortex_get_machine_binding(binding_id);
    }
    
    return -1;
}

/* Verify binding matches current environment */
int cortex_verify_binding(const uint8_t expected_binding[32], int bind_policy, 
                         const char* context_path) {
    if (!expected_binding) return -1;
    
    uint8_t current_binding[32];
    if (cortex_get_binding_id(bind_policy, context_path, current_binding) != 0) {
        return -1;
    }
    
    int match = (memcmp(expected_binding, current_binding, 32) == 0);
    
    /* Secure cleanup */
    cc_secure_zero(current_binding, sizeof(current_binding));
    
    return match ? 0 : -1;
}

/* Get human-readable binding description */
int cortex_describe_binding(int bind_policy, const char* context_path, 
                           char* description, size_t desc_len) {
    if (!description || desc_len == 0) return -1;
    
    if (bind_policy == CC_BIND_VOLUME) {
        char uuid[256] = {0};
        char fs_uuid[256] = {0};
        char label[256] = {0};
        
        if (get_volume_info(context_path ? context_path : "/", uuid, fs_uuid, label) == 0) {
            snprintf(description, desc_len, "Volume: %s %s (%s)", 
                    label[0] ? label : "Unlabeled",
                    uuid[0] ? uuid : "No-UUID", 
                    fs_uuid[0] ? fs_uuid : "No-FS-UUID");
        } else {
            snprintf(description, desc_len, "Volume: Unknown");
        }
    } else if (bind_policy == CC_BIND_MACHINE) {
        char machine_id[256] = {0};
        char cpu_brand[256] = {0};
        char dmi_serial[256] = {0};
        
        if (get_machine_info(machine_id, cpu_brand, dmi_serial) == 0) {
            snprintf(description, desc_len, "Machine: %s", 
                    machine_id[0] ? machine_id : "Unknown");
        } else {
            snprintf(description, desc_len, "Machine: Unknown");
        }
    } else {
        snprintf(description, desc_len, "Unknown binding policy");
    }
    
    return 0;
}

/* Check if we're on a removable volume */
int cortex_is_removable_volume(const char* path) {
    if (!path) return 0;
    
    /* Check if path is on a removable device */
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    
    /* This is a simplified check - in practice would examine udev properties */
    FILE* fp = fopen("/proc/mounts", "r");
    if (!fp) return 0;
    
    char* line = NULL;
    size_t len = 0;
    int is_removable = 0;
    
    while (getline(&line, &len, fp) != -1) {
        char device[256], mount_point[256];
        if (sscanf(line, "%255s %255s", device, mount_point) == 2) {
            if (strncmp(path, mount_point, strlen(mount_point)) == 0) {
                /* Check if device starts with /dev/sd (USB) or similar */
                if (strncmp(device, "/dev/sd", 7) == 0 || 
                    strncmp(device, "/dev/nvme", 9) == 0) {
                    /* Additional check could examine /sys/block/device/removable */
                    is_removable = 1;
                }
                break;
            }
        }
    }
    
    free(line);
    fclose(fp);
    return is_removable;
}

/* Find the best path for volume binding (prefer removable volumes) */
int cortex_find_binding_path(char* best_path, size_t path_len) {
    if (!best_path || path_len == 0) return -1;
    
    /* Check current directory first */
    char cwd[512];
    if (getcwd(cwd, sizeof(cwd))) {
        if (cortex_is_removable_volume(cwd)) {
            strncpy(best_path, cwd, path_len - 1);
            best_path[path_len - 1] = '\0';
            return 0;
        }
    }
    
    /* Check common removable mount points */
    const char* candidates[] = {
        "/media",
        "/mnt", 
        "/run/media",
        cwd,
        "/"
    };
    
    for (size_t i = 0; i < sizeof(candidates)/sizeof(candidates[0]); i++) {
        if (cortex_is_removable_volume(candidates[i])) {
            strncpy(best_path, candidates[i], path_len - 1);
            best_path[path_len - 1] = '\0';
            return 0;
        }
    }
    
    /* Fall back to current working directory */
    if (cwd[0]) {
        strncpy(best_path, cwd, path_len - 1);
        best_path[path_len - 1] = '\0';
        return 0;
    }
    
    /* Ultimate fallback */
    strncpy(best_path, "/", path_len - 1);
    best_path[path_len - 1] = '\0';
    return 0;
}
