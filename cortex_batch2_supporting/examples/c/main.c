/*
 * CortexCrypt C Example
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cortexcrypt.h>

/* Create a test file */
static int create_test_file(const char* path, const char* content) {
    FILE* fp = fopen(path, "w");
    if (!fp) {
        perror("Failed to create test file");
        return -1;
    }
    
    fprintf(fp, "%s", content);
    fclose(fp);
    
    return 0;
}

/* Read and display file content */
static void display_file(const char* path) {
    FILE* fp = fopen(path, "r");
    if (!fp) {
        perror("Failed to open file");
        return;
    }
    
    char buffer[1024];
    printf("File content (%s):\n", path);
    while (fgets(buffer, sizeof(buffer), fp)) {
        printf("  %s", buffer);
    }
    printf("\n");
    
    fclose(fp);
}

int main(void) {
    printf("CortexCrypt C Example\n");
    printf("====================\n\n");
    
    /* Initialize library */
    if (cc_init() != CC_OK) {
        fprintf(stderr, "Failed to initialize CortexCrypt\n");
        return 1;
    }
    
    /* Open context */
    cc_ctx_t* ctx = cc_open();
    if (!ctx) {
        fprintf(stderr, "Failed to open CortexCrypt context\n");
        cc_cleanup();
        return 1;
    }
    
    /* Set passphrase */
    const char* passphrase = "demo-passphrase-42";
    if (cc_set_passphrase(ctx, passphrase, strlen(passphrase)) != CC_OK) {
        fprintf(stderr, "Failed to set passphrase: %s\n", cc_get_error(ctx));
        cc_close(ctx);
        cc_cleanup();
        return 1;
    }
    
    printf("✓ CortexCrypt initialized with passphrase\n");
    
    /* Create test file */
    const char* test_content = "Hello, CortexCrypt!\nThis is a test of neural-augmented encryption.\nThe file is bound to this environment.\n";
    
    if (create_test_file("demo.txt", test_content) != 0) {
        cc_close(ctx);
        cc_cleanup();
        return 1;
    }
    
    printf("✓ Created test file\n");
    display_file("demo.txt");
    
    /* Encrypt file */
    printf("Encrypting file...\n");
    int encrypt_result = cc_encrypt_file(ctx, "demo.txt", "demo.cortex", 
                                        "aes", CC_BIND_VOLUME, "C SDK demo");
    
    if (encrypt_result != CC_OK) {
        fprintf(stderr, "Encryption failed: %s\n", cc_get_error(ctx));
        unlink("demo.txt");
        cc_close(ctx);
        cc_cleanup();
        return encrypt_result;
    }
    
    printf("✓ File encrypted to demo.cortex\n");
    
    /* Show file info */
    printf("\nFile information:\n");
    cc_file_info_t info;
    if (cc_info(ctx, "demo.cortex", &info) == CC_OK) {
        printf("  Format version: %d\n", info.version);
        printf("  Cipher: %s\n", (info.cipher_id == CC_CIPHER_AES256_GCM) ? "AES-256-GCM" : "Unknown");
        printf("  Binding: %s\n", (info.flags & CC_FLAG_BIND_VOLUME) ? "Volume" : "Machine");
        printf("  Header size: %d bytes\n", info.header_len);
        printf("  Ciphertext size: %zu bytes\n", info.ciphertext_size);
        
        if (info.file_meta_json) {
            printf("  Metadata: %s\n", info.file_meta_json);
        }
        if (info.note) {
            printf("  Note: %s\n", info.note);
        }
        
        cc_free_info(&info);
    }
    
    /* Verify file */
    printf("\nVerifying file integrity...\n");
    if (cc_verify(ctx, "demo.cortex") == CC_OK) {
        printf("✓ File integrity verified\n");
    } else {
        fprintf(stderr, "✗ File verification failed: %s\n", cc_get_error(ctx));
    }
    
    /* Decrypt file */
    printf("\nDecrypting file...\n");
    int decrypt_result = cc_decrypt_file(ctx, "demo.cortex", "demo_decrypted.txt");
    
    if (decrypt_result != CC_OK) {
        fprintf(stderr, "Decryption failed: %s\n", cc_get_error(ctx));
        unlink("demo.txt");
        unlink("demo.cortex");
        cc_close(ctx);
        cc_cleanup();
        return decrypt_result;
    }
    
    printf("✓ File decrypted to demo_decrypted.txt\n");
    display_file("demo_decrypted.txt");
    
    /* Verify content matches */
    FILE* orig = fopen("demo.txt", "r");
    FILE* decrypted = fopen("demo_decrypted.txt", "r");
    
    if (orig && decrypted) {
        char orig_buf[1024], dec_buf[1024];
        size_t orig_len = fread(orig_buf, 1, sizeof(orig_buf), orig);
        size_t dec_len = fread(dec_buf, 1, sizeof(dec_buf), decrypted);
        
        if (orig_len == dec_len && memcmp(orig_buf, dec_buf, orig_len) == 0) {
            printf("✓ Decrypted content matches original\n");
        } else {
            printf("✗ Decrypted content does not match original\n");
        }
        
        fclose(orig);
        fclose(decrypted);
    }
    
    /* Check daemon status */
    printf("\nDaemon status: %s\n", cc_daemon_status() ? "Running" : "Stopped");
    
    /* Show binding information */
    uint8_t binding_id[32];
    if (cc_get_binding_id(CC_BIND_VOLUME, binding_id) == CC_OK) {
        printf("Volume binding ID: ");
        for (int i = 0; i < 8; i++) {
            printf("%02x", binding_id[i]);
        }
        printf("...\n");
    }
    
    /* Cleanup */
    printf("\nCleaning up...\n");
    unlink("demo.txt");
    unlink("demo.cortex");
    unlink("demo_decrypted.txt");
    
    cc_close(ctx);
    cc_cleanup();
    
    printf("\n✓ CortexCrypt C example completed successfully\n");
    printf("\nKey points demonstrated:\n");
    printf("- File encryption with volume binding\n");
    printf("- Neural network augmented key derivation\n");
    printf("- AEAD encryption (AES-256-GCM)\n");
    printf("- Secure passphrase handling\n");
    printf("- File format with metadata\n");
    
    return 0;
}
