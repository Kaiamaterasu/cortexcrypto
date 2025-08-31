/*
 * CortexCrypt CLI Tool
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <termios.h>
#include <sys/stat.h>

#include <cortexcrypt.h>

#define VERSION "1.0.0"

/* CLI state */
typedef struct {
    const char* command;
    const char* input_file;
    const char* output_file;
    const char* cipher;
    const char* bind_policy_str;
    const char* note;
    const char* admin_token;
    int bind_policy;
    int no_password;
    int verbose;
    int help;
} cli_args_t;

/* Print usage */
static void print_usage(const char* program) {
    printf("CortexCrypt v%s - Zero-cost, offline, NN-augmented encryption\n\n", VERSION);
    printf("Usage: %s <command> [options]\n\n", program);
    
    printf("Commands:\n");
    printf("  encrypt     Encrypt file to .cortex format\n");
    printf("  decrypt     Decrypt .cortex file\n");
    printf("  info        Show file information (metadata only)\n");
    printf("  verify      Verify file integrity\n");
    printf("  rebind      Change binding policy (admin operation)\n");
    printf("\n");
    
    printf("Encrypt options:\n");
    printf("  --in <file>        Input file path\n");
    printf("  --out <file>       Output .cortex file path\n");
    printf("  --cipher <type>    Cipher: aes (default) or xchacha\n");
    printf("  --bind <policy>    Binding: volume (default) or machine\n");
    printf("  --note <text>      Optional note\n");
    printf("  --no-pass          Use device binding only (no passphrase)\n");
    printf("\n");
    
    printf("Decrypt options:\n");
    printf("  --in <file>        Input .cortex file path\n");
    printf("  --out <file>       Output file path\n");
    printf("\n");
    
    printf("Info/Verify options:\n");
    printf("  --in <file>        Input .cortex file path\n");
    printf("\n");
    
    printf("Rebind options:\n");
    printf("  --in <file>        Input .cortex file path\n");
    printf("  --to <policy>      New binding policy (volume or machine)\n");
    printf("  --admin-token <t>  Admin token for authorization\n");
    printf("\n");
    
    printf("Global options:\n");
    printf("  -v, --verbose      Verbose output\n");
    printf("  -h, --help         Show this help\n");
    printf("\n");
    
    printf("Examples:\n");
    printf("  %s encrypt --in hash.txt --out hash.cortex --bind volume\n", program);
    printf("  %s decrypt --in hash.cortex --out hash.txt\n", program);
    printf("  %s info --in crypto.cortex\n", program);
    printf("\n");
    
    printf("Return codes:\n");
    printf("  0  Success\n");
    printf("  2  Binding mismatch\n");
    printf("  3  File corrupted\n");
    printf("  4  File locked\n");
    printf("  5  Authentication required\n");
}

/* Print cortexctl usage */
static void print_cortexctl_usage(const char* program) {
    printf("CortexCtl v%s - CortexCrypt Management Tool\n\n", VERSION);
    printf("Usage: %s <command>\n\n", program);
    
    printf("Commands:\n");
    printf("  status      Show daemon and system status\n");
    printf("  uninstall   Securely remove CortexCrypt (requires authentication)\n");
    printf("\n");
    
    printf("Examples:\n");
    printf("  %s status\n", program);
    printf("  %s uninstall\n", program);
}

/* Secure password input */
static int read_password(char* buffer, size_t buffer_size) {
    struct termios old_termios, new_termios;
    
    /* Disable echo */
    if (tcgetattr(STDIN_FILENO, &old_termios) != 0) {
        return -1;
    }
    
    new_termios = old_termios;
    new_termios.c_lflag &= ~ECHO;
    
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_termios) != 0) {
        return -1;
    }
    
    printf("Passphrase: ");
    fflush(stdout);
    
    /* Read password */
    if (!fgets(buffer, buffer_size, stdin)) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_termios);
        return -1;
    }
    
    /* Restore terminal */
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_termios);
    printf("\n");
    
    /* Remove newline */
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }
    
    return 0;
}

/* Parse command line arguments */
static int parse_args(int argc, char** argv, cli_args_t* args) {
    memset(args, 0, sizeof(*args));
    
    if (argc < 2) {
        return -1;
    }
    
    args->command = argv[1];
    
    /* Default values */
    args->bind_policy = CC_BIND_VOLUME;
    args->bind_policy_str = "volume";
    
    static struct option long_options[] = {
        {"in",          required_argument, 0, 'i'},
        {"out",         required_argument, 0, 'o'},
        {"cipher",      required_argument, 0, 'c'},
        {"bind",        required_argument, 0, 'b'},
        {"to",          required_argument, 0, 't'},
        {"note",        required_argument, 0, 'n'},
        {"admin-token", required_argument, 0, 'a'},
        {"no-pass",     no_argument,       0, 'p'},
        {"verbose",     no_argument,       0, 'v'},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    optind = 2; /* Skip program name and command */
    
    while ((opt = getopt_long(argc, argv, "i:o:c:b:t:n:a:pvh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            args->input_file = optarg;
            break;
        case 'o':
            args->output_file = optarg;
            break;
        case 'c':
            args->cipher = optarg;
            break;
        case 'b':
            args->bind_policy_str = optarg;
            if (strcmp(optarg, "volume") == 0) {
                args->bind_policy = CC_BIND_VOLUME;
            } else if (strcmp(optarg, "machine") == 0) {
                args->bind_policy = CC_BIND_MACHINE;
            } else {
                fprintf(stderr, "Invalid bind policy: %s\n", optarg);
                return -1;
            }
            break;
        case 't':
            args->bind_policy_str = optarg;
            if (strcmp(optarg, "volume") == 0) {
                args->bind_policy = CC_BIND_VOLUME;
            } else if (strcmp(optarg, "machine") == 0) {
                args->bind_policy = CC_BIND_MACHINE;
            } else {
                fprintf(stderr, "Invalid target policy: %s\n", optarg);
                return -1;
            }
            break;
        case 'n':
            args->note = optarg;
            break;
        case 'a':
            args->admin_token = optarg;
            break;
        case 'p':
            args->no_password = 1;
            break;
        case 'v':
            args->verbose = 1;
            break;
        case 'h':
            args->help = 1;
            break;
        default:
            return -1;
        }
    }
    
    return 0;
}

/* Command: encrypt */
static int cmd_encrypt(const cli_args_t* args) {
    if (!args->input_file || !args->output_file) {
        fprintf(stderr, "Error: --in and --out required for encrypt\n");
        return 1;
    }
    
    /* Check input file exists */
    if (access(args->input_file, R_OK) != 0) {
        fprintf(stderr, "Error: Cannot read input file: %s\n", args->input_file);
        return 1;
    }
    
    /* Open CortexCrypt context */
    cc_ctx_t* ctx = cc_open();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to initialize CortexCrypt\n");
        return 1;
    }
    
    /* Set passphrase if not using --no-pass */
    if (!args->no_password) {
        char password[256];
        if (read_password(password, sizeof(password)) != 0) {
            fprintf(stderr, "Error: Failed to read passphrase\n");
            cc_close(ctx);
            return 1;
        }
        
        if (cc_set_passphrase(ctx, password, strlen(password)) != CC_OK) {
            fprintf(stderr, "Error: Failed to set passphrase\n");
            memset(password, 0, sizeof(password));
            cc_close(ctx);
            return 1;
        }
        
        memset(password, 0, sizeof(password));
    }
    
    if (args->verbose) {
        printf("Encrypting %s -> %s\n", args->input_file, args->output_file);
        printf("Cipher: %s\n", args->cipher ? args->cipher : "aes");
        printf("Binding: %s\n", args->bind_policy_str);
        if (args->note) printf("Note: %s\n", args->note);
    }
    
    /* Encrypt file */
    int result = cc_encrypt_file(ctx, args->input_file, args->output_file,
                                args->cipher, args->bind_policy, args->note);
    
    if (result != CC_OK) {
        fprintf(stderr, "Encryption failed: %s\n", cc_get_error(ctx));
        cc_close(ctx);
        return result;
    }
    
    if (args->verbose) {
        printf("Encryption successful\n");
        
        /* Show file size comparison */
        size_t orig_size = cc_file_size(args->input_file);
        size_t encrypted_size = cc_file_size(args->output_file);
        printf("Original size: %zu bytes\n", orig_size);
        printf("Encrypted size: %zu bytes\n", encrypted_size);
        printf("Overhead: %zu bytes\n", encrypted_size - orig_size);
    } else {
        printf("Encrypted: %s\n", args->output_file);
    }
    
    cc_close(ctx);
    return 0;
}

/* Command: decrypt */
static int cmd_decrypt(const cli_args_t* args) {
    if (!args->input_file || !args->output_file) {
        fprintf(stderr, "Error: --in and --out required for decrypt\n");
        return 1;
    }
    
    /* Check input file exists */
    if (access(args->input_file, R_OK) != 0) {
        fprintf(stderr, "Error: Cannot read input file: %s\n", args->input_file);
        return 1;
    }
    
    /* Open CortexCrypt context */
    cc_ctx_t* ctx = cc_open();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to initialize CortexCrypt\n");
        return 1;
    }
    
    /* Read passphrase */
    char password[256];
    if (read_password(password, sizeof(password)) != 0) {
        fprintf(stderr, "Error: Failed to read passphrase\n");
        cc_close(ctx);
        return 1;
    }
    
    if (cc_set_passphrase(ctx, password, strlen(password)) != CC_OK) {
        fprintf(stderr, "Error: Failed to set passphrase\n");
        memset(password, 0, sizeof(password));
        cc_close(ctx);
        return 1;
    }
    
    memset(password, 0, sizeof(password));
    
    if (args->verbose) {
        printf("Decrypting %s -> %s\n", args->input_file, args->output_file);
    }
    
    /* Decrypt file */
    int result = cc_decrypt_file(ctx, args->input_file, args->output_file);
    
    if (result != CC_OK) {
        fprintf(stderr, "Decryption failed: %s\n", cc_get_error(ctx));
        cc_close(ctx);
        return result;
    }
    
    if (args->verbose) {
        printf("Decryption successful\n");
        size_t size = cc_file_size(args->output_file);
        printf("Decrypted size: %zu bytes\n", size);
    } else {
        printf("Decrypted: %s\n", args->output_file);
    }
    
    cc_close(ctx);
    return 0;
}

/* Command: info */
static int cmd_info(const cli_args_t* args) {
    if (!args->input_file) {
        fprintf(stderr, "Error: --in required for info\n");
        return 1;
    }
    
    /* Open CortexCrypt context */
    cc_ctx_t* ctx = cc_open();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to initialize CortexCrypt\n");
        return 1;
    }
    
    /* Get file info */
    cc_file_info_t info;
    int result = cc_info(ctx, args->input_file, &info);
    
    if (result != CC_OK) {
        fprintf(stderr, "Failed to read file info: %s\n", cc_get_error(ctx));
        cc_close(ctx);
        return result;
    }
    
    /* Display information */
    printf("CortexCrypt File Information\n");
    printf("File: %s\n", args->input_file);
    printf("Format version: %d\n", info.version);
    printf("Cipher: %s\n", cortex_cipher_name(info.cipher_id));
    
    /* Binding info */
    printf("Binding: ");
    if (info.flags & CC_FLAG_BIND_VOLUME) {
        printf("Volume");
    } else if (info.flags & CC_FLAG_BIND_MACHINE) {
        printf("Machine");
    } else {
        printf("Unknown");
    }
    
    if (info.flags & CC_FLAG_DISALLOW_COPY) {
        printf(" (Copy Disallowed)");
    }
    if (info.flags & CC_FLAG_LOCK_IF_MISMATCH) {
        printf(" (Lock on Mismatch)");
    }
    printf("\n");
    
    printf("Header size: %d bytes\n", info.header_len);
    printf("Ciphertext size: %zu bytes\n", info.ciphertext_size);
    
    /* Show metadata if available */
    if (info.file_meta_json) {
        printf("Metadata: %s\n", info.file_meta_json);
    }
    
    if (info.note) {
        printf("Note: %s\n", info.note);
    }
    
    /* Show binding description */
    char binding_desc[512];
    int bind_policy = (info.flags & CC_FLAG_BIND_VOLUME) ? CC_BIND_VOLUME : CC_BIND_MACHINE;
    if (cortex_describe_binding(bind_policy, args->input_file, binding_desc, sizeof(binding_desc)) == 0) {
        printf("Current %s\n", binding_desc);
    }
    
    cc_free_info(&info);
    cc_close(ctx);
    return 0;
}

/* Command: verify */
static int cmd_verify(const cli_args_t* args) {
    if (!args->input_file) {
        fprintf(stderr, "Error: --in required for verify\n");
        return 1;
    }
    
    /* Open CortexCrypt context */
    cc_ctx_t* ctx = cc_open();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to initialize CortexCrypt\n");
        return 1;
    }
    
    if (args->verbose) {
        printf("Verifying %s\n", args->input_file);
    }
    
    /* Verify file */
    int result = cc_verify(ctx, args->input_file);
    
    if (result == CC_OK) {
        printf("Verification successful\n");
    } else {
        fprintf(stderr, "Verification failed: %s\n", cc_get_error(ctx));
    }
    
    cc_close(ctx);
    return result;
}

/* Command: status (cortexctl) */
static int cmd_status(void) {
    printf("CortexCrypt System Status\n");
    printf("========================\n");
    
    /* Check daemon */
    int daemon_running = cc_daemon_status();
    printf("Daemon (cortexd): %s\n", daemon_running ? "Running" : "Stopped");
    
    /* Check library */
    printf("Library version: %s\n", cc_version());
    printf("Supported ciphers: %s\n", cc_supported_ciphers());
    
    /* Check models */
    printf("Models directory: /usr/local/share/cortexcrypt/models\n");
    printf("KDF MLP model: %s\n", 
           access("/usr/local/share/cortexcrypt/models/kdf_mlp.onnx", R_OK) == 0 ? "Present" : "Missing");
    printf("Anomaly model: %s\n",
           access("/usr/local/share/cortexcrypt/models/anomaly_autoencoder.onnx", R_OK) == 0 ? "Present" : "Missing");
    
    /* Check current binding */
    uint8_t binding_id[32];
    if (cc_get_binding_id(CC_BIND_VOLUME, binding_id) == 0) {
        char hex[65];
        cc_bytes_to_hex(binding_id, 32, hex);
        printf("Volume binding ID: %s\n", hex);
    }
    
    if (cc_get_binding_id(CC_BIND_MACHINE, binding_id) == 0) {
        char hex[65];
        cc_bytes_to_hex(binding_id, 32, hex);
        printf("Machine binding ID: %s\n", hex);
    }
    
    return daemon_running ? 0 : 1;
}

/* Command: uninstall (cortexctl) */
static int cmd_uninstall(void) {
    printf("CortexCrypt Secure Uninstall\n");
    printf("============================\n");
    printf("WARNING: This will permanently remove CortexCrypt from your system.\n");
    printf("All .cortex files will become permanently inaccessible.\n\n");
    
    printf("Enter 'CONFIRM UNINSTALL' to proceed: ");
    char confirmation[64];
    if (!fgets(confirmation, sizeof(confirmation), stdin)) {
        printf("\nUninstall cancelled.\n");
        return 1;
    }
    
    /* Remove newline */
    char* nl = strchr(confirmation, '\n');
    if (nl) *nl = '\0';
    
    if (strcmp(confirmation, "CONFIRM UNINSTALL") != 0) {
        printf("Uninstall cancelled.\n");
        return 1;
    }
    
    /* Read admin passphrase */
    char admin_pass[256];
    printf("\nAdmin passphrase: ");
    if (read_password(admin_pass, sizeof(admin_pass)) != 0) {
        fprintf(stderr, "Failed to read admin passphrase\n");
        return 1;
    }
    
    /* Execute uninstall script */
    printf("\nExecuting secure uninstall...\n");
    int result = system("sudo /usr/local/bin/cortex-uninstall");
    
    memset(admin_pass, 0, sizeof(admin_pass));
    
    if (result == 0) {
        printf("CortexCrypt has been securely removed.\n");
    } else {
        fprintf(stderr, "Uninstall failed or was cancelled.\n");
    }
    
    return result;
}

/* Main function */
int main(int argc, char** argv) {
    cli_args_t args;
    
    /* Handle cortexctl commands */
    const char* program = argv[0];
    if (strstr(program, "cortexctl")) {
        if (argc < 2) {
            print_cortexctl_usage(program);
            return 1;
        }
        
        if (strcmp(argv[1], "status") == 0) {
            return cmd_status();
        } else if (strcmp(argv[1], "uninstall") == 0) {
            return cmd_uninstall();
        } else {
            fprintf(stderr, "Unknown cortexctl command: %s\n", argv[1]);
            print_cortexctl_usage(program);
            return 1;
        }
    }
    
    /* Parse arguments */
    if (parse_args(argc, argv, &args) != 0) {
        print_usage(program);
        return 1;
    }
    
    if (args.help) {
        print_usage(program);
        return 0;
    }
    
    /* Set verbose logging */
    if (args.verbose) {
        cc_set_log_level(CC_LOG_INFO);
    }
    
    /* Execute command */
    if (strcmp(args.command, "encrypt") == 0) {
        return cmd_encrypt(&args);
    } else if (strcmp(args.command, "decrypt") == 0) {
        return cmd_decrypt(&args);
    } else if (strcmp(args.command, "info") == 0) {
        return cmd_info(&args);
    } else if (strcmp(args.command, "verify") == 0) {
        return cmd_verify(&args);
    } else {
        fprintf(stderr, "Unknown command: %s\n", args.command);
        print_usage(program);
        return 1;
    }
}
