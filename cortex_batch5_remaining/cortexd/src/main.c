/*
 * CortexCrypt Daemon (cortexd)
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <syslog.h>

#include "daemon.h"
#include "telemetry.h"
#include "neural.h"

/* Global daemon state */
static daemon_ctx_t g_daemon;
static int g_running = 1;

/* Signal handler */
static void signal_handler(int sig) {
    switch (sig) {
    case SIGTERM:
    case SIGINT:
        syslog(LOG_INFO, "Received signal %d, shutting down", sig);
        g_running = 0;
        break;
    case SIGHUP:
        syslog(LOG_INFO, "Received SIGHUP, reloading configuration");
        /* TODO: Reload models if needed */
        break;
    }
}

/* Setup signal handlers */
static void setup_signals(void) {
    struct sigaction sa;
    
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    
    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);
}

/* Create UNIX socket server */
static int create_socket_server(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    /* Remove existing socket file */
    unlink(DAEMON_SOCKET_PATH);
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DAEMON_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "Failed to bind socket: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    /* Set socket permissions */
    chmod(DAEMON_SOCKET_PATH, 0666);
    
    if (listen(fd, 10) < 0) {
        syslog(LOG_ERR, "Failed to listen on socket: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    return fd;
}

/* Handle client request */
static void handle_client_request(int client_fd, const char* request) {
    char response[512] = {0};
    
    if (strncmp(request, "PING", 4) == 0) {
        strcpy(response, "PONG");
    } else if (strncmp(request, "GET_ANOMALY_SCORE", 17) == 0) {
        float score = daemon_get_anomaly_score(&g_daemon);
        snprintf(response, sizeof(response), "%.6f", score);
    } else if (strncmp(request, "GET_STATUS", 10) == 0) {
        snprintf(response, sizeof(response), 
                "daemon_pid=%d,uptime=%ld,anomaly_score=%.3f",
                getpid(), time(NULL) - g_daemon.start_time, 
                daemon_get_anomaly_score(&g_daemon));
    } else if (strncmp(request, "RELOAD_MODELS", 13) == 0) {
        if (daemon_reload_models(&g_daemon) == 0) {
            strcpy(response, "OK");
        } else {
            strcpy(response, "ERROR");
        }
    } else {
        strcpy(response, "UNKNOWN_COMMAND");
    }
    
    send(client_fd, response, strlen(response), 0);
}

/* Handle client connection */
static void* handle_client(void* arg) {
    int client_fd = *(int*)arg;
    free(arg);
    
    char buffer[1024];
    ssize_t recv_len = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    
    if (recv_len > 0) {
        buffer[recv_len] = '\0';
        handle_client_request(client_fd, buffer);
    }
    
    close(client_fd);
    return NULL;
}

/* Main daemon loop */
static void daemon_loop(void) {
    int server_fd = create_socket_server();
    if (server_fd < 0) {
        syslog(LOG_ERR, "Failed to create socket server");
        return;
    }
    
    syslog(LOG_INFO, "Daemon listening on %s", DAEMON_SOCKET_PATH);
    
    while (g_running) {
        fd_set readfds;
        struct timeval timeout;
        
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(server_fd + 1, &readfds, NULL, NULL, &timeout);
        
        if (activity < 0 && errno != EINTR) {
            syslog(LOG_ERR, "Select error: %s", strerror(errno));
            break;
        }
        
        if (activity > 0 && FD_ISSET(server_fd, &readfds)) {
            int client_fd = accept(server_fd, NULL, NULL);
            if (client_fd >= 0) {
                /* Handle client in separate thread */
                pthread_t thread;
                int* client_fd_ptr = malloc(sizeof(int));
                *client_fd_ptr = client_fd;
                
                if (pthread_create(&thread, NULL, handle_client, client_fd_ptr) == 0) {
                    pthread_detach(thread);
                } else {
                    close(client_fd);
                    free(client_fd_ptr);
                }
            }
        }
        
        /* Update telemetry */
        daemon_update_telemetry(&g_daemon);
    }
    
    close(server_fd);
    unlink(DAEMON_SOCKET_PATH);
    syslog(LOG_INFO, "Daemon shutdown complete");
}

/* Daemonize process */
static int daemonize(void) {
    pid_t pid = fork();
    
    if (pid < 0) {
        return -1;
    }
    
    /* Parent process exits */
    if (pid > 0) {
        exit(0);
    }
    
    /* Child becomes session leader */
    if (setsid() < 0) {
        return -1;
    }
    
    /* Fork again to prevent acquiring controlling terminal */
    pid = fork();
    if (pid < 0) {
        return -1;
    }
    
    if (pid > 0) {
        exit(0);
    }
    
    /* Change working directory */
    if (chdir("/") != 0) {
        /* Log error but continue */
    }
    
    /* Close standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    /* Redirect to /dev/null */
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);
    
    return 0;
}

/* Print usage */
static void print_usage(const char* program) {
    printf("CortexCrypt Daemon v1.0.0\n");
    printf("Usage: %s [options]\n\n", program);
    printf("Options:\n");
    printf("  -d, --daemon       Run as daemon (background)\n");
    printf("  -f, --foreground   Run in foreground\n");
    printf("  -m, --models <dir> Models directory (default: /usr/local/share/cortexcrypt/models)\n");
    printf("  -v, --verbose      Verbose logging\n");
    printf("  -h, --help         Show this help\n");
}

/* Main function */
int main(int argc, char** argv) {
    int daemon_mode = 1;
    int verbose = 0;
    const char* models_dir = "/usr/local/share/cortexcrypt/models";
    
    /* Parse command line */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--daemon") == 0) {
            daemon_mode = 1;
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--foreground") == 0) {
            daemon_mode = 0;
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--models") == 0) {
            if (i + 1 < argc) {
                models_dir = argv[++i];
            }
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    /* Initialize syslog */
    openlog("cortexd", LOG_PID | LOG_CONS, LOG_DAEMON);
    
    if (verbose) {
        setlogmask(LOG_UPTO(LOG_DEBUG));
    } else {
        setlogmask(LOG_UPTO(LOG_INFO));
    }
    
    syslog(LOG_INFO, "CortexCrypt daemon starting");
    
    /* Initialize daemon context */
    if (daemon_init(&g_daemon, models_dir) != 0) {
        syslog(LOG_ERR, "Failed to initialize daemon");
        return 1;
    }
    
    /* Setup signal handlers */
    setup_signals();
    
    /* Daemonize if requested */
    if (daemon_mode) {
        if (daemonize() != 0) {
            syslog(LOG_ERR, "Failed to daemonize");
            daemon_cleanup(&g_daemon);
            return 1;
        }
    }
    
    /* Write PID file */
    FILE* pid_fp = fopen("/run/cortexd.pid", "w");
    if (pid_fp) {
        fprintf(pid_fp, "%d\n", getpid());
        fclose(pid_fp);
    }
    
    syslog(LOG_INFO, "Daemon initialized, PID %d", getpid());
    
    /* Main daemon loop */
    daemon_loop();
    
    /* Cleanup */
    daemon_cleanup(&g_daemon);
    unlink("/run/cortexd.pid");
    closelog();
    
    return 0;
}
