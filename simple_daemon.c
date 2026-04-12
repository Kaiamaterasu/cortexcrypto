/*
 * Simple CortexCrypt Daemon - Minimal Version for Testing
 * Provides basic anomaly score without complex telemetry
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <errno.h>

#define SOCKET_PATH "/tmp/cortexd.sock"

static int running = 1;

void signal_handler(int sig) {
    printf("Received signal %d, shutting down\n", sig);
    running = 0;
}

void handle_request(int client_fd, const char* request) {
    char response[64];
    
    printf("Received request: %s\n", request);
    
    if (strncmp(request, "PING", 4) == 0) {
        strcpy(response, "PONG");
    } else if (strncmp(request, "GET_ANOMALY_SCORE", 17) == 0) {
        strcpy(response, "0.15");  // Return low, safe anomaly score
    } else if (strncmp(request, "GET_STATUS", 10) == 0) {
        strcpy(response, "daemon_pid=1234,uptime=100,anomaly_score=0.15");
    } else {
        strcpy(response, "UNKNOWN_COMMAND");
    }
    
    printf("Sending response: %s\n", response);
    send(client_fd, response, strlen(response), 0);
}

int main() {
    printf("Starting simple CortexCrypt daemon...\n");
    
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    
    // Create socket
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }
    
    // Remove existing socket
    unlink(SOCKET_PATH);
    
    // Bind socket
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }
    
    // Listen
    if (listen(server_fd, 5) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }
    
    printf("Daemon listening on %s\n", SOCKET_PATH);
    
    // Main loop
    while (running) {
        fd_set readfds;
        struct timeval timeout;
        
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(server_fd + 1, &readfds, NULL, NULL, &timeout);
        
        if (activity > 0 && FD_ISSET(server_fd, &readfds)) {
            int client_fd = accept(server_fd, NULL, NULL);
            if (client_fd >= 0) {
                char buffer[1024];
                ssize_t len = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
                if (len > 0) {
                    buffer[len] = '\0';
                    handle_request(client_fd, buffer);
                }
                close(client_fd);
            }
        }
    }
    
    close(server_fd);
    unlink(SOCKET_PATH);
    printf("Daemon shutdown complete\n");
    return 0;
}
