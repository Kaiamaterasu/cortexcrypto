/*
 * CortexCrypt Daemon Client Implementation
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "daemon_client.h"

#define DAEMON_SOCKET_PATH "/tmp/cortexd.sock"

/* Connect to daemon with timeout */
int daemon_connect(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    
    /* Set socket to non-blocking mode */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DAEMON_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    int result = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (result < 0 && errno == EINPROGRESS) {
        /* Connection in progress, wait for completion with timeout */
        fd_set writefds;
        struct timeval timeout;
        
        FD_ZERO(&writefds);
        FD_SET(fd, &writefds);
        timeout.tv_sec = 3; /* 3 second timeout */
        timeout.tv_usec = 0;
        
        result = select(fd + 1, NULL, &writefds, NULL, &timeout);
        if (result <= 0) {
            /* Timeout or error */
            close(fd);
            return -1;
        }
        
        /* Check if connection succeeded */
        int so_error;
        socklen_t len = sizeof(so_error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0 || so_error != 0) {
            close(fd);
            return -1;
        }
    } else if (result < 0) {
        close(fd);
        return -1;
    }
    
    /* Set socket back to blocking mode */
    fcntl(fd, F_SETFL, flags);
    
    /* Set socket timeouts */
    struct timeval timeout = {3, 0}; /* 3 seconds */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    return fd;
}

/* Send request and get response */
int daemon_request(int fd, const char* request, char* response, size_t response_len) {
    if (fd < 0 || !request || !response || response_len == 0) {
        return -1;
    }
    
    /* Send request */
    ssize_t sent = send(fd, request, strlen(request), 0);
    if (sent < 0) {
        return -1;
    }
    
    /* Receive response */
    ssize_t received = recv(fd, response, response_len - 1, 0);
    if (received < 0) {
        return -1;
    }
    
    response[received] = '\0';
    return 0;
}

/* Close daemon connection */
void daemon_disconnect(int fd) {
    if (fd >= 0) {
        close(fd);
    }
}
