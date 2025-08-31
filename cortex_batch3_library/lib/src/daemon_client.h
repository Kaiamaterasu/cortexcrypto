/*
 * CortexCrypt Daemon Client Header
 * Copyright 2024 CortexCrypt Contributors
 * Licensed under Apache 2.0
 */

#ifndef DAEMON_CLIENT_H
#define DAEMON_CLIENT_H

#include <stddef.h>

/* Function declarations */
int daemon_connect(void);
int daemon_request(int fd, const char* request, char* response, size_t response_len);
void daemon_disconnect(int fd);

#endif /* DAEMON_CLIENT_H */
