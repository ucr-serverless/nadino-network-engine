#ifndef SOCK_H_
#define SOCK_H_

#include <inttypes.h>
#include <stdlib.h>

#define SOCK_SYNC_MSG "sync"

ssize_t sock_utils_read(int sock_fd, void *buffer, size_t len);
ssize_t sock_utils_write(int sock_fd, void *buffer, size_t len);

int sock_utils_bind(char *port);
int sock_utils_connect(char *server_name, char *port);

#endif /* SOCK_H_ */
