/*
# Copyright 2022 University of California, Riverside
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
*/

#ifndef IO_H
#define IO_H

#include <fcntl.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "common.h"
#include "http.h"
#include "log.h"
#include "spright.h"

#define MAX_TENANTS (1U << 8)
#define N_EVENTS_MAX (1U << 17)

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct
{
    int fd[2]; // 0: read end, 1: write end
    int weight;
    uint32_t tenant_id;
} tenant_pipe;

extern tenant_pipe tenant_pipes[MAX_TENANTS];

// pass in the nf_id, doesn't need to assign value to global value fn_id in common.h
// return the skt when use skt
// skt is no use in rte_ring case
int new_io_init(uint8_t nf_id, int* skt);
int io_init(void);
int new_io_exit(uint8_t current_fn);
int io_exit(void);
int new_io_rx(uint8_t current_fn, void **obj);
int io_rx(void **obj);
int new_io_tx(uint8_t current_fn, void *obj, uint8_t next_fn);
int io_tx(void *obj, uint8_t next_fn);

int get_gcd_weight(void);
int get_max_weight(void);

int init_tenant_pipes(void);
int write_pipe(struct http_transaction *txn);
struct http_transaction *read_pipe(tenant_pipe *tp);
int add_regular_pipe_to_epoll(int epoll_fd, struct epoll_event *ev, int pipe_fd);
int add_weighted_pipes_to_epoll(int epoll_fd, struct epoll_event *ev);

int set_nonblocking(int fd);
ssize_t read_full(int fd, void *buf, size_t count);
int get_client_info(int client_socket, char *ip_addr, int ip_addr_len);
int create_server_socket(const char *ip, int port);
void configure_keepalive(int sockfd);

int retry_connect(int sockfd, struct sockaddr *addr);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* IO_H */
