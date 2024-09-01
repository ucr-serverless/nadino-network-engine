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

#include "control_server.h"
#include "RDMA_utils.h"
#include "bitmap.h"
#include "c_lib.h"
#include "c_map.h"
#include "http.h"
#include "ib.h"
#include "log.h"
#include "rdma_config.h"
#include "sock_utils.h"
#include <generic/rte_spinlock.h>
#include <stdint.h>
#include <sys/epoll.h>

int destroy_control_server_socks()
{
    if (!cfg->control_server_socks)
    {
        return 0;
    }
    for (size_t i = 0; i < cfg->n_nodes; i++)
    {
        if (cfg->control_server_socks[i])
        {
            close(cfg->control_server_socks[i]);
        }
    }
    return 0;
}

int control_server_socks_init()
{
    cfg->control_server_socks = (int *)calloc(cfg->n_nodes, sizeof(int));

    if (unlikely(cfg->control_server_socks == NULL))
    {
        log_error("allocate control server fd fail");
        goto error;
    }
    int ret = 0;
    uint32_t node_num = cfg->n_nodes;
    uint32_t self_idx = cfg->local_node_idx;
    char buffer[6];
    int sock_fd = -1;
    uint32_t connected_nodes = 0;
    for (size_t i = 0; i < self_idx; i++)
    {
        sprintf(buffer, "%u", cfg->nodes[i].control_server_port);

        do
        {
            sock_fd = sock_utils_connect(cfg->nodes[i].ip_address, buffer);

        } while (sock_fd <= 0);

        log_info("Connected to server: %s: %s", cfg->nodes[i].ip_address, buffer);
        cfg->control_server_socks[i] = sock_fd;
        connected_nodes++;
    }
    log_info("connected to all servers with idx lower than %d", self_idx);
    if (connected_nodes == node_num - 1)
    {
        return 0;
    }
    sprintf(buffer, "%u", cfg->nodes[self_idx].control_server_port);
    int bind_fd = sock_utils_bind(buffer);
    if (bind_fd <= 0)
    {
        log_error("failed to open listen socket");
        return -1;
    }
    listen(bind_fd, 10);
    int peer_fd = 0;
    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len = sizeof(struct sockaddr_in);
    char client_ip[INET_ADDRSTRLEN];
    log_info("accepting connections from other nodes");
    while (connected_nodes < node_num - 1)
    {
        peer_fd = accept(bind_fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (peer_fd < 0)
        {
            continue;
        }
        inet_ntop(AF_INET, &peer_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        log_info("client ip %s connected", client_ip);
        for (size_t i = self_idx + 1; i < node_num; i++)
        {
            if (strcmp(cfg->nodes[i].ip_address, client_ip) == 0)
            {
                cfg->control_server_socks[i] = peer_fd;
                connected_nodes++;
            }
        }
    }
    cfg->control_server_socks[self_idx] = 0;
    log_info("control_server_socks initialized");
    close(bind_fd);

    int keepalive = 1;

    for (size_t i = 0; i < node_num; i++)
    {
        if (cfg->control_server_socks[i])
        {
            ret = setsockopt(cfg->control_server_socks[i], SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
            if (ret < 0)
            {
                log_fatal("setsockopt(TCP_KEEPIDLE) control server");
                goto error;
            }
            ret = set_socket_nonblocking(cfg->control_server_socks[i]);
            if (ret < 0)
            {
                log_fatal("set sock non_blocking fail");
                goto error;
            }
        }
    }

    return 0;
error:
    destroy_control_server_socks();
    return -1;
}

int exchange_rdma_info()
{
    int ret = 0;
    uint32_t local_idx = cfg->local_node_idx;
    uint32_t node_num = cfg->n_nodes;
    ret = init_local_ib_res(&(cfg->rdma_ctx), &(cfg->node_res[local_idx].ibres));
    for (size_t i = 0; i < node_num; i++)
    {
        if (i == local_idx)
        {
            continue;
        }
        if (i < local_idx)
        {
            ret = send_ib_res(&(cfg->node_res[local_idx].ibres), cfg->control_server_socks[i]);
            if (ret != RDMA_SUCCESS)
            {
                log_error("send res to node idx %d failed", i);
                goto error;
            }
            log_debug("local ibres sent to node %u", i);
            ret = recv_ib_res(&(cfg->node_res[i].ibres), cfg->control_server_socks[i]);
            if (ret != RDMA_SUCCESS)
            {
                log_error("recv res from node idx %d failed", i);
                goto error;
            }
            log_debug("remote ibres recv from node %u", i);
        }
        if (i > local_idx)
        {
            ret = recv_ib_res(&(cfg->node_res[i].ibres), cfg->control_server_socks[i]);
            if (ret != RDMA_SUCCESS)
            {
                log_error("recv res from node idx %d failed", i);
                goto error;
            }
            log_debug("remote ibres recv from node %u", i);
            ret = send_ib_res(&(cfg->node_res[local_idx].ibres), cfg->control_server_socks[i]);
            if (ret != RDMA_SUCCESS)
            {
                log_error("send res to node idx %d failed", i);
                goto error;
            }
            log_debug("local ibres sent to node %u", i);
        }
    }
    log_debug("finished exchange information with all nodes");
    for (size_t i = 0; i < node_num; i++)
    {
        ret = rdma_node_res_init(&(cfg->node_res[i].ibres), &(cfg->node_res[i]));
        if (ret != RDMA_SUCCESS)
        {
            log_error("recv res from node idx %d failed", i);
            goto error;
        }
        print_ib_res(&(cfg->node_res[i].ibres));
    }
    for (size_t i = 0; i < cfg->node_res[local_idx].n_qp; i++)
    {
        cfg->node_res[local_idx].qpres[i].qp = cfg->rdma_ctx.qps[i];
    }
    return 0;
error:
    return -1;
}

int control_server_ep_init(int *epfd)
{
    int ret = 0;
    struct epoll_event event;
    uint32_t node_num = cfg->n_nodes;
    uint32_t self_idx = cfg->local_node_idx;

    *epfd = epoll_create1(0);
    if (unlikely(*epfd == -1))
    {
        log_error("epoll_create1() error: %s", strerror(errno));
        return -1;
    }
    size_t i = 0;
    for (; i < node_num; i++)
    {
        if (i == self_idx)
        {
            continue;
        }
        event.events = EPOLLIN;
        event.data.fd = cfg->control_server_socks[i];
        ret = epoll_ctl(*epfd, EPOLL_CTL_ADD, cfg->control_server_socks[i], &event);
        if (unlikely(ret == -1))
        {
            log_error("epoll_ctl() error: %s", strerror(errno));
            goto error;
        }
    }

    return 0;
error:
    for (size_t j = 0; j < i; j++)
    {
        if (j == self_idx)
        {
            continue;
        }
        ret = epoll_ctl(*epfd, EPOLL_CTL_DEL, cfg->control_server_socks[i], NULL);
        if (unlikely(ret == -1))
        {
            log_error("epoll_ctl() error: %s", strerror(errno));
            return -1;
        }

        ret = close(*epfd);
    }
    return -1;
}

int process_control_server_msg(struct control_server_msg *msg)
{

    uint32_t source_node_idx = msg->source_node_idx;
    struct rdma_node_res *remote_node_res = NULL;
    struct qp_res *remote_qp_res = NULL;
    int ret = 0;
    uint32_t slot_idx = 0;
    uint32_t n_slot = 0;
    if (msg->msg_t == REALEASE)
    {
        log_debug("recv relaease msg from node %u, qp %u", msg->source_node_idx, msg->source_qp_num);
        remote_node_res = &cfg->node_res[source_node_idx];
        ret = qp_num_to_qp_res(remote_node_res, msg->source_qp_num, &remote_qp_res);
        if (ret != RDMA_SUCCESS)
        {
            log_error("remote qp num invalid");
            goto error;
        }
        slot_idx = msg->slot_idx;
        log_debug("slot idx is %u", slot_idx);
        n_slot = msg->n_slot;
        log_debug("release slot start %u, len %u", slot_idx, n_slot);

        do
        {
            ret = rte_spinlock_trylock(&remote_qp_res->lock);

        } while (ret != 1);
        ret = bitmap_clear_consecutive(remote_qp_res->mr_bitmap, slot_idx, n_slot);
        /* bitmap_print_bit(remote_qp_res->mr_bitmap); */
        rte_spinlock_unlock(&remote_qp_res->lock);

        if (ret != 0)
        {
            log_error("bitmap slot idx or number is invalid");
            goto error;
        }
    }

    return 0;
error:
    return -1;
}
int control_server_thread(void *arg)
{
    struct epoll_event event[N_EVENTS_MAX];
    int epfd = 0;
    int n_fds;
    int ret;
    int i;

    log_debug("control server thread init finished");
    epfd = *(int *)arg;
    struct control_server_msg msg;

    while (1)
    {
        n_fds = epoll_wait(epfd, event, N_EVENTS_MAX, -1);
        if (unlikely(n_fds == -1))
        {
            log_error("epoll_wait() error: %s", strerror(errno));
            return -1;
        }

        log_debug("%d NEW EVENTS READY =======", n_fds);

        for (i = 0; i < n_fds; i++)
        {
            int sockfd = event[i].data.fd;
            if (sock_utils_read(sockfd, (void *)&msg, sizeof(struct control_server_msg)) !=
                sizeof(struct control_server_msg))
            {
                log_error("recv control_msg error");
                return -1;
            }

            ret = process_control_server_msg(&msg);

            if (unlikely(ret == -1))
            {
                log_error("event_process() error");
            }
        }
    }

    return 0;
}

int send_release_signal(struct control_server_msg *msg)
{
    log_debug("send release signal");
    log_debug("release signal dst_idx %u, sr_idx %u, slot_idx %u, addr %p, qpn: %u, n_slot: %u", msg->dest_node_idx,
              msg->source_node_idx, msg->slot_idx, msg->bf_addr, msg->source_qp_num, msg->n_slot);
    if (sock_utils_write(cfg->control_server_socks[msg->dest_node_idx], msg, sizeof(struct control_server_msg)) !=
        sizeof(struct control_server_msg))
    {
        goto error;
    }
    return 0;
error:
    log_error("Error, send_release_signal to node %u, local qp: %u\n", msg->source_node_idx, msg->source_qp_num);
    return -1;
}
