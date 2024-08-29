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
#include "sock_utils.h"

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
        }
        if (ret < 0)
        {
            log_fatal("setsockopt(TCP_KEEPIDLE) control server");
            goto error;
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
    }
    for (size_t i = 0; i < cfg->node_res[local_idx].n_qp; i++)
    {
        cfg->node_res[local_idx].qpres[i].qp = cfg->rdma_ctx.qps[i];
    }
    return 0;
error:
    return -1;
}
