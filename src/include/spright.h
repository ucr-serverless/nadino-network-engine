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

#ifndef SPRIGHT_H
#define SPRIGHT_H

#include <stdint.h>

#include <glib.h>
#include <rte_mempool.h>

#include "RDMA_utils.h"
#include "ib.h"
#include "io.h"
#include "log.h"
#include "rdma_config.h"

#define MEMZONE_NAME "SPRIGHT_MEMZONE"
#define ROUTING_TABLE_SIZE 256
#define HOSTNAME_MAX 256

#define EXTERNAL_SERVER_PORT 8080
// decricated use cfg->nodes[cfg->local_node_idx].port or g_ctx->rpc_svr_port
// #define INTERNAL_SERVER_PORT 8084

#ifdef __cplusplus
extern "C"
{
#endif

struct spright_cfg_s
{
    struct rte_mempool *mempool;
    uint32_t local_mempool_size;
    uint32_t local_mempool_elt_size;

    char name[64];

    int n_tenants;
    struct
    {
        uint8_t id;
        uint8_t routes[ROUTING_TABLE_SIZE];
        uint8_t n_routes;
        int weight;
    } tenants[256];

    uint8_t n_nfs;
    struct
    {
        char name[64];

        uint8_t n_threads;

        struct
        {
            uint8_t memory_mb;
            uint32_t sleep_ns;
            uint32_t compute;
        } param;

        uint8_t tenant_id;
        uint32_t fn_id;
        uint8_t node;
        uint8_t mode;
    } nf[UINT8_MAX + 1];

    uint8_t n_routes;
    struct
    {
        uint8_t id;
        char name[64];

        uint8_t length;
        uint8_t hop[UINT8_MAX + 1];
        uint8_t weight;
    } route[UINT8_MAX + 1];

    uint8_t n_nodes;
    uint8_t local_node_idx;
    struct
    {
        uint8_t node_id;
        char hostname[HOSTNAME_MAX];
        char ip_address[64];
        uint16_t port;
        char rdma_device[HOSTNAME_MAX];
        char comch_server_device[HOSTNAME_MAX];
        char comch_client_device[HOSTNAME_MAX];
        char comch_client_rep_device[HOSTNAME_MAX];
        uint32_t sgid_idx;
        int sockfd;
        uint8_t mode;
    } nodes[UINT8_MAX + 1];

    uint8_t inter_node_rt[ROUTING_TABLE_SIZE];


    struct
    {
        uint8_t is_remote_memory;
        uint16_t port;
    } memory_manager;

    int use_rdma;
    int use_one_side;
    uint32_t rdma_n_init_task;
    uint32_t rdma_n_init_recv_req;

    // int *control_server_socks;
    // int control_server_epfd;
    void **local_mempool_addrs;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SPRIGHT_H */
