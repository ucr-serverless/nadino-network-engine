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

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libconfig.h>

#include <rte_branch_prediction.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_memzone.h>

#include "RDMA_utils.h"
#include "c_lib.h"
#include "http.h"
#include "ib.h"
#include "io.h"
#include "log.h"
#include "rdma_config.h"
#include "sock_utils.h"
#include "spright.h"
#include "utility.h"

#define MEMPOOL_NAME "SPRIGHT_MEMPOOL"
#define REMOTE_MEMPOOL_NAME "REMOTE_MEMPOOL"

#define N_MEMPOOL_ELEMENTS (1U << 16)

static void cfg_print(void)
{
    uint8_t i;
    uint8_t j;

    printf("Name: %s\n", cfg->name);

    printf("Number of Tenants: %d\n", cfg->n_tenants);
    printf("Tenants:\n");
    for (i = 0; i < cfg->n_tenants; i++)
    {
        printf("\tID: %hhu\n", i);
        printf("\tWeight: %d\n", cfg->tenants[i].weight);
        printf("\n");
    }

    printf("Number of NFs: %hhu\n", cfg->n_nfs);
    printf("NFs:\n");
    for (i = 0; i < cfg->n_nfs; i++)
    {
        printf("\tID: %hhu\n", i + 1);
        printf("\tName: %s\n", cfg->nf[i].name);
        printf("\tNumber of Threads: %hhu\n", cfg->nf[i].n_threads);
        printf("\tParams:\n");
        printf("\t\tmemory_mb: %hhu\n", cfg->nf[i].param.memory_mb);
        printf("\t\tsleep_ns: %u\n", cfg->nf[i].param.sleep_ns);
        printf("\t\tcompute: %u\n", cfg->nf[i].param.compute);
        printf("\tNode: %u\n", cfg->nf[i].node);
        printf("\n");
    }

    printf("Number of Routes: %hhu\n", cfg->n_routes);
    printf("Routes:\n");
    for (i = 0; i < cfg->n_routes; i++)
    {
        printf("\tID: %hhu\n", i);
        printf("\tName: %s\n", cfg->route[i].name);
        printf("\tLength = %hhu\n", cfg->route[i].length);
        if (cfg->route[i].length > 0)
        {
            printf("\tHops = [");
            for (j = 0; j < cfg->route[i].length; j++)
            {
                printf("%hhu ", cfg->route[i].hop[j]);
            }
            printf("\b]\n");
        }
        printf("\n");
    }

    printf("Number of Nodes: %hhu\n", cfg->n_nodes);
    printf("Local Node Index: %u\n", cfg->local_node_idx);
    printf("Nodes:\n");
    for (i = 0; i < cfg->n_nodes; i++)
    {
        printf("\tID: %hhu\n", i);
        printf("\tHostname: %s\n", cfg->nodes[i].hostname);
        printf("\tIP Address: %s\n", cfg->nodes[i].ip_address);
        printf("\tPort = %u\n", cfg->nodes[i].port);
        printf("\tdevice_idx = %u\n", cfg->nodes[i].device_idx);
        printf("\tsgid_idx = %u\n", cfg->nodes[i].sgid_idx);
        printf("\tib_port = %u\n", cfg->nodes[i].ib_port);
        printf("\tqp_num = %u\n", cfg->nodes[i].qp_num);
        printf("\n");
    }

    printf("RDMA slot_size: %u \n", cfg->rdma_slot_size);
    printf("RDMA mr_size: %u \n", cfg->rdma_remote_mr_size);
    printf("RDMA mr_per_qp: %u \n", cfg->rdma_remote_mr_per_qp);

    print_rt_table();
}

static int cfg_init(char *cfg_file)
{
    config_setting_t *subsubsetting = NULL;
    config_setting_t *subsetting = NULL;
    config_setting_t *setting = NULL;
    const char *name = NULL;
    const char *hostname = NULL;
    const char *ip_address = NULL;
    config_t config;
    int value;
    int ret;
    int id;
    int n;
    int m;
    int i;
    int j;
    int node;
    int port;
    int weight;

    log_debug("size of http_transaction: %lu\n", sizeof(struct http_transaction));

    /* TODO: Change "flags" argument */
    cfg->mempool = rte_mempool_create(MEMPOOL_NAME, N_MEMPOOL_ELEMENTS, sizeof(struct http_transaction), 0, 0, NULL,
                                      NULL, NULL, NULL, rte_socket_id(), 0);
    if (unlikely(cfg->mempool == NULL))
    {
        log_error("rte_mempool_create() error: %s", rte_strerror(rte_errno));
        goto error;
    }

    config_init(&config);

    ret = config_read_file(&config, cfg_file);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_error("config_read_file() error: line %d: %s", config_error_line(&config), config_error_text(&config));
        goto error;
    }

    ret = config_lookup_string(&config, "name", &name);
    if (unlikely(ret == CONFIG_FALSE))
    {
        /* TODO: Error message */
        goto error;
    }

    strcpy(cfg->name, name);

    setting = config_lookup(&config, "nfs");
    if (unlikely(setting == NULL))
    {
        /* TODO: Error message */
        goto error;
    }

    ret = config_setting_is_list(setting);
    if (unlikely(ret == CONFIG_FALSE))
    {
        /* TODO: Error message */
        goto error;
    }

    n = config_setting_length(setting);
    cfg->n_nfs = n;

    for (i = 0; i < n; i++)
    {
        subsetting = config_setting_get_elem(setting, i);
        if (unlikely(subsetting == NULL))
        {
            /* TODO: Error message */
            goto error;
        }

        ret = config_setting_is_group(subsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        ret = config_setting_lookup_int(subsetting, "id", &id);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        ret = config_setting_lookup_string(subsetting, "name", &name);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        strcpy(cfg->nf[id - 1].name, name);

        ret = config_setting_lookup_int(subsetting, "n_threads", &value);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        cfg->nf[id - 1].n_threads = value;

        subsubsetting = config_setting_lookup(subsetting, "params");
        if (unlikely(subsubsetting == NULL))
        {
            /* TODO: Error message */
            goto error;
        }

        ret = config_setting_is_group(subsubsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        ret = config_setting_lookup_int(subsubsetting, "memory_mb", &value);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        cfg->nf[id - 1].param.memory_mb = value;

        ret = config_setting_lookup_int(subsubsetting, "sleep_ns", &value);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        cfg->nf[id - 1].param.sleep_ns = value;

        ret = config_setting_lookup_int(subsubsetting, "compute", &value);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        cfg->nf[id - 1].param.compute = value;

        ret = config_setting_lookup_int(subsetting, "node", &node);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_info("Set default node as 0.");
            node = 0;
        }

        cfg->nf[id - 1].node = node;
        set_node(id, node);
    }

    setting = config_lookup(&config, "routes");
    if (unlikely(setting == NULL))
    {
        /* TODO: Error message */
        goto error;
    }

    ret = config_setting_is_list(setting);
    if (unlikely(ret == CONFIG_FALSE))
    {
        /* TODO: Error message */
        goto error;
    }

    n = config_setting_length(setting);
    cfg->n_routes = n + 1;

    strcpy(cfg->route[0].name, "Default");
    cfg->route[0].length = 0;

    for (i = 0; i < n; i++)
    {
        subsetting = config_setting_get_elem(setting, i);
        if (unlikely(subsetting == NULL))
        {
            /* TODO: Error message */
            goto error;
        }

        ret = config_setting_is_group(subsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        ret = config_setting_lookup_int(subsetting, "id", &id);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }
        else if (unlikely(id == 0))
        {
            /* TODO: Error message */
            goto error;
        }

        ret = config_setting_lookup_string(subsetting, "name", &name);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        strcpy(cfg->route[id].name, name);

        subsubsetting = config_setting_lookup(subsetting, "hops");
        if (unlikely(subsubsetting == NULL))
        {
            /* TODO: Error message */
            goto error;
        }

        ret = config_setting_is_array(subsubsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error;
        }

        m = config_setting_length(subsubsetting);
        cfg->route[id].length = m;

        for (j = 0; j < m; j++)
        {
            value = config_setting_get_int_elem(subsubsetting, j);
            cfg->route[id].hop[j] = value;
        }
    }

    char local_hostname[HOST_NAME_MAX];
    if (gethostname(local_hostname, sizeof(local_hostname)) == -1)
    {
        log_error("gethostname() failed");
        goto error;
    }
    int is_hostname_matched = -1;

    setting = config_lookup(&config, "nodes");
    if (unlikely(setting == NULL))
    {
        log_warn("Nodes configuration is missing.");
        goto error;
    }

    ret = config_setting_is_list(setting);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_warn("Nodes configuration is missing.");
        goto error;
    }

    n = config_setting_length(setting);
    cfg->n_nodes = n;

    for (i = 0; i < n; i++)
    {
        subsetting = config_setting_get_elem(setting, i);
        if (unlikely(subsetting == NULL))
        {
            log_warn("Node configuration is missing.");
            goto error;
        }

        ret = config_setting_is_group(subsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node configuration is missing.");
            goto error;
        }

        ret = config_setting_lookup_int(subsetting, "id", &id);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node ID is missing.");
            goto error;
        }

        ret = config_setting_lookup_string(subsetting, "hostname", &hostname);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node hostname is missing.");
            goto error;
        }

        strcpy(cfg->nodes[id].hostname, hostname);

        /* Compare the hostnames */
        if (strcmp(local_hostname, cfg->nodes[id].hostname) == 0)
        {
            cfg->local_node_idx = i;
            is_hostname_matched = 1;
            log_info("Hostnames match: %s, node index: %u", local_hostname, i);
        }
        else
        {
            log_debug("Hostnames do not match. Got: %s, Expected: %s", local_hostname, hostname);
        }

        ret = config_setting_lookup_string(subsetting, "ip_address", &ip_address);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node ip_address is missing.");
            goto error;
        }

        strcpy(cfg->nodes[id].ip_address, ip_address);

        ret = config_setting_lookup_int(subsetting, "port", &port);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node port is missing.");
            goto error;
        }

        cfg->nodes[id].port = port;

        ret = config_setting_lookup_int(subsetting, "device_idx", &value);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("RDMA device_idx is missing.");
            goto error;
        }

        cfg->nodes[id].device_idx = value;

        ret = config_setting_lookup_int(subsetting, "sgid_idx", &value);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("RDMA sgid_idx is missing.");
            goto error;
        }

        cfg->nodes[id].sgid_idx = value;

        ret = config_setting_lookup_int(subsetting, "ib_port", &value);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("RDMA ib_port is missing.");
            goto error;
        }

        cfg->nodes[id].ib_port = value;

        ret = config_setting_lookup_int(subsetting, "qp_num", &value);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("RDMA qp_num is missing.");
            goto error;
        }

        cfg->nodes[id].qp_num = value;
    }

    setting = config_lookup(&config, "tenants");
    if (unlikely(setting == NULL))
    {
        log_error("Tenants configuration is required.");
        goto error;
    }

    ret = config_setting_is_list(setting);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_error("Tenants configuration is required.");
        goto error;
    }

    n = config_setting_length(setting);
    cfg->n_tenants = n;

    for (i = 0; i < n; i++)
    {
        subsetting = config_setting_get_elem(setting, i);
        if (unlikely(subsetting == NULL))
        {
            log_error("Tenant-%d's configuration is required.", i);
            goto error;
        }

        ret = config_setting_is_group(subsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_error("Tenant-%d's configuration is required.", i);
            goto error;
        }

        ret = config_setting_lookup_int(subsetting, "id", &id);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_error("Tenant-%d's ID is required.", i);
            goto error;
        }

        ret = config_setting_lookup_int(subsetting, "weight", &weight);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_error("Tenant-%d's weight is required.", i);
            goto error;
        }

        cfg->tenants[id].weight = weight;
    }

    if (is_hostname_matched == -1)
    {
        log_error("No matched hostname in %s", cfg_file);
        goto error;
    }

    setting = config_lookup(&config, "rdma_settings");
    if (unlikely(setting == NULL))
    {
        /* TODO: Error message */
        goto error;
    }

    ret = config_setting_is_group(setting);
    if (unlikely(ret == CONFIG_FALSE))
    {
        /* TODO: Error message */
        goto error;
    }

    ret = config_setting_lookup_int(setting, "slot_size", &value);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_error("rdma slot_size setting is required.");
        goto error;
    }

    cfg->rdma_slot_size = (uint32_t)value;

    ret = config_setting_lookup_int(setting, "mr_size", &value);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_error("rdma mr_size setting is required.");
        goto error;
    }

    cfg->rdma_remote_mr_size = (uint32_t)value;

    ret = config_setting_lookup_int(setting, "mr_per_qp", &value);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_error("rdma mr_per_qp setting is required.");
        goto error;
    }

    cfg->rdma_remote_mr_per_qp = (uint32_t)value;

    cfg->remote_mempool =
        rte_mempool_create(REMOTE_MEMPOOL_NAME, cfg->nodes[cfg->local_node_idx].qp_num * cfg->rdma_remote_mr_per_qp,
                           cfg->rdma_remote_mr_size, 0, 0, NULL, NULL, NULL, NULL, rte_socket_id(), 0);

    if (unlikely(cfg->remote_mempool == NULL))
    {
        log_error("rte_mempool_create() remote_mempool error: %s", rte_strerror(rte_errno));
        goto error;
    }

    cfg_print();

    config_destroy(&config);
    cfg_print();
    log_debug("finished\n");

    return 0;

error:
    config_destroy(&config);
    return -1;
}

static int cfg_exit(void)
{
    if (cfg->local_mempool_addrs)
    {
        free(cfg->local_mempool_addrs);
        cfg->local_mempool_addrs = NULL;
    }
    if (cfg->remote_mempool_addrs)
    {
        free(cfg->remote_mempool_addrs);
        cfg->remote_mempool_addrs = NULL;
    }
    if (cfg->mempool)
    {

        rte_mempool_free(cfg->mempool);
        cfg->mempool = NULL;
    }
    if (cfg->remote_mempool)
    {

        rte_mempool_free(cfg->remote_mempool);
        cfg->remote_mempool = NULL;
    }

    if (cfg->control_server_socks)
    {
        free(cfg->control_server_socks);
        cfg->control_server_socks = NULL;
    }
    if (cfg->node_res)
    {
        for (size_t i = 0; i < cfg->n_nodes; i++)
        {
            destroy_rdma_node_res(&(cfg->node_res[i]));
        }
        free(cfg->node_res);
        cfg->node_res = NULL;
    }
    if (cfg->local_mempool_to_mr_map)
    {
        delete_c_map(cfg->local_mempool_to_mr_map);
        cfg->local_mempool_to_mr_map = NULL;
    }

    return 0;
}

static void save_mempool_element_address(struct rte_mempool *mp, void *opaque, void *obj, unsigned int idx)
{
    void **addr_list = (void **)opaque;
    addr_list[idx] = obj;
}

static void retrieve_mempool_addresses(struct rte_mempool *mp, void **addr_list)
{
    rte_mempool_obj_iter(mp, save_mempool_element_address, addr_list);
}

static int compare_addr(void *left, void *right)
{

    uint64_t *left_op = (uint64_t *)left;
    uint64_t *right_op = (uint64_t *)right;
    if (left_op < right_op)
    {
        return -1;
    }
    else if (left_op > right_op)
    {
        return 1;
    }
    else
    {
        return 0;
    }
    return 0;
}

int rdma_init()
{
    int ret = 0;

    struct rdma_param rparams = {
        .local_mr_num = N_MEMPOOL_ELEMENTS,
        .local_mr_size = sizeof(struct http_transaction),
        .qp_num = cfg->nodes[cfg->local_node_idx].qp_num,
        .device_idx = cfg->nodes[cfg->local_node_idx].device_idx,
        .sgid_idx = cfg->nodes[cfg->local_node_idx].sgid_idx,
        .ib_port = cfg->nodes[cfg->local_node_idx].ib_port,
        .remote_mr_num = rparams.qp_num * cfg->rdma_remote_mr_per_qp,
        .remote_mr_size = cfg->rdma_remote_mr_size,
    };

    cfg->local_mempool_addrs = (void **)calloc(rparams.local_mr_num, sizeof(void *));
    if (!cfg->local_mempool_addrs)
    {
        log_error("failed to allocate local_mempool_addrs");
        goto error;
    }
    cfg->remote_mempool_addrs = (void **)calloc(rparams.remote_mr_num, sizeof(void *));
    if (!cfg->local_mempool_addrs)
    {
        log_error("failed to allocate local_mempool_addrs");
        goto error;
    }

    retrieve_mempool_addresses(cfg->mempool, cfg->local_mempool_addrs);
    retrieve_mempool_addresses(cfg->remote_mempool, cfg->remote_mempool_addrs);

    log_debug("init ctx");
    ret = init_ib_ctx(&cfg->rdma_ctx, &rparams, cfg->local_mempool_addrs, cfg->remote_mempool_addrs);

    if (unlikely(ret != RDMA_SUCCESS))
    {
        log_error("init ib ctx fail");
        goto error;
    }

    cfg->local_mempool_to_mr_map = new_c_map(compare_addr, NULL, NULL);
    if (!cfg->local_mempool_to_mr_map)
    {
        log_error("failed to allocate local_mempool_to_mr_map");
        goto error;
    }

    for (size_t i = 0; i < rparams.local_mr_num; i++)
    {
        ret = insert_c_map(cfg->local_mempool_to_mr_map, (void *)&(cfg->local_mempool_addrs[i]), sizeof(void *),
                           (void *)&(cfg->rdma_ctx.local_mrs[i]), sizeof(struct ibv_mr*));
        if (ret != clib_true)
        {
            log_error("failed to insert the %d th mr_info to map", i);
            goto error;
        }
    }
    return 0;
error:
    destroy_ib_ctx(&cfg->rdma_ctx);
    return -1;
}

static int destroy_control_server_socks()
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

static int control_server_socks_init()
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
        sprintf(buffer, "%u", cfg->nodes[i].port);
        printf("%s", buffer);

        do
        {
            sock_fd = sock_utils_connect(cfg->nodes[i].ip_address, buffer);

        } while (sock_fd <= 0);

        cfg->control_server_socks[i] = sock_fd;
        connected_nodes++;
    }
    log_debug("connected to servers with lower idx");
    if (connected_nodes == node_num - 1)
    {
        return 0;
    }
    sprintf(buffer, "%u", cfg->nodes[self_idx].port);
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
    log_debug("accepting connections from other nodes");
    while (connected_nodes < node_num)
    {
        peer_fd = accept(bind_fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (peer_fd < 0)
        {
            continue;
        }
        inet_ntop(AF_INET, &peer_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        log_debug("client ip %s", client_ip);
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
    log_debug("control_server_socks initialized");
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

static int exchange_rdma_node_res()
{
    cfg->node_res = (struct rdma_node_res *)calloc(cfg->n_nodes, sizeof(struct rdma_node_res));

    if (unlikely(cfg->node_res == NULL))
    {
        log_error("allocate node res fail");
        goto error;
    }
    int ret = 0;
    uint32_t local_idx = cfg->local_node_idx;
    uint32_t node_num = cfg->n_nodes;
    ret = init_local_ib_res(&(cfg->rdma_ctx), cfg->node_res[local_idx].ibres);
    for (size_t i = 0; i < node_num; i++)
    {
        if (i == local_idx)
        {
            continue;
        }
        if (i < local_idx)
        {
            ret = send_ib_res(cfg->node_res[local_idx].ibres, cfg->control_server_socks[i]);
            if (ret != RDMA_SUCCESS)
            {
                log_error("send res to node idx %d failed", i);
                goto error;
            }
            ret = recv_ib_res(cfg->node_res[i].ibres, cfg->control_server_socks[i]);
            if (ret != RDMA_SUCCESS)
            {
                log_error("recv res from node idx %d failed", i);
                goto error;
            }
        }
        if (i > local_idx)
        {
            ret = recv_ib_res(cfg->node_res[i].ibres, cfg->control_server_socks[i]);
            if (ret != RDMA_SUCCESS)
            {
                log_error("recv res from node idx %d failed", i);
                goto error;
            }
            ret = send_ib_res(cfg->node_res[local_idx].ibres, cfg->control_server_socks[i]);
            if (ret != RDMA_SUCCESS)
            {
                log_error("send res to node idx %d failed", i);
                goto error;
            }
        }
    }
    log_debug("finished exchange information with all nodes");
    for (size_t i = 0; i < node_num; i++)
    {
        ret = init_rdma_node_res(cfg->node_res[i].ibres, &(cfg->node_res[i]));
        if (ret != RDMA_SUCCESS)
        {
            log_error("recv res from node idx %d failed", i);
            goto error;
        }
    }
    return 0;
error:
    return -1;
}

static int shm_mgr(char *cfg_file)
{
    const struct rte_memzone *memzone = NULL;
    int ret;

    fn_id = -1;

    memzone = rte_memzone_reserve(MEMZONE_NAME, sizeof(*cfg), rte_socket_id(), 0);
    if (unlikely(memzone == NULL))
    {
        log_error("rte_memzone_reserve() error: %s", rte_strerror(rte_errno));
        goto error;
    }

    memset(memzone->addr, 0U, sizeof(*cfg));

    cfg = memzone->addr;

    ret = cfg_init(cfg_file);
    if (unlikely(ret == -1))
    {
        log_error("cfg_init() error");
        goto error;
    }

    ret = control_server_socks_init();
    if (unlikely(ret == -1))
    {
        log_error("control_server_socks_init() error");
        goto error;
    }

    ret = exchange_rdma_node_res();
    if (unlikely(ret == -1))
    {
        log_error("exchange_rdma_node_res() error");
        goto error;
    }

    ret = io_init();
    if (unlikely(ret == -1))
    {
        log_error("io_init() error");
        goto error;
    }

    /* TODO: Exit loop on interrupt */
    while (1)
    {
        sleep(30);
    }

    ret = io_exit();
    if (unlikely(ret == -1))
    {
        log_error("io_exit() error");
        goto error;
    }

    ret = cfg_exit();
    if (unlikely(ret == -1))
    {
        log_error("cfg_exit() error");
        goto error;
    }

    ret = rte_memzone_free(memzone);
    if (unlikely(ret < 0))
    {
        log_error("rte_memzone_free() error: %s", rte_strerror(-ret));
        return -1;
    }

    return 0;

error:
    destroy_control_server_socks();
    cfg_exit();
    rte_memzone_free(memzone);
    return -1;
}

int main(int argc, char **argv)
{
    int ret;

    ret = rte_eal_init(argc, argv);
    if (unlikely(ret == -1))
    {
        log_error("rte_eal_init() error: %s", rte_strerror(rte_errno));
        goto error_0;
    }

    argc -= ret;
    argv += ret;

    if (unlikely(argc == 1))
    {
        log_error("Configuration file not provided");
        goto error_1;
    }

    ret = shm_mgr(argv[1]);
    if (unlikely(ret == -1))
    {
        log_error("shm_mgr() error");
        goto error_1;
    }

    ret = rte_eal_cleanup();
    if (unlikely(ret < 0))
    {
        log_error("rte_eal_cleanup() error: %s", rte_strerror(-ret));
        goto error_0;
    }

    return 0;

error_1:
    rte_eal_cleanup();
error_0:
    return 1;
}
