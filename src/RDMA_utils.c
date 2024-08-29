/*
# Copyright 2024 University of California, Riverside
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

#include "RDMA_utils.h"
#include "bitmap.h"
#include "c_lib.h"
#include "c_array.h"
#include "common.h"
#include "log.h"
#include "rdma_config.h"
#include "sock_utils.h"
#include "utility.h"
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#define FIND_SLOT_RETRY_MAX 3

int rdma_init()
{
    int ret = 0;

    struct rdma_param rparams = {
        .local_mr_num = cfg->mempool_size,
        .local_mr_size = cfg->mempool_elt_size,
        .qp_num = cfg->nodes[cfg->local_node_idx].qp_num,
        .device_idx = cfg->nodes[cfg->local_node_idx].device_idx,
        .sgid_idx = cfg->nodes[cfg->local_node_idx].sgid_idx,
        .ib_port = cfg->nodes[cfg->local_node_idx].ib_port,
        .remote_mr_num = cfg->remote_mempool_size,
        .remote_mr_size = cfg->remote_mempool_elt_size,
        .init_cqe_num = cfg->rdma_init_cqe_num,
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

    log_info("init RDMA ctx");
    ret = init_ib_ctx(&cfg->rdma_ctx, &rparams, cfg->local_mempool_addrs, cfg->remote_mempool_addrs);
    log_info("init RDMA ctx finished");

    if (unlikely(ret != RDMA_SUCCESS))
    {
        log_error("init ib ctx fail");
        goto error;
    }

    cfg->local_mp_elt_to_mr_map = new_c_map(compare_addr, NULL, NULL);
    if (!cfg->local_mp_elt_to_mr_map)
    {
        log_error("failed to allocate local_mp_elt_to_mr_map");
        goto error;
    }

    for (size_t i = 0; i < rparams.local_mr_num; i++)
    {
        insert_c_map(cfg->local_mp_elt_to_mr_map, cfg->local_mempool_addrs[i], sizeof(void *),
                     (void *)(cfg->rdma_ctx.local_mrs[i]), sizeof(struct ibv_mr *));
    }
    cfg->node_res = (struct rdma_node_res *)calloc(cfg->n_nodes, sizeof(struct rdma_node_res));

    if (unlikely(cfg->node_res == NULL))
    {
        log_error("allocate node res fail");
        goto error;
    }
    return 0;
error:
    return -1;
}

int rdma_exit()
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
    if (cfg->local_mp_elt_to_mr_map)
    {
        delete_c_map(cfg->local_mp_elt_to_mr_map);
        cfg->local_mp_elt_to_mr_map = NULL;
    }
    destroy_ib_ctx(&cfg->rdma_ctx);
    return 0;
}

int rdma_qp_connection_init_node(uint32_t remote_node_idx)
{
    uint32_t node_num = cfg->n_nodes;
    uint32_t local_idx = cfg->local_node_idx;
    int ret = 0;
    struct rdma_node_res *local_res = &(cfg->node_res[local_idx]);
    struct rdma_node_res *remote_res = &(cfg->node_res[remote_node_idx]);
    uint32_t remote_n_qp = remote_res->n_qp;
    uint32_t local_n_qp = local_res->n_qp;
    uint32_t local_qp_slot_start = 0;
    uint32_t remote_qp_slot_start = 0;
    uint32_t n_qp_connect = 0;
    if (remote_node_idx > local_idx)
    {
        local_qp_slot_start = (remote_node_idx - 1) * (local_n_qp / (node_num - 1));
        remote_qp_slot_start = local_idx * (remote_n_qp / (node_num - 1));
    }
    else
    {
        local_qp_slot_start = remote_node_idx * (local_n_qp / (node_num - 1));
        remote_qp_slot_start = (local_idx - 1) * (remote_n_qp / (node_num - 1));
    }
    if (remote_n_qp > local_n_qp)
    {
        n_qp_connect = local_n_qp / (node_num - 1);
    }
    else
    {
        n_qp_connect = remote_n_qp / (node_num - 1);
    }
    for (size_t i = 0; i < n_qp_connect; i++)
    {
        uint32_t peer_qp_num = cfg->node_res[remote_node_idx].qpres[remote_qp_slot_start + i].qp_num;
        ret = modify_qp_init_to_rts(cfg->rdma_ctx.qps[local_qp_slot_start + i], &cfg->node_res[local_idx].ibres,
                                    &cfg->node_res[remote_node_idx].ibres, peer_qp_num);
        if (ret != RDMA_SUCCESS)
        {
            log_error("init qp to node: %u, qp_num: %u failed", remote_node_idx, remote_qp_slot_start + i);
            goto error;
        }
        struct qp_res *qpres = &(local_res->qpres[local_qp_slot_start + i]);
        qpres->peer_qp_id.qp_num = peer_qp_num;
        qpres->peer_qp_id.node_id = remote_node_idx;
        qpres->status = CONNECTED;
        push_back_c_array(cfg->node_res[remote_node_idx].connected_qp_res, &qpres, sizeof(struct qp_res*));
    }
    log_debug("%u RDMA_connections to node: %u established", n_qp_connect, remote_node_idx);
    return 0;
error:

    return -1;
}

int rdma_qp_connection_init()
{
    int ret = 0;
    uint32_t node_num = cfg->n_nodes;
    uint32_t local_idx = cfg->local_node_idx;
    for (size_t i = 0; i < node_num; i++)
    {
        if (i == local_idx)
        {
            continue;
        }
        ret = rdma_qp_connection_init_node(i);
        if (ret != 0)
        {
            log_error("connect qp to node: %u failed", i);
            goto error;
        }
    }
    return 0;
error:
    return -1;
}

int rdma_node_res_init(struct ib_res *ibres, struct rdma_node_res *noderes)
{
    int ret = 0;
    if (!ibres || !(noderes))
    {
        return RDMA_FAILURE;
    }
    if (ibres->n_qp * cfg->rdma_remote_mr_per_qp != ibres->n_mr)
    {
        log_fatal("The number of mr is not equal to the number of qp times mr_per_qp");
        return RDMA_FAILURE;
    }
    (noderes)->n_qp = ibres->n_qp;
    (noderes)->qp_num_to_qp_res_map = new_c_map(compare_qp_num, NULL, NULL);
    noderes->connected_qp_res = new_c_array(ibres->n_qp, compare_qp_res, NULL);
    (noderes)->qpres = (struct qp_res *)calloc(ibres->n_qp, sizeof(struct qp_res));
    if (!(noderes)->qpres)
    {
        log_error("Failed to allocate qp_res");
        return RDMA_FAILURE;
    }
    for (size_t i = 0; i < ibres->n_qp; i++)
    {
        struct qp_res* qp_res_addr = &(noderes->qpres[i]);
        insert_c_map((noderes)->qp_num_to_qp_res_map, &(ibres->qp_nums[i]), sizeof(uint32_t), &(qp_res_addr),
                     sizeof(struct qp_res*));
        ret = init_qp_bitmap(cfg->rdma_remote_mr_per_qp, cfg->rdma_remote_mr_size, cfg->rdma_slot_size,
                             &((noderes)->qpres[i].mr_bitmap));
        if (ret != RDMA_SUCCESS)
        {
            return RDMA_FAILURE;
        }
        noderes->qpres[i].qp_num = ibres->qp_nums[i];
        (noderes)->qpres[i].mr_info_num = cfg->rdma_remote_mr_per_qp;
        (noderes)->qpres[i].start = ibres->mrs + i * cfg->rdma_remote_mr_per_qp;
        noderes->qpres[i].outstanding_cnt = 0;
        noderes->qpres[i].unsignaled_cnt = 0;
        noderes->qpres[i].peer_qp_id.qp_num = 0;
        noderes->qpres[i].peer_qp_id.node_id = 0;
        noderes->qpres[i].last_slot_idx = 0;
        noderes->qpres[i].status = DISCONNECTED;
    }

    return RDMA_SUCCESS;
}

int reset_qp_res(struct qp_res *qpres)
{
    if (!qpres)
    {
        return RDMA_FAILURE;
    }
    qpres->unsignaled_cnt = 0;
    qpres->outstanding_cnt = 0;
    qpres->status = DISCONNECTED;
    qpres->peer_qp_id.qp_num = 0;
    qpres->peer_qp_id.node_id = 0;
    qpres->last_slot_idx = 0;
    bitmap_clear_all(qpres->mr_bitmap);
    return RDMA_SUCCESS;
}

int destroy_rdma_node_res(struct rdma_node_res *node_res)
{
    if (!node_res)
    {
        return RDMA_SUCCESS;
    }
    if (!node_res->qpres)
    {
        return RDMA_SUCCESS;
    }
    for (size_t i = 0; i < node_res->n_qp; i++)
    {
        if (node_res->qpres[i].mr_bitmap)
        {
            bitmap_deallocate(node_res->qpres[i].mr_bitmap);
        }
    }
    if (node_res->qp_num_to_qp_res_map)
    {
        delete_c_map(node_res->qp_num_to_qp_res_map);
        node_res->qp_num_to_qp_res_map = NULL;
    }
    if (node_res->connected_qp_res)
    {
        delete_c_array(node_res->connected_qp_res);
        node_res->connected_qp_res = NULL;
    }
    destroy_ib_res(&(node_res->ibres));
    free(node_res->qpres);
    return RDMA_SUCCESS;
}

int init_qp_bitmap(uint32_t mr_num, uint32_t single_mr_size, uint32_t slot_size, bitmap **bp)
{
    assert(single_mr_size % slot_size == 0);
    *bp = bitmap_allocate(mr_num * single_mr_size / slot_size);
    if (!bp)
    {
        log_error("Error, allocate bitmap\n");
        exit(1);
    }
    return RDMA_SUCCESS;
}

int find_avaliable_slot_inside_mr(bitmap *bp, uint32_t mr_bp_idx_start, uint32_t mr_blk_len, uint32_t msg_blk_len,
                                  uint32_t *slot_idx)
{
    if (mr_blk_len < msg_blk_len)
    {
        log_error("Error, meg size is larger than mr size\n");
        return RDMA_FAILURE;
    }
    bool success = true;
    for (size_t i = 0; i <= mr_blk_len - msg_blk_len; i++)
    {
        for (size_t j = 0; j < msg_blk_len; j++)
        {
            if (bitmap_read(bp, mr_bp_idx_start + i + j) == 1)
            {
                i = i + j;
                success = false;
                break;
            }
        }
        if (success)
        {
            *slot_idx = mr_bp_idx_start + i;
            return RDMA_SUCCESS;
        }
        success = true;
    }
    return RDMA_FAILURE;
}

int find_avaliable_slot_try(bitmap *bp, uint32_t message_size, uint32_t slot_size, struct mr_info *start,
                            uint32_t mr_info_len, uint32_t *slot_idx, uint32_t *slot_num, void **raddr, uint32_t *rkey)
{
    assert(mr_info_len > 0);
    assert(start);
    uint32_t result_slot_idx = 0;
    uint32_t bp_idx_start_per_mr = 0;
    uint32_t msg_blk_len = memory_len_to_slot_len(message_size, slot_size);
    int ret = 0;
    for (size_t i = 0; i < mr_info_len; i++)
    {
        size_t mr_blk_len = start[i].length / slot_size;
        assert(start[i].length % slot_size == 0);

        ret = find_avaliable_slot_inside_mr(bp, bp_idx_start_per_mr, mr_blk_len, msg_blk_len, &result_slot_idx);
        if (ret == RDMA_SUCCESS)
        {
            *slot_idx = result_slot_idx;
            *slot_num = msg_blk_len;
            *rkey = start[i].rkey;
            *raddr = (unsigned char *)start[i].addr + slot_size * (result_slot_idx - bp_idx_start_per_mr);
            return RDMA_SUCCESS;
        }
        bp_idx_start_per_mr += mr_blk_len;
    }
    return RDMA_FAILURE;
}

int find_avaliable_slot_inner(bitmap *bp, uint32_t message_size, uint32_t slot_size, struct mr_info *start,
                              uint32_t n_mr_info, uint32_t *slot_idx_start, uint32_t *n_slot, void **raddr,
                              uint32_t *rkey)
{
    int ret = 0;
    for (size_t i = 0; i < FIND_SLOT_RETRY_MAX; i++)
    {
        ret =
            find_avaliable_slot_try(bp, message_size, slot_size, start, n_mr_info, slot_idx_start, n_slot, raddr, rkey);
        if (ret == RDMA_SUCCESS)
        {
            return RDMA_SUCCESS;
        }
    }
    log_error("Error, can not find avaliable slot in %d retries\n", FIND_SLOT_RETRY_MAX);
    return RDMA_FAILURE;
}

int find_avaliable_slot(uint32_t local_qp_num, uint32_t message_size, uint32_t *slot_idx_start, uint32_t *n_slot,
                        void **raddr, uint32_t *rkey)
{
    struct rdma_node_res *noderes = cfg->node_res;
    int ret = 0;
    struct qp_res *local_qpres = NULL;
    ret = qp_num_to_qp_res(noderes, local_qp_num, &local_qpres);
    if (ret != RDMA_SUCCESS)
    {
        log_fatal("illegal local qp num");
        return RDMA_FAILURE;
    }
    return find_avaliable_slot_inner(local_qpres->mr_bitmap, message_size, cfg->rdma_slot_size, local_qpres->start,
                                     local_qpres->mr_info_num, slot_idx_start, n_slot, raddr, rkey);
}

int remote_slot_idx_convert(uint32_t slot_idx, struct mr_info *start, uint32_t mr_info_len, uint32_t blk_size,
                            void **addr, uint32_t *rkey)
{
    assert(mr_info_len > 0);
    assert(start);
    uint32_t blk_len_per_mr = 0;
    size_t i = 0;
    for (; i < mr_info_len; i++)
    {
        blk_len_per_mr = start[i].length / blk_size;
        assert(blk_len_per_mr != 0);
        if (slot_idx >= blk_len_per_mr)
        {
            slot_idx -= blk_len_per_mr;
            continue;
        }
        else
        {
            break;
        }
    }
    if (i == mr_info_len)
    {
        return RDMA_FAILURE;
    }
    *addr = start[i].addr + blk_size * slot_idx;
    *rkey = start[i].rkey;
    return RDMA_SUCCESS;
}

int remote_addr_convert_slot_idx(void *remote_addr, uint32_t remote_len, struct mr_info *start, uint32_t mr_info_len,
                                 uint32_t slot_size, uint32_t *slot_idx, uint32_t *slot_num)
{
    uint32_t result = 0;
    for (size_t i = 0; i < mr_info_len; i++)
    {
        if ((unsigned char *)start[i].addr <= (unsigned char *)remote_addr &&
            (unsigned char *)remote_addr < (unsigned char *)start[i].addr + start[i].length)
        {
            if ((unsigned char *)remote_addr + remote_len <= (unsigned char *)start[i].addr + start[i].length)
            {
                uint32_t slot_diff = (unsigned char *)remote_addr - (unsigned char *)start[i].addr;
                if (slot_diff % slot_size != 0)
                {
                    return RDMA_FAILURE;
                }
                result += slot_diff / slot_size;
                *slot_idx = result;
                *slot_num = memory_len_to_slot_len(remote_len, slot_size);
                return RDMA_SUCCESS;
            }
        }
        result += start[i].length / slot_size;
    }
    return RDMA_FAILURE;
}

int qp_num_to_qp_res(struct rdma_node_res *res, uint32_t qp_num, struct qp_res **qpres)
{
    int ret = 0;
    struct clib_map *map = res->qp_num_to_qp_res_map;
    ret = find_c_map(map, &qp_num, (void **)qpres);
    if (ret == clib_false)
    {
        log_error("Error, can not find qp_num %d", qp_num);
        return RDMA_FAILURE;
    }
    return RDMA_SUCCESS;
}

int local_slot_idx_convert(struct rdma_node_res *local_res, uint32_t local_qp_num, uint32_t slot_idx,
                           uint32_t mr_info_num, uint32_t blk_size, void **addr)
{
    struct qp_res *local_qpres = NULL;
    if (qp_num_to_qp_res(local_res, local_qp_num, &local_qpres) != RDMA_SUCCESS)
    {
        return RDMA_FAILURE;
    }
    struct mr_info *start = local_qpres->start;
    uint32_t n_slot_per_mr = 0;

    size_t i = 0;
    for (; i < mr_info_num; i++)
    {
        n_slot_per_mr = start[i].length / blk_size;
        assert(n_slot_per_mr != 0);
        if (slot_idx >= n_slot_per_mr)
        {
            slot_idx -= n_slot_per_mr;
            continue;
        }
        else
        {
            break;
        }
    }
    if (i == mr_info_num)
    {
        return RDMA_FAILURE;
    }
    *addr = start[i].addr + blk_size * slot_idx;
    return RDMA_SUCCESS;
}

uint32_t memory_len_to_slot_len(uint32_t len, uint32_t slot_size)
{
    assert(len > 0);
    assert(slot_size > 0);
    return (len + slot_size - 1) / slot_size;
}


int rdma_rpc_client(void *arg)
{
    int epoll_fd;
    struct epoll_event ev, events[N_EVENTS_MAX];
    int nfds;
    int ret;

    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1)
    {
        log_error("epoll_create1() error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    ret = add_weighted_pipes_to_epoll(epoll_fd, &ev);
    if (ret == -1)
    {
        return ret;
    }

    int gcd_weight = get_gcd_weight();
    int max_weight = get_max_weight();
    int current_index = -1;
    int current_weight = max_weight;
    struct http_transaction *txn = NULL;

    while (1)
    {
        nfds = epoll_wait(epoll_fd, events, N_EVENTS_MAX, -1);
        if (nfds == -1)
        {
            log_error("epoll_wait() error: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        for (int n = 0; n < nfds; n++)
        {
            tenant_pipe *tp = (tenant_pipe *)events[n].data.ptr;

            log_debug("Tenant-%d's pipe is ready to be consumed ...", tp->tenant_id);

            while (1)
            {
                current_index = (current_index + 1) % cfg->n_tenants;
                if (current_index == 0)
                {
                    current_weight -= gcd_weight;
                    if (current_weight <= 0)
                    {
                        current_weight = max_weight;
                    }
                }

                log_debug("Tenant ID: %d \t Assigned Weight: %d \t Current Weight: %d ", current_index,
                          tenant_pipes[current_index].weight, current_weight);

                if (current_index == tp->tenant_id && tenant_pipes[current_index].weight >= current_weight)
                {

                    txn = read_pipe(tp);
                    if (txn == NULL)
                    {
                        close(tp->fd[0]);
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, tp->fd[0], NULL);
                    }

                    /* uint8_t peer_node_idx = get_node(txn->next_fn); */


                    rte_mempool_put(cfg->mempool, txn);

                    break;
                }
            }
        }
    }

    close(epoll_fd);
    return -1;
    return 0;
}

int rdma_rpc_server(void *arg)
{
    int n_events = 10;
    int i;
    struct http_transaction *txn = NULL;
    int *pipefd_dispacher = (int*)arg;


    while (1)
    {
        for (i = 0; i < n_events; i++)
        {

            log_debug("Receiving from PEER GW.");
            ssize_t total_bytes_received = 0;
            if (total_bytes_received == -1)
            {
                log_error("read_full() error");
                goto error_1;
            }
            else if (total_bytes_received != sizeof(*txn))
            {
                log_error("Incomplete transaction received: expected %ld, got %zd", sizeof(*txn), total_bytes_received);
                goto error_1;
            }

            log_debug("Bytes received: %zd. \t sizeof(*txn): %ld.", total_bytes_received, sizeof(*txn));

            // Send txn to local function
            log_debug("\tRoute id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u", txn->route_id, txn->hop_count,
                      cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn);
            ssize_t bytes_written = write(pipefd_dispacher[1], &txn, sizeof(struct http_transaction *));
            if (unlikely(bytes_written == -1))
            {
                log_error("write() error: %s", strerror(errno));
                goto error_1;
            }
        }
    }

error_1:
    return -1;
}
