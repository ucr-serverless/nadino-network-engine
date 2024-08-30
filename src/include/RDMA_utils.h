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

#ifndef RDMA_UTILS
#define RDMA_UTILS

#include "bitmap.h"
#include "c_lib.h"
#include "common.h"
#include "ib.h"
#include "qp.h"
#include "rdma_config.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

enum qp_status
{
    CONNECTED,
    DISCONNECTED,
};
struct qp_id
{
    uint32_t node_id;
    uint32_t qp_num;
};
struct qp_res
{
    struct ibv_qp *qp;
    uint32_t qp_num;
    struct mr_info *start;
    uint32_t mr_info_num;
    bitmap *mr_bitmap;
    uint32_t unsignaled_cnt;
    uint32_t outstanding_cnt;
    enum qp_status status;
    struct qp_id peer_qp_id;
    uint32_t last_slot_idx;
};

struct rdma_node_res
{
    uint32_t n_qp;
    struct ib_res ibres;
    struct qp_res *qpres;
    // map qp_num to the pointer to qp_res
    struct clib_map *qp_num_to_qp_res_map;
    struct clib_array *connected_qp_res;
};

int rdma_init();

int rdma_exit();

int rdma_qp_connection_init();

int rdma_node_res_init(struct ib_res *ibres, struct rdma_node_res *node_res);
int reset_qp_res(struct qp_res *qpres);
int destroy_rdma_node_res(struct rdma_node_res *node_res);

int init_qp_bitmap(uint32_t mr_per_qp, uint32_t mr_len, uint32_t slot_size, bitmap **bp);

int find_avaliable_slot(uint32_t local_qp_num, uint32_t message_size, uint32_t *slot_idx_start, uint32_t *n_slot,
                        void **raddr, uint32_t *rkey);

int remote_addr_convert_slot_idx(void *remote_addr, uint32_t remote_len, struct mr_info *start, uint32_t mr_info_len,
                                 uint32_t slot_size, uint32_t *slot_idx, uint32_t *slot_num);

int qp_num_to_qp_res(struct rdma_node_res *res, uint32_t qp_num, struct qp_res **qpres);

int local_slot_idx_convert(struct rdma_node_res *local_res, uint32_t local_qp_num, uint32_t slot_idx,
                           uint32_t mr_info_num, uint32_t slot_size, void **addr);

uint32_t memory_len_to_slot_len(uint32_t len, uint32_t slot_size);

int rdma_rpc_client(void *arg);

int rdma_rpc_server(void *arg);

#endif // !RDMA_UTILS
