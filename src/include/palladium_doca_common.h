/*
# Copyright 2025 University of California, Riverside
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

#ifndef PALLADIUM_DOCA_COMMON_H
#define PALLADIUM_DOCA_COMMON_H

#include <memory>
#include <unordered_map>
#include <iostream>
#include "doca_comch.h"
#include "doca_ctx.h"
#include "common_doca.h"
#include "doca_rdma.h"
#include "rdma_common_doca.h"

struct r_connection_res {
    struct doca_rdma_connection* conn;

};

struct gateway_tenant_res {
    uint32_t tenant_id;
    struct doca_buf_inventory *inv;
    struct doca_mmap *mmap;
    uint64_t mp_ptr;
    std::unique_ptr<char[]> rdma_desctriptor;
    uint32_t r_des_sz;
    std::unique_ptr<char[]> mp_descriptor;
    uint32_t mp_des_sz;
    struct doca_ctx *ctx;
    struct doca_rdma *rdma;
    std::unordered_map<struct doca_rdma_connection*, struct r_connection_res> r_conn_to_res;
    uint32_t weight;


};

struct fn_res {
    uint32_t fn_id;
    struct doca_comch_connection* comch_conn;
    uint32_t tenant_id;
    uint32_t node_id;
};

struct gateway_ctx {
    struct rdma_resources r_res;
    struct rdma_config r_config;
    std::unordered_map<uint32_t, struct fn_res> fn_id_to_res;
    std::unordered_map<uint64_t, struct doca_buf*>ptr_to_doca_buf;
    std::unordered_map<struct doca_buf*, struct doca_rdma_task_receive*> doca_buf_to_rr;
    std::unordered_map<uint32_t, std::unique_ptr<struct gateway_tenant_res>> tenant_id_to_res;
    std::unordered_map<uint32_t, uint32_t> route_id_to_tenant;



};

#endif /* PALLADIUM_DOCA_COMMON_H */
