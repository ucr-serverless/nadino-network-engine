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

#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <iostream>
#include "doca_comch.h"
#include "doca_ctx.h"
#include "common_doca.h"
#include "doca_log.h"
#include "doca_rdma.h"
#include "rdma_common_doca.h"
#include "log.h"
#include "rte_mempool.h"
#include "spright.h"

#define RUNTIME_ERROR_ON_FAIL(_expression_, _log)                                                                                  \
    {                                                                                                                  \
                                                                                                                       \
        if ((_expression_))                                                                                  \
        {                                                                                                              \
            throw std::runtime_error(_log);                                                                                           \
        }                                                                                                              \
    }
const std::string mempool_prefix = "PALLADIUM";
const uint32_t MAX_NGX_WORKER = 8;
const uint32_t MAX_WORKER = 1;
const uint32_t MAX_TASK_PER_RDMA_CTX = 10000;

enum Palladium_mode {
    // use skt and naive ing
    SPRIGHT = 0,
    // run palladium on the host (same with function)
    PALLADIUM_HOST = 1,
    // run the palladium multi tenancy expt(two node), don't use p-ing
    PALLADIUM_MULTITENANCY_EXPT = 2,
    // connect with ing
    PALLADIUM_DPU = 3,
    // run on dpu and connect with p-ing
    PALLADIUM_ALL = 4,
};
enum fd_type {
    ING_FD = 0,
    RPC_FD = 1,
    OOB_FD = 2,
    RDMA_PE_FD = 3,
    COMCH_PE_FD = 4,
    CLIENT_FD = 5,
    PALLADIUM_WORKER_CLIENT_FD = 6,
    PALLADIUM_ING_CLIENT_FD = 7,

};
struct fd_ctx_t{
    enum fd_type fd_tp;
    int sockfd;
    // is_server is deprecated, should use the fd_tp
    int is_server;     // 1 for server_fd, 0 for client_fd
    int peer_svr_fd;   // Peer server_fd (for client_fd)
};
struct r_connection_res {
    struct doca_rdma_connection* conn;
    // save for reconnect
    std::string descriptor;
    uint32_t node_id;
};
struct fn_res {
    uint32_t fn_id;
    struct doca_comch_connection* comch_conn;
    uint32_t tenant_id;
    uint32_t node_id;
};

// could be used as task_ctx_data
struct doca_buf_res {
    struct doca_buf *buf;
    struct doca_rdma_task_receive *rr;
    uint32_t tenant_id;
    uint64_t ptr;
    uint32_t range;

};
// could be used as rdma_ctx_data
struct gateway_tenant_res {
    uint32_t tenant_id;
    struct doca_buf_inventory *inv;
    struct doca_mmap *mmap;
    struct rte_mempool *mp_ptr;
    uint32_t r_des_sz;
    uint32_t mp_des_sz;
    struct doca_ctx *rdma_ctx;
    struct doca_rdma *rdma;
    std::unordered_map<struct doca_rdma_connection*, struct r_connection_res> r_conn_to_res;
    // connections between workers
    std::unordered_map<uint32_t, std::vector<struct doca_rdma_connection*>> peer_node_id_to_connections;
    // connections between DNE and ngx workers
    std::unordered_map<uint32_t, std::vector<struct doca_rdma_connection*>> ngx_wk_id_to_connections;
    uint32_t weight;
    uint32_t n_submitted_rr;
    std::vector<uint32_t> routes;
    // the size of mp buffer
    uint32_t buf_sz;
    // the number of mp buffers
    uint32_t n_buf;
    uint64_t mmap_start;
    uint64_t mmap_range;
    // save the raw ptrs of mp elt in vector
    std::vector<uint64_t> element_addr;
    // save the ptrs of rr bufs
    std::vector<uint64_t> rr_element_addr;
    // void** to hold all addresses of the mp elt
    // std::unique_ptr<void*[]> mp_elts;

    bool task_submitted;
    // void** to hold all addresses of the elt to be used as recv requests
    // the number of elements in the rr_mp_elts
    std::unordered_map<uint64_t, struct doca_buf_res>ptr_to_doca_buf_res;




};


struct route_res {
    uint32_t route_id;
    std::vector<uint32_t> hop;
    uint32_t tenant_id;
};

struct node_res {
    uint32_t node_id;
    std::string hostname;
    std::string ip_addr;
    int oob_skt_fd;

};

struct gateway_ctx {
    uint32_t node_id;
    std::unordered_map<uint32_t, struct fn_res> fn_id_to_res;
    // keeps order
    std::map<uint32_t, struct gateway_tenant_res> tenant_id_to_res;
    std::unordered_map<uint32_t, struct route_res> route_id_to_res;
    // keeps order
    std::map<uint32_t, struct node_res> node_id_to_res;
    struct doca_dev *rdma_dev;
    uint32_t gid_index;
    uint16_t conn_per_ngx_worker;
    uint16_t conn_per_worker;
    // the amount of recv requests to post
    uint32_t rr_per_ctx;
    // the max amount of tasks to allocate when create rdma
    uint32_t max_rdma_task_per_ctx;
    struct rdma_cb_config rdma_cb;
    struct doca_pe *rdma_pe;
    struct doca_pe *comch_pe;
    struct doca_comch_server *comch_server;
    struct doca_dev *comch_dev;
    struct doca_dev_rep *comch_dev_rep;
    struct spright_cfg_s *cfg;
    std::string rdma_device;
    std::string comch_server_device;
    std::string comch_client_device;
    // local ip addr
    std::string ip_addr;
    // 
    uint16_t rpc_svr_port;
    // for naive ing
    // TODO: read from cfg file
    uint16_t ing_port;
    // store the malloced meories for easier free up
    // maybe not useful
    std::vector<fd_ctx_t> fd_ctx;
    // std::unique_ptr<struct fd_ctx_t> rdma_pe_fd_ctx;
    // std::unique_ptr<struct fd_ctx_t> comch_pe_fd_ctx;
    int oob_skt_sv_fd;
    std::map<int, struct fd_ctx_t*> fd_to_fd_ctx;
    std::unordered_map<struct doca_ctx*, uint32_t> rdma_ctx_to_tenant_id;

    uint32_t gtw_fn_id;

    uint8_t current_term;
    bool should_connect_p_ing;


    gateway_ctx(struct spright_cfg_s *cfg);
    void print_gateway_ctx();




};

enum doca_log_level my_log_level_to_doca_log_level(enum my_log_level level);

doca_error_t send_then_connect_rdma(struct doca_rdma *rdma, std::vector<struct doca_rdma_connection*> &connections, std::unordered_map<struct doca_rdma_connection*, struct r_connection_res> &r_conn_to_res, uint32_t n_connections,
                                                     int sock_fd);
doca_error_t recv_then_connect_rdma(struct doca_rdma *rdma, std::vector<struct doca_rdma_connection*> &connections, std::unordered_map<struct doca_rdma_connection*, struct r_connection_res> &r_conn_to_res, uint32_t n_connections,
                                                     int sock_fd);

doca_error_t submit_rdam_recv_tasks_from_ptrs(struct doca_rdma *rdma, struct gateway_ctx *gtw_ctx, uint32_t tenant_id, uint32_t mem_range, std::vector<uint64_t> &ptrs);

doca_error_t submit_rdma_recv_tasks_from_raw_ptrs(struct doca_rdma *rdma, struct gateway_ctx *gtw_ctx, uint32_t tenant_id, uint32_t mem_range, uint64_t* ptrs, uint32_t ptr_sz);

doca_error_t create_doca_bufs(struct gateway_ctx *gtw_ctx, uint32_t tenant_id, uint32_t mem_range, void **ptrs, uint32_t n);
void print_gateway_ctx(const gateway_ctx* ctx);
void add_addr_to_vec(struct rte_mempool *mp, void *opaque, void *obj, unsigned int idx);
// return the start address and the memrange
std::pair<uint64_t, uint64_t> detect_mp_gap_and_return_range(struct rte_mempool *mp, std::vector<uint64_t> *addr);
void LOG_AND_FAIL(doca_error_t &result);

void init_same_node_rdma_config_cb(struct gateway_ctx*);
void init_cross_node_rdma_config_cb(struct gateway_ctx*);

int oob_skt_init(struct gateway_ctx *g_ctx);

void gtw_same_node_send_imm_completed_callback(struct doca_rdma_task_send_imm *send_task, union doca_data task_user_data,
                                       union doca_data ctx_user_data);

void gtw_same_node_send_imm_completed_err_callback(struct doca_rdma_task_send_imm *send_task, union doca_data task_user_data,
                                           union doca_data ctx_user_data);

void gtw_same_node_rdma_recv_to_fn_callback(struct doca_rdma_task_receive *rdma_receive_task, union doca_data task_user_data,
                                  union doca_data ctx_user_data);

void gtw_same_node_rdma_recv_err_callback(struct doca_rdma_task_receive *rdma_receive_task, union doca_data task_user_data,
                            union doca_data ctx_user_data);

void gtw_same_node_rdma_state_changed_callback(const union doca_data user_data, struct doca_ctx *ctx,
                                               enum doca_ctx_states prev_state, enum doca_ctx_states next_state);

int rdma_send(struct http_transaction *txn, struct gateway_ctx *g_ctx, uint32_t tenant_id);
doca_error_t register_pe_to_ep(struct doca_pe *pe, int ep_fd, struct fd_ctx_t *fd_tp, struct gateway_ctx *g_ctx);
doca_error_t create_doca_bufs_from_vec(struct gateway_ctx *gtw_ctx, uint32_t tenant_id, uint32_t mem_range, std::vector<uint64_t> &ptrs);
#endif /* PALLADIUM_DOCA_COMMON_H */
