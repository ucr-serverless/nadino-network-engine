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

#include "palladium_doca_common.h"
#include "common_doca.h"
#include "doca_buf_inventory.h"
#include "doca_error.h"
#include "doca_log.h"
#include "doca_rdma.h"
#include "io.h"
#include "log.h"
#include "rdma_common_doca.h"
#include "sock_utils.h"
#include "spright.h"
#include <algorithm>
#include <cstdint>
#include <memory>
#include <nlohmann/detail/value_t.hpp>
#include <rdma/rdma_cma.h>
#include <set>
#include <stdexcept>
#include <cstring>

DOCA_LOG_REGISTER(PALLADIUM_GATEWAY::COMMON);
using namespace std;

enum doca_log_level my_log_level_to_doca_log_level(enum my_log_level level) {
    switch (level) {
    case LOG_TRACE:
        return DOCA_LOG_LEVEL_TRACE;
        break;
    case LOG_DEBUG:
        return DOCA_LOG_LEVEL_DEBUG;
        break;
    case LOG_INFO:
        return DOCA_LOG_LEVEL_INFO;
        break;
    case LOG_WARN:
        return DOCA_LOG_LEVEL_WARNING;
        break;
    case LOG_ERROR:
        return DOCA_LOG_LEVEL_ERROR;
        break;
    case LOG_FATAL:
        return DOCA_LOG_LEVEL_CRIT;
        break;
    default:

        return DOCA_LOG_LEVEL_DISABLE;
    }
};

doca_error_t connect_multi_rdma_flag(struct doca_rdma *rdma, vector<struct doca_rdma_connection*> &connections, unordered_map<struct doca_rdma_connection*, struct r_connection_res> &r_conn_to_res, uint32_t n_connections,
                                                     int sock_fd, bool send_first)
{
    doca_error_t result = DOCA_SUCCESS;
    uint32_t i = 0;

    connections.clear();
    connections.reserve(n_connections);
    
    r_conn_to_res.clear();

    unique_ptr<char[]> recv_descriptor = make_unique<char[]>(MAX_RDMA_DESCRIPTOR_SZ);
    void *descriptor_ptr = nullptr;
    size_t des_sz;
    uint32_t recv_sz;
    /* 1-by-1 to setup all the connections */
    log_info("total %d connections", n_connections);
    for (i = 0; i < n_connections; i++)
    {
        log_info("Start to establish RDMA connection [%d]", i);

        /* Export RDMA connection details */
        result = doca_rdma_export(rdma, const_cast<const void**>(&(descriptor_ptr)),
                                  &(des_sz), &connections[i]);
        if (result != DOCA_SUCCESS)
        {
            log_error("Failed to export RDMA: %s", doca_error_get_descr(result));
            return result;
        }
        r_conn_to_res.insert({connections[i], {connections[i], string((char*)descriptor_ptr, des_sz)}});

        if (send_first) {
            result = sock_send_buffer(r_conn_to_res[connections[i]].descriptor.c_str(), r_conn_to_res[connections[i]].descriptor.size(), sock_fd);
            if (result != DOCA_SUCCESS)
            {
                log_error("Failed to send details from sender: %s", doca_error_get_descr(result));
                return result;
            }
            result = sock_recv_buffer((void *)recv_descriptor.get(), &recv_sz,
                                      MAX_RDMA_DESCRIPTOR_SZ, sock_fd);
            if (result != DOCA_SUCCESS)
            {
                log_error("Failed to write and read connection details from receiver: %s", doca_error_get_descr(result));
                return result;
            }

        }
        else {
            result = sock_recv_buffer((void *)recv_descriptor.get(), &recv_sz,
                                      MAX_RDMA_DESCRIPTOR_SZ, sock_fd);
            if (result != DOCA_SUCCESS)
            {
                log_error("Failed to write and read connection details from receiver: %s", doca_error_get_descr(result));
                return result;
            }
            result = sock_send_buffer(r_conn_to_res[connections[i]].descriptor.c_str(), r_conn_to_res[connections[i]].descriptor.size(), sock_fd);
            if (result != DOCA_SUCCESS)
            {
                log_error("Failed to send details from sender: %s", doca_error_get_descr(result));
                return result;
            }

        }
        // print_buffer_hex(resources->rdma_conn_descriptor, resources->rdma_conn_descriptor_size);

        // print_buffer_hex(resources->remote_rdma_conn_descriptor, resources->remote_rdma_conn_descriptor_size);

        /* Connect RDMA */
        result = doca_rdma_connect(rdma, (void*)recv_descriptor.get(),
                                   recv_sz, connections[i]);
        if (result != DOCA_SUCCESS)
            log_error("Failed to connect the sender's RDMA to the receiver's RDMA: %s",
                         doca_error_get_descr(result));

        /* Free remote connection descriptor */

        log_info("RDMA connection [%d] is establshed", i);
    }
    log_info("All [%d] RDMA connections have been establshed", n_connections);

    return result;
}
doca_error_t send_then_connect_rdma(struct doca_rdma *rdma, vector<struct doca_rdma_connection*> &connections, unordered_map<struct doca_rdma_connection*, struct r_connection_res> &r_conn_to_res, uint32_t n_connections,
                                                     int sock_fd) {
    return connect_multi_rdma_flag(rdma, connections, r_conn_to_res, n_connections, sock_fd, true);
}
doca_error_t recv_then_connect_rdma(struct doca_rdma *rdma, vector<struct doca_rdma_connection*> &connections, unordered_map<struct doca_rdma_connection*, struct r_connection_res> &r_conn_to_res, uint32_t n_connections,
                                                     int sock_fd) {
    return connect_multi_rdma_flag(rdma, connections, r_conn_to_res, n_connections, sock_fd, false);
}

doca_error_t create_doca_bufs(struct gateway_ctx *gtw_ctx, uint32_t tenant_id, uint64_t start, uint32_t mem_range, uint32_t n) {
    doca_error_t result;
    if (gtw_ctx->tenant_id_to_res.count(tenant_id) == 0) {
        log_fatal("tenant_id %u not valid", tenant_id);
        return DOCA_ERROR_UNEXPECTED;

    }
    uint32_t n_inv;
    // TODO: test inv size and n
    struct gateway_tenant_res &t_res = gtw_ctx->tenant_id_to_res[tenant_id];
    result = doca_buf_inventory_get_num_elements(t_res.inv, &n_inv);
    if (n_inv < n) {
        throw runtime_error("inv not big enough");
    }
    struct doca_buf *d_buf;
    char * ptr = nullptr;
    for (uint32_t i = 0; i < n; i++) {
        ptr = reinterpret_cast<char*>(start);
        if (gtw_ctx->ptr_to_doca_buf_res.count(start) == 0) {
            char * ptr = reinterpret_cast<char*>(start);
            result = get_buf_from_inv_with_zero_data_len(t_res.inv, t_res.mmap, ptr, mem_range, &d_buf);
            if (result != DOCA_SUCCESS)
            {
                log_error("Failed to allocate DOCA buffer to DOCA buffer inventory: %s" ,
                             doca_error_get_descr(result));
                return result;
            }
            gtw_ctx->ptr_to_doca_buf_res.insert({start, {d_buf, nullptr, tenant_id, start, mem_range}});

        }
        start += mem_range;
    }
    return DOCA_SUCCESS;

}
doca_error_t submit_rdma_recv_tasks_from_ptrs(struct doca_rdma *rdma, struct gateway_ctx *gtw_ctx, uint32_t tenant_id, uint32_t mem_range, std::vector<uint64_t> &ptrs) {
    doca_error_t result;
    if (gtw_ctx->tenant_id_to_res.count(tenant_id) == 0) {
        log_fatal("tenant_id %u not valid", tenant_id);
        return DOCA_ERROR_UNEXPECTED;

    }
    struct gateway_tenant_res &t_res = gtw_ctx->tenant_id_to_res[tenant_id];
    struct doca_buf *d_buf;
    size_t index = 0;
    struct doca_rdma_task_receive *r_task;
    union doca_data task_data;
    for (auto p: ptrs) {
        if (gtw_ctx->ptr_to_doca_buf_res.count(p) == 0) {
            char * ptr = reinterpret_cast<char*>(p);
            result = get_buf_from_inv_with_zero_data_len(t_res.inv, t_res.mmap, ptr, mem_range, &d_buf);
            if (result != DOCA_SUCCESS)
            {
                log_error("Failed to allocate DOCA buffer to DOCA buffer inventory: %s" ,
                             doca_error_get_descr(result));
                return result;
            }
            gtw_ctx->ptr_to_doca_buf_res.insert({p, {d_buf, nullptr, tenant_id, p, mem_range}});

        }
        task_data.ptr = reinterpret_cast<void*>(&gtw_ctx->ptr_to_doca_buf_res[p]);
        if (t_res.n_submitted_rr >= gtw_ctx->rr_per_ctx) {
            break;
        }

        result = submit_recv_task(rdma, d_buf, task_data, &r_task);
        t_res.n_submitted_rr++;

        gtw_ctx->ptr_to_doca_buf_res[p].rr = r_task;
        LOG_ON_FAILURE(result);
        
    }
    return DOCA_SUCCESS;

}
void gateway_ctx::print_gateway_ctx() {
    std::cout << "gateway_ctx::node_id: " << this->node_id << std::endl;

    // Print fn_id_to_res
    std::cout << "gateway_ctx::fn_id_to_res:" << std::endl;
    for (const auto& pair : this->fn_id_to_res) {
        std::cout << "  Key: " << pair.first << ", Value: { fn_id: " << pair.second.fn_id
                  << ", tenant_id: " << pair.second.tenant_id << ", node_id: " << pair.second.node_id
                  << ", comch_conn addr: " << pair.second.comch_conn << " }" << std::endl;
    }

    // Print ptr_to_doca_buf_res
    std::cout << "gateway_ctx::ptr_to_doca_buf_res:" << std::endl;
    for (const auto& pair : this->ptr_to_doca_buf_res) {
        std::cout << "  Key: " << pair.first << ", Value: { tenant_id: " << pair.second.tenant_id
                  << ", range: " << pair.second.range << ", ptr: " << pair.second.ptr
                  << ", rr addr: " << pair.second.rr << ", buf addr: " << pair.second.buf << " }" << std::endl;
    }

    // Print tenant_id_to_res
    std::cout << "gateway_ctx::tenant_id_to_res:" << std::endl;
    for (const auto& pair : this->tenant_id_to_res) {
        std::cout << "  Key: " << pair.first << ", Value: { tenant_id: " << pair.second.tenant_id
                  << ", inv addr: " << pair.second.inv << ", mmap addr: " << pair.second.mmap
                  << ", rdma_ctx addr: " << pair.second.rdma_ctx << ", rdma addr: " << pair.second.rdma << ", n_buf: " << pair.second.n_buf << ", buf_sz: " << pair.second.buf_sz
                  << " }" << std::endl;
    }

    std::cout << "gateway_ctx::route_id_to_res:" << std::endl;
    for (const auto& pair : this->route_id_to_res) {
        std::cout << "  Key: " << pair.first << ", Value: { route_id: " << pair.second.route_id << std::endl;
        cout<< "[ ";
        for (auto h: pair.second.hop) {
            cout << to_string(h) << " ";
        }
        cout<< "]" << endl;
    }


    // Print route_id_to_tenant
    std::cout << "gateway_ctx::route_id_to_tenant:" << std::endl;
    for (const auto& pair : this->route_id_to_tenant) {
        std::cout << "  Key: " << pair.first << ", Value: " << pair.second << std::endl;
    }

    std::cout << "gateway_ctx::node_id_to_res:" << std::endl;
    for (const auto& pair : this->node_id_to_res) {
        std::cout << "node_id: " << pair.first << ", Value: { node_id: " << pair.second.node_id << " , ip_addr: " << pair.second.ip_addr << " , hostname: " << pair.second.hostname << " } " << std::endl;
    }
    // Print pointer fields
    std::cout << "gateway_ctx::rdma_dev addr: " << this->rdma_dev << std::endl;
    std::cout << "gateway_ctx::rdma_pe addr: " << this->rdma_pe << std::endl;
    std::cout << "gateway_ctx::comch_pe addr: " << this->comch_pe << std::endl;
    std::cout << "gateway_ctx::comch_server addr: " << this->comch_server << std::endl;
    std::cout << "gateway_ctx::comch_dev addr: " << this->comch_dev << std::endl;
    std::cout << "gateway_ctx::comch_dev_rep addr: " << this->comch_dev_rep << std::endl;

    // Print other scalar fields
    std::cout << "gateway_ctx::gid_index: " << this->gid_index << std::endl;
    std::cout << "gateway_ctx::conn_per_ngx_worker: " << this->conn_per_ngx_worker << std::endl;
    std::cout << "gateway_ctx::conn_per_worker: " << this->conn_per_worker << std::endl;
    std::cout << "gateway_ctx::rr_per_ctx: " << this->rr_per_ctx << std::endl;
    std::cout << "gateway_ctx::max_rdma_task_per_ctx: " << this->max_rdma_task_per_ctx << std::endl;
    std::cout << "gateway_ctx::address: " << this->ip_addr << std::endl;
    std::cout << "gateway_ctx::rpc_svr_port: " << this->rpc_svr_port << std::endl;
}

gateway_ctx::gateway_ctx(struct spright_cfg_s *cfg) {
    this->node_id = cfg->local_node_idx;
    for (uint8_t i = 0; i < cfg->n_nfs; i++) {
        uint32_t nf_id = cfg->nf[i].fn_id;
        this->fn_id_to_res.insert({nf_id, {nf_id, nullptr, cfg->nf[i].tenant_id, cfg->nf[i].node}});
    }
    for (uint8_t i = 0; i < cfg->n_tenants; i++) {
        uint32_t tenant_id = cfg->tenants[i].id;
        this->tenant_id_to_res[tenant_id];
        auto& j = this->tenant_id_to_res[tenant_id];
        j.tenant_id = tenant_id;
        j.weight = cfg->tenants[i].weight;
        j.n_submitted_rr = 0;
        j.n_buf = cfg->local_mempool_size;
        j.buf_sz = cfg->local_mempool_elt_size;
        for (uint8_t k = 0; k < cfg->tenants[i].n_routes; k++) {
            uint8_t route_id = cfg->tenants[i].routes[k];
            j.routes.push_back(route_id);
            this->route_id_to_tenant[route_id] = tenant_id;
        }
    }
    for (uint8_t i = 0; i < cfg->n_routes; i++) {
        uint32_t route_id = cfg->route[i].id;
        this->route_id_to_res[route_id];
        this->route_id_to_res[route_id].route_id = route_id;
        this->route_id_to_res[route_id].hop = vector<uint32_t>(cfg->route[i].hop, cfg->route[i].hop + cfg->route[i].length);
    }
    for (uint8_t i = 0; i < cfg->n_nodes; i++) {
        uint32_t node_id = cfg->nodes[i].node_id;
        if (node_id == this->node_id) {
            continue;
        }
        this->node_id_to_res[node_id];
        this->node_id_to_res[node_id].ip_addr = string(cfg->nodes[i].ip_address);
        this->node_id_to_res[node_id].hostname = string(cfg->nodes[i].hostname);
        this->node_id_to_res[node_id].oob_skt_fd = 0;

    }
    this->gid_index = cfg->nodes[this->node_id].sgid_idx;
    this->rdma_device = string(cfg->nodes[this->node_id].rdma_device);
    this->comch_server_device = string(cfg->nodes[this->node_id].comch_server_device);
    this->comch_client_device = string(cfg->nodes[this->node_id].comch_client_device);
    this->rpc_svr_port = cfg->nodes[this->node_id].port;
    this->ip_addr = string(cfg->nodes[this->node_id].ip_address);
    this->max_rdma_task_per_ctx = cfg->rdma_n_init_task;
    this->rr_per_ctx = cfg->rdma_n_init_recv_req;

}

void add_add_to_vec(struct rte_mempool *mp, void *opaque, void *obj, unsigned int idx)
{
    std::vector<uint64_t> *vec = (std::vector<uint64_t> *)opaque;
    vec->push_back(reinterpret_cast<uint64_t>(obj));
}
pair<uint64_t, uint64_t> detect_mp_gap_and_return_range(struct rte_mempool *mp, std::vector<uint64_t> *addr) {

    set<uint64_t> gap;
    rte_mempool_obj_iter(mp, add_add_to_vec, addr);
    std::sort(addr->begin(), addr->end());
    log_info("size of vec %u", addr->size());
    for (size_t i = 1; i < addr->size(); i++) {
        // log_info("%ld", addr[i] - addr[i - 1]);
        gap.insert((*addr)[i] - (*addr)[i - 1]);
    }
    log_info("size of gaps: %u", gap.size());
    for (auto& element : gap) {
        log_info("gaps: %ld", element);
    }
    return { addr->front(), ( addr->back() - addr->front()  )+ *begin(gap) };

}

void LOG_AND_FAIL(doca_error_t &result) {
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed: %s", doca_error_get_descr(result));
        throw std::runtime_error("fail");
    }
}

void gtw_same_node_send_imm_completed_callback(struct doca_rdma_task_send_imm *send_task, union doca_data task_user_data,
                                       union doca_data ctx_user_data)
{
    // struct rdma_resources *resources = (struct rdma_resources *)ctx_user_data.ptr;
    // doca_error_t *first_encountered_error = (doca_error_t *)task_user_data.ptr;
    // struct doca_buf *src_buf = NULL;
    // doca_error_t result = DOCA_SUCCESS, tmp_result;

    // DOCA_LOG_INFO("RDMA send task was done successfully");
    //
    // src_buf = (struct doca_buf *)doca_rdma_task_send_imm_get_src_buf(send_task);
    // tmp_result = doca_buf_dec_refcount(src_buf, NULL);
    // if (tmp_result != DOCA_SUCCESS)
    // {
    //     DOCA_LOG_ERR("Failed to decrease src_buf count: %s", doca_error_get_descr(tmp_result));
    //     DOCA_ERROR_PROPAGATE(result, tmp_result);
    // }
    // TODO: find send req and potentially resubmit it
    doca_task_free(doca_rdma_task_send_imm_as_task(send_task));
}

void gtw_same_node_send_imm_completed_err_callback(struct doca_rdma_task_send_imm *send_task, union doca_data task_user_data,
                                           union doca_data ctx_user_data)
{
    // struct rdma_resources *resources = (struct rdma_resources *)ctx_user_data.ptr;
    struct doca_task *task = doca_rdma_task_send_imm_as_task(send_task);
    doca_error_t result;

    struct doca_buf *src_buf = (struct doca_buf *)doca_rdma_task_send_imm_get_src_buf(send_task);
    /* Update that an error was encountered */
    result = doca_task_get_status(task);
    DOCA_LOG_ERR("RDMA send task failed: %s", doca_error_get_descr(result));

    doca_task_free(task);
    result = doca_buf_dec_refcount(src_buf, NULL);
    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to decrease src_buf count: %s", doca_error_get_descr(result));
}

void gtw_same_node_rdma_recv_to_fn_callback(struct doca_rdma_task_receive *rdma_receive_task, union doca_data task_user_data,
                                  union doca_data ctx_user_data)
{

    // DOCA_LOG_INFO("message received");
    struct rdma_resources *resources = (struct rdma_resources *)ctx_user_data.ptr;
    doca_error_t result;
    struct doca_rdma_task_send_imm *send_task;

    const struct doca_rdma_connection *conn = doca_rdma_task_receive_get_result_rdma_connection(rdma_receive_task);

    struct doca_rdma_connection *rdma_connection = (struct doca_rdma_connection *)conn;

    // auto [src_buf, dst_buf] = conn_buf_pair[rdma_connection];
    struct doca_buf *buf = doca_rdma_task_receive_get_dst_buf(rdma_receive_task);
    if (buf == NULL)
    {
        DOCA_LOG_ERR("get src buf fail");
    }

    // DOCA_LOG_INFO("the get ptr %p, the ptr in map %p", buf, dst_buf);
    doca_buf_reset_data_len(buf);
    // print_doca_buf_len(buf);

    // resubmit tasks
    result = doca_task_submit(doca_rdma_task_receive_as_task(rdma_receive_task));
    JUMP_ON_DOCA_ERROR(result, free_task);

    // result = submit_send_imm_task(resources->rdma, rdma_connection, src_buf, 0, task_user_data, &send_task);
    JUMP_ON_DOCA_ERROR(result, free_task);
    return;

free_task:
    result = doca_buf_dec_refcount(buf, NULL);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to decrease dst_buf count: %s", doca_error_get_descr(result));
        DOCA_ERROR_PROPAGATE(result, result);
    }
    doca_task_free(doca_rdma_task_receive_as_task(rdma_receive_task));
}

void gtw_same_node_rdma_recv_err_callback(struct doca_rdma_task_receive *rdma_receive_task, union doca_data task_user_data,
                            union doca_data ctx_user_data)
{
    DOCA_LOG_ERR("rdma recv task failed");

    struct doca_task *task = doca_rdma_task_receive_as_task(rdma_receive_task);
    doca_error_t *first_encountered_error = (doca_error_t *)task_user_data.ptr;
    doca_error_t result;

    /* Update that an error was encountered */
    result = doca_task_get_status(task);
    DOCA_ERROR_PROPAGATE(*first_encountered_error, result);
    DOCA_LOG_ERR("RDMA send task failed: %s", doca_error_get_descr(result));
    struct doca_buf *dst_buf = NULL;

    dst_buf = doca_rdma_task_receive_get_dst_buf(rdma_receive_task);

    // struct rdma_resources *resources = (struct rdma_resources*)ctx_user_data.ptr;
    // DOCA_LOG_INFO("thread [%d] received [%d] recv completion, received buffer addr %p, resource-buffer, %p",
    // resources->id, resources->n_received_req, dst_buf, resources->dst_buf); print_doca_buf_len(dst_buf);
    // print_doca_buf_len(resources->dst_buf);

    result = doca_buf_dec_refcount(dst_buf, NULL);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to decrease dst_buf count: %s", doca_error_get_descr(result));
        DOCA_ERROR_PROPAGATE(result, result);
    }

    doca_task_free(task);
    // doca_error_t result;
}

void gtw_same_node_rdma_state_changed_callback(const union doca_data user_data, struct doca_ctx *ctx,
                                               enum doca_ctx_states prev_state, enum doca_ctx_states next_state)
{

    struct rdma_resources *resources = (struct rdma_resources *)user_data.ptr;
    doca_error_t result;
    char started = '1';
    (void)ctx;
    (void)prev_state;

    switch (next_state)
    {
    case DOCA_CTX_STATE_IDLE:
        DOCA_LOG_INFO("CC server context has been stopped");
        /* We can stop progressing the PE */

        resources->run_pe_progress = false;
        break;
    case DOCA_CTX_STATE_STARTING:
        /**
         * The context is in starting state, this is unexpected for CC server.
         */
        DOCA_LOG_ERR("server context entered into starting state");
        break;
    case DOCA_CTX_STATE_RUNNING:
        DOCA_LOG_INFO("RDMA server context is running. Waiting for clients to connect");
        result = rdma_multi_conn_recv_export_and_connect(resources, resources->connections, resources->cfg->n_thread,
                                                         resources->cfg->sock_fd);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_INFO("multiple connection error");
        }
        result = init_inventory(&resources->buf_inventory, resources->cfg->n_thread * 2);
        JUMP_ON_DOCA_ERROR(result, error);

        // result = rdma_multi_conn_send_prepare_and_submit_task(resources);
        JUMP_ON_DOCA_ERROR(result, error);
        // send start signal

        DOCA_LOG_INFO("sent start signal");
        sock_utils_write(resources->cfg->sock_fd, &started, sizeof(char));


        break;
    case DOCA_CTX_STATE_STOPPING:
        /**
         * The context is in stopping, this can happen when fatal error encountered or when stopping context.
         * doca_pe_progress() will cause all tasks to be flushed, and finally transition state to idle
         */
        DOCA_LOG_INFO("CC server context entered into stopping state. Terminating connections with clients");
        break;
    default:
        break;
    }
    return;

error:
    DOCA_LOG_INFO("ctx change error");
    doca_ctx_stop(ctx);
    destroy_inventory(resources->buf_inventory);
    destroy_rdma_resources(resources, resources->cfg);
    
}

void init_same_node_rdma_config_cb(struct gateway_ctx *g_ctx) {
    // the struct is defined in c, so use NULL
    struct rdma_cb_config &cb = g_ctx->rdma_cb;
    cb.ctx_user_data = reinterpret_cast<void*>(g_ctx);
    cb.data_path_mode = false;
    cb.doca_rdma_connect_request_cb = NULL;
    cb.doca_rdma_connect_established_cb = NULL;
    cb.doca_rdma_connect_failure_cb = NULL;
    cb.doca_rdma_disconnect_cb = NULL;



}

void init_cross_node_rdma_config_cb(struct gateway_ctx *g_ctx) {
    // the struct is defined in c, so use NULL
    struct rdma_cb_config &cb = g_ctx->rdma_cb;
    cb.ctx_user_data = reinterpret_cast<void*>(g_ctx);
    cb.data_path_mode = false;
    cb.doca_rdma_connect_request_cb = NULL;
    cb.doca_rdma_connect_established_cb = NULL;
    cb.doca_rdma_connect_failure_cb = NULL;
    cb.doca_rdma_disconnect_cb = NULL;



}
int oob_skt_init(struct gateway_ctx *g_ctx)
{
    uint32_t node_num = g_ctx->cfg->n_nodes;
    uint32_t self_idx = g_ctx->node_id;
    char buffer[6];
    int sock_fd = -1;
    uint32_t connected_nodes = 0;
    for (auto &i : g_ctx->node_id_to_res)
    {
        // server as a client to index lower than itself
        if (g_ctx->node_id > i.first) {
            break;
        }
        sock_fd = 0;
        do
        {
            sock_fd = sock_utils_connect(g_ctx->node_id_to_res[i.first].ip_addr.c_str(), to_string(g_ctx->rpc_svr_port).c_str());

        } while (sock_fd <= 0);

        log_info("Connected to server: %s: %u", g_ctx->node_id_to_res[i.first].ip_addr.c_str(), g_ctx->rpc_svr_port);
        g_ctx->node_id_to_res[i.first].oob_skt_fd = sock_fd;
        connected_nodes++;
    }
    log_info("connected to all servers with idx lower than %d", self_idx);
    if (connected_nodes == node_num - 1)
    {
        return 0;
    }
    // listen(g_ctx->oob_skt_sv_fd, 10);
    int peer_fd = 0;
    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len = sizeof(struct sockaddr_in);
    char client_ip[INET_ADDRSTRLEN];
    log_info("accepting connections from other nodes");
    while (connected_nodes < node_num - 1)
    {
        peer_fd = accept(g_ctx->oob_skt_sv_fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (peer_fd < 0)
        {
            continue;
        }
        // TODO: change to string comparison
        inet_ntop(AF_INET, &peer_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        string c_ip = client_ip;
        log_info("client %s connected", c_ip.c_str());
        for (auto& i : g_ctx->node_id_to_res)
        {
            if (i.second.ip_addr == c_ip)
            {
                if (i.first < g_ctx->node_id) {
                    log_error("reconnected and ignore");
                    continue;
                }
                g_ctx->node_id_to_res[i.first].oob_skt_fd = sock_fd;
                connected_nodes++;
            }
        }
    }
    log_info("control_server_socks initialized");


    for (auto &i : g_ctx->node_id_to_res)
    {
        configure_keepalive(i.second.oob_skt_fd);
    }

    return 0;
}
