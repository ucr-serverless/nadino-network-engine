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
    this->gid_index = cfg->nodes[this->node_id].sgid_idx;
    this->rdma_device = string(cfg->nodes[this->node_id].rdma_device);
    this->comch_server_device = string(cfg->nodes[this->node_id].comch_server_device);
    this->comch_client_device = string(cfg->nodes[this->node_id].comch_client_device);
    this->port = cfg->nodes[this->node_id].port;
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

void init_rdma_config_cb(struct gateway_ctx *g_ctx) {
    struct rdma_cb_config &cb = g_ctx->rdma_cb;
    cb.ctx_user_data = reinterpret_cast<void*>(g_ctx);



}
