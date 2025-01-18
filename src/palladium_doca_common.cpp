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
#include <algorithm>
#include <memory>
#include <nlohmann/detail/value_t.hpp>
#include <rdma/rdma_cma.h>
#include <stdexcept>

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
