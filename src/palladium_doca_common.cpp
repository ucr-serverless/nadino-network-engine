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
#include "comch_ctrl_path_common.h"
#include "common_doca.h"
#include "doca_buf.h"
#include "doca_buf_inventory.h"
#include "doca_comch.h"
#include "doca_ctx.h"
#include "doca_error.h"
#include "doca_log.h"
#include "doca_pe.h"
#include "doca_rdma.h"
#include "glib.h"
#include "http.h"
#include "io.h"
#include "log.h"
#include "rdma_common_doca.h"
#include "rte_branch_prediction.h"
#include "rte_mempool.h"
#include "sock_utils.h"
#include "spright.h"
#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <ctime>
#include <iostream>
#include <memory>
#include <nlohmann/detail/value_t.hpp>
#include <nlohmann/json_fwd.hpp>
#include <rdma/rdma_cma.h>
#include <set>
#include <stdexcept>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <fstream>

DOCA_LOG_REGISTER(PALLADIUM_GATEWAY::COMMON);
using namespace std;

void r_connection_res::print_r_conn_res() {
    log_info("ngx_id: %d, is ngx connection: %d", this->node_id, this->is_ngx_connection, this->is_ngx_connection);


}
nlohmann::json read_json_from_file(const std::string&& path) {

    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Error: Could not open file at path: " + path);
    }

    try {
        json jsonData;
        file >> jsonData;
        return jsonData;
    } catch (const std::exception& e) {
        throw std::runtime_error("Error parsing JSON file: " + std::string(e.what()));
    }
}

void expt_settings::read_from_json(json& data, uint32_t nf_id)
{
    try {
        string id = to_string(nf_id);
        log_info("get nf id [%d]", nf_id);
        if (data.contains(id) && data[id].is_object()) {
            this->batch_sz = data[id]["batch_sz"];
            this->sleep_time = data[id]["sleep_time"];
            this->bf_mode = data[id]["bf_mode"];
            this->expected_pkt = data[id]["exp_msg"];
            this->dummy_nf_expt = data["dummy_nf_expt"];
        } else {
            std::cerr << "Error: ID " << nf_id << " not found in the JSON file." << std::endl;
        }

    } catch (const std::exception& e) {
        log_error("json parsing not valid %s", e.what());
    }
}

void read_gtw_st_from_json(json& data, struct gateway_ctx *g_ctx)
{
    try {
        g_ctx->send_batch = data["send_batch"];
        g_ctx->is_dummy_nf = data["dummy_nf_expt"]==1?false:true;

    } catch (const std::exception& e) {
        log_error("json parsing not valid %s", e.what());
    }
}

void expt_settings::print_settings()
{
    cout << "batch size " << this->batch_sz << endl;
    cout << "sleep time " << this->sleep_time << endl;
    cout << "bf_mode " << this->bf_mode << endl;
    cout << "expected_msg " << this->expected_pkt << endl;
    cout << "dummy_nf_expt" << this->dummy_nf_expt << endl;

}
void timer::start_timer()
{
    int ret = clock_gettime(CLOCK_MONOTONIC_RAW, &this->start);
    this->current_second = 0;
    RUNTIME_ERROR_ON_FAIL(ret != 0, "start timer fail");
}

bool timer::is_one_second_past()
{
    // log_info("counting time");
    int ret = clock_gettime(CLOCK_MONOTONIC_RAW, &this->current);
    RUNTIME_ERROR_ON_FAIL(ret != 0, "get current time fail");
    double time_diff = calculate_timediff_sec(&this->current, &this->start);
    if (time_diff - (double)current_second > 1) {
        current_second++;
        return true;
    }
    return false;

}

// does not include spright mode
bool is_gtw_on_host(enum Palladium_mode &mode) {
    return mode == PALLADIUM_HOST_WORKER || mode == PALLADIUM_HOST;

}

bool is_use_rdma(enum Palladium_mode &mode) {
    return !(mode == SPRIGHT);

}
bool is_gtw_on_dpu(enum Palladium_mode &mode) {
    return mode == PALLADIUM_DPU || mode == PALLADIUM_DPU_WORKER;

}

void test_tenant(struct gateway_ctx *g_ctx, uint64_t tenant_id) {
    if (!g_ctx->tenant_id_to_res.count(tenant_id)) {
        throw runtime_error("tenant_id not valid" + to_string(tenant_id));
    }
}
std::pair<uint64_t, uint64_t> findMinimalDifference(const std::vector<uint64_t>& numbers, uint64_t target) {
    if (numbers.empty()) {
        throw std::invalid_argument("The vector is empty.");
    }

    uint64_t minDiff = std::numeric_limits<uint64_t>::max();
    uint64_t candidate = 0;

    for (uint64_t num : numbers) {
        uint64_t diff = (num > target) ? (num - target) : (target - num);
        if (diff != minDiff) {
            candidate = num;
        }
        minDiff = std::min(minDiff, diff);
    }

    return {candidate, minDiff};
}

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
    const void *descriptor_ptr;
    size_t des_sz;
    uint32_t recv_sz;
    /* 1-by-1 to setup all the connections */
    log_info("total %d connections", n_connections);
    for (i = 0; i < n_connections; i++)
    {
        connections.push_back(nullptr);
        log_debug("connections size: %d, current connection num: %d", connections.size(), i);
        log_info("Start to establish RDMA connection [%d]", i);

        /* Export RDMA connection details */
        result = doca_rdma_export(rdma, &(descriptor_ptr),
                                  &(des_sz), &connections[i]);
        if (result != DOCA_SUCCESS)
        {
            log_error("Failed to export RDMA: %s", doca_error_get_descr(result));
            return result;
        }
        r_conn_to_res.insert({connections[i], {connections[i], string((char*)descriptor_ptr, des_sz)}});

        if (send_first) {
            log_info("send first");
            result = sock_send_buffer(r_conn_to_res[connections[i]].descriptor.c_str(), r_conn_to_res[connections[i]].descriptor.size(), sock_fd);
            if (result != DOCA_SUCCESS)
            {
                log_error("Failed to send details from sender: %s", doca_error_get_descr(result));
                return result;
            }
            log_info("send data");
            result = sock_recv_buffer((void *)recv_descriptor.get(), &recv_sz,
                                      MAX_RDMA_DESCRIPTOR_SZ, sock_fd);
            if (result != DOCA_SUCCESS)
            {
                log_error("Failed to write and read connection details from receiver: %s", doca_error_get_descr(result));
                return result;
            }
            log_info("recv data");

        }
        else {
            log_info("recv first");
            result = sock_recv_buffer((void *)recv_descriptor.get(), &recv_sz,
                                      MAX_RDMA_DESCRIPTOR_SZ, sock_fd);
            if (result != DOCA_SUCCESS)
            {
                log_error("Failed to write and read connection details from receiver: %s", doca_error_get_descr(result));
                return result;
            }
            log_info("received data");
            result = sock_send_buffer(r_conn_to_res[connections[i]].descriptor.c_str(), r_conn_to_res[connections[i]].descriptor.size(), sock_fd);
            if (result != DOCA_SUCCESS)
            {
                log_error("Failed to send details from sender: %s", doca_error_get_descr(result));
                return result;
            }
            log_info("send data");

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

doca_error_t create_doca_bufs_from_vec(struct gateway_ctx *gtw_ctx, uint32_t tenant_id, uint32_t mem_range, vector<uint64_t> &ptrs) {
    doca_error_t result;
    if (gtw_ctx->tenant_id_to_res.count(tenant_id) == 0) {
        log_fatal("tenant_id %u not valid", tenant_id);
        return DOCA_ERROR_UNEXPECTED;

    }
    uint32_t n_inv;
    // TODO: test inv size and n
    DOCA_LOG_INFO("ptrs have %zu elements", ptrs.size());
    struct gateway_tenant_res &t_res = gtw_ctx->tenant_id_to_res[tenant_id];
    result = doca_buf_inventory_get_num_elements(t_res.inv, &n_inv);
    if (n_inv < ptrs.size()) {
        log_error("pts size %u, inventory %u", ptrs.size(), n_inv);
        throw runtime_error("inv not big enough");
    }
    struct doca_buf *d_buf;
    for (uint64_t p : ptrs) {
        if (gtw_ctx->tenant_id_to_res[tenant_id].ptr_to_doca_buf_res.count(p) == 0) {
            result = get_buf_from_inv_with_zero_data_len(t_res.inv, t_res.mmap, (char*)p, mem_range, &d_buf);
            if (result != DOCA_SUCCESS)
            {
                log_error("Failed to allocate DOCA buffer to DOCA buffer inventory: %s" ,
                             doca_error_get_descr(result));
                throw runtime_error("get buf fail");
                return result;
            }
            t_res.ptr_to_doca_buf_res.insert({p, {d_buf, nullptr, tenant_id, p, mem_range, false}});
            t_res.buf_to_ptr.insert({d_buf, p});

        }
    }
    return DOCA_SUCCESS;

}
doca_error_t create_doca_bufs(struct gateway_ctx *gtw_ctx, uint32_t tenant_id, uint32_t mem_range, uint64_t *ptrs, uint32_t n) {
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
    for (uint32_t i = 0; i < n; i++) {
        if (gtw_ctx->tenant_id_to_res[tenant_id].ptr_to_doca_buf_res.count(ptrs[i]) == 0) {
            result = get_buf_from_inv_with_zero_data_len(t_res.inv, t_res.mmap, (char*)ptrs[i], mem_range, &d_buf);
            if (result != DOCA_SUCCESS)
            {
                log_error("Failed to allocate DOCA buffer to DOCA buffer inventory: %s" ,
                             doca_error_get_descr(result));
                throw runtime_error("get buf fail");
                return result;
            };
            gtw_ctx->tenant_id_to_res[tenant_id].ptr_to_doca_buf_res.insert({ptrs[i], {d_buf, nullptr, tenant_id, ptrs[i], mem_range, false}});

        }
    }
    return DOCA_SUCCESS;

}
doca_error_t submit_rdma_recv_tasks_from_vec(struct doca_rdma *rdma, struct gateway_ctx *g_ctx, uint32_t tenant_id, uint32_t mem_range, std::vector<uint64_t> &ptrs) {
    if (!g_ctx) {
        throw runtime_error("g_ctx is empty");
    }
    if (ptrs.empty()) {
        throw runtime_error("ptrs is empty");
    }
    doca_error_t result;
    if (g_ctx->tenant_id_to_res.count(tenant_id) == 0) {
        log_fatal("tenant_id %u not valid", tenant_id);
        return DOCA_ERROR_UNEXPECTED;

    }
    struct gateway_tenant_res &t_res = g_ctx->tenant_id_to_res[tenant_id];
    struct doca_buf *d_buf;
    size_t index = 0;
    struct doca_rdma_task_receive *r_task;
    union doca_data task_data;
    for (auto p: ptrs) {
        if (!t_res.ptr_to_doca_buf_res.count(p)) {
            auto [close_ptr, diff] = findMinimalDifference(t_res.element_addr, p);
            DOCA_LOG_INFO("can't find addresses %p, minimal diff is %lu to %p", (void*)p, diff, (void*)close_ptr);
            char * ptr = reinterpret_cast<char*>(p);
            result = get_buf_from_inv_with_zero_data_len(t_res.inv, t_res.mmap, ptr, mem_range, &d_buf);
            if (result != DOCA_SUCCESS)
            {
                log_error("Failed to allocate DOCA buffer to DOCA buffer inventory: %s" ,
                             doca_error_get_descr(result));
                return result;
            }
            t_res.ptr_to_doca_buf_res.insert({p, {d_buf, nullptr, tenant_id, p, mem_range, false}});

        }
        task_data.u64 = tenant_id;
        if (t_res.n_submitted_rr >= g_ctx->rr_per_ctx) {
            break;
        }
        if (is_gtw_on_dpu(g_ctx->p_mode)) {
            t_res.ptr_to_doca_buf_res[p].in_dpu_recv_buf_pool = true;
            t_res.dpu_recv_buf_pool.push(p);
        }

        d_buf = t_res.ptr_to_doca_buf_res[p].buf;
        doca_buf_reset_data_len(d_buf);

        result = submit_recv_task(rdma, d_buf, task_data, &r_task);
        t_res.n_submitted_rr++;

        // now not useful, will be used to resubmit rr task
        g_ctx->tenant_id_to_res[tenant_id].ptr_to_doca_buf_res[p].rr = r_task;
        LOG_ON_FAILURE(result);
        
    }
    return DOCA_SUCCESS;

}
doca_error_t submit_rdma_recv_tasks_from_raw_ptrs(struct doca_rdma *rdma, struct gateway_ctx *gtw_ctx, uint32_t tenant_id, uint32_t mem_range, uint64_t* ptrs, uint32_t ptr_sz) {
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
    uint64_t p = 0;
    for (uint32_t i = 0; i < ptr_sz; i++) {
        p = ptrs[i];
        if (gtw_ctx->tenant_id_to_res[tenant_id].ptr_to_doca_buf_res.count(p) == 0) {
            char * ptr = reinterpret_cast<char*>(p);
            result = get_buf_from_inv_with_zero_data_len(t_res.inv, t_res.mmap, ptr, mem_range, &d_buf);
            if (result != DOCA_SUCCESS)
            {
                log_error("Failed to allocate DOCA buffer to DOCA buffer inventory: %s" ,
                             doca_error_get_descr(result));
                return result;
            }
            gtw_ctx->tenant_id_to_res[tenant_id].ptr_to_doca_buf_res.insert({p, {d_buf, nullptr, tenant_id, p, mem_range, false}});

        }
        task_data.u64 = tenant_id;
        if (t_res.n_submitted_rr >= gtw_ctx->rr_per_ctx) {
            break;
        }
        if (is_gtw_on_dpu(gtw_ctx->p_mode)) {
            t_res.ptr_to_doca_buf_res[p].in_dpu_recv_buf_pool = true;
            t_res.dpu_recv_buf_pool.push(p);
        }
        d_buf = t_res.ptr_to_doca_buf_res[p].buf;

        doca_buf_reset_data_len(d_buf);
        result = submit_recv_task(rdma, d_buf, task_data, &r_task);
        t_res.n_submitted_rr++;

        gtw_ctx->tenant_id_to_res[tenant_id].ptr_to_doca_buf_res[p].rr = r_task;
        LOG_ON_FAILURE(result);
        
    }
    return DOCA_SUCCESS;

}

void mm_res::print_mm_res() {
    cout<< "mm_res: { " << " ip: " << this->ip << ", port: " << this->port << ", device: " << this->device << " }" << endl;

}

void gateway_ctx::print_gateway_ctx() {

    void * ptr;
    std::cout << "gateway_ctx::node_id: " << this->node_id << std::endl;

    // Print fn_id_to_res
    std::cout << "gateway_ctx::fn_id_to_res:" << std::endl;
    for (const auto& pair : this->fn_id_to_res) {
        std::cout << "  Key: " << pair.first << ", Value: { fn_id: " << pair.second.fn_id
                  << ", tenant_id: " << pair.second.tenant_id << ", node_id: " << pair.second.node_id
                  << ", comch_conn addr: " << pair.second.comch_conn << ", nf_mode: " << nf_mode_str[static_cast<int>(pair.second.nf_mode)] << " }" << std::endl;
    }

    // Print ptr_to_doca_buf_res

    // Print tenant_id_to_res
    std::cout << "gateway_ctx::tenant_id_to_res:" << std::endl;
    for (const auto& pair : this->tenant_id_to_res) {
        std::cout << "  Key: " << pair.first << ", Value: { tenant_id: " << pair.second.tenant_id
            << ", inv addr: " << pair.second.inv << ", mmap addr: " << pair.second.mmap
            << ", rdma_ctx addr: " << pair.second.rdma_ctx << ", rdma addr: " << pair.second.rdma << ", n_buf: " << pair.second.n_buf << ", buf_sz: " << pair.second.buf_sz
            << " }" << std::endl;
        std::cout << "tenant weight: " << pair.second.weight << endl;;
        std::cout << "tenant current_credit: " << pair.second.current_credit << endl;;
        std::cout << "gateway_ctx::tenant_id_to_res::ptr_to_doca_buf_res:" << std::endl;
        // for (auto& inner_pair: pair.second.ptr_to_doca_buf_res) {
        //     std::cout << "  Key: " << inner_pair.first << ", Value: { tenant_id: " << inner_pair.second.tenant_id
        //         << ", range: " << inner_pair.second.range << ", ptr: " << inner_pair.second.ptr
        //         << ", rr addr: " << inner_pair.second.rr << ", buf addr: " << inner_pair.second.buf << " ptr_from_buf: ";
        //     if (inner_pair.second.buf) {
        //
        //         doca_buf_get_data(inner_pair.second.buf, &ptr);
        //         cout << reinterpret_cast<uint64_t>(ptr);
        //
        //     }
        //     cout << " } " << std::endl;
        //
        // }
        // cout << std::endl;
        // std::cout << "element addr: {" << std::endl;
        // for (auto &p : pair.second.element_addr) {
        //     std::cout << p << " ";
        // }
        // std::cout << " }" << std::endl;

        // cout << std::endl;
        // std::cout << "rr element addr: {" << std::endl;
        // for (auto &p : pair.second.rr_element_addr) {
        //     std::cout << p << " ";
        // }
        // std::cout << " }" << std::endl;
        // if (pair.second.task_submitted) {
        //     std::cout << "task submitted";
        // } else {
        //     std::cout << "task not submitted";
        //
        // }
        for (auto &conn_res : pair.second.r_conn_to_res) {
            cout << "conn: " << conn_res.first << "{ " << conn_res.second.conn << "node:" << conn_res.second.node_id << " is ngx " << conn_res.second.is_ngx_connection << " }" << endl;
        }
        cout<<endl;
    }

    std::cout << "gateway_ctx::route_id_to_res:" << std::endl;
    for (const auto& pair : this->route_id_to_res) {
        std::cout << "  Key: " << pair.first << ", Value: { route_id: " << pair.second.route_id << std::endl;
        cout<< "[ ";
        for (auto h: pair.second.hop) {
            cout << to_string(h) << " ";
        }
        cout<< "]" << endl;
        cout << "tenant_id: " << pair.second.tenant_id << endl;
        std::cout << " } " << endl;
    }



    std::cout << "gateway_ctx::node_id_to_res:" << std::endl;
    for (const auto& pair : this->node_id_to_res) {
        std::cout << "node_id: " << pair.first << ", Value: { node_id: " << pair.second.node_id << " , ip_addr: " << pair.second.ip_addr << " , hostname: " << pair.second.hostname << " , oob_skt " << pair.second.oob_skt_fd << ", dpu_hostname: " << pair.second.dpu_ip_addr << ", dpu_hostname: " << pair.second.dpu_ip_addr  << " } " << std::endl;
    }
 
    this->m_res.print_mm_res();


    // Print pointer fields
    std::cout << "gateway_ctx::rdma_dev addr: " << this->rdma_dev << std::endl;
    std::cout << "gateway_ctx::rdma_pe addr: " << this->rdma_pe << std::endl;
    std::cout << "gateway_ctx::comch_pe addr: " << this->comch_server_pe << std::endl;
    std::cout << "gateway_ctx::rdma_device: " << this->rdma_device << std::endl;
    std::cout << "gateway_ctx::comch_server name: " << this->comch_server_device_name << std::endl;
    std::cout << "gateway_ctx::comch_client name: " << this->comch_client_device_name << std::endl;
    std::cout << "gateway_ctx::comch_client_rep_device_name name: " << this->comch_client_rep_device_name << std::endl;
    std::cout << "gateway_ctx::comch_server addr: " << this->comch_server << std::endl;
    std::cout << "gateway_ctx::comch_dev addr: " << this->comch_server_dev << std::endl;
    std::cout << "gateway_ctx::comch_server_pe: " << this->comch_server_pe << std::endl;
    std::cout << "gateway_ctx::comch_dev_rep addr: " << this->comch_client_dev_rep << std::endl;

    // Print other scalar fields
    std::cout << "gateway_ctx::gid_index: " << this->gid_index << std::endl;
    std::cout << "gateway_ctx::conn_per_ngx_worker: " << this->conn_per_ngx_worker << std::endl;
    std::cout << "gateway_ctx::conn_per_worker: " << this->conn_per_worker << std::endl;
    std::cout << "gateway_ctx::rr_per_ctx: " << this->rr_per_ctx << std::endl;
    std::cout << "gateway_ctx::max_rdma_task_per_ctx: " << this->max_rdma_task_per_ctx << std::endl;
    std::cout << "gateway_ctx::address: " << this->ip_addr << std::endl;
    std::cout << "gateway_ctx::dpu_addr: " << this->dpu_ip_addr << std::endl;
    std::cout << "gateway_ctx::rpc_svr_port: " << this->rpc_svr_port << std::endl;
    std::cout << "gateway_ctx::gtw_fn_id: " << this->gtw_fn_id << std::endl;
    std::cout << "gateway_ctx::current_term: " << this->current_term << std::endl;
    std::cout << "gateway_ctx::should_connect_p_ing: " << this->should_connect_p_ing << std::endl;
    std::cout << "gateway_ctx::mode: " << palladium_mode_str[static_cast<int>(this->p_mode)] << std::endl;
    std::cout << "gateway_ctx::receive_req: " << this->receive_req << std::endl;
    std::cout << "gateway_ctx::send_batch: " << this->send_batch << std::endl;
}

gateway_ctx::gateway_ctx(struct spright_cfg_s *cfg) {
    this->cfg = cfg;
    this->node_id = cfg->local_node_idx;
    this->gtw_fn_id = 0;
    this->p_mode = static_cast<enum Palladium_mode>(cfg->nodes[this->node_id].mode);
    this->receive_req = cfg->nodes[this->node_id].receive_req == 1?true: false;
    for (uint8_t i = 0; i < cfg->n_nfs; i++) {
        uint32_t nf_id = cfg->nf[i].fn_id;
        this->fn_id_to_res.insert({nf_id, {nf_id, nullptr, cfg->nf[i].tenant_id, cfg->nf[i].node, static_cast<enum nf_mode>(cfg->nf[i].mode)}});
    }
    // route_res contains tenant_id so init first
    for (uint8_t i = 0; i < cfg->n_routes; i++) {
        uint32_t route_id = cfg->route[i].id;
        this->route_id_to_res[route_id];
        this->route_id_to_res[route_id].route_id = route_id;
        this->route_id_to_res[route_id].hop = vector<uint32_t>(cfg->route[i].hop, cfg->route[i].hop + cfg->route[i].length);
    }
    for (uint8_t i = 0; i < cfg->n_tenants; i++) {
        uint32_t tenant_id = cfg->tenants[i].id;
        this->tenant_id_to_res[tenant_id];
        auto& j = this->tenant_id_to_res[tenant_id];
        j.tenant_id = tenant_id;
        j.weight = cfg->tenants[i].weight;
        j.current_credit = 0;
        j.n_submitted_rr = 0;
        j.n_buf = cfg->local_mempool_size;
        j.buf_sz = cfg->local_mempool_elt_size;
        j.task_submitted = false;
        j.tenant_connected = 0;
        j.current_portion = 0;
        for (uint8_t k = 0; k < cfg->tenants[i].n_routes; k++) {
            uint8_t route_id = cfg->tenants[i].routes[k];
            j.routes.push_back(route_id);
            this->route_id_to_res[route_id].tenant_id = tenant_id;
        }
    }
    // add the route id 0 to the tenant with lowest id
    this->tenant_id_to_res.begin()->second.routes.push_back(0);
    this->route_id_to_res[0].tenant_id = this->tenant_id_to_res.begin()->second.tenant_id;

    for (uint8_t i = 0; i < cfg->n_nodes; i++) {
        uint32_t node_id = cfg->nodes[i].node_id;
        if (node_id == this->node_id) {
            continue;
        }
        this->node_id_to_res[node_id];
        this->node_id_to_res[node_id].node_id = node_id;
        this->node_id_to_res[node_id].ip_addr = string(cfg->nodes[i].ip_address);
        this->node_id_to_res[node_id].hostname = string(cfg->nodes[i].hostname);
        this->node_id_to_res[node_id].dpu_hostname = string(cfg->nodes[i].dpu_hostname);
        this->node_id_to_res[node_id].oob_skt_fd = 0;
        this->node_id_to_res[node_id].dpu_ip_addr = string(cfg->nodes[i].dpu_addr);

    }

    this->m_res.port = cfg->memory_manager.port;
    this->m_res.device = string(cfg->memory_manager.mm_device);

    this->gid_index = cfg->nodes[this->node_id].sgid_idx;
    this->rdma_device = string(cfg->nodes[this->node_id].rdma_device);
    // TODO: read from file
    this->conn_per_worker = 10;
    this->conn_per_ngx_worker = 10;
    this->rdma_device = string(cfg->nodes[this->node_id].rdma_device);

    this->comch_server_device_name = string(cfg->nodes[this->node_id].comch_server_device);
    this->comch_client_device_name = string(cfg->nodes[this->node_id].comch_client_device);
    this->comch_client_rep_device_name = string(cfg->nodes[this->node_id].comch_client_rep_device);
    this->rpc_svr_port = cfg->nodes[this->node_id].port;
    this->ip_addr = string(cfg->nodes[this->node_id].ip_address);

    this->m_res.ip = this->ip_addr;
    this->dpu_ip_addr = string(cfg->nodes[this->node_id].dpu_addr);

    this->ing_port = 8080;
    this->max_rdma_task_per_ctx = cfg->rdma_n_init_task;
    this->rr_per_ctx = cfg->rdma_n_init_recv_req;
    this->current_term = 0;
    this->should_connect_p_ing = false;

    this->gtw_json_data = read_json_from_file(string(cfg->json_path));
    this->weight_total_changed = false;
    this->total_weight = 0;
    this->received_batch = 0;
    this->total_credit = 0;

    read_gtw_st_from_json(this->gtw_json_data, this);

}

void add_addr_to_vec(struct rte_mempool *mp, void *opaque, void *obj, unsigned int idx)
{
    std::vector<uint64_t> *vec = (std::vector<uint64_t> *)opaque;
    vec->push_back(reinterpret_cast<uint64_t>(obj));
}
pair<uint64_t, uint64_t> detect_mp_gap_and_return_range(struct rte_mempool *mp, std::vector<uint64_t> *addr) {

    set<uint64_t> gap;
    rte_mempool_obj_iter(mp, add_addr_to_vec, addr);
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

// release the buffer, add it to pool
void gtw_dpu_send_imm_completed_callback(struct doca_rdma_task_send_imm *send_task, union doca_data task_user_data,
                                       union doca_data ctx_user_data)
{
    struct gateway_ctx *g_ctx = (struct gateway_ctx *)ctx_user_data.ptr;
    uint32_t tenant_id = task_user_data.u64;
    auto& t_res = g_ctx->tenant_id_to_res[tenant_id];
    
    struct doca_buf *src_buf = NULL;
    src_buf = (struct doca_buf *)doca_rdma_task_send_imm_get_src_buf(send_task);
    void *raw_ptr = NULL;
    doca_buf_get_data(src_buf, &raw_ptr);
    // recycle the element
    uint64_t p = reinterpret_cast<uint64_t>(raw_ptr);
    auto& ptr_res = t_res.ptr_to_doca_buf_res[p];
    // recycle the memory
    t_res.dpu_recv_buf_pool.push(p);
    struct doca_task *task = doca_rdma_task_send_imm_as_task(send_task);
    doca_error_t result;

    result = doca_task_get_status(task);
    DOCA_LOG_TRC("RDMA send task success: %s", doca_error_get_descr(result));

    doca_task_free(task);
}
void gtw_same_node_send_imm_completed_callback(struct doca_rdma_task_send_imm *send_task, union doca_data task_user_data,
                                       union doca_data ctx_user_data)
{
    struct gateway_ctx *g_ctx = (struct gateway_ctx *)ctx_user_data.ptr;
    uint32_t tenant_id = task_user_data.u64;
    
    struct doca_buf *src_buf = NULL;
    src_buf = (struct doca_buf *)doca_rdma_task_send_imm_get_src_buf(send_task);
    void *raw_ptr = NULL;
    doca_buf_get_data(src_buf, &raw_ptr);
    // recycle the element
    // log_info("before recycle the buf, raw ptr is %lu", raw_ptr);
    // log_info("mp_ptr, %lu", g_ctx->tenant_id_to_res[tenant_id].mp_ptr);
    rte_mempool_put(g_ctx->tenant_id_to_res[tenant_id].mp_ptr, raw_ptr);
    // log_info("after recycle the buf, raw ptr is %lu", raw_ptr);
    struct doca_task *task = doca_rdma_task_send_imm_as_task(send_task);
    doca_error_t result;

    result = doca_task_get_status(task);
    // DOCA_LOG_INFO("RDMA send task success: %s", doca_error_get_descr(result));

    doca_task_free(task);
}

void gtw_dpu_send_imm_completed_err_callback(struct doca_rdma_task_send_imm *send_task, union doca_data task_user_data,
                                           union doca_data ctx_user_data)
{
    struct gateway_ctx *g_ctx = (struct gateway_ctx *)ctx_user_data.ptr;
    uint32_t tenant_id = task_user_data.u64;
    auto& t_res = g_ctx->tenant_id_to_res[tenant_id];
    
    struct doca_buf *src_buf = NULL;
    src_buf = (struct doca_buf *)doca_rdma_task_send_imm_get_src_buf(send_task);
    void *raw_ptr = NULL;
    doca_buf_get_data(src_buf, &raw_ptr);

    uint64_t p = reinterpret_cast<uint64_t>(raw_ptr);
    auto& ptr_res = t_res.ptr_to_doca_buf_res[p];
    t_res.dpu_recv_buf_pool.push(p);

    struct doca_task *task = doca_rdma_task_send_imm_as_task(send_task);
    doca_error_t result;

    result = doca_task_get_status(task);
    DOCA_LOG_ERR("RDMA send task failed: %s", doca_error_get_descr(result));

    doca_task_free(task);
}
void gtw_same_node_send_imm_completed_err_callback(struct doca_rdma_task_send_imm *send_task, union doca_data task_user_data,
                                           union doca_data ctx_user_data)
{
    struct gateway_ctx *g_ctx = (struct gateway_ctx *)ctx_user_data.ptr;
    uint32_t tenant_id = task_user_data.u64;
    
    struct doca_buf *src_buf = NULL;
    src_buf = (struct doca_buf *)doca_rdma_task_send_imm_get_src_buf(send_task);
    void *raw_ptr = NULL;
    doca_buf_get_data(src_buf, &raw_ptr);
    // recycle the element
    rte_mempool_put(g_ctx->tenant_id_to_res[tenant_id].mp_ptr, raw_ptr);

    struct doca_task *task = doca_rdma_task_send_imm_as_task(send_task);
    doca_error_t result;

    result = doca_task_get_status(task);
    DOCA_LOG_ERR("RDMA send task failed: %s", doca_error_get_descr(result));

    doca_task_free(task);
}

int dispatch_msg_to_fn_by_fn_id(struct gateway_ctx *gtw_ctx, void* txn, uint32_t target_fn_id)
{
    int ret;

    if (gtw_ctx->fn_id_to_res[target_fn_id].node_id != cfg->local_node_idx) {
        log_error("received fn_id %zu not a local function index", target_fn_id);
        return -1;
    }
    ret = io_tx(txn, target_fn_id);
    if (unlikely(ret == -1))
    {
        log_error("io_tx() error");
        return -1;
    }

    return 0;
}

int dispatch_msg_to_fn_by_fn_id_with_comch(struct gateway_ctx *gtw_ctx, void* txn, uint32_t target_fn_id)
{
    if (!gtw_ctx->fn_id_to_res.count(target_fn_id)) {
        log_fatal("target_fn_id: %d not valid", target_fn_id);
        throw runtime_error("fn_id not valid");
    }
    auto &f_res = gtw_ctx->fn_id_to_res[target_fn_id];

    auto comch_conn = f_res.comch_conn;

    doca_error_t result;
    struct doca_comch_task_send *task;
    union doca_data data;
    data.ptr = gtw_ctx;

    // task_data is the gtw_ctx
    result = comch_server_send_msg_retry(gtw_ctx->comch_server, comch_conn, &txn, sizeof(uint64_t), data, &task);
    LOG_ON_FAILURE(result);
    return 0;
}

void gtw_dpu_rdma_recv_to_fn_callback(struct doca_rdma_task_receive *rdma_receive_task, union doca_data task_user_data,
                                  union doca_data ctx_user_data)
{

    // possible that ngx transmit data and the immediate is not fn_id, but route_id
    struct gateway_ctx *g_ctx = (struct gateway_ctx *)ctx_user_data.ptr;
    uint32_t tenant_id = task_user_data.u64;
    if (!g_ctx->tenant_id_to_res.count(tenant_id)) {
        throw runtime_error("tenant_id illegal %d" + to_string(tenant_id));
    }
    struct gateway_tenant_res &t_res = g_ctx->tenant_id_to_res[tenant_id];

    // DOCA_LOG_INFO("message received");
    doca_error_t result;

    const struct doca_rdma_connection *r_conn = doca_rdma_task_receive_get_result_rdma_connection(rdma_receive_task);


    auto& conn_res = t_res.r_conn_to_res[const_cast<struct doca_rdma_connection*>(r_conn)];

    struct doca_buf *buf = doca_rdma_task_receive_get_dst_buf(rdma_receive_task);
    if (buf == NULL)
    {
        DOCA_LOG_ERR("get src buf fail");
    }
    // TODO: add route 0 processing and just return 
    uint32_t imme = get_imme_from_task(rdma_receive_task);
    uint32_t fn_id = imme;
    if (conn_res.is_ngx_connection) {
        // online boutique experiment on forward to nf1 by default
        // dymmy nf
        fn_id = 1;

        // if (!g_ctx->is_dummy_nf) {
        //     fn_id = 1;
        // }
        // else {
        //     if (!g_ctx->route_id_to_res.count(imme)) {
        //         log_error("route [%d] not valid", imme);
        //         throw std::runtime_error("route not avaliable");
        //     }
        //     if (g_ctx->route_id_to_res[imme].hop.size() == 0) {
        //         log_error("route not legal 0 length [%d]", imme);
        //         throw std::runtime_error("route not legal");
        //
        //     }
        //     fn_id = g_ctx->route_id_to_res[imme].hop[0];
        //
        // }

    }

    // doca_buf_reset_data_len(buf);
    void * dst_ptr = NULL;
    doca_buf_get_data(buf, &dst_ptr);

    uint64_t dst_p = reinterpret_cast<uint64_t>(dst_ptr);
    log_debug("get next fn: %d, ptr: %lu", fn_id, dst_p);
    if (!t_res.ptr_to_doca_buf_res.count(dst_p)) {
        auto [close_ptr, diff] = findMinimalDifference(t_res.element_addr, dst_p);
        throw runtime_error("buf not found, minimal diff is " + to_string(diff) + ": " + to_string(close_ptr));
    }
    auto &dst_p_res = t_res.ptr_to_doca_buf_res[dst_p];


    // send to function
    dispatch_msg_to_fn_by_fn_id_with_comch(g_ctx, dst_ptr, fn_id);


    // post a new receive req
    //
    uint64_t p;

    // while (t_res.dpu_recv_buf_pool.empty()) {
    //     log_fatal("recv buf pool is empty");
    //     std::this_thread::sleep_for(std::chrono::microseconds(10));
    // }
    // because we freed the recv task at the end
    dst_p_res.rr = nullptr;
    // TODO: add the rr reuse strategy
    doca_task_free(doca_rdma_task_receive_as_task(rdma_receive_task));

    if (t_res.dpu_recv_buf_pool.empty()) {
        log_warn("The receive pool of tenant_id [%d] is empty now", tenant_id);
        return;
    }

    p = t_res.dpu_recv_buf_pool.front();
    t_res.dpu_recv_buf_pool.pop();

    if (!t_res.ptr_to_doca_buf_res.count(p)) {
        auto [close_ptr, diff] = findMinimalDifference(t_res.element_addr, p);
        throw runtime_error("buf not found, minimal diff is " + to_string(diff) + ": " + to_string(close_ptr));
    }
    auto& buf_res = t_res.ptr_to_doca_buf_res[p];

    struct doca_rdma_task_receive *recv_task;
    // data len reset
    doca_buf_reset_data_len(buf_res.buf);
    result = submit_recv_task_ignore_bad_state(t_res.rdma, buf_res.buf, task_user_data, &recv_task);
    LOG_AND_FAIL(result);

    buf_res.rr = recv_task;


    return;

}

void gtw_same_node_rdma_recv_to_fn_callback(struct doca_rdma_task_receive *rdma_receive_task, union doca_data task_user_data,
                                  union doca_data ctx_user_data)
{

    struct gateway_ctx *g_ctx = (struct gateway_ctx *)ctx_user_data.ptr;
    uint32_t tenant_id = task_user_data.u64;
    if (!g_ctx->tenant_id_to_res.count(tenant_id)) {
        throw runtime_error("tenant_id illegal %d" + to_string(tenant_id));
    }
    struct gateway_tenant_res &t_res = g_ctx->tenant_id_to_res[tenant_id];

    // DOCA_LOG_INFO("message received");
    doca_error_t result;

    const struct doca_rdma_connection *conn = doca_rdma_task_receive_get_result_rdma_connection(rdma_receive_task);

    // struct doca_rdma_connection *rdma_connection = (struct doca_rdma_connection *)conn;

    struct doca_buf *buf = doca_rdma_task_receive_get_dst_buf(rdma_receive_task);
    if (buf == NULL)
    {
        DOCA_LOG_ERR("get src buf fail");
    }
    uint32_t imme = get_imme_from_task(rdma_receive_task);

    // doca_buf_reset_data_len(buf);
    void * dst_ptr = NULL;
    doca_buf_get_data(buf, &dst_ptr);
    // log_info("get next fn: %d, ptr: %p", imme, dst_ptr);

    // send to function
    dispatch_msg_to_fn_by_fn_id(g_ctx, dst_ptr, imme);


    // post a new receive req
    struct rte_mempool *mp = g_ctx->tenant_id_to_res[tenant_id].mp_ptr;
    void *ptr = NULL;

    // get a new buffer
    int ret = rte_mempool_get(mp, &ptr);
    if (unlikely(ret != 0)) {
        DOCA_LOG_ERR("can't get new buffer, in use: %d, total: %d", rte_mempool_avail_count(mp), t_res.n_buf);
        throw std::runtime_error("no memory");
    }

    uint64_t u64_ptr = reinterpret_cast<uint64_t>(ptr);
    if (!t_res.ptr_to_doca_buf_res.count(u64_ptr)) {
        auto [close_ptr, diff] = findMinimalDifference(t_res.element_addr, u64_ptr);
        throw runtime_error("buf not found, minimal diff is " + to_string(diff) + ": " + to_string(close_ptr));
    }
    struct doca_rdma_task_receive *recv_task;
    // data len reset
    result = submit_recv_task(t_res.rdma, t_res.ptr_to_doca_buf_res[u64_ptr].buf, task_user_data, &recv_task);
    LOG_AND_FAIL(result);


    doca_task_free(doca_rdma_task_receive_as_task(rdma_receive_task));

    return;

}

void gtw_same_node_rdma_recv_err_callback(struct doca_rdma_task_receive *rdma_receive_task, union doca_data task_user_data,
                            union doca_data ctx_user_data)
{
    DOCA_LOG_ERR("rdma recv task failed");

    struct gateway_ctx *g_ctx = (struct gateway_ctx *)ctx_user_data.ptr;
    uint32_t tenant_id = task_user_data.u64;
    if (!g_ctx->tenant_id_to_res.count(tenant_id)) {
        throw runtime_error("tenant_id illegal %d" + to_string(tenant_id));
    }
    struct gateway_tenant_res &t_res = g_ctx->tenant_id_to_res[tenant_id];

    struct doca_task *task = doca_rdma_task_receive_as_task(rdma_receive_task);
    doca_error_t result;
    struct doca_buf *buf = doca_rdma_task_receive_get_dst_buf(rdma_receive_task);
    if (buf == NULL)
    {
        DOCA_LOG_ERR("get dst buf fail");
    }

    void * dst_ptr = NULL;
    doca_buf_get_data(buf, &dst_ptr);

    struct rte_mempool *mp = t_res.mp_ptr;

    rte_mempool_put(mp, dst_ptr);

    /* Update that an error was encountered */
    result = doca_task_get_status(task);
    DOCA_LOG_ERR("RDMA send task failed: %s", doca_error_get_descr(result));

    // dst_buf = doca_rdma_task_receive_get_dst_buf(rdma_receive_task);
    doca_task_free(task);
}

void gtw_dpu_rdma_recv_err_callback(struct doca_rdma_task_receive *rdma_receive_task, union doca_data task_user_data,
                            union doca_data ctx_user_data)
{
    DOCA_LOG_ERR("rdma recv task failed");

    struct gateway_ctx *g_ctx = (struct gateway_ctx *)ctx_user_data.ptr;
    uint32_t tenant_id = task_user_data.u64;
    if (!g_ctx->tenant_id_to_res.count(tenant_id)) {
        throw runtime_error("tenant_id illegal %d" + to_string(tenant_id));
    }
    struct gateway_tenant_res &t_res = g_ctx->tenant_id_to_res[tenant_id];

    struct doca_task *task = doca_rdma_task_receive_as_task(rdma_receive_task);
    doca_error_t result;

    /* Update that an error was encountered */
    result = doca_task_get_status(task);
    DOCA_LOG_ERR("RDMA send task failed: %s", doca_error_get_descr(result));

    struct doca_buf *buf = doca_rdma_task_receive_get_dst_buf(rdma_receive_task);
    if (buf == NULL)
    {
        DOCA_LOG_ERR("get dst buf fail");
    }
    void * dst_ptr = NULL;
    doca_buf_get_data(buf, &dst_ptr);

    uint64_t dst_p = reinterpret_cast<uint64_t>(dst_ptr);
    if (!t_res.ptr_to_doca_buf_res.count(dst_p)) {
        auto [close_ptr, diff] = findMinimalDifference(t_res.element_addr, dst_p);
        throw runtime_error("buf not found, minimal diff is " + to_string(diff) + ": " + to_string(close_ptr));
    }
    auto &dst_p_res = t_res.ptr_to_doca_buf_res[dst_p];


    // because we freed the recv task at the end
    dst_p_res.rr = nullptr;
    // if the buf is in the recv_buf_pool we push it, if not it is from the nf, don't use it
    t_res.dpu_recv_buf_pool.push(dst_p);
    // dst_buf = doca_rdma_task_receive_get_dst_buf(rdma_receive_task);
    doca_task_free(task);
}

// create connection between workers and post receive request
void gtw_same_node_rdma_state_changed_callback(const union doca_data user_data, struct doca_ctx *ctx,
                                               enum doca_ctx_states prev_state, enum doca_ctx_states next_state)
{

    struct gateway_ctx *g_ctx = (struct gateway_ctx *)user_data.ptr;
    DOCA_LOG_INFO("the ptr addr %p", (void*)g_ctx);
    uint32_t tenant_id = g_ctx->rdma_ctx_to_tenant_id[ctx];
    DOCA_LOG_INFO("the tenant id %u", tenant_id);

    struct gateway_tenant_res &t_res = g_ctx->tenant_id_to_res[tenant_id];
    DOCA_LOG_INFO("tenant id [%d]'s ctx is changing", tenant_id);
    (void)prev_state;
    doca_error_t result;

    switch (next_state)
    {
    case DOCA_CTX_STATE_IDLE:
        DOCA_LOG_INFO("RDMA server context from tenant [%d] has been stopped", tenant_id);

        break;
    case DOCA_CTX_STATE_STARTING:
        /**
         * The context is in starting state, this is unexpected for CC server.
         */
        DOCA_LOG_INFO("RDMA server context from tenant [%d] starting", tenant_id);
        break;
    case DOCA_CTX_STATE_RUNNING:
        DOCA_LOG_INFO("RDMA server context from tenant [%d] running", tenant_id);
        for (auto& node_res: g_ctx->node_id_to_res) {
            DOCA_LOG_INFO("connect to node: %d", node_res.first);
            // the node_id_to_res doesn't contain it self
            if (node_res.first < g_ctx->node_id) {
                result = recv_then_connect_rdma(t_res.rdma, t_res.peer_node_id_to_connections[node_res.first], t_res.r_conn_to_res, 1, g_ctx->node_id_to_res[node_res.first].oob_skt_fd);
                LOG_ON_FAILURE(result);
            }
            else if (node_res.first == g_ctx->node_id) {

                throw std::runtime_error("node_id_to_res map contains itself");
            }
            else {
                result = send_then_connect_rdma(t_res.rdma, t_res.peer_node_id_to_connections[node_res.first], t_res.r_conn_to_res, 1, g_ctx->node_id_to_res[node_res.first].oob_skt_fd);
                LOG_ON_FAILURE(result);

            }
            for (auto conn:t_res.peer_node_id_to_connections[node_res.first]) {
                t_res.r_conn_to_res[conn].node_id = node_res.first;
                t_res.r_conn_to_res[conn].is_ngx_connection = false;
            }


        }
        if (g_ctx->receive_req) {
            log_info("try connect RDMA with ngx worker");
            // use the cfg->ngx_id for default id
            // only support one ngx worker now with one connection
            t_res.ngx_wk_id_to_connections[0];
            result = recv_then_connect_rdma(t_res.rdma, t_res.ngx_wk_id_to_connections[cfg->ngx_id], t_res.r_conn_to_res, 1, g_ctx->ngx_oob_skt);
            LOG_ON_FAILURE(result);
            for (auto& conn : t_res.ngx_wk_id_to_connections[0]) {
                t_res.r_conn_to_res[conn].node_id = 0;
                t_res.r_conn_to_res[conn].is_ngx_connection = true;
                t_res.r_conn_to_res[conn].print_r_conn_res();
            }
            log_info("ngx worker connection established");

        }
        DOCA_LOG_INFO("submit rr");

        result = submit_rdma_recv_tasks_from_vec(t_res.rdma, g_ctx, tenant_id, t_res.buf_sz, t_res.rr_element_addr);
        LOG_AND_FAIL(result);
        g_ctx->tenant_id_to_res[tenant_id].task_submitted = true;
        log_info("g_ctx addr %p", g_ctx);
        g_ctx->print_gateway_ctx();

        if (t_res.task_submitted) {
            DOCA_LOG_INFO("tenant [%d] rr submitted", tenant_id);

        }
        break;
    case DOCA_CTX_STATE_STOPPING:
        /**
         * The context is in stopping, this can happen when fatal error encountered or when stopping context.
         * doca_pe_progress() will cause all tasks to be flushed, and finally transition state to idle
         */
        DOCA_LOG_INFO("RDMA server context from tenant [%d] stopping", tenant_id);
        break;
    default:
        break;
    }
    return;

    
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
    cb.send_imm_task_comp_cb = gtw_same_node_send_imm_completed_callback;
    cb.send_imm_task_comp_err_cb = gtw_same_node_send_imm_completed_err_callback;
    cb.msg_recv_cb = gtw_same_node_rdma_recv_to_fn_callback;
    cb.msg_recv_err_cb = gtw_same_node_rdma_recv_err_callback;
    cb.state_change_cb = gtw_same_node_rdma_state_changed_callback;



}

void init_dpu_rdma_config_cb(struct gateway_ctx *g_ctx) {
    // the struct is defined in c, so use NULL
    struct rdma_cb_config &cb = g_ctx->rdma_cb;
    cb.ctx_user_data = reinterpret_cast<void*>(g_ctx);
    cb.data_path_mode = false;
    cb.doca_rdma_connect_request_cb = NULL;
    cb.doca_rdma_connect_established_cb = NULL;
    cb.doca_rdma_connect_failure_cb = NULL;
    cb.doca_rdma_disconnect_cb = NULL;
    cb.send_imm_task_comp_cb = gtw_dpu_send_imm_completed_callback;
    cb.send_imm_task_comp_err_cb = gtw_dpu_send_imm_completed_err_callback;
    cb.msg_recv_err_cb = gtw_dpu_rdma_recv_err_callback;
    cb.msg_recv_cb = gtw_dpu_rdma_recv_to_fn_callback;
    cb.state_change_cb = gtw_same_node_rdma_state_changed_callback;



}
int oob_skt_init(struct gateway_ctx *g_ctx)
{
    uint32_t node_num = g_ctx->node_id_to_res.size();
    uint32_t self_idx = g_ctx->node_id;
    char buffer[6];
    int sock_fd = -1;
    uint32_t connected_nodes = 0;
    string peer_ip;
    for (auto &i : g_ctx->node_id_to_res)
    {
        // server as a client to index lower than itself
        if (g_ctx->node_id < i.first) {
            break;
        }
        sock_fd = 0;
        if (is_gtw_on_host(g_ctx->p_mode)) {
            peer_ip = g_ctx->node_id_to_res[i.first].ip_addr;
        }
        else if (is_gtw_on_dpu(g_ctx->p_mode)) {
            peer_ip = g_ctx->node_id_to_res[i.first].dpu_ip_addr;

        } else {
            throw runtime_error("not implemented");
        }
        log_debug("connect to %s", peer_ip.c_str());


        // TODO: add retry count
        do
        {
            sock_fd = sock_utils_connect(peer_ip.c_str(), to_string(g_ctx->rpc_svr_port).c_str());
             std::this_thread::sleep_for(std::chrono::seconds(3));

        } while (sock_fd <= 0);
        // if (retry == 0) {
        //     log_error("failed to Connected to server: %s: %u", g_ctx->node_id_to_res[i.first].ip_addr.c_str(), g_ctx->rpc_svr_port);
        //     return -1;
        // }

        log_info("Connected to server: %s: %u", peer_ip.c_str(), g_ctx->rpc_svr_port);
        g_ctx->node_id_to_res[i.first].oob_skt_fd = sock_fd;
        connected_nodes++;
    }
    log_info("connected to all servers with idx lower than %d", self_idx);
    if (connected_nodes == node_num)
    {
        return 0;
    }
    // listen(g_ctx->oob_skt_sv_fd, 10);
    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len = sizeof(struct sockaddr_in);
    char client_ip[INET_ADDRSTRLEN];
    log_info("accepting connections from other nodes");
    while (connected_nodes < node_num)
    {
        sock_fd = accept(g_ctx->oob_skt_sv_fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (sock_fd < 0)
        {
            continue;
        }
        inet_ntop(AF_INET, &peer_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        string c_ip = client_ip;
        log_info("client %s connected", c_ip.c_str());
        for (auto& i : g_ctx->node_id_to_res)
        {
            if (is_gtw_on_dpu(g_ctx->p_mode)) {
                if (i.second.dpu_ip_addr == c_ip)
                {
                    if (i.first < g_ctx->node_id) {
                        log_error("reconnected and ignore");
                        continue;
                    }
                    g_ctx->node_id_to_res[i.first].oob_skt_fd = sock_fd;
                    connected_nodes++;
                }

            }
            if (is_gtw_on_host(g_ctx->p_mode)) {
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
    }
    log_info("control_server_socks initialized");

    // connect socket from the ingress worker
    if (g_ctx->receive_req ) {
        log_info("wait for ngx to connect");
            sock_fd = accept(g_ctx->oob_skt_sv_fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
            if (sock_fd < 0)
            {
                log_error("skt accept fail");
            }
            inet_ntop(AF_INET, &peer_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            g_ctx->ngx_oob_skt = sock_fd;
            log_fatal("the ngx oob skt is %d", g_ctx->ngx_oob_skt);

            configure_keepalive(g_ctx->ngx_oob_skt);
            string expected_ngx_ip(cfg->ngx_ip);
            string comming_ip(client_ip);
            if (expected_ngx_ip == comming_ip) {
            }
        log_info("ngx worker skt connected");

    }
    log_info("ngx connected");

    for (auto &i : g_ctx->node_id_to_res)
    {
        configure_keepalive(i.second.oob_skt_fd);
    }

    return 0;
}

// TODO: combine with_fd_tp and this func
doca_error_t register_pe_to_ep(struct doca_pe *pe, int ep_fd,  int *pe_fd)
{
    doca_event_handle_t event_handle = doca_event_invalid_handle;
    struct epoll_event events_in;
    events_in.events = EPOLLIN;

    *pe_fd = event_handle;


    DOCA_LOG_INFO("Registering PE event");

    /* doca_event_handle_t is a file descriptor that can be added to an epoll */
    doca_error_t ret = doca_pe_get_notification_handle(pe, &event_handle);
    if (ret != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("get event handle fail");
    }

    if (epoll_ctl(ep_fd, EPOLL_CTL_ADD, event_handle, &events_in) != 0)
    {
        DOCA_LOG_ERR("Failed to register epoll, error=%d", errno);
        return DOCA_ERROR_OPERATING_SYSTEM;
    }

    return DOCA_SUCCESS;
}
// deprecat soon
doca_error_t register_pe_to_ep_with_fd_tp(struct doca_pe *pe, int ep_fd, struct fd_ctx_t *fd_tp, struct gateway_ctx *g_ctx)
{
    doca_event_handle_t event_handle = doca_event_invalid_handle;
    struct epoll_event events_in;
    events_in.events = EPOLLIN;
    events_in.data.ptr = reinterpret_cast<void*>(fd_tp);

    fd_tp->sockfd = event_handle;
    g_ctx->fd_to_fd_ctx[event_handle] = fd_tp;

    DOCA_LOG_INFO("Register PE event");

    /* doca_event_handle_t is a file descriptor that can be added to an epoll */
    doca_error_t ret = doca_pe_get_notification_handle(pe, &event_handle);
    if (ret != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("get event handle fail");
    }

    fd_tp->sockfd = event_handle;
    if (epoll_ctl(ep_fd, EPOLL_CTL_ADD, event_handle, &events_in) != 0)
    {
        DOCA_LOG_ERR("Failed to register epoll, error=%d", errno);
        return DOCA_ERROR_OPERATING_SYSTEM;
    }

    return DOCA_SUCCESS;
}

// inter node send
int rdma_send(struct http_transaction *txn, struct gateway_ctx *g_ctx, uint32_t tenant_id)
{
    // log_info("send using rdma!!!!");
    int ret;

    test_tenant(g_ctx, tenant_id);
    struct gateway_tenant_res &t_res = g_ctx->tenant_id_to_res[tenant_id];
    uint32_t next_fn = txn->next_fn;
    if (!g_ctx->fn_id_to_res.count(next_fn)) {
        log_error("invalid next_fn: %d", next_fn);
        return -1;
    }
    uint64_t u64_ptr = reinterpret_cast<uint64_t>(txn);

    uint32_t next_node_id = g_ctx->fn_id_to_res[next_fn].node_id;
    if (!t_res.peer_node_id_to_connections.count(next_node_id)) {
        log_error("invalid next_node: %d", next_node_id);
        return -1;
    }

    // just use the first connection now
    // TODO: use different connections
    struct doca_rdma_connection *conn = t_res.peer_node_id_to_connections[next_node_id][0];

    if (!t_res.ptr_to_doca_buf_res.count(u64_ptr)) {
        log_error("invalid next_node: %d", next_node_id);
        return -1;
    }
    struct doca_buf * buf = t_res.ptr_to_doca_buf_res[u64_ptr].buf;

    struct doca_rdma_task_send_imm *task;

    union doca_data data;
    data.u64 = tenant_id;

    // set the buf data ptr to be all data
    // size_t len = 0;
    // doca_buf_get_len(buf, &len);
        doca_buf_set_data_len(buf, sizeof(struct http_transaction));

    doca_error_t result = submit_send_imm_task_ignore_bad_state(t_res.rdma, conn, buf, next_fn, data, &task);
    if (result != DOCA_SUCCESS) {
        log_error("submit send imme task fail");
        return -1;
    }
    // log_info("send success");

    

    return 0;
}

int dpu_gateway_rx(void *arg)
{
    log_debug("DPU rx");
    struct gateway_ctx *g_ctx = (struct gateway_ctx*)arg;

    while (true)
    {
        doca_pe_progress(g_ctx->rdma_pe);
    }

    return 1;
    log_debug("rx return");
}

int dpu_gateway_tx(void *arg)
{
    log_debug("DPU tx");
    struct gateway_ctx *g_ctx = (struct gateway_ctx*)arg;
    log_info("comch_server_pe: %p, rdma_pe: %p", g_ctx->comch_server_pe, g_ctx->rdma_pe);

    while (true)
    {
        doca_pe_progress(g_ctx->comch_server_pe);
    }
    return 1;

    log_debug("tx return");
}

int dpu_gateway_tx_expt(void *arg)
{
    log_debug("DPU tx");
    struct gateway_ctx *g_ctx = (struct gateway_ctx*)arg;
    log_info("comch_server_pe: %p, rdma_pe: %p", g_ctx->comch_server_pe, g_ctx->rdma_pe);
    g_ctx->g_timer.start_timer();


    for (auto& i: g_ctx->tenant_id_to_res) {
        log_info("tenant [%d], weight: %u, credit %u", i.first, i.second.weight, i.second.current_credit);
    }

    vector<int> rps(g_ctx->tenant_id_to_res.size(), 0);

    // in this mode we only have one pe, rdma also use the comch_server_pe
    while (true)
    {
        // while (g_ctx->received_batch < g_ctx->send_batch) {
        // only one event comes a time.
        doca_pe_progress(g_ctx->comch_server_pe);
        // }
        schedule_and_send(g_ctx);
        // dummy_schedule_and_send(g_ctx);
        bool is_print = g_ctx->g_timer.is_one_second_past();
        if (g_ctx->p_mode == PALLADIUM_DPU && is_print) {
            int idx = 0;
            for(auto& i : g_ctx->tenant_id_to_res) {
                rps[idx] = i.second.pkt_in_last_sec;
                idx++;
                i.second.pkt_in_last_sec = 0;
            }
            DOCA_LOG_INFO("%d,%d,%d,%d", g_ctx->g_timer.current_second, rps[0], rps[1], rps[2]);
        }
    }
    log_debug("tx return");
    return 1;

}

void gateway_comch_state_changed_callback(const union doca_data user_data, struct doca_ctx *ctx,
                                                enum doca_ctx_states prev_state, enum doca_ctx_states next_state)
{

    struct gateway_ctx *g_ctx = (struct gateway_ctx *)user_data.ptr;
    (void)ctx;
    (void)prev_state;

    switch (next_state)
    {
    case DOCA_CTX_STATE_IDLE:
        DOCA_LOG_INFO("CC server context has been stopped");
        /* We can stop progressing the PE */

        break;
    case DOCA_CTX_STATE_STARTING:
        /**
         * The context is in starting state, this is unexpected for CC server.
         */
        DOCA_LOG_ERR("server context entered into starting state");
        break;
    case DOCA_CTX_STATE_RUNNING:
        DOCA_LOG_INFO("CC server context is running. Waiting for clients to connect");

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
}

void gateway_disconnection_event_callback(struct doca_comch_event_connection_status_changed *event,
                                         struct doca_comch_connection *comch_conn, uint8_t change_success)
{

    log_error("comch disconnected");

    (void)event;
    (void)change_success;
    struct doca_comch_server *comch_server = doca_comch_server_get_server_ctx(comch_conn);
    union doca_data data;
    //
    doca_error_t result = doca_ctx_get_user_data(doca_comch_server_as_ctx(comch_server), &data);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("get user data fail");
    }

    struct gateway_ctx* g_ctx = (struct gateway_ctx*)data.u64;


    if (!g_ctx->comch_conn_to_res.count(comch_conn)) {
        log_error("can not find the comch conn");
        return;
    }
    uint32_t tenant_id = g_ctx->comch_conn_to_res[comch_conn].tenant_id;
    g_ctx->tenant_id_to_res[tenant_id].tenant_connected = 0;
    g_ctx->weight_total_changed = true;
    g_ctx->total_credit -= g_ctx->tenant_id_to_res[tenant_id].current_credit;
    g_ctx->tenant_id_to_res[tenant_id].current_credit = 0;
}

void gateway_connection_event_callback(struct doca_comch_event_connection_status_changed *event,
                                      struct doca_comch_connection *comch_conn, uint8_t change_success)
{
    (void)event;
    (void)change_success;
    DOCA_LOG_INFO("client connected");
    struct doca_comch_server *comch_server = doca_comch_server_get_server_ctx(comch_conn);
    union doca_data data;

    // the connection user data is set in the cb config
    // it is the *g_cfg
    doca_error_t result = doca_ctx_get_user_data(doca_comch_server_as_ctx(comch_server), &data);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("get user data fail");
    }
    result = doca_comch_connection_set_user_data(comch_conn, data);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("set connection user data fail");
    }
}

// add message to the queue
void gateway_message_recv_expt_callback(struct doca_comch_event_msg_recv *event, uint8_t *recv_buffer, uint32_t msg_len,
                                  struct doca_comch_connection *comch_connection)
{
    doca_error_t result;

    uint32_t fn_id;
    struct doca_rdma_task_send_imm *send_task;
    struct doca_buf *buf;
    struct doca_rdma_connection *conn;
    uint32_t tenant_id;
    uint32_t node_id;
    // when new connection arrive set to be g_ctx
    union doca_data user_data = doca_comch_connection_get_user_data(comch_connection);
    struct gateway_ctx *g_ctx = (struct gateway_ctx *)user_data.ptr;
    union doca_data r_ctx_data;
    // r_ctx_data.u64 = tenant_id;
    // struct doca_comch_client *comch_client = doca_comch_client_get_client_ctx(comch_connection);
    // save the connection for send back

    (void)event;
    RUNTIME_ERROR_ON_FAIL(msg_len != sizeof(struct comch_msg), "msg len error");
    struct comch_msg *msg = (struct comch_msg*)recv_buffer;
    log_debug("received ptr: %llu, next_fn: %u, ng_id: %u", msg->ptr, msg->next_fn, msg->ngx_id);
    if (msg->next_fn == 0 && msg->ptr == 0) {
        log_info("received connection from fn [%d]", msg->ngx_id);
        fn_id = msg->ngx_id;
        if (!g_ctx->fn_id_to_res.count(fn_id)) {
            throw runtime_error("fn id not valid");
        }
        struct fn_res &f_res = g_ctx->fn_id_to_res[fn_id];
        f_res.comch_conn = comch_connection;
        g_ctx->comch_conn_to_res[comch_connection];
        g_ctx->comch_conn_to_res[comch_connection].tenant_id = f_res.tenant_id;
        g_ctx->comch_conn_to_res[comch_connection].fn_id = fn_id;
        tenant_id = f_res.tenant_id;

        g_ctx->tenant_id_to_res[tenant_id].tenant_connected = 1;
        g_ctx->weight_total_changed = true;
        uint32_t weight = g_ctx->tenant_id_to_res[tenant_id].weight;
        g_ctx->tenant_id_to_res[tenant_id].current_credit = weight;
        g_ctx->total_credit += weight;
        return;
    }

    if (!g_ctx->comch_conn_to_res.count(comch_connection)) {
        throw runtime_error("unknown comch connection");
    }
    tenant_id = g_ctx->comch_conn_to_res[comch_connection].tenant_id;
    log_debug("tenant id is %d", tenant_id);
    r_ctx_data.u64 = tenant_id;
    struct gateway_tenant_res &t_res = g_ctx->tenant_id_to_res[tenant_id];
    if (!t_res.ptr_to_doca_buf_res.count(msg->ptr)) {
        throw runtime_error("ptr not valid");

    }
    buf = t_res.ptr_to_doca_buf_res[msg->ptr].buf;
    log_debug("buf ptr: %llu", msg->ptr);

    t_res.tenant_send_queue.emplace(msg->ptr, msg->next_fn, msg->ngx_id);
    g_ctx->received_batch++;
    return;


    /* DOCA_LOG_INFO("Message received: '%.*s'", (int)msg_len, recv_buffer); */
    // DOCA_LOG_INFO("send task requires %f", calculate_timediff_usec(&end, &start));
    // if (result != DOCA_SUCCESS)
    // {
    //     DOCA_LOG_ERR("failed to send pong");
    // }
}

void dispatch(struct gateway_ctx *g_ctx, struct comch_msg *msg, struct gateway_tenant_res &t_res, uint32_t tenant_id) {

    log_debug("dispatch");

    uint32_t fn_id = msg->next_fn;
    uint32_t node_id = g_ctx->fn_id_to_res[fn_id].node_id;
    auto buf = t_res.ptr_to_doca_buf_res[msg->ptr].buf;
    struct doca_rdma_connection *conn;
    union doca_data r_ctx_data;
    r_ctx_data.u64 = tenant_id;

    struct doca_rdma_task_send_imm *send_task;
    doca_error_t result;
    if (t_res.peer_node_id_to_connections[node_id].empty()) {
        log_error("no connection to peer node");
        return;
    }
    if (msg->next_fn == 0) {
        log_info("return to ngx");

        if (t_res.ngx_wk_id_to_connections[cfg->ngx_id].empty()) {
            log_error("no connection to ngx");
            return;
        }
        conn = t_res.ngx_wk_id_to_connections[cfg->ngx_id][0];
    }
    else {
        fn_id = msg->next_fn;
        node_id = g_ctx->fn_id_to_res[fn_id].node_id;
        if (t_res.peer_node_id_to_connections[node_id].empty()) {
            log_error("no connection to peer node");
            return;
        }
        conn = t_res.peer_node_id_to_connections[node_id][0];

    }
        doca_buf_set_data_len(buf, sizeof(struct http_transaction));


    // count how many pkt been send out

    result = submit_send_imm_task_ignore_bad_state(t_res.rdma, conn, buf, msg->next_fn, r_ctx_data, &send_task);
    LOG_ON_FAILURE(result);
    LOG_AND_FAIL(result);

}

void dummy_schedule_and_send(struct gateway_ctx *g_ctx) {
    for (auto& i: g_ctx->tenant_id_to_res) {
        // log_debug("credit for tenant [%d] before schedule: %u", i.first, i.second.current_credit);
        auto& t_res = i.second;
        while (!t_res.tenant_send_queue.empty()) {
            struct comch_msg msg = t_res.tenant_send_queue.front();
            t_res.tenant_send_queue.pop();
            // potentially send by a batch
            log_debug("dispath tenant[%u]: p: %lu", i.first, msg.ptr);
            dispatch(g_ctx, &msg, t_res, i.first);
            t_res.pkt_in_last_sec++;

        }
        // log_debug("current credit for tenant [%d] after schedule, %u", i.first, i.second.current_credit);
    }
}
void schedule_and_send(struct gateway_ctx *g_ctx) {
    uint32_t send_cnt_this_time;
    // // clear the batch counter
    // g_ctx->received_batch = 0;
    // if (g_ctx->weight_total_changed) {
    //     g_ctx->weight_total_changed = false;
    //     g_ctx->total_weight = 0;
    //     for (auto &i: g_ctx->tenant_id_to_res) {
    //         if (i.second.tenant_connected == 1) {
    //             g_ctx->total_weight += i.second.weight;
    //
    //         }
    //     }
    //     for (auto &i: g_ctx->tenant_id_to_res) {
    //         if (i.second.tenant_connected == 1) {
    //             i.second.current_portion = g_ctx->send_batch * i.second.weight / g_ctx->total_weight;
    //         }
    //         else {
    //             i.second.current_portion = 0;
    //         }
    //         log_info("tenant [%d] portion: %u", i.first, i.second.current_portion);
    //     }
    //
    // }
    for (auto& i: g_ctx->tenant_id_to_res) {
        // log_debug("credit for tenant [%d] before schedule: %u", i.first, i.second.current_credit);
        auto& t_res = i.second;
        send_cnt_this_time = min(i.second.current_credit, (uint32_t)t_res.tenant_send_queue.size());
        if (send_cnt_this_time == 0) {
            goto next_tenant;
        }
        // log_info("queue size for tenant_id [%d] is %u", i.first, t_res.tenant_send_queue.size());
        // TODO: don't do deficit first
        // if (send_cnt_this_time == 0) {
        //     t_res.current_credit = min(t_res.current_credit + 1, t_res.weight);
        //     goto next_tenant;
        // }
        for (uint32_t j = 0; j < send_cnt_this_time; j++) {
            struct comch_msg msg = t_res.tenant_send_queue.front();
            t_res.tenant_send_queue.pop();
            // potentially send by a batch
            // log_debug("dispath tenant[%u]: p: %lu", i.first, msg.ptr);
            dispatch(g_ctx, &msg, t_res, i.first);
            t_res.pkt_in_last_sec++;

        }
//         t_res.current_credit -= send_cnt_this_time;
next_tenant:
        g_ctx->total_credit -= send_cnt_this_time;
        i.second.current_credit -= send_cnt_this_time;
        if (g_ctx->total_credit == 0) {
            for (auto &j: g_ctx->tenant_id_to_res) {
                if (j.second.tenant_connected == 1) {
                    j.second.current_credit = j.second.weight;
                    g_ctx->total_credit += j.second.weight;
                }
            }

        }
        continue;
        // log_debug("current credit for tenant [%d] after schedule, %u", i.first, i.second.current_credit);
    }
}

void gateway_message_recv_callback(struct doca_comch_event_msg_recv *event, uint8_t *recv_buffer, uint32_t msg_len,
                                  struct doca_comch_connection *comch_connection)
{
    doca_error_t result;

    uint32_t fn_id;
    struct doca_rdma_task_send_imm *send_task;
    struct doca_buf *buf;
    struct doca_rdma_connection *conn;
    uint32_t tenant_id;
    uint32_t node_id;
    // when new connection arrive set to be g_ctx
    union doca_data user_data = doca_comch_connection_get_user_data(comch_connection);
    struct gateway_ctx *g_ctx = (struct gateway_ctx *)user_data.ptr;
    union doca_data r_ctx_data;
    // r_ctx_data.u64 = tenant_id;
    // struct doca_comch_client *comch_client = doca_comch_client_get_client_ctx(comch_connection);
    // save the connection for send back

    (void)event;
    RUNTIME_ERROR_ON_FAIL(msg_len != sizeof(struct comch_msg), "msg len error");
    struct comch_msg *msg = (struct comch_msg*)recv_buffer;
    log_debug("received ptr: %llu, next_fn: %u, ng_id: %u", msg->ptr, msg->next_fn, msg->ngx_id);
    if (msg->next_fn == 0 && msg->ptr == 0) {
        log_info("received connection from fn [%d]", msg->ngx_id);
        fn_id = msg->ngx_id;
        if (!g_ctx->fn_id_to_res.count(fn_id)) {
            throw runtime_error("fn id not valid");
        }
        struct fn_res &f_res = g_ctx->fn_id_to_res[fn_id];
        f_res.comch_conn = comch_connection;
        g_ctx->comch_conn_to_res[comch_connection];
        g_ctx->comch_conn_to_res[comch_connection].tenant_id = f_res.tenant_id;
        g_ctx->comch_conn_to_res[comch_connection].fn_id = fn_id;
        return;
    }

    if (!g_ctx->comch_conn_to_res.count(comch_connection)) {
        throw runtime_error("unknown comch connection");
    }
    tenant_id = g_ctx->comch_conn_to_res[comch_connection].tenant_id;
    log_debug("tenant id is %d", tenant_id);
    r_ctx_data.u64 = tenant_id;
    struct gateway_tenant_res &t_res = g_ctx->tenant_id_to_res[tenant_id];
    if (!t_res.ptr_to_doca_buf_res.count(msg->ptr)) {
        throw runtime_error("ptr not valid");

    }
    buf = t_res.ptr_to_doca_buf_res[msg->ptr].buf;
    log_debug("buf ptr: %llu", msg->ptr);

    // only connect one ngx worker 0
    if (msg->next_fn == 0) {
        log_info("return to ngx");

        if (t_res.ngx_wk_id_to_connections[cfg->ngx_id].empty()) {
            log_error("no connection to ngx");
            return;
        }
        conn = t_res.ngx_wk_id_to_connections[cfg->ngx_id][0];
    }
    else {
        fn_id = msg->next_fn;
        node_id = g_ctx->fn_id_to_res[fn_id].node_id;
        if (t_res.peer_node_id_to_connections[node_id].empty()) {
            log_error("no connection to peer node");
            return;
        }
        conn = t_res.peer_node_id_to_connections[node_id][0];
    }


        doca_buf_set_data_len(buf, sizeof(struct http_transaction));

    // t_res.pkt_in_last_sec++;
    result = submit_send_imm_task_ignore_bad_state(t_res.rdma, conn, buf, msg->next_fn, r_ctx_data, &send_task);
    LOG_AND_FAIL(result);


    /* DOCA_LOG_INFO("Message received: '%.*s'", (int)msg_len, recv_buffer); */
    // DOCA_LOG_INFO("send task requires %f", calculate_timediff_usec(&end, &start));
    // if (result != DOCA_SUCCESS)
    // {
    //     DOCA_LOG_ERR("failed to send pong");
    // }
}
void init_comch_server_cb_tenant_expt(struct gateway_ctx *g_ctx) {
    log_info("tenant expt cb");
    struct comch_cb_config &cb_cfg = g_ctx->comch_server_cb;
    cb_cfg.data_path_mode = false;
    cb_cfg.ctx_user_data = (void*)g_ctx;
    cb_cfg.send_task_comp_cb = basic_send_task_completion_callback;
    cb_cfg.send_task_comp_err_cb = basic_send_task_completion_err_callback;
    // TODO: change
    cb_cfg.msg_recv_cb = gateway_message_recv_expt_callback;
    cb_cfg.new_consumer_cb = nullptr;
    cb_cfg.expired_consumer_cb = nullptr;
    cb_cfg.ctx_state_changed_cb = gateway_comch_state_changed_callback;
    cb_cfg.server_connection_event_cb = gateway_connection_event_callback;
    cb_cfg.server_disconnection_event_cb = gateway_disconnection_event_callback;


}

// use this callback for the online boutique
void init_comch_server_cb(struct gateway_ctx *g_ctx) {
    log_info("normal expt cb");
    struct comch_cb_config &cb_cfg = g_ctx->comch_server_cb;
    cb_cfg.data_path_mode = false;
    cb_cfg.ctx_user_data = (void*)g_ctx;
    cb_cfg.send_task_comp_cb = basic_send_task_completion_callback;
    cb_cfg.send_task_comp_err_cb = basic_send_task_completion_err_callback;
    // TODO: change
    cb_cfg.msg_recv_cb = gateway_message_recv_callback;
    cb_cfg.new_consumer_cb = nullptr;
    cb_cfg.expired_consumer_cb = nullptr;
    cb_cfg.ctx_state_changed_cb = gateway_comch_state_changed_callback;
    cb_cfg.server_connection_event_cb = gateway_connection_event_callback;
    cb_cfg.server_disconnection_event_cb = gateway_disconnection_event_callback;


}


