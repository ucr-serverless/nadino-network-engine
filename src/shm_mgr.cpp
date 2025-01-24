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

#include <algorithm>
#include <complex>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <set>
#include <stdexcept>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
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
#include "control_server.h"
#include "doca_error.h"
#include "http.h"
#include "ib.h"
#include "io.h"
#include "log.h"
#include "rdma_config.h"
#include "sock_utils.h"
#include "spright.h"
#include "utility.h"
#include "common_doca.h"
#include <unordered_map>
#include <vector>
#include <ranges>
#include "rdma_common_doca.h"
#include "palladium_doca_common.h"

DOCA_LOG_REGISTER(MEMORY_MANAGER::MAIN);

using namespace std;




struct tenant_res {
    uint32_t id;
    unique_ptr<char[]> mempool_descriptor;
    struct rte_mempool *mempool;
    string mempool_name;
    struct doca_mmap *mp_mmap;
    unique_ptr<void*[]> buf_ptrs;
    unique_ptr<void*[]> receive_request_ptrs;
    uint64_t start;
    uint64_t range;


    void set_id(uint32_t id) {
        this->id = id;
        this->mempool_name = mempool_prefix + to_string(id);
        cout << this->mempool_name << endl;
    }
    ~tenant_res() {
        if (this->mempool != nullptr) {
            rte_mempool_free(this->mempool);
        }
        log_info("%d mp destroied", this->id);
    }

};

struct mm_ctx : public gateway_ctx {
    struct doca_dev *mm_dev; /* DOCA device */
    struct doca_pe *mm_pe;           /* DOCA progress engine */
    int mm_svr_skt;

    unordered_map<uint32_t, struct tenant_res> mm_tenant_id_to_res;

    mm_ctx(struct spright_cfg_s* cfg): gateway_ctx(cfg) {};
};

struct mm_ctx *m_ctx;

doca_error_t allocate_host_export_res(struct mm_ctx *m_ctx)
{
    doca_error_t result;
    result = open_rdma_device_and_pe(m_ctx->m_res.device.c_str(), &m_ctx->mm_dev, &m_ctx->mm_pe);
    LOG_AND_FAIL(result);

    for (auto &i : m_ctx->mm_tenant_id_to_res) {
        result = create_two_side_mmap_from_local_memory(&i.second.mp_mmap, reinterpret_cast<void*>(i.second.start), reinterpret_cast<size_t>(i.second.range), m_ctx->mm_dev);
        if (result != DOCA_SUCCESS)
        {
            DOCA_LOG_ERR("Failed to create DOCA mmap: %s", doca_error_get_descr(result));
            throw std::runtime_error("create mmap failed");
        }

    }

    return result;
}

// init the local mempool inside cfg compatible with old code(skt baseline)
static int init_cfg_local_mempool(void) {
    cfg->mempool = rte_mempool_create(SPRIGHT_MEMPOOL_NAME, cfg->local_mempool_size, cfg->local_mempool_elt_size, 0, 0, NULL,
                                      NULL, NULL, NULL, rte_socket_id(), 0);
    if (unlikely(cfg->mempool == NULL))
    {
        log_error("rte_mempool_create() error: %s", rte_strerror(rte_errno));
        return -1;
    }
    return 0;

}



static int cfg_exit(void)
{
    if (cfg->mempool)
    {
        rte_mempool_free(cfg->mempool);
        cfg->mempool = NULL;
    }
    return 0;
}

static int shm_mgr(char *cfg_file)
{
    const struct rte_memzone *memzone = NULL;
    int ret;
    int gateway_fd = 0;
    struct sockaddr_in peer_addr;
    vector<uint64_t> addr;
    set<uint64_t> gaps;

    socklen_t peer_addr_len = sizeof(struct sockaddr_in);

    fn_id = -1;

    memzone = rte_memzone_reserve(MEMZONE_NAME, sizeof(*cfg), rte_socket_id(), 0);
    if (unlikely(memzone == NULL))
    {
        log_error("rte_memzone_reserve() error: %s", rte_strerror(rte_errno));
        return -1;
    }

    memset(memzone->addr, 0U, sizeof(*cfg));

    cfg = (struct spright_cfg_s *)memzone->addr;

    ret = cfg_init(cfg_file, cfg);
    if (unlikely(ret == -1))
    {
        log_error("cfg_init() error");
        return -1;
    }

    struct mm_ctx real_m_ctx(cfg);
    m_ctx = &real_m_ctx;

    if (m_ctx->p_mode == SPRIGHT) {
        log_info("does not use rdma");
        ret = init_cfg_local_mempool();
        JUMP_ON_PE_FAILURE(ret, -1, "mempool init fail", error);
        auto [start, end] = detect_mp_gap_and_return_range(cfg->mempool, &addr);
        log_info("start addr %p, end addr %p", start, end);
        // rte_mempool_obj_iter(cfg->mempool, add_add_to_vec, &addr);
        // std::sort(addr.begin(), addr.end());
        // log_info("size of vec %u", addr.size());
        // for (size_t i = 1; i < addr.size(); i++) {
        //     // log_info("%ld", addr[i] - addr[i - 1]);
        //     gaps.insert(addr[i] - addr[i - 1]);
        // }
        // log_info("size of gaps: %u", gaps.size());
        // for (auto& element : gaps) {
        //     log_info("gaps: %ld", element);
        // }



    }
    else {
        // allocate tenant res
        for (size_t i = 0; i < cfg->n_tenants; i++) {

            uint32_t id = cfg->tenants[i].id;
            addr.clear();
            struct tenant_res ts(id);
            m_ctx->mm_tenant_id_to_res[id];

            auto &t_res = m_ctx->mm_tenant_id_to_res[id];
            t_res.set_id(id);

            t_res.mempool = rte_mempool_create(t_res.mempool_name.c_str(), cfg->local_mempool_size, cfg->local_mempool_elt_size, 0, 0, NULL, NULL, NULL, NULL, rte_socket_id(), 0);
            if (!t_res.mempool) {
                throw runtime_error("mp error");
            }

            t_res.mempool_descriptor = make_unique<char[]>(MAX_RDMA_DESCRIPTOR_SZ);
            t_res.buf_ptrs = make_unique<void*[]>(cfg->local_mempool_size);

            retrieve_mempool_addresses(t_res.mempool, t_res.buf_ptrs.get());


            if (m_ctx->p_mode == PALLADIUM_DPU_WORKER) {

                t_res.receive_request_ptrs = make_unique<void*[]>(cfg->local_mempool_size/2);
                ret = rte_mempool_get_bulk(t_res.mempool, t_res.receive_request_ptrs.get(), cfg->local_mempool_size/2);
                RUNTIME_ERROR_ON_FAIL(ret != 0, "get bulk fail");

            }
            if (m_ctx->p_mode == PALLADIUM_DPU) {
                t_res.receive_request_ptrs = make_unique<void*[]>(cfg->local_mempool_size);
                ret = rte_mempool_get_bulk(t_res.mempool, t_res.receive_request_ptrs.get(), cfg->local_mempool_size);
                RUNTIME_ERROR_ON_FAIL(ret != 0, "get bulk fail");

            }
            auto [start, end] = detect_mp_gap_and_return_range(t_res.mempool, &addr);
            t_res.start = start;
            t_res.range = end;
            log_info("start addr %p, range %u", start, end);
        }



    }
    log_info("mempool inited");

    if (is_gtw_on_dpu(m_ctx->p_mode)) {
        m_ctx->mm_svr_skt = create_server_socket(m_ctx->m_res.ip.c_str(), (int)m_ctx->m_res.port);
        if (unlikely(m_ctx->mm_svr_skt == -1))
        {
            log_error("socket() error: %s", strerror(errno));
            return -1;
        }
        listen(m_ctx->mm_svr_skt, 5);
        log_info("listen to connection from gateway");
        gateway_fd = accept(m_ctx->mm_svr_skt, (struct sockaddr *)&peer_addr, &peer_addr_len);
        log_info("connected to gateway");
    }




    // ret = io_init();
    // if (unlikely(ret == -1))
    // {
    //     log_error("io_init() error");
    //     goto error;
    // }



    /* TODO: Exit loop on interrupt */
    while (1)
    {
        sleep(30);
    }

    // ret = io_exit();
    // if (unlikely(ret == -1))
    // {
    //     log_error("io_exit() error");
    //     goto error;
    // }

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
    cfg_exit();
    rte_memzone_free(memzone);
    return -1;
}
// create a skt connection with the gateway on the DPU and export the mempool descriptor(# of element, size of element)
// create multiple mempools for multitenancy support by separate the mempool name
// on the gateway create different RDMA ctx for different mempool and connect with each other.
int main(int argc, char **argv)
{
    int ret;

    int level = log_get_level();

#ifdef DEBUG
    log_info("debug mode!!!");
    log_set_level(1);
    level = 1;
#endif
    enum my_log_level lv = static_cast<enum my_log_level>(level);

    ret = rte_eal_init(argc, argv);

    if (unlikely(ret == -1))
    {
        log_error("rte_eal_init() error: %s", rte_strerror(rte_errno));
        goto error_0;
    }
    doca_error result;
    struct doca_log_backend *sdk_log;
    result = create_doca_log_backend(&sdk_log, my_log_level_to_doca_log_level(lv));
    LOG_ON_FAILURE(result);

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
