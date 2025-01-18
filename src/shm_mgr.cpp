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

#include <iostream>
#include <memory>
#include <netinet/in.h>
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

DOCA_LOG_REGISTER(MEMORY_MANAGER::MAIN);

using namespace std;

const string mempool_prefix = "PALLADIUM";

struct tenant_res {
    uint8_t id;
    unique_ptr<char[]> mempool_descriptor;
    struct rte_mempool *mempool;
    string mempool_name;
    tenant_res(uint8_t id) {
        this->id = id;
        this->mempool_descriptor = make_unique<char[]>(MAX_RDMA_DESCRIPTOR_SZ);
        this->mempool_name = mempool_prefix + to_string(id);
        cout << this->mempool_name << endl;
        this->mempool = rte_mempool_create(this->mempool_name.c_str(), cfg->local_mempool_size, cfg->local_mempool_elt_size, 0, 0, NULL, NULL, NULL, NULL, rte_socket_id(), 0);
        if (unlikely(this->mempool == NULL))
        {
            log_error("rte_mempool_create() error: %s", rte_strerror(rte_errno));
        }
    }
    ~tenant_res() {
        if (this->mempool != nullptr) {
            rte_mempool_free(this->mempool);
        }
        log_info("%d mp destroied", this->id);
    }

};

// TODO: need to add the comch setting(client devname)

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
    unordered_map<uint8_t, unique_ptr<tenant_res>> id_to_tenant;
    int gateway_fd = 0;
    int self_fd = 0;
    struct sockaddr_in peer_addr;

    socklen_t peer_addr_len = sizeof(struct sockaddr_in);

    fn_id = -1;

    memzone = rte_memzone_reserve(MEMZONE_NAME, sizeof(*cfg), rte_socket_id(), 0);
    if (unlikely(memzone == NULL))
    {
        log_error("rte_memzone_reserve() error: %s", rte_strerror(rte_errno));
        goto error;
    }

    memset(memzone->addr, 0U, sizeof(*cfg));

    cfg = (struct spright_cfg_s *)memzone->addr;

    ret = cfg_init(cfg_file, cfg);
    if (unlikely(ret == -1))
    {
        log_error("cfg_init() error");
        goto error;
    }

    if (cfg->use_rdma == 0) {
        log_info("does not use rdma");
        ret = init_cfg_local_mempool();
        JUMP_ON_PE_FAILURE(ret, -1, "mempool init fail", error);

    }
    else {
        // allocate tenant res
        for (size_t i = 0; i < cfg->n_tenants; i++) {
            id_to_tenant.emplace(cfg->tenants[i].id, make_unique<tenant_res>(cfg->tenants[i].id));
        }
        string ip = "0.0.0.0";
        self_fd = sock_utils_bind(ip.c_str(), to_string(cfg->memory_manager.port).c_str());
        listen(self_fd, 5);
        log_info("listen to connection from gateway");
        gateway_fd = accept(self_fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
        log_info("connected to gateway");



    }



    log_info("mempool inited");

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

    ret = rte_eal_init(argc, argv);
    if (unlikely(ret == -1))
    {
        log_error("rte_eal_init() error: %s", rte_strerror(rte_errno));
        goto error_0;
    }
    doca_error result;
    struct doca_log_backend *sdk_log;
    result = create_doca_log_backend(&sdk_log, DOCA_LOG_LEVEL_WARNING);

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
