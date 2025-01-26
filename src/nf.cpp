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

#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdexcept>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

#include <rte_branch_prediction.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_memzone.h>

#include "http.h"
#include "io.h"
#include "log.h"
#include "palladium_doca_common.h"
#include "rte_mempool.h"
#include "spright.h"
#include "palladium_nf_common.h"
#include <sys/eventfd.h>


DOCA_LOG_REGISTER(PALLADIUM_NF::MAIN);
struct nf_ctx *n_ctx;

static int autoscale_memory(uint8_t mb)
{
    char *buffer = NULL;

    if (unlikely(mb == 0))
    {
        return 0;
    }

    buffer = (char *)malloc(1000000 * mb * sizeof(char));
    if (unlikely(buffer == NULL))
    {
        log_error("malloc() error: %s", strerror(errno));
        return -1;
    }

    buffer[0] = 'a';
    buffer[1000000 * mb - 1] = 'a';

    free(buffer);

    return 0;
}

static int autoscale_sleep(uint32_t ns)
{
    struct timespec interval;
    int ret;

    interval.tv_sec = ns / 1000000000;
    interval.tv_nsec = ns % 1000000000;

    ret = nanosleep(&interval, NULL);
    if (unlikely(ret == -1))
    {
        log_error("nanosleep() error: %s", rte_strerror(errno));
        return -1;
    }

    return 0;
}

static int autoscale_compute(uint32_t n)
{
    uint32_t i;

    for (i = 2; i < sqrt(n); i++)
    {
        if (n % i == 0)
        {
            break;
        }
    }

    return 0;
}

static void *nf_worker(void *arg)
{
    struct http_transaction *txn = NULL;
    ssize_t bytes_written;
    ssize_t bytes_read;
    uint8_t index;
    int ret;

    /* TODO: Careful with this pointer as it may point to a stack */
    index = (uint64_t)arg;

    while (1)
    {
        bytes_read = read(n_ctx->pipefd_rx[index][0], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_read == -1))
        {
            log_error("read() error: %s", strerror(errno));
            return NULL;
        }

        log_debug("Fn#%d is processing request.\n", n_ctx->nf_id);

        ret = autoscale_memory(cfg->nf[n_ctx->nf_id - 1].param.memory_mb);
        if (unlikely(ret == -1))
        {
            log_error("autoscale_memory() error");
            return NULL;
        }

        ret = autoscale_sleep(cfg->nf[n_ctx->nf_id - 1].param.sleep_ns);
        if (unlikely(ret == -1))
        {
            log_error("autoscale_sleep() error");
            return NULL;
        }

        ret = autoscale_compute(cfg->nf[n_ctx->nf_id - 1].param.compute);
        if (unlikely(ret == -1))
        {
            log_error("autoscale_compute() error");
            return NULL;
        }

        bytes_written = write(n_ctx->pipefd_tx[index][1], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_written == -1))
        {
            log_error("write() error: %s", strerror(errno));
            return NULL;
        }
    }

    return NULL;
}



/* TODO: Cleanup on errors */
static int nf(uint32_t nf_id)
{
    int level = log_get_level();

#ifdef DEBUG
    log_info("debug mode!!!");
    log_set_level(1);
    level = 1;
    
#endif
    enum my_log_level lv = static_cast<enum my_log_level>(level);

    doca_error_t result;
    struct doca_log_backend *sdk_log;
    result = create_doca_log_backend(&sdk_log, my_log_level_to_doca_log_level(lv));
    const struct rte_memzone *memzone = NULL;
    pthread_t thread_worker[UINT8_MAX];
    pthread_t thread_rx;
    pthread_t thread_tx;
    uint32_t tenant_id;
    uint8_t i;
    int ret;
    struct epoll_event event;

    // fn_id = nf_id;

    memzone = rte_memzone_lookup(MEMZONE_NAME);
    if (unlikely(memzone == NULL))
    {
        log_error("rte_memzone_lookup() error");
        return -1;
    }


    cfg = (struct spright_cfg_s *)memzone->addr;

    struct nf_ctx real_nf_ctx(cfg, nf_id);

    real_nf_ctx.print_nf_ctx();
    real_nf_ctx.print_gateway_ctx();



    n_ctx = &real_nf_ctx;

    ret = new_io_init(nf_id, &n_ctx->inter_fn_skt);
    if (unlikely(ret == -1))
    {
        log_error("io_init() error");
        return -1;
    }
    if (n_ctx->inter_fn_skt < 0) {
        throw std::runtime_error("skt error");
    }
    log_debug("the inter nf skt is %d", n_ctx->inter_fn_skt);

    tenant_id = n_ctx->fn_id_to_res[n_ctx->nf_id].tenant_id;
    auto& routes = n_ctx->tenant_id_to_res[tenant_id].routes;
    auto& n_res = n_ctx->fn_id_to_res[n_ctx->nf_id];
    auto& t_res = n_ctx->tenant_id_to_res[tenant_id];
    std::string mp_name = mempool_prefix + std::to_string(tenant_id);

    if (n_ctx->p_mode != SPRIGHT) {
        t_res.mp_ptr = rte_mempool_lookup(mp_name.c_str());
        if (!t_res.mp_ptr) {
            throw std::runtime_error("palladium mempool didn't found");

        }

    }


    for (auto i: routes) {
        if (!n_ctx->route_id_to_res[i].hop.empty()) {
            if (n_ctx->route_id_to_res[i].hop[0] == n_ctx->nf_id) {
                n_ctx->routes_start_from_nf.push_back(i);
            }

        }
    }
    // if (n_res.nf_mode == ACTIVE_SEND && n_ctx->routes_start_from_nf.empty()) {
    //     throw std::runtime_error("no avaliable_routes");
    // }

    real_nf_ctx.print_nf_ctx();

    for (i = 0; i < cfg->nf[n_ctx->nf_id - 1].n_threads; i++)
    {
        ret = pipe(real_nf_ctx.pipefd_rx[i]);
        if (unlikely(ret == -1))
        {
            log_error("pipe() error: %s", strerror(errno));
            return -1;
        }

        ret = pipe(real_nf_ctx.pipefd_tx[i]);
        if (unlikely(ret == -1))
        {
            log_error("pipe() error: %s", strerror(errno));
            return -1;
        }
    }

    n_ctx->rx_ep_fd = epoll_create1(0);
    if (unlikely(n_ctx->rx_ep_fd == -1))
    {
        log_error("epoll_create1() error: %s", strerror(errno));
    }
    // create a ckt to listen to external client
    //
    n_ctx->ing_fd = create_server_socket(cfg->nodes[cfg->local_node_idx].ip_address, n_ctx->ing_port);
    if (unlikely(n_ctx->ing_fd == -1))
    {
        log_error("socket() error: %s", strerror(errno));
        return -1;
    }
    struct fd_ctx_t *cmd_ckt_ctx = (struct fd_ctx_t *)malloc(sizeof(struct fd_ctx_t));
    cmd_ckt_ctx->sockfd = n_ctx->ing_fd;
    cmd_ckt_ctx->fd_tp = ING_FD;

    n_ctx->fd_to_fd_ctx[n_ctx->ing_fd] = cmd_ckt_ctx;
    struct epoll_event ing_event;
    ing_event.events = EPOLLIN;
    ing_event.data.ptr = reinterpret_cast<void*>(cmd_ckt_ctx);

    ret = epoll_ctl(n_ctx->rx_ep_fd, EPOLL_CTL_ADD, n_ctx->ing_fd, &ing_event);
    if (unlikely(ret == -1))
    {
        log_error("epoll_ctl() error: %s", strerror(errno));
        return -1;
    }

    if (n_res.nf_mode == ACTIVE_SEND) {
        struct epoll_event pp_event;
        ret = pipe(n_ctx->tx_rx_pp);
        if (unlikely(ret == -1))
        {
            log_error("pipe() error: %s", strerror(errno));
            return -1;
        }
        ret = set_nonblocking(n_ctx->tx_rx_pp[0]);
        if (unlikely(ret == -1))
        {
            log_error("set set_nonblocking error");
        }

        struct fd_ctx_t *tx_rx_pp_fd = (struct fd_ctx_t *)malloc(sizeof(struct fd_ctx_t));
        tx_rx_pp_fd->fd_tp = EVENT_FD;
        tx_rx_pp_fd->sockfd = n_ctx->tx_rx_pp[0];

        // n_ctx->fd_to_fd_ctx[n_ctx->tx_rx_event_fd] = tx_rx_pp_fd;

        pp_event.data.ptr = reinterpret_cast<void*>(tx_rx_pp_fd);
        pp_event.events = EPOLLIN;

        ret = epoll_ctl(n_ctx->rx_ep_fd, EPOLL_CTL_ADD, n_ctx->tx_rx_pp[0], &pp_event);
        if (unlikely(ret == -1))
        {
            log_error("epoll_ctl() error: %s", strerror(errno));
            throw std::runtime_error("add ep pp");
        }
        // n_ctx->tx_rx_event_fd = eventfd(0, 0);
        // RUNTIME_ERROR_ON_FAIL(n_ctx->tx_rx_event_fd < 0, "event fd fail");
        // struct epoll_event tx_rx_ev;
        // struct fd_ctx_t *tx_rx_ev_fd = (struct fd_ctx_t *)malloc(sizeof(struct fd_ctx_t));
        // tx_rx_ev_fd->fd_tp = EVENT_FD;
        // tx_rx_ev_fd->sockfd = n_ctx->tx_rx_event_fd;
        //
        // n_ctx->fd_to_fd_ctx[n_ctx->tx_rx_event_fd] = tx_rx_ev_fd;
        //
        // tx_rx_ev.events = EPOLLIN;
        // tx_rx_ev.data.ptr = reinterpret_cast<void*>(tx_rx_ev_fd);
        //
        // ret = epoll_ctl(n_ctx->rx_ep_fd, EPOLL_CTL_ADD, n_ctx->tx_rx_event_fd, &tx_rx_ev);
        // if (unlikely(ret == -1))
        // {
        //     log_error("epoll_ctl() error: %s", strerror(errno));
        //     return -1;
        // }
        log_debug("event fd added");
    }



    ret = set_nonblocking(n_ctx->inter_fn_skt);
    RUNTIME_ERROR_ON_FAIL(ret == -1, "set_nonblocking fail");


    struct fd_ctx_t *inter_fn_skt_fd = (struct fd_ctx_t *)malloc(sizeof(struct fd_ctx_t));
    inter_fn_skt_fd->fd_tp = INTER_FNC_SKT_FD;
    inter_fn_skt_fd->sockfd = n_ctx->inter_fn_skt;

    event.events = EPOLLIN;
    event.data.ptr = reinterpret_cast<void*>(inter_fn_skt_fd);

    ret = epoll_ctl(n_ctx->rx_ep_fd, EPOLL_CTL_ADD, n_ctx->inter_fn_skt, &event);
    if (unlikely(ret == -1))
    {
        log_error("epoll_ctl() error: %s", strerror(errno));
        return -1;
    }
    // TODO: init the resource

    // TODO: change the flag to mode
    if (is_gtw_on_dpu(n_ctx->p_mode)) {
        log_info("dpu mode");

        init_comch_client_cb(n_ctx);

        result = open_doca_device_with_pci(n_ctx->comch_client_device_name.c_str(), NULL, &(n_ctx->comch_client_dev));
        LOG_AND_FAIL(result);

        result =
            init_comch_client(comch_server_name.c_str(), n_ctx->comch_client_dev, &n_ctx->comch_client_cb, &(n_ctx->comch_client), &(n_ctx->comch_client_pe), &(n_ctx->comch_client_ctx));
        LOG_AND_FAIL(result);

        struct fd_ctx_t *comch_pe_fd_tp = (struct fd_ctx_t *)malloc(sizeof(struct fd_ctx_t));
        comch_pe_fd_tp->fd_tp = COMCH_PE_FD;
        result = register_pe_to_ep_with_fd_tp(n_ctx->comch_client_pe, n_ctx->rx_ep_fd, comch_pe_fd_tp, n_ctx);
        LOG_AND_FAIL(result);

    }
    n_ctx->wait_point.emplace(1);

    ret = pthread_create(&thread_rx, NULL, &basic_nf_rx, n_ctx);
    if (unlikely(ret != 0))
    {
        log_error("pthread_create() error: %s", strerror(ret));
        return -1;
    }

    ret = pthread_create(&thread_tx, NULL, &basic_nf_tx, n_ctx);
    if (unlikely(ret != 0))
    {
        log_error("pthread_create() error: %s", strerror(ret));
        return -1;
    }

    for (i = 0; i < cfg->nf[n_ctx->nf_id - 1].n_threads; i++)
    {
        ret = pthread_create(&thread_worker[i], NULL, &nf_worker, (void *)(uint64_t)i);
        if (unlikely(ret != 0))
        {
            log_error("pthread_create() error: %s", strerror(ret));
            return -1;
        }
    }

    for (i = 0; i < cfg->nf[n_ctx->nf_id - 1].n_threads; i++)
    {
        ret = pthread_join(thread_worker[i], NULL);
        if (unlikely(ret != 0))
        {
            log_error("pthread_join() error: %s", strerror(ret));
            return -1;
        }
    }

    ret = pthread_join(thread_rx, NULL);
    if (unlikely(ret != 0))
    {
        log_error("pthread_join() error: %s", strerror(ret));
        return -1;
    }

    ret = pthread_join(thread_tx, NULL);
    if (unlikely(ret != 0))
    {
        log_error("pthread_join() error: %s", strerror(ret));
        return -1;
    }

    for (i = 0; i < cfg->nf[n_ctx->nf_id - 1].n_threads; i++)
    {
        ret = close(real_nf_ctx.pipefd_rx[i][0]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }

        ret = close(real_nf_ctx.pipefd_rx[i][1]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }

        ret = close(real_nf_ctx.pipefd_tx[i][0]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }

        ret = close(real_nf_ctx.pipefd_tx[i][1]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }
    }

    ret = new_io_exit(n_ctx->nf_id);
    if (unlikely(ret == -1))
    {
        log_error("io_exit() error");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    log_set_level_from_env();

    uint8_t nf_id;
    int ret;

    ret = rte_eal_init(argc, argv);
    if (unlikely(ret == -1))
    {
        log_error("rte_eal_init() error: %s", rte_strerror(rte_errno));
        goto error_0;
    }

    argc -= ret;
    argv += ret;

    if (unlikely(argc == 1))
    {
        log_error("Network Function ID not provided");
        goto error_1;
    }

    errno = 0;
    nf_id = strtol(argv[1], NULL, 10);
    if (unlikely(errno != 0 || nf_id < 1))
    {
        log_error("Invalid value for Network Function ID");
        goto error_1;
    }
    log_info("the nf id is, %d", nf_id);

    ret = nf(nf_id);
    if (unlikely(ret == -1))
    {
        log_error("nf() error");
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
