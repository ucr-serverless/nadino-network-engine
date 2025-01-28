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

    ret = nf(nf_id, n_ctx, nf_worker);
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
