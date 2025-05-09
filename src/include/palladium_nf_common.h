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

#ifndef PALLADIUM_NF_COMMON_H
#define PALLADIUM_NF_COMMON_H

#include <climits>
#include <ctime>
#include <latch>
#include <optional>
#include <stdint.h>
#include "comch_ctrl_path_common.h"
#include "doca_comch.h"
#include "palladium_doca_common.h"
#include "spright.h"
#include "io.h"



struct nf_ctx : public gateway_ctx {
    uint32_t nf_id;
    int pipefd_tx[UINT8_MAX][2];
    int pipefd_rx[UINT8_MAX][2];
    struct doca_comch_client *comch_client;
    struct doca_comch_connection *comch_conn;
    struct doca_ctx *comch_client_ctx;
    struct doca_pe *comch_client_pe;
    struct doca_dev *comch_client_dev;
    uint8_t current_worker;
    uint8_t n_worker;
    int inter_fn_skt;
    int rx_ep_fd;
    int ing_fd;
    struct comch_cb_config comch_client_cb;
    int tx_rx_event_fd;

    int tx_rx_pp[2];

    uint32_t expected_pkt;
    uint32_t received_pkg;

    uint32_t received_batch;


    struct timespec start;
    struct timespec end;

    std::vector<uint32_t> routes_start_from_nf;
    std::optional<std::latch> wait_point;
    std::optional<std::latch> wait_for_init_comch;

    uint32_t ing_port;
    uint32_t client_fd;

    struct timer nf_timer;
    nlohmann::json json_data;
    struct expt_settings expt_setting;
    nf_ctx(struct spright_cfg_s *cfg, uint32_t nf_id);

    void print_nf_ctx();


};

int write_to_worker(struct nf_ctx *n_ctx, void* txn);
    
void init_comch_client_cb(struct nf_ctx *n_ctx);

void *basic_nf_rx(void *arg);

void *basic_nf_tx(void *arg);


void *run_tenant_expt(struct nf_ctx *n_ctx);

void rtc_init_comch_client_cb(struct nf_ctx *n_ctx);

int forward_or_end(struct nf_ctx * n_ctx, struct http_transaction *txn);

void rtc_init_comch_client_cb(struct nf_ctx *n_ctx);

void bf_pkt_comch_client_cb(struct nf_ctx *n_ctx);

int p_nf(uint32_t nf_id, struct nf_ctx **n_ctx, void *(*nf_worker) (void *));

#endif /* PALLADIUM_NF_COMMON_H */
