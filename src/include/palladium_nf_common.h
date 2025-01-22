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
#include <stdint.h>
#include "palladium_doca_common.h"
#include "spright.h"

struct nf_ctx : public gateway_ctx {
    uint32_t nf_id;
    int pipefd_tx[UINT8_MAX][2];
    int pipefd_rx[UINT8_MAX][2];

    nf_ctx(struct spright_cfg_s *cfg, uint32_t nf_id) : gateway_ctx(cfg), nf_id(nf_id) {};
    void print_nf_ctx();

};
    
void *basic_nf_rx(void *arg);

void *basic_nf_tx(void *arg);
#endif /* PALLADIUM_NF_COMMON_H */
