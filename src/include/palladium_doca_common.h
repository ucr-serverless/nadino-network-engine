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

#ifndef PALLADIUM_DOCA_COMMON_H
#define PALLADIUM_DOCA_COMMON_H

#include <unordered_map>
#include <iostream>
#include "doca_ctx.h"
#include "common_doca.h"
#include "rdma_common_doca.h"


struct gateway_ctx {
    std::unordered_map<uint32_t, uint32_t> fn_id_to_tenant_id;
    std::unordered_map<uint32_t, struct doca_comch_connection*> fn_id_to_comch;
    std::unordered_map<struct doca_buf*, struct doca_rdma_task_receive*> buf_to_rr;


};
#endif /* PALLADIUM_DOCA_COMMON_H */
