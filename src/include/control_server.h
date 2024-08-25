/*
# Copyright 2024 University of California, Riverside
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

#ifndef CONTROL_SERVER_H
#define CONTROL_SERVER_H

#include "RDMA_utils.h"
#include "common.h"
#include "spright.h"
#include <rte_branch_prediction.h>
#include <stdint.h>

enum ctl_svr_msg_t
{
    REALEASE,
    CONNECT,
    DISCONNECT,
};

struct control_server_msg
{
    enum ctl_svr_msg_t msg_t;

    uint32_t node_idx;
    uint32_t qp_num;
    void *bf_addr;
    uint32_t bf_len;
};

int destroy_control_server_socks();
int control_server_socks_init();
int exchange_rdma_info();
#endif // !CONTROL_SERVER_H
