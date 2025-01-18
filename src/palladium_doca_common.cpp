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
#include "doca_log.h"
#include "log.h"


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
