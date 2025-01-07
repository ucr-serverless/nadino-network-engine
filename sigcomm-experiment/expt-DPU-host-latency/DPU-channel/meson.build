#
# Copyright (c) 2021-2024 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted
# provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright notice, this list of
#       conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright notice, this list of
#       conditions and the following disclaimer in the documentation and/or other materials
#       provided with the distribution.
#     * Neither the name of the NVIDIA CORPORATION nor the names of its contributors may be used
#       to endorse or promote products derived from this software without specific prior written
#       permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NVIDIA CORPORATION BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TOR (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

project('DPU_channel', 'c',
  default_options: ['warning_level=3', 'optimization=3', 'buildtype=release'],
  meson_version: '>= 0.61.2'
)
# Comment this line to restore warnings of experimental DOCA features
add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: ['c', 'cpp'])

doca_argp_dep = dependency('doca-argp', required: true)
doca_comch_dep = dependency('doca-comch', required: true)
doca_common = dependency('doca-common', required: true)
doca_rdma_dep = dependency('doca-rdma', required: true)
doca_dma_dep = dependency('doca-dma', required: true)

# doca_base = '/opt/mellanox/doca/'
# common_dir_path = '/opt/mellanox/doca/applications/common'
# samples_dir_path = '/opt/mellanox/doca/samples'

# subdir('comch_ctrl_path_client')
# subdir('comch_ctrl_path_server')

binaries = [
  ['DPU_channel', [ 'secure_channel_core.c', 'secure_channel.c', 'comch_utils.c', 'utils.c', 'common.c', ]],
  ['doca_comch_ctrl_path_client', ['comch_ctrl_path_client/comch_ctrl_path_client_sample.c', 'comch_ctrl_path_client/comch_ctrl_path_client_main.c', 'comch_ctrl_path_common.c', 'common.c']],
  ['doca_comch_ctrl_path_server', ['comch_ctrl_path_server/comch_ctrl_path_server_sample.c', 'comch_ctrl_path_server/comch_ctrl_path_server_main.c', 'comch_ctrl_path_common.c', 'common.c']],
  ]
# app_srcs = [
# 	'secure_channel_core.c',
#     'secure_channel.c',
# 	'comch_utils.c',
# 	'utils.c',
# 	'common.c',
# ]

base_c_args = [
	'-Wno-missing-braces',
	'-Wno-missing-field-initializers',
    '-Wno-pedantic',
]

app_inc_dirs = [
  include_directories('/opt/mellanox/doca/applications/common'),
  include_directories('/opt/mellanox/doca/include'),
]
foreach bin : binaries
  executable(bin[0],
    sources: bin[1],
    include_directories: app_inc_dirs,
    c_args: base_c_args,
    dependencies: [doca_common, doca_rdma_dep, doca_argp_dep, doca_comch_dep, doca_dma_dep],
    install: false
    )
  endforeach
