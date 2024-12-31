#
# Copyright (c) 2022-2024 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
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
project('DPU_rdma', 'c',
  default_options: ['warning_level=3', 'optimization=3', 'buildtype=release'],
  meson_version: '>= 0.61.2'
)
doca_argp_dep = dependency('doca-argp', required: true)
doca_comch_dep = dependency('doca-comch', required: true)
doca_common = dependency('doca-common', required: true)
doca_dma_dep = dependency('doca-dma', required: true)
doca_rdma_dep = dependency('doca-rdma', required: true)
# Comment this line to restore warnings of experimental DOCA features
add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: ['c', 'cpp'])
app_dependencies = [doca_argp_dep, doca_comch_dep, doca_common, doca_dma_dep, doca_rdma_dep]

app_srcs = [
	'dma_copy_core.c',
	'../expt-DPU-channel/comch_utils.c',
	'pack.c',
	'../expt-DPU-channel/utils.c',
	'../expt-DPU-channel/common.c',
    'dma_copy.c',
]

app_inc_dirs = [
  '../expt-DPU-channel'
  ]

base_c_args = [
	'-Wno-missing-braces',
	'-Wno-missing-field-initializers',
]
executable('DPU_rdma',
	   app_srcs,
	   c_args : base_c_args,
	   dependencies : app_dependencies,
	   include_directories : app_inc_dirs,
	   install: false)
