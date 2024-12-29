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

project('palladium-gateway', 'c',
  license: 'Apache-2.0',
  default_options: ['warning_level=3', 'optimization=3', 'buildtype=release'],
  meson_version: '>= 0.61.2'
)

# test if we are on DPU or Host
dependency_doca = dependency('doca-common', required: false)
if dependency_doca.found()
  doca_found = true
  doca_inc = '/opt/mellanox/doca/include'
  c_compiler = meson.get_compiler('c')
  if c_compiler.has_header_symbol(doca_inc + '/doca_build_config.h', 'DOCA_ARCH_DPU', dependencies: dependency_doca)
      is_dpu = true
  else
      is_dpu = false
  endif
  is_host = not is_dpu
  message('DOCA is found')
  if is_dpu
    message('We are on DPU')
  else
    message('We are on Host')
  endif
else
  doca_found = false
  message('DOCA is not found!!')
endif



# Disable compiler warnings
add_project_arguments(['-Wno-unused-parameter', '-Wno-sign-compare', '-Wno-pointer-arith'], language: 'c')
#add_project_arguments('-Wno-error=sign-compare', language: 'c')


# Check for deps
libconfig_dep = dependency('libconfig', required: true)
dpdk_dep = dependency('libdpdk', required: true)
glib_dep = dependency('glib-2.0', required: true)
ibverbs_dep = dependency('libibverbs', required: true)

inc_dirs = include_directories('src/include', 'src/cstl/inc', 'src/log', 'RDMA_lib/include')

root_dir = meson.project_source_root()

# # Define the name of the static library
# rdma_lib_name = 'libRDMA_lib.a'
#
# # Create a custom target to build the library
sk_msg_kern = custom_target(
  'sk_msg_kern',
  output: 'sk_msg_kern.o',
  command: ['clang', '-g', '-O2', '-target', 'bpf', '-c', '-o', root_dir / 'ebpf/sk_msg_kern.o', root_dir / 'ebpf/sk_msg_kern.c'],
  build_by_default: true  # Ensures this target is built by default
)
#
# rdma_dep = declare_dependency(
#   link_args: [rdma_lib.full_path()],
# )

# Define compiler and linker flags
cflags = ['-MMD', '-MP', '-O3', '-Wall', '-Werror', '-DLOG_USE_COLOR']
ldflags = ['-L/usr/lib64']
ldlibs = ['-lbpf', '-lm', '-pthread', '-luuid']

# src files for common objects
common_src = [
  'src/log/log.c',
  'src/utility.c',
  'src/timer.c',
  'src/io_helper.c',
  'src/common.c',
  'src/sock_utils.c',
  'src/bitmap.c',
  'src/RDMA_utils.c',
  'src/control_server.c',
]

# Include the cstl directory in root build
#subdir('RDMA_lib')

incdir = include_directories('RDMA_lib/include')
rdma_dep = declare_dependency(
  include_directories: incdir,
  link_args: ['-L' + root_dir + '/RDMA_lib', '-lRDMA_lib', ]
  )

common_objs = static_library('common', common_src,
  include_directories: inc_dirs,
  c_args: cflags,
  link_args: ldflags + ldlibs,
  dependencies: [libconfig_dep, dpdk_dep, glib_dep, rdma_dep, ibverbs_dep],

)

subdir('src/cstl')



# Binaries definitions
# TODO: use loops to define binaries
binaries = [
  ['sharing',['sigcomm-experiment/expt-sharing/QP_sharing.c']],
  ['ping_pong_DPU',['sigcomm-experiment/expt-DPU-rdma/ping_pong_DPU.c']],
  ['sockmap_manager', ['src/sockmap_manager.c']],
  ['shm_mgr_rte_ring', ['src/io_rte_ring.c', 'src/shm_mgr.c']],
  ['shm_mgr_sk_msg', ['src/io_sk_msg.c', 'src/shm_mgr.c']],
  ['gateway_rte_ring', ['src/io_rte_ring.c', 'src/gateway.c']],
  ['gateway_sk_msg', ['src/io_sk_msg.c', 'src/gateway.c']],
  ['nf_rte_ring', ['src/io_rte_ring.c', 'src/nf.c']],
  ['nf_sk_msg', ['src/io_sk_msg.c', 'src/nf.c']],
  ['nf_adservice_rte_ring', ['src/io_rte_ring.c', 'src/online_boutique/adservice.c']],
  ['nf_adservice_sk_msg', ['src/io_sk_msg.c', 'src/online_boutique/adservice.c']],
  ['nf_currencyservice_rte_ring', ['src/io_rte_ring.c', 'src/online_boutique/currencyservice.c']],
  ['nf_currencyservice_sk_msg', ['src/io_sk_msg.c', 'src/online_boutique/currencyservice.c']],
  ['nf_emailservice_rte_ring', ['src/io_rte_ring.c', 'src/online_boutique/emailservice.c']],
  ['nf_emailservice_sk_msg', ['src/io_sk_msg.c', 'src/online_boutique/emailservice.c']],
  ['nf_paymentservice_rte_ring', ['src/io_rte_ring.c', 'src/online_boutique/paymentservice.c']],
  ['nf_paymentservice_sk_msg', ['src/io_sk_msg.c', 'src/online_boutique/paymentservice.c']],
  ['nf_shippingservice_rte_ring', ['src/io_rte_ring.c', 'src/online_boutique/shippingservice.c']],
  ['nf_shippingservice_sk_msg', ['src/io_sk_msg.c', 'src/online_boutique/shippingservice.c']],
  ['nf_productcatalogservice_rte_ring', ['src/io_rte_ring.c', 'src/online_boutique/productcatalogservice.c']],
  ['nf_productcatalogservice_sk_msg', ['src/io_sk_msg.c', 'src/online_boutique/productcatalogservice.c']],
  ['nf_cartservice_rte_ring', ['src/io_rte_ring.c', 'src/online_boutique/cartservice.c']],
  ['nf_cartservice_sk_msg', ['src/io_sk_msg.c', 'src/online_boutique/cartservice.c']],
  ['nf_recommendationservice_rte_ring', ['src/io_rte_ring.c', 'src/online_boutique/recommendationservice.c']],
  ['nf_recommendationservice_sk_msg', ['src/io_sk_msg.c', 'src/online_boutique/recommendationservice.c']],
  ['nf_frontendservice_rte_ring', ['src/io_rte_ring.c', 'src/shm_rpc.c', 'src/online_boutique/frontendservice.c']],
  ['nf_frontendservice_sk_msg', ['src/io_sk_msg.c', 'src/shm_rpc.c', 'src/online_boutique/frontendservice.c']],
  ['nf_checkoutservice_rte_ring', ['src/io_rte_ring.c', 'src/online_boutique/checkoutservice.c']],
  ['nf_checkoutservice_sk_msg', ['src/io_sk_msg.c', 'src/online_boutique/checkoutservice.c']],
]

# Generate bins
foreach bin : binaries
  executable(bin[0],
    sources: bin[1] + common_src,
    include_directories: inc_dirs,
    c_args: cflags,
    link_args: ldflags + ldlibs,
    dependencies: [libconfig_dep, dpdk_dep, glib_dep, rdma_dep, ibverbs_dep],
    link_with: [common_objs, libclib_dep],
    install: false
  )
endforeach
