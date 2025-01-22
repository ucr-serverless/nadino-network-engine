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

project('palladium-gateway', ['cpp', 'c'],
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
add_project_arguments(['-Wno-unused-parameter', '-Wno-sign-compare', '-Wno-pointer-arith', '-D DOCA_ALLOW_EXPERIMENTAL_API'], language: 'c')
add_project_arguments(['-std=c++20', '-D DOCA_ALLOW_EXPERIMENTAL_API'], language: 'cpp')
#add_project_arguments('-Wno-error=sign-compare', language: 'c')

# Define a custom macro for debug builds
if get_option('buildtype') == 'debug'
    add_global_arguments('-DDEBUG', language: 'cpp')
endif


# Check for deps
libconfig_dep = dependency('libconfig', required: true)
dpdk_dep = dependency('libdpdk', required: true)
glib_dep = dependency('glib-2.0', required: true)
ibverbs_dep = dependency('libibverbs', required: true)
json_dep = dependency('nlohmann_json', required: true)
doca_argp_dep = dependency('doca-argp', required: true)
doca_comch_dep = dependency('doca-comch', required: true)
doca_rdma_dep = dependency('doca-rdma', required: true)
doca_common = dependency('doca-common', required: true)
doca_dma_dep = dependency('doca-dma', required: true)

inc_dirs = include_directories('src/include', 'src/cstl/inc', 'src/log', 'RDMA_lib/include', 'DOCA_lib/include', '/opt/mellanox/doca/include')

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
cflags = ['-MMD', '-MP', '-O3', '-Wall', '-Wextra', '-DLOG_USE_COLOR']
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
  # 'src/RDMA_utils.c',
  # 'src/control_server.c',
]

# Include the cstl directory in root build
#subdir('RDMA_lib')
#

rdma_dir = root_dir + '/RDMA_lib'
rdma_build_dir = rdma_dir + '/build'

rdma_incdir = include_directories('RDMA_lib/include')
rdma_dep = declare_dependency(
  include_directories: rdma_incdir,
  link_args: ['-L' + root_dir + '/RDMA_lib', '-lRDMA_lib', ]
  )

build_rdma = custom_target(
    'build_RDMA',
    output: 'RDMA',       # File(s) produced by the script
    command: ['meson', 'setup', rdma_build_dir, rdma_dir, '&&', 'ninja', '-C', rdma_build_dir, '-v'],  # Command to execute the script
    build_by_default: true        # Ensure it runs by default
)
build_rdma_dep = declare_dependency(
  sources: build_rdma
  )

doca_dir = root_dir + '/DOCA_lib'
doca_build_dir = doca_dir + '/build'
doca_incdir = include_directories('DOCA_lib/include', '/opt/mellanox/doca/include')

doca_dep = declare_dependency(
  include_directories: doca_incdir,
  link_args: ['-L' + root_dir + '/DOCA_lib', '-lDOCA_lib', ]
  )
build_doca = custom_target(
    'build_DOCA',
    output: 'DOCA',       # File(s) produced by the script
    command: ['meson', 'setup', doca_build_dir, doca_dir, '&&', 'ninja', '-C', doca_build_dir, '-v'],  # Command to execute the script
    build_by_default: true        # Ensure it runs by default
)
build_doca_dep = declare_dependency(
  sources: build_doca
  )


subdir('src/cstl')

common_objs = static_library('common', common_src,
  include_directories: inc_dirs,
  c_args: cflags,
  link_args: ldflags + ldlibs,
  dependencies: [libconfig_dep, dpdk_dep, glib_dep, rdma_dep, ibverbs_dep, doca_dep],

)

# ==== cpp binaries ======

cpp_common = [
  'src/palladium_doca_common.cpp',
  'src/palladium_nf_common.cpp',
  ]
cpp_binaries = [
  ['shm_mgr_rte_ring', ['src/io_rte_ring.c', 'src/shm_mgr.cpp']],
  ['shm_mgr_sk_msg', ['src/io_sk_msg.c', 'src/shm_mgr.cpp']],
  ['gateway_rte_ring', ['src/io_rte_ring.c', 'src/gateway.cpp']],
  ['gateway_sk_msg', ['src/io_sk_msg.c', 'src/gateway.cpp']],
  ['nf_rte_ring', ['src/io_rte_ring.c', 'src/nf.cpp']],
  ['nf_sk_msg', ['src/io_sk_msg.c', 'src/nf.cpp']],
  ]

foreach bin : cpp_binaries
  executable(bin[0],
    sources: bin[1] + cpp_common,
    include_directories: inc_dirs,
    cpp_args: cflags,
    link_args: ldflags + ldlibs,
    dependencies: [libconfig_dep, dpdk_dep, glib_dep, rdma_dep, ibverbs_dep, build_rdma_dep, doca_dep, build_doca_dep, json_dep, doca_common, doca_rdma_dep, doca_argp_dep, doca_comch_dep, doca_dma_dep],
    link_with: [common_objs, libclib_dep],
    install: false
  )
endforeach

# ==== c binaries ======
binaries = [
  ['sharing',['sigcomm-experiment/expt-sharing/QP_sharing.c']],
  ['rdma_interrupt_lat',['sigcomm-experiment/expt-DPU-host-latency/rdma_interrupt_lat.c']],
  ['sockmap_manager', ['src/sockmap_manager.c']],
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
    sources: bin[1],
    include_directories: inc_dirs,
    c_args: cflags,
    link_args: ldflags + ldlibs,
    dependencies: [libconfig_dep, dpdk_dep, glib_dep, rdma_dep, ibverbs_dep, build_rdma_dep, doca_dep, build_doca_dep],
    link_with: [common_objs, libclib_dep],
    install: false
  )
endforeach

# ======= test binaries =======
test_binaries = [
  ['json', ['test/json.cpp']],
  ]

foreach bin : test_binaries
  executable(bin[0],
    sources: bin[1],
    include_directories: inc_dirs,
    c_args: cflags,
    link_args: ldflags + ldlibs,
    dependencies: [libconfig_dep, dpdk_dep, glib_dep, rdma_dep, ibverbs_dep, build_rdma_dep, doca_dep, build_doca_dep, json_dep],
    link_with: [common_objs],
    install: false
  )
endforeach

# ======= experiment related binaries =======
expt_dir = 'sigcomm-experiment'
expt_rdma_dir = expt_dir + '/expt-DPU-rdma'
expt_channel_dir = expt_dir + '/expt-DPU-host-latency/DPU-channel'
expt_scalability_dir = expt_dir + '/expt-DPU-channel-scalability'

doca_cpp_binary = [
  ['comch_sr_client', [ expt_scalability_dir + '/comch_sr_client.cpp' ]],
  ['comch_sr_server', [ expt_scalability_dir + '/comch_sr_server.cpp' ]],
  ['rdma_client', [ expt_scalability_dir + '/rdma_client.cpp' ]],
  ['rdma_server', [ expt_scalability_dir + '/rdma_server.cpp' ]],
  ['rdma_host_export', [ expt_scalability_dir + '/rdma_host_export.cpp' ]],

  ]

doca_binary = [
  ['client', [ expt_scalability_dir + '/tcp/client.c']],
  ['server', [ expt_scalability_dir + '/tcp/server.c']],
  ['tcp_bench', [ expt_scalability_dir + '/tcp/tcp_bench.c']],
  ['DPU_rdma',[	expt_rdma_dir + '/dma_copy_core.c', expt_rdma_dir + '/dma_copy.c', expt_rdma_dir + '/ping_pong_DPU.c',
]],
  ['DPU_channel', [ expt_channel_dir + '/secure_channel_core.c', expt_channel_dir + '/secure_channel.c']],
  ['doca_comch_ctrl_path_client', [expt_channel_dir + '/comch_ctrl_path_client/comch_ctrl_path_client_sample.c', expt_channel_dir + '/comch_ctrl_path_client/comch_ctrl_path_client_main.c']],
  ['doca_comch_ctrl_path_server', [expt_channel_dir + '/comch_ctrl_path_server/comch_ctrl_path_server_sample.c', expt_channel_dir + '/comch_ctrl_path_server/comch_ctrl_path_server_main.c']],
  ]

doca_cflags = [
	'-Wno-missing-braces',
	'-Wno-missing-field-initializers',
    '-Wno-pedantic',
    '-Wno-unused-function',
    '-Wno-deprecated-declarations',
    '-D DOCA_ALLOW_EXPERIMENTAL_API',
]

doca_inc_dir = ['sigcomm-experiment/expt-DPU-host-latency/DPU-channel', 'sigcomm-experiment/expt-DPU-rdma', '/opt/mellanox/doca/include']

if doca_found

  foreach bin : doca_binary
    executable(bin[0],
      sources: bin[1],
      include_directories: doca_inc_dir + inc_dirs,
      c_args: cflags + doca_cflags,
      link_args: ldflags + ldlibs,
      dependencies: [libconfig_dep, dpdk_dep, glib_dep, rdma_dep, ibverbs_dep, build_rdma_dep, doca_dep, build_doca_dep, doca_common, doca_rdma_dep, doca_argp_dep, doca_comch_dep, doca_dma_dep],
      link_with: [common_objs],
      install: false
    )
  endforeach
  foreach bin : doca_cpp_binary
    executable(bin[0],
      sources: bin[1],
      include_directories: doca_inc_dir + inc_dirs,
      cpp_args: cflags + doca_cflags,
      link_args: ldflags + ldlibs,
      dependencies: [libconfig_dep, dpdk_dep, glib_dep, rdma_dep, ibverbs_dep, build_rdma_dep, doca_dep, build_doca_dep, doca_common, doca_rdma_dep, doca_argp_dep, doca_comch_dep, doca_dma_dep],
      link_with: [common_objs],
      install: false
    )
  endforeach
endif
  
