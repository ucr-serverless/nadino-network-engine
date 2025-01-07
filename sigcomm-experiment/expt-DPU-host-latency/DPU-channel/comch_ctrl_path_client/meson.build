#
# Copyright (c) 2023-2024 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
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

# project('DOCA_SAMPLE', 'C', 'CPP',
# 	# Get version number from file.
# 	version: run_command(find_program('cat'),
# 		files('/opt/mellanox/doca/applications/VERSION'), check: true).stdout().strip(),
# 	license: 'Proprietary',
# 	default_options: ['buildtype=debug'],
# 	meson_version: '>= 0.61.2'
# )


client_dependencies = []
# Required for all DOCA programs
client_dependencies += dependency('doca-common')
# The DOCA library of the client itself
client_dependencies += dependency('doca-comch')
# Utility DOCA library for executables
client_dependencies += dependency('doca-argp')

client_src = [
	# The sample itself
	'comch_ctrl_path_client_sample.c',
	# Main function for the sample's executable
	'comch_ctrl_path_client_main.c',
	# Common code for the DOCA library samples
	'../comch_ctrl_path_common.c',
	# Common code for all DOCA samples
	'../common.c',
]

client_inc_dirs  = []
# Common DOCA library logic
client_inc_dirs += include_directories('..')
# Common DOCA logic (clients)

executable('doca_comch_ctrl_path_client', client_src,
	c_args : '-Wno-missing-braces',
	dependencies : client_dependencies,
	include_directories: client_inc_dirs,
	install: false)
