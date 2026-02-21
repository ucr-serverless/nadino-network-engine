## installing NADINO-gateway dependencies
This guideline is for install dependencies (libbpf, DPDK RTE lib, ...). 

First change directory to where NADINO-gateway's root directory.

```bash
bash sigcomm-experiment/env-setup/001-env_setup_master.sh
bash sigcomm-experiment/env-setup/002-env_setup_master.sh
```

## setup huge page

By default, script `002-env_setup_master.sh` would run command `sudo sysctl -w vm.nr_hugepages=<number>` to setup huge page count.

On x86 platform, 2MB hugepage is the default.

You can check huge page status by running

```bash
cat /proc/meminfo | grep Huge
```

If your system have less memory and fail to allocate hugepage, you can reduce the number of hugepage been allocated by running `sudo sysctl -w vm.nr_hugepages=<number_of_huge_page>`.

Notice, once the hugepage number is changed, you should [modify the cfg file to change `local_mempool_size` setting](change-cfg-file.md) to ensure shared manager can find enough hugepage for shared memory pool initialization.



