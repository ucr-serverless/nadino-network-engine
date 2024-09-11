## installing palladium-gateway dependencies
This guideline is for install dependencies (libbpf, DPDK RTE lib, ...). 

First change directory to where palladium-gateway's root directory.
```bash

bash sigcomm-experiment/env-setup/001-env_setup_master.sh
bash sigcomm-experiment/env-setup/002-env_setup_master.sh


```

## setup huge page

By default, script `002-env_setup_master.sh` would run command `sudo sysctl -w vm.nr_hugepages=32768`` to setup huge page count.

On x86 platform, 2mb hugepage is the default.

You can check huge page status by running
```
cat /proc/meminfo | grep Huge
```

If your system have less and memory and fail to allocate these many hugepage, you can reduce the number of hugepage been allocated by running `sudo sysctl -w vm.nr_hugepages=<number_of_huge_page>`

But notice, once the hugepage number be changed, you should modify the cfg files to ensure shared manager can find enough hugepage for shared memory pool.



