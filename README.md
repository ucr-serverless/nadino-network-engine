# PALLADIUM

## Installation guideline (on Cloudlab) ##

This guideline is mainly for deploying PALLADIUM on [NSF Cloudlab](https://www.cloudlab.us/). 


First, clone palladium-gateway to your machine and update the git submodule RDMA\_lib.
```
git clone git@github.com:ucr-serverless/palladium-gateway.git
cd palladium-gateway
git submodule update --init --recursive
```


Our development environment is Cloudlab node type c6525-25g
Refer to [Cloudlab machine type](https://docs.cloudlab.us/hardware.html) page for more detail.


Follow steps below to set up palladium-gateway dependencies and get ready to run:

- [Setup the DOCA environment on DPU](https://docs.nvidia.com/doca/sdk/nvidia+doca+installation+guide+for+linux/index.html)
- [Installing PALLADIUM dependencies](/docs/install-dependencies.md)
- remember to call `git submodule update --init --recursive` to pull RDMA\_lib
- build the RDMA_lib
    ```
    cd RDMA_lib
    meson setup build --reconfigure
    ninja -C build/ -v
    ```
- setup palladium-gateway with `meson setup build`

- compile binaries with `ninja -C build/ -v`

- [Change cfg file](/docs/change-cfg-file.md)


### the tenant experiment

follow the order

1. start memory manager on the host1
2. start sockmap manager on the host1
3. start memory manager on the host2
4. start sockmap manager on the host2
5. start gateway on dpu1
6. start gateway on dpu2
8. start functions on host1
9. start functions on host2




worker1 host

```bash
sudo ./run.sh shm_mgr ./cfg/simple_six_tenant_dpu_two_node.cfg
sudo ./run.sh sockmap_manager
sudo ./run.sh nf 1
sudo ./run.sh nf 2
sudo ./run.sh nf 3
sudo ./run.sh nf 4
sudo ./run.sh nf 5
sudo ./run.sh nf 6
```

dpu1

```bash
sudo ./run.sh gateway ./cfg/simple_six_tenant_dpu_two_node.cfg

```

worker2 host

```bash
sudo ./run.sh shm_mgr ./cfg/simple_six_tenant_dpu_two_node.cfg
sudo ./run.sh sockmap_manager
sudo ./run.sh nf 7
sudo ./run.sh nf 8
sudo ./run.sh nf 9
sudo ./run.sh nf 10
sudo ./run.sh nf 11
sudo ./run.sh nf 12
```

dpu2

```bash
sudo ./run.sh gateway ./cfg/simple_six_tenant_dpu_two_node.cfg

```

### the three tenant test

follow the order

1. start memory manager on the host1
2. start sockmap manager on the host1
3. start memory manager on the host2
4. start sockmap manager on the host2
5. start gateway on dpu1
6. start gateway on dpu2
8. start functions on host1
9. start functions on host2




worker1 host

```bash
sudo ./run.sh shm_mgr ./cfg/simple_multi_tenant_dpu_two_node.cfg
sudo ./run.sh sockmap_manager
sudo ./run.sh nf 1
sudo ./run.sh nf 2
sudo ./run.sh nf 3
```

dpu1

```bash
sudo ./run.sh gateway ./cfg/simple_multi_tenant_dpu_two_node.cfg | tee result.txt


```

worker2 host

```bash
sudo ./run.sh shm_mgr ./cfg/simple_multi_tenant_dpu_two_node.cfg

sudo ./run.sh sockmap_manager
sudo ./run.sh nf 4
sudo ./run.sh nf 5
sudo ./run.sh nf 6
```

dpu2

```bash
sudo ./run.sh gateway ./cfg/simple_multi_tenant_dpu_two_node.cfg

```

### troubleshooting

If the EAL initialization is wrong, try allocate hugepage with `sudo sysctl -w vm.nr_hugepages=32768`
