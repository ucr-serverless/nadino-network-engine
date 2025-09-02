# NADINO Network Engine and Functions

## Installation guideline (on Cloudlab) ##

This guideline is mainly for deploying NADINO's network engine and functions on [NSF Cloudlab](https://www.cloudlab.us/). 


First, clone the repo to your machine and update the git submodule RDMA\_lib.
```
git clone git@github.com:ucr-serverless/nadino-network-engine.git
cd nadino-network-engine
git submodule update --init --recursive
```


Our development environment is Cloudlab node type c6525-25g
Refer to [Cloudlab machine type](https://docs.cloudlab.us/hardware.html) page for more detail.


Follow steps below to set up nadino-network-engine dependencies and get ready to run:

- [Setup the DOCA environment on DPU](https://docs.nvidia.com/doca/sdk/nvidia+doca+installation+guide+for+linux/index.html)
- [Installing NADINO dependencies](/docs/install-dependencies.md)
- remember to call `git submodule update --init --recursive` to pull RDMA\_lib
- build the RDMA_lib
    ```
    cd RDMA_lib
    meson setup build --reconfigure
    ninja -C build/ -v
    ```
- setup nadino-network-engine with `meson setup build`

- compile binaries with `ninja -C build/ -v`

- [Change cfg file](/docs/change-cfg-file.md)

## run with dummy function chain

On node 1

```bash
sudo ./run.sh shm_mgr ./cfg/my-palladium-cpu.cfg
sudo ./run.sh gateway cfg/my-palladium-cpu.cfg
sudo ./run.sh nf 1
```

On node 2

```bash
sudo ./run.sh shm_mgr ./cfg/my-palladium-cpu.cfg
sudo ./run.sh gateway cfg/my-palladium-cpu.cfg
sudo ./run.sh nf 2
```

If dpdk eal init have the access error, try allocate huge page.

```bash
sudo ./run.sh shm_mgr cfg/online-boutique-palladium-host.cfg
sudo ./run.sh gateway cfg/online-boutique-palladium-host.cfg
sudo ./run.sh frontendservice 1
sudo ./run.sh recommendationservice 5
sudo ./run.sh checkoutservice 7


```

```bash
sudo ./run.sh shm_mgr cfg/online-boutique-palladium-host.cfg
sudo ./run.sh gateway cfg/online-boutique-palladium-host.cfg
sudo ./run.sh currencyservice 2
sudo ./run.sh productcatalogservice 3
sudo ./run.sh cartservice 4
sudo ./run.sh shippingservice 6
sudo ./run.sh paymentservice 8
sudo ./run.sh emailservice 9
sudo ./run.sh adservice 10
```

## fuyao

```
git checkout fuyao
git submodule update
```

worker1
```bash
sudo ./run.sh shm_mgr ./cfg/online-boutique-multi-nodes-one-side.cfg
sudo ./run.sh gateway cfg/online-boutique-multi-nodes-one-side.cfg
sudo ./run.sh frontendservice 1
sudo ./run.sh recommendationservice 5
sudo ./run.sh checkoutservice 7
```


worker 2
```bash
sudo ./run.sh shm_mgr ./cfg/online-boutique-multi-nodes-one-side.cfg
sudo ./run.sh gateway cfg/online-boutique-multi-nodes-one-side.cfg
sudo ./run.sh currencyservice 2
sudo ./run.sh productcatalogservice 3
sudo ./run.sh cartservice 4
sudo ./run.sh shippingservice 6
sudo ./run.sh paymentservice 8
sudo ./run.sh emailservice 9
sudo ./run.sh adservice 10

```


## DNE with P-ING


follow the order

1. start memory manager on the host1
2. start sockmap manager on the host1
3. start memory manager on the host2
4. start sockmap manager on the host2
5. start gateway on dpu1
6. start gateway on dpu2
7. start P-ing on host3
8. start functions on host1
9. start functions on host2




worker1 host

```bash
sudo ./run.sh shm_mgr ./cfg/online-boutique-palladium-dpu.cfg
sudo ./run.sh sockmap_manager
sudo ./run.sh frontendservice 1
sudo ./run.sh recommendationservice 5
sudo ./run.sh checkoutservice 7
```

dpu1

```bash
sudo ./run.sh gateway ./cfg/online-boutique-palladium-dpu.cfg
```

worker2 host

```bash
sudo ./run.sh shm_mgr ./cfg/online-boutique-palladium-dpu.cfg
sudo ./run.sh sockmap_manager
sudo ./run.sh currencyservice 2
sudo ./run.sh productcatalogservice 3
sudo ./run.sh cartservice 4
sudo ./run.sh shippingservice 6
sudo ./run.sh paymentservice 8
sudo ./run.sh emailservice 9
sudo ./run.sh adservice 10
```

dpu2

```bash
sudo ./run.sh gateway ./cfg/online-boutique-palladium-dpu.cfg
```

## CNE with P-ING


follow the order

1. start memory manager on the host1
2. start memory manager on the host2
3. start gateway on dpu1
4. start gateway on dpu2
5. start P-ing on host3
6. start functions on host1
7. start functions on host2




worker1 host

```bash
sudo ./run.sh shm_mgr ./cfg/online-boutique-palladium-dpu.cfg
sudo ./run.sh frontendservice 1
sudo ./run.sh recommendationservice 5
sudo ./run.sh checkoutservice 7
```


worker2 host

```bash
sudo ./run.sh shm_mgr ./cfg/online-boutique-palladium-dpu.cfg
sudo ./run.sh currencyservice 2
sudo ./run.sh productcatalogservice 3
sudo ./run.sh cartservice 4
sudo ./run.sh shippingservice 6
sudo ./run.sh paymentservice 8
sudo ./run.sh emailservice 9
sudo ./run.sh adservice 10
```

## DNE without P-ING with simple function chains

follow the order

1. start memory manager on the host1
2. start memory manager on the host2
3. start gateway on dpu1
4. start gateway on dpu2
5. start functions on host1
6. start functions on host2




worker1 host

```bash
sudo ./run.sh shm_mgr ./cfg/my-palladium-cpu.cfg
sudo ./run.sh frontendservice 1
sudo ./run.sh recommendationservice 5
sudo ./run.sh checkoutservice 7
```


worker2 host

```bash
sudo ./run.sh shm_mgr ./cfg/my-palladium-cpu.cfg
sudo ./run.sh currencyservice 2
sudo ./run.sh productcatalogservice 3
sudo ./run.sh cartservice 4
sudo ./run.sh shippingservice 6
sudo ./run.sh paymentservice 8
sudo ./run.sh emailservice 9
sudo ./run.sh adservice 10
```


## test

use `wrk -t1 -c90 -d30s http://192.168.10.61:8080/1/cart -H "Connection: Close"` to test for cart endpoint
use `wrk -t1 -c90 -d30s http://192.168.10.61:8080/1/ -H "Connection: Close"` to test for default endpoint

use the `pidstat 1` to monitor the CPU usage

