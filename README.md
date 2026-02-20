# NADINO Network Engine and Functions

## Installation guideline (on Cloudlab) ##

This guideline is mainly for deploying NADINO's network engine and functions on [NSF Cloudlab](https://www.cloudlab.us/). 


First, clone the repo to your machine and update the git submodule RDMA\_lib.
```
git clone git@github.com:ucr-serverless/nadino-network-engine.git
cd nadino-network-engine
git submodule update --init --recursive
```


Our development environment is Cloudlab node type r7525 with 4 nodes

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


## DNE with NADINO-ingress

Two tmux scripts are provided to automate the terminal setup on each host.
Each script opens a session with 16 panes in a tiled layout and pre-fills the
commands (without executing them), so you can launch each process in the
correct order by pressing Enter in the appropriate pane.

Run from the project root on the respective host:

```bash
# On worker1 host
./scripts/tmux_dne_host1.sh

# On worker2 host
./scripts/tmux_dne_host2.sh
```

Follow the order

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
sudo ./run.sh shm_mgr ./cfg/ae_online-boutique-palladium-dpu.cfg
sudo ./run.sh sockmap_manager
sudo ./run.sh frontendservice 1
sudo ./run.sh recommendationservice 5
sudo ./run.sh checkoutservice 7
```

dpu1

```bash
sudo ./run.sh gateway ./cfg/ae_online-boutique-palladium-dpu.cfg
```

worker2 host

```bash
sudo ./run.sh shm_mgr ./cfg/ae_online-boutique-palladium-dpu.cfg
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
sudo ./run.sh gateway ./cfg/ae_online-boutique-palladium-dpu.cfg
```

## CNE with NADINO ingress


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
sudo ./run.sh shm_mgr ./cfg/online-boutique-palladium-host.cfg
sudo ./run.sh cpu_gateway ./cfg/online-boutique-palladium-host.cfg
sudo ./run.sh frontendservice 1
sudo ./run.sh recommendationservice 5
sudo ./run.sh checkoutservice 7
```


worker2 host

```bash
sudo ./run.sh shm_mgr ./cfg/online-boutique-palladium-host.cfg
sudo ./run.sh cpu_gateway ./cfg/online-boutique-palladium-host.cfg
sudo ./run.sh currencyservice 2
sudo ./run.sh productcatalogservice 3
sudo ./run.sh cartservice 4
sudo ./run.sh shippingservice 6
sudo ./run.sh paymentservice 8
sudo ./run.sh emailservice 9
sudo ./run.sh adservice 10
```

## CNE without P-ING with simple function chains

CNE features a simple http ingress.

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

### NAIDNO ingress

Notice the IP should be changed to the IP of [NADINO-ingress](https://github.com/ucr-serverless/nadino-ingress).

use `wrk -t1 -c50 -d10s http://10.10.1.3:80/rdma/1/cart -H "Connection: Close"` to test for cart endpoint

use `wrk -t1 -c50 -d10s http://10.10.1.3:80/rdam/1/ -H "Connection: Close"` to test default endpoint

use `wrk -t1 -c50 -d10s "http://10.10.1.3:80/rdam/1/product?1YMWWN1N4O" -H "Connection: Close"` to test the product function chain

use the `pidstat 1` to monitor the CPU usage

### default ingress

Notice the IP should be changed to the IP of NADINO-network engine on host 1.

use `wrk -t1 -c50 -d10s http://10.10.1.3:80/1/cart -H "Connection: Close"` to test for cart endpoint

use `wrk -t1 -c50 -d10s http://10.10.1.3:80/1/ -H "Connection: Close"` to test default endpoint

use `wrk -t1 -c50 -d10s "http://10.10.1.3:80/1/product?1YMWWN1N4O" -H "Connection: Close"` to test the product function chain

