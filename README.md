# NADINO Network Engine

NADINO is a high-performance serverless networking system that offloads inter-function
communication from the host CPU using RDMA. The **NADINO Network Engine (DNE)** manages the
shared-memory data plane and function-chain routing on each worker node.

There are two deployment variants:

| Variant | Abbreviation | Gateway placement |
|---------|-------------|-------------------|
| DPU Network Engine | **DNE** | Runs on a BlueField-2 DPU |
| CPU Network Engine | **CNE** | Runs on the host CPU |

The companion project [nadino-ingress](https://github.com/ucr-serverless/nadino-ingress) provides
the HTTP front-end that forwards incoming requests to the DNE/CNE over RDMA.

## Requirements

- Ubuntu 22.04, kernel 5.15+
- NVIDIA/Mellanox ConnectX-4 or later NIC (for RDMA)
- Tested on CloudLab [`r7525`](https://docs.cloudlab.us/hardware.html) nodes with the
  [dpu-same-lan](https://www.cloudlab.us/p/KKProjects/dpu-same-lan) network profile

## Getting Started

```bash
git clone https://github.com/ucr-serverless/nadino-network-engine.git
cd nadino-network-engine
git submodule update --init --recursive
```

## Installation

### 1. Install RDMA Driver (DOCA)

Install the DOCA-host package on each host node. This installs the `mlx5` RDMA kernel driver
and the required user-space libraries (`libibverbs`, `librdmacm`, etc.).

```bash
wget https://www.mellanox.com/downloads/DOCA/DOCA_v2.10.0/host/doca-host_2.10.0-093000-25.01-ubuntu2204_amd64.deb
sudo dpkg -i doca-host_2.10.0-093000-25.01-ubuntu2204_amd64.deb
sudo apt-get update
sudo apt-get -y install doca-all
```

Verify the driver is loaded:

```bash
lsmod | grep mlx5
# Expected: mlx5_core and mlx5_ib (or similar)
```

### DPU setup

For the DPU (BlueField) side, follow the
[Bluefield2 DPU setup on cloudlab](./docs/BlueField2-DPU-Setup-Guide.md)


### 2. Install Build Dependencies

Run the provided environment-setup scripts from the project root. The first script upgrades the
kernel (a reboot is required); the second installs libbpf, DPDK RTE libraries, and other
dependencies.

```bash
bash sigcomm-experiment/env-setup/001-env_setup_master.sh
bash sigcomm-experiment/env-setup/002-env_setup_master.sh
```

### 3. Configure Hugepages

The `002-env_setup_master.sh` script allocates hugepages automatically. To check the current
state:

```bash
cat /proc/meminfo | grep Huge
```

If your node has less memory and hugepage allocation fails, reduce the count:

```bash
sudo sysctl -w vm.nr_hugepages=32768
```

> **Note**: If you change the hugepage count, update `local_mempool_size` in your `.cfg` file so
> the shared memory manager can initialize correctly. See [docs/change-cfg-file.md](docs/change-cfg-file.md).

### 6. Build NADINO Network Engine

```bash
meson setup build
ninja -C build/ -v
```

## Configuration

Config files live in the `cfg/` directory. Refer to the table below for starting points:

| Config file | Purpose |
|---|---|
| `cfg/ae_online-boutique-palladium-dpu.cfg` | Online Boutique, DNE (DPU gateway) |

*NOTE: The `cfg/ae_online-boutique-palladium-dpu.cfg` is a setup that is used on 4 node r7525 cloudlab setting.*

See [docs/change-cfg-file.md](docs/change-cfg-file.md) for a full reference of all cfg fields,
including how to set `device_idx`, `sgid_idx`, `ib_port`, and `qp_num` for your hardware.

To auto-detect the correct RDMA parameters for a CloudLab node:

```bash
python RDMA_lib/scripts/get_cloudlab_node_settings.py
```

## Running

All components are launched via `run.sh`. Each component must be started **in order** and run
as root. Use `tmux` or `byobu` to manage multiple panes.

### Component Overview

| Component | Command | Role |
|-----------|---------|------|
| Shared memory manager | `run.sh shm_mgr <cfg>` | Initializes DPDK shared memory pool |
| DPU gateway | `run.sh gateway <cfg>` | Runs on BlueField DPU (DNE) |
| CPU gateway | `run.sh cpu_gateway <cfg>` | Runs on host CPU (CNE) |
| Network function | `run.sh <service_name> <nf_id>` | Runs a single function |
| Sockmap manager | `run.sh sockmap_manager` | eBPF SK_MSG path manager (DNE only) |

*NOTE*:  For artifact evaluation, the `cfg/ae_online-boutique-palladium-dpu.cfg` is a setup that is used on 4 node r7525 cloudlab setting.

### Quick Test — Two Node, Dummy Function Chain

```bash
# Start shared memory manager with the example config (2 dummy NFs)
sudo ./run.sh shm_mgr ./cfg/ae_simple_dpu.cfg

# Start gateway (CPU mode)
sudo ./run.sh cpu_gateway ./cfg/ae_simple_dpu.cfg

# Start 4 dummy NFs (each in a separate pane)
sudo ./run.sh nf 1
```

On the second node:

```bash
# Start shared memory manager with the example config (4 dummy NFs)
sudo ./run.sh shm_mgr ./cfg/ae_simple_dpu.cfg

# Start gateway (CPU mode)
sudo ./run.sh cpu_gateway ./cfg/ae_simple_dpu.cfg

# Start 4 dummy NFs (each in a separate pane)
sudo ./run.sh nf 2
```
Test with curl (gateway listens on port 8080):

```bash
curl http://10.10.1.1:8080/
```

### DNE Deployment — Online Boutique (2 Worker Nodes + 2 DPUs + NADINO ingress)

Two tmux setup scripts are provided to pre-fill all commands across 16 panes. Run from the
project root on each host:

```bash
# On worker1 host
./scripts/tmux_dne_host1.sh

# On worker2 host
./scripts/tmux_dne_host2.sh
```

Start components in the following order:

1. Shared memory manager on **worker1 host**
2. Sockmap manager on **worker1 host**
3. Shared memory manager on **worker2 host**
4. Sockmap manager on **worker2 host**
5. Gateway on **DPU1**
6. Gateway on **DPU2**
7. Start NADINO ingress on the **ingress node** (see [nadino-ingress](https://github.com/ucr-serverless/nadino-ingress))
8. Functions on **worker1 host**
9. Functions on **worker2 host**

**Worker1 host:**

```bash
sudo ./run.sh shm_mgr ./cfg/ae_online-boutique-palladium-dpu.cfg
sudo ./run.sh sockmap_manager
sudo ./run.sh frontendservice 1
sudo ./run.sh recommendationservice 5
sudo ./run.sh checkoutservice 7
```

**DPU1:**

```bash
sudo ./run.sh gateway ./cfg/ae_online-boutique-palladium-dpu.cfg
```

**Worker2 host:**

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

**DPU2:**

```bash
sudo ./run.sh gateway ./cfg/ae_online-boutique-palladium-dpu.cfg
```

### CNE Deployment — Online Boutique (2 Worker Nodes, CPU Gateway)

Start components in the following order:

1. Shared memory manager on **worker1 host**
2. CPU gateway on **worker1 host**
3. Shared memory manager on **worker2 host**
4. CPU gateway on **worker2 host**
5. Start NADINO ingress on the **ingress node**
6. Functions on **worker1 host**
7. Functions on **worker2 host**

**Worker1 host:**

```bash
sudo ./run.sh shm_mgr ./cfg/online-boutique-palladium-host.cfg
sudo ./run.sh cpu_gateway ./cfg/online-boutique-palladium-host.cfg
sudo ./run.sh frontendservice 1
sudo ./run.sh recommendationservice 5
sudo ./run.sh checkoutservice 7
```

**Worker2 host:**

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

## Testing

### With nadino-ingress

After starting the network engine and [nadino-ingress](https://github.com/ucr-serverless/nadino-ingress),
send load to the ingress node (replace `10.10.1.3` with the ingress IP):

```bash
# Cart endpoint
wrk -t1 -c50 -d10s http://10.10.1.3:80/rdma/1/cart -H "Connection: Close"

# Default (homepage) endpoint
wrk -t1 -c50 -d10s http://10.10.1.3:80/rdma/1/ -H "Connection: Close"

# Product endpoint
wrk -t1 -c50 -d10s "http://10.10.1.3:80/rdma/1/product?1YMWWN1N4O" -H "Connection: Close"
```

### Without nadino-ingress (CNE built-in HTTP ingress)

The CNE includes a simple HTTP ingress on port 80. Replace `10.10.1.3` with the worker1 host IP:

```bash
wrk -t1 -c50 -d10s http://10.10.1.3:80/1/cart -H "Connection: Close"
wrk -t1 -c50 -d10s http://10.10.1.3:80/1/ -H "Connection: Close"
wrk -t1 -c50 -d10s "http://10.10.1.3:80/1/product?1YMWWN1N4O" -H "Connection: Close"
```

Monitor CPU usage during the test:

```bash
pidstat 1
```

## Troubleshooting

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for known issues and fixes.

**DPDK hugepage allocation error**

```
No free 2048 kB hugepages reported on node 0
```

Allocate or increase hugepages:

```bash
sudo sysctl -w vm.nr_hugepages=32768
```

**libbpf shared library not found**

```
error while loading shared libraries: libbpf.so.0: cannot open shared object file
```

On Ubuntu 22.04 the pre-installed libbpf version may conflict. Re-link the library:

```bash
sudo cp /path/to/libbpf/src/libbpf.so.0.6.0 /lib/x86_64-linux-gnu/
sudo ln -sf /lib/x86_64-linux-gnu/libbpf.so.0.6.0 /lib/x86_64-linux-gnu/libbpf.so.0
```

## Documentation

| File | Contents |
|------|----------|
| [docs/change-cfg-file.md](docs/change-cfg-file.md) | Full cfg file field reference and RDMA tuning |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Known issues and solutions |
| [nadino-ingress README](https://github.com/ucr-serverless/nadino-ingress) | HTTP ingress setup (DPDK/F-stack) |
