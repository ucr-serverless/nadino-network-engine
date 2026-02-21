# Configuration File Reference

Config files for NADINO Network Engine live in the `cfg/` directory and use
[libconfig](https://hyperrealm.github.io/libconfig/) syntax.

## Choosing a Config File

| File | Use case |
|------|----------|
| `cfg/example.cfg` | Single-node dummy function chain (4 NFs) |
| `cfg/online-boutique-palladium-host.cfg` | Online Boutique, CNE (CPU gateway, 2 nodes) |
| `cfg/ae_online-boutique-palladium-dpu.cfg` | Online Boutique, DNE (DPU gateway, 2 nodes) |
| `cfg/simple-two-nodes-palladium-dpu.cfg` | Simple 2-node DNE setup |
| `cfg/example_cloudlab.cfg` | CloudLab example with hostname fields |

## Node Settings (`nodes` group)

Each entry in the `nodes` group identifies a worker node. On CloudLab, set the `hostname` field
to the allocated node's hostname.

```
device_idx`, `sgid_idx`, `ib_port`, and `qp_num` must reflect your RDMA hardware:
```

| Field | Description |
|-------|-------------|
| `device_idx` | Index of the RDMA device (from `ibv_devinfo`) |
| `sgid_idx` | GID index to use (e.g. 3 for RoCEv2 on most CloudLab setups) |
| `ib_port` | InfiniBand port number of the RDMA device |
| `qp_num` | Number of queue pairs to initialize — **must be the same on all nodes** |

To auto-detect the correct values for a CloudLab node:

```bash
python RDMA_lib/scripts/get_cloudlab_node_settings.py
```

This script runs `ibv_devinfo -v`, `lspci | grep Mellanox`, and `show_gids` and prints the
recommended values. Requires the OFED/DOCA driver to be installed. Only ConnectX-4 and later
devices are supported.

## Hugepage / Mempool Setting

`local_mempool_size` controls how many elements the shared memory manager allocates from the
DPDK hugepage pool. If hugepage allocation was reduced (e.g. `vm.nr_hugepages=32768`), lower
this value until `shm_mgr` initializes successfully.

```bash
# Check available hugepages
cat /proc/meminfo | grep Huge
```

## RDMA Transport Settings

These options control the RDMA data path. Most deployments can leave them at their defaults.

| Option | Description |
|--------|-------------|
| `use_rdma` | `1` = RDMA, `0` = TCP socket fallback |
| `use_one_side` | `1` = one-sided (RDMA READ/WRITE), `0` = two-sided (SEND/RECV) |
| `mr_per_qp` | Memory regions per queue pair (one-sided only; set `0` for two-sided) |
| `init_cqe_num` | Initial completion queue size (actual size may be lower due to device limits) |
| `max_send_wr` | Upper bound on the send queue depth (actual value may be capped by the device) |

### Two-sided RDMA (default for most configs)

```ini
use_rdma = 1;
use_one_side = 0;
mr_per_qp = 0;
```

### One-sided RDMA

```ini
use_rdma = 1;
use_one_side = 1;
mr_per_qp = 4;   # tune based on your workload
```
