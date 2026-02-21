# Usage

See the **Running** section of [README.md](../README.md) for complete instructions.

## Run Modes

NADINO Network Engine supports two I/O backends, selected by the `RTE_RING` environment variable:

| Mode | env var | Description |
|------|---------|-------------|
| SK_MSG (default) | *(unset)* | Uses eBPF SK_MSG for inter-function descriptor delivery |
| RTE Ring | `RTE_RING=1` | Uses DPDK RTE Ring for inter-function descriptor delivery |

Both modes share the same DPDK mempool backend.

## Starting Components

```bash
# Shared memory manager (always first)
sudo ./run.sh shm_mgr <cfg_file>

# Gateway — DPU (DNE) or CPU (CNE)
sudo ./run.sh gateway <cfg_file>       # DPU gateway
sudo ./run.sh cpu_gateway <cfg_file>   # CPU gateway

# Network functions
sudo ./run.sh nf <nf_id>              # Generic dummy NF
sudo ./run.sh <service_name> <nf_id>  # Named online-boutique service
```

## Using RTE Ring Mode

Prefix commands with `RTE_RING=1`:

```bash
sudo RTE_RING=1 ./run.sh shm_mgr cfg/example.cfg
sudo RTE_RING=1 ./run.sh gateway cfg/example.cfg
sudo RTE_RING=1 ./run.sh nf 1
```
