# Troubleshooting

## libbpf shared library not found

**Error:**

```
error while loading shared libraries: libbpf.so.0: cannot open shared object file: No such file or directory
```

**Cause:** Ubuntu 22.04 ships libbpf 0.5.0, which conflicts with the version compiled by the
setup scripts.

**Fix:** Re-link the library after running the install scripts:

```bash
# Adjust path to wherever libbpf was built (e.g. /mydata/spright/libbpf/src)
cd /path/to/libbpf/src

sudo cp libbpf.so.0.6.0 /lib/x86_64-linux-gnu/
sudo ln -sf /lib/x86_64-linux-gnu/libbpf.so.0.6.0 /lib/x86_64-linux-gnu/libbpf.so.0
```

---

## DPDK hugepage allocation failure

**Error:**

```
No free 2048 kB hugepages reported on node 0
```

**Fix:** Allocate hugepages and retry:

```bash
sudo sysctl -w vm.nr_hugepages=32768
```

After changing the hugepage count, update `local_mempool_size` in your `.cfg` file accordingly.
See [change-cfg-file.md](change-cfg-file.md) for details.

---

## DPDK EAL initialization — access error

**Symptom:** Any NADINO component exits immediately after printing DPDK EAL initialization
messages.

**Common causes and fixes:**

1. **Hugepages not allocated** — see above.

2. **Another DPDK primary process is already running:**

   ```
   Cannot create lock on '/var/run/dpdk/rte/config'. Is another primary process running?
   ```

   Kill existing processes and retry:

   ```bash
   pkill -f shm_mgr
   pkill -f gateway
   ```

3. **ASLR enabled** (required disabled for DPDK multi-process):

   ```bash
   echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
   ```

---

## Shared memory manager fails to initialize mempool

**Symptom:** `shm_mgr` exits with a mempool or hugepage error shortly after start.

**Fix:** Reduce `local_mempool_size` in the `.cfg` file to match the number of hugepages
available on the node. See [change-cfg-file.md](change-cfg-file.md).

---

## RDMA connection refused or timeout

**Symptom:** Gateway or NF cannot connect to the RDMA peer.

**Checks:**

1. Verify the RDMA device is visible: `ibv_devinfo`
2. Verify `device_idx`, `sgid_idx`, and `ib_port` in the `.cfg` match your hardware.
   Use the helper script:

   ```bash
   python RDMA_lib/scripts/get_cloudlab_node_settings.py
   ```

3. Ensure both nodes use the same `qp_num` in their `.cfg` files.

4. Check that the DOCA/OFED driver is loaded: `lsmod | grep mlx5`
