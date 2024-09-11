# change cfg file

## online-boutique-multi-nodes-two-side.cfg

This is the example cfg file for palladium-gateway using two side RDMA primitives.

### nodes setting

cfg files in `cfg/` directory are supposed to used under for Cloudlab environment.
Notice: although they could work in other environment, but there are no guarantee.


If you want to run experiments on Cloudlab c6525-25g machine, you should change the host name field under the `nodes` group.
Then the cfg file is ready for the experiment.

If you are not using the Cloudlab c6525-25g machine, the four fields `device_idx`, `sgid_idx`, `ib_port` and `qp_num` are subject to change.

- `device_idx`: the index of RDMA device
- `sgid_idx`: the index of sgid to be used
- `ib_port`: the ib port of RDMA device
- `qp_num`: the total number of queue pairs to be initialized

**Notice: qp_num field should be the same cross different nodes.**

`device_idx` ,`sgid_idx` and `ib_port` are subject the RDMA device and should be changed accordingly.

If you are using cloudlab machines, you can run the following command to get the `device_idx`, `sgid_idx` and `ib_port` number and change the setting accordingly on individual machine base.

```bash
python RDMA_lib/scripts/get_cloudlab_node_settings.py
```

This python script will run `ibv_devinfo -v`, `lspci | grep 'Mellanox'` and `show_gids` command under the hood and parse the output.

Please ensure the OFED driver is installed and then run this script.
Also notice only ConnectX-4 and above RDMA device is supported.

### RDMA settings

If you want to use two side RDMA primitive in palladium-gateway, you can leave all settings  unchanged if you do not [change huge page size in your system.](install-dependencies.md)

- `local_mempool_size`: the number of elements in local mempool.
If the number of DPDK huge page is changed, you should change this value accordingly until the shm_mgr can successfully initialize.

**You can leave the following options unchanged**
**They are only for your reference**

- `use_rdma`: whether the palladium-gateway should use RDMA or TCP socket. If it is set to 0, use TCP socket. If it is set to 1, use RDMA. The setting `use_one_side`, `mr_per_qp`, `init_cqe_num`, `max_send_wr` is only meaningful when `use_rdma` is set to 1 (RDMA is used).

- `use_one_side`: whether one-side RDMA primitives or two-side RDMA primitives should be used. When this option is set to 1, one-side primitives would be used. When this option is set to 0, two-side option would be used.

- `mr_per_qp`: This option is only valid for one-side primitives (when `use_one_side` is set to 1). This value determines how many memory regions will be managed by a queue pair. When two-side primitives are used ('use_one_side' is set to 0), leave this value to be zero.

- `init_cqp_num`: This option determines the initial size of RDMA completion queue size. Notice the program would try to allocate as much completion queue elements. The real completion queue size may be smaller than the value you give in this option.

- `max_send_wr`: This options determines the upper bound of the size for send queue in RDMA. Notice the real value maybe smaller than the value you provided.

