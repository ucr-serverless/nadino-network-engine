# primitive comparison

This experiment will compare two side send with one side write with immediate data.

## CPU usage on Receiver side

On one machine start the server program with

```
python cmp.py -p 10001 -c cmd_gen -d <device_idx> -i <ib_port> -x <sgid_idx>

```
Notice server will listen on port 10001.

On the other machine start the client program with


```
python cmp.py -p 10001 -c cmd_gen -d <device_idx> -i <ib_port> -x <sgid_idx> -H <server_ip>

```
The client will specify the server_ip parameter.

The RDMA related setting(`device_idx`, `ib_port` and `sgid_idx`) can be determined by the following method.

The server_ip should also be also using the IP address bind to the RDMA device.

### determine RDMA specific settings

The `-d`, `-x` and `-i` setting specifies the RDMA device index, sgid index and ip port settings. These settings should be adjusted on a per node basis.

Please follow the following steps to determine these values.
![](../../docs/figures/gid_instruction.png)

1. determine a interface to use, note the interfaces on two nodes should in same IP sub network so they can talk to each other.

2. Choose the row with v2 instead of v1, which stands for RoCEv2 support.

3. determine the device index, which is number in yellow square labeled 3, and the full name of the device.

4. determine the ip port setting(`-i`), which is the number in the yellow sqare labeled 4.

5. determine the sgid index setting(`-x`), which is the number in the yellow sqare labeled 5.

For example, follow the setting in the picture, we should be using `python exp1.py --n_core 16 --n_qp 128 -x 3 -i 1 -d 2` on the server node and `python exp1.py --n_core 16 --n_qp 128 -x 3 -i 1 -d 2 --server_ip 10.10.1.1` on the client node.


