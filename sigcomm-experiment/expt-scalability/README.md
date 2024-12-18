# RDMA scalability test

This experiment contains necessary code to produce the scalability experiment in paper.

## QP scalability issue.

In this experiment, we demonstrate the scalability issue when RDMA QP number increases. To saturate the link speed, we run different `perftest` program on different cores and aggregate their bandwidth. Specially, we use `taskset` tool to run `perftest` on different core. Each perftest instance would establish several QP connections.

The experiment is down on cloudlab `c6525-25g` machine with ConnectX-5 NIC and 25G link speed.
The machine is equipped with a CPU with 16 physical cores and 32 hyper-threaded cores without NUMA.

## Run the experiment

### setup the RDMA device
First, we need to have a two node machine with RDMA support.

To install the RDMA OFED driver on host, please refer to [doc](https://docs.nvidia.com/networking/display/mlnxofedv461000/downloading+mellanox+ofed)

For DPU, the OFED driver should be setted up when DOCA is configured.

One machine will be the server and ther other machine will be the client.

### determine server IP

On the server side, the command will be like `python exp1.py --n_core 16 --n_qp 128 -x <sgid index> -i <ib port> -d <device index>`

On the client side, the command will have an extra option to specify the server IP, like `python exp1.py --n_core 16 --n_qp 128 -x <sgid index> -i <ib port> -d <device index> --server_ip 10.10.1.1`

### determine RDMA specific settings

The `-d`, `-x` and `-i` setting specifies the RDMA device index, sgid index and ip port settings. These settings should be adjusted on a per node basis.

Please follow the following steps to determine these values.
![](../../docs/figures/gid_instruction.png)

1. determine a interface to use, note the interfaces on two nodes should in same IP sub network so they can talk to each other.

2. Choose the row with v2 instead of v1, which stands for RoCEv2 support.

3. determine the device index(`-d`), which is number in yellow square labeled 3.

4. determine the ip port setting(`-i`), which is the number in the yellow sqare labeled 4.

5. determine the sgid index setting(`-x`), which is the number in the yellow sqare labeled 5.

For example, follow the setting in the picture, we should be using `python exp1.py --n_core 16 --n_qp 128 -x 3 -i 1 -d 2` on the server node and `python exp1.py --n_core 16 --n_qp 128 -x 3 -i 1 -d 2 --server_ip 10.10.1.1` on the client node.

### run under different settings
We need to run the server side first on one node then run the client side after on the other node and make sure **--n_core and --n_qp** settings are same across two nodes.
In this experiment, we will run the experiment on different paramters and collect the result. specically, we will first set `--n_core` to 2, and change the `--n_qp` 

**NOTE: run one server side command first, then run the corresponding client side command, wait untill the client finished, then repeat**
**THe result will be collected in the result.txt file**

```bash
# on the server side
python exp1.py --n_core 2 --n_qp 4 -x 3 -i 1 -d 2
# on the client side
python exp1.py --n_core 2 --n_qp 4 -x 3 -i 1 -d 2 --server_ip 10.10.1.1 >> result.txt
```

```bash
# on the server side
python exp1.py --n_core 2 --n_qp 4 -x 3 -i 1 -d 2
# on the client side
python exp1.py --n_core 2 --n_qp 4 -x 3 -i 1 -d 2 --server_ip 10.10.1.1 >> result.txt
```

test with `--n_qp` from the list `[4, 32, 128, 256, 512, 1024, 2048]`


Then we run another set of experiment with `--n_core` set to 16

```bash
# on the server side
python exp1.py --n_core 16 --n_qp 4 -x 3 -i 1 -d 2
# on the client side
python exp1.py --n_core 16 --n_qp 4 -x 3 -i 1 -d 2 --server_ip 10.10.1.1 >> result.txt
```

```bash
# on the server side
python exp1.py --n_core 16 --n_qp 4 -x 3 -i 1 -d 2
# on the client side
python exp1.py --n_core 16 --n_qp 4 -x 3 -i 1 -d 2 --server_ip 10.10.1.1 >> result.txt
```

test with `--n_qp` from the list `[4, 32, 128, 256, 512, 1024, 2048]`

