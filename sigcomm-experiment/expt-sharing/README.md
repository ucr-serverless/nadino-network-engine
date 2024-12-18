# RDMA sharing test

This experiment contains necessary code to produce the sharing experiment in paper.

## Run the experiment

### setup the RDMA device
First, we need to have a two node machine with RDMA support.

To install the RDMA OFED driver on host, please refer to [doc](https://docs.nvidia.com/networking/display/mlnxofedv461000/downloading+mellanox+ofed)

For DPU, the OFED driver should be setted up when DOCA is configured.

One machine will be the server and ther other machine will be the client.

### compile the code

First, under the base directory of the `palladium-gateway`, issue

`git submodule update --init --recursive`

to download git submodules

Then install dependencies by

```bash
bash sigcomm-experiment/env-setup/001-env_setup_master.sh
bash sigcomm-experiment/env-setup/002-env_setup_master.sh
```

Then make

```
make all
```

The binary `bin/sharing` should be generated

### determine IP and port

On the server side, the command will be like 
`./bin/sharing --local_ip 10.10.1.1 --port 10001 -i 1 -x 3 -d 2 -p 2000000`

On the client side, the command will have an extra option to specify the server IP, like `./bin/sharing --port 10001  -i 1 -x 3 -d 2 --server_ip 10.10.1.1 -p 2000000 -t 128`

The `--local_ip` option would be used by the server for listening.

The `--server_ip` option would be used by the client to connect.

Therefore these two IP should be the server's listening IP.

Also, the `--port` setting will be used by client and server thus should be set to the same.

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


### experiment specific setting

For our experiment, we will fix `-p`, which is the message to send, as `2000000`

We will change the `-t` setting of the client, which allocate threads.

For each setting, start the server by `./bin/sharing --local_ip 10.10.1.1 --port 10001 -i 1 -x 3 -d 2 -p 2000000`

Then run a client with different `-t` settings

**NOTE: run one server side command first, then run the corresponding client side command, wait untill the client finished, then repeat**
**THe result will be collected in the result.txt file**

**The `-l` will run the program without locking**
```bash
# on the server side
./bin/sharing --local_ip 10.10.1.1 --port 10001 -i 1 -x 3 -d 2 -p 20000000
# on the client side
./bin/sharing --port 10001  -i 1 -x 3 -d 2 --server_ip 10.10.1.1 -p 20000000 -l >> result.txt
```

```bash
# one thread with lock
# on the server side
./bin/sharing --local_ip 10.10.1.1 --port 10001 -i 1 -x 3 -d 2 -p 20000000
# on the client side
./bin/sharing --port 10001  -i 1 -x 3 -d 2 --server_ip 10.10.1.1 -p 20000000 -t 1 >> result.txt
```

```bash
# two thread with lock
# on the server side
./bin/sharing --local_ip 10.10.1.1 --port 10001 -i 1 -x 3 -d 2 -p 20000000
# on the client side
./bin/sharing --port 10001  -i 1 -x 3 -d 2 --server_ip 10.10.1.1 -p 20000000 -t 1 >> result.txt
```

run the program with `-t` value from list `[2, 4, 8, 16, 32, 64, 128]`
