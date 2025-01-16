# expt-DPU-channel-scalability

## comch_sr_client

The `-s` option determines the size of the message.
The `-p` option determines the local PCIe device address, which could be get from the `/opt/mellanox/doca/tools/doca_caps --list-devs` command.

The `-r` option determines the remote device's PCIe address.

The `-ts` option determines how many threads would the client create to exchange data with the server.

```bash
./build/comch_sr_client -s 2 -n 100000 -p 0000:d8:00.0 -ts 256
```

## comch_sr_server

```bash
./build/comch_sr_server -s 2 -n 100000 -p 0000:03:00.0 -r 0000:d8:00.0 -ts 256
```

## rdma_server
The `-ts` option controls how many thread would the client initiate and communicate with the server.
The server would be run on DPU and the client would be run on the host where DPU resides.

```mermaid
flowchart LR
    A[DPU] <--> B[Host]
```

```bash
# DPU
./build/rdma_server -d mlx5_0 -g 5 -p 10000 -n 10 -s 12 -ts 1
```


```bash
# Host
./build/rdma_client -d mlx5_0 -g 5 -p 10000 -n 10 -s 12 -ts 1 -a 192.168.10.42
```

## off path mode

```mermaid
flowchart LR
    A[DPU2] <-->|2| B[DPU1]
    B <--> |1| C(Host)
```
The DPU1 would be the server and it should be run first, then run the host command.
After the host connected with the DPU1, init the command on DPU2 and the experiment would start
```bash
# host
./build/rdma_host_export -d mlx5_0 -g 5 -p 10000 -s 12 -ts 2 -a 192.168.10.42
```

```bash
# dpu1
./build/rdma_server -d mlx5_2 -g 1 -p 10000 -n 1000 -s 12 -ts 2 -he
```

```bash
# dpu2
./build/rdma_client -d mlx5_2 -g 1 -p 10000 -n 100000 -s 12 -ts 2 -a 192.168.10.42
```
## on path mode

```mermaid
flowchart LR
    A[DPU2] <-->|2| B[DPU1]
    B <--> |1| C(Host)
```
The DPU1 would be the server and it should be run first, then run the host command.
After the host connected with the DPU1, init the command on DPU2 and the experiment would start
```bash
# host
./build/rdma_host_export -d mlx5_0 -g 5 -p 10000 -s 12 -ts 2 -a 192.168.10.42
```

```bash
# dpu1
./build/rdma_server -d mlx5_2 -g 1 -p 10000 -n 1000 -s 12 -ts 2 -he -onp
```

```bash
# dpu2
./build/rdma_client -d mlx5_2 -g 1 -p 10000 -n 100000 -s 12 -ts 2 -a 192.168.10.42
```
