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

```bash
./build/rdma_server -d mlx5_0 -g 5 -p 10000 -n 10 -s 12 -ts 1
```

## rdma_client

```bash
./build/rdma_client -d mlx5_0 -g 5 -p 10000 -n 10 -s 12 -ts 1 -a 192.168.10.42
```
