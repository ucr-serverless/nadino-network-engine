# RDMA scalability test

This experiment contains necessary code to produce the scalability experiment in paper.

# QP scalability issue.

In this experiment, we demonstrate the scalability issue when RDMA QP number increases. To saturate the link speed, we run different `perftest` program on different cores and aggregate their bandwidth. Specially, we use `taskset` tool to run `perftest` on different core. Each perftest instance would establish several QP connections.

The experiment is down on cloudlab `c6525-25g` machine with ConnectX-5 NIC and 25G link speed.
The machine is equipped with a CPU with 16 physical cores and 32 hyper-threaded cores without NUMA.
