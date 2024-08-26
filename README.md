# PALLADIUM

## Installation guideline (on Cloudlab) ##

This guideline is mainly for deploying PALLADIUM on [NSF Cloudlab](https://www.cloudlab.us/). We focus on a single-node deployment to demonstrate the shared memory processing supported by SPRIGHT. Currently SPRIGHT offers several deployment options: Process-on-bare-metal (POBM mode), Kubernetes pod (K8S mode), and Knative functions (Kn mode).

```
git clone git@github.com:ucr-serverless/palladium-gateway.git
git submodule update --init --recursive
```










Follow steps below to set up PALLADIUM:
- [Creating a 3-node cluster on Cloudlab](docs/01-create-cluster-on-cloudlab.md)
- [Upgrading kernel](docs/02-upgrade-kernel-install-deps.md)
- Install the [OFED driver](https://network.nvidia.com/products/infiniband-drivers/linux/mlnx_ofed/) for Mallonox RDMA device (only CX4 above is supported)
- [Installing PALLADIUM dependencies](docs/02-upgrade-kernel-install-deps.md)
- change cfg settings

- [Setting up Kubernetes & Knative](docs/03-setup-k8s-kn.md)
- [Setting up SPRIGHT](docs/04-setup-spright.md)

<!-- ## Documentation ##
Please refer to the [SPRIGHT documentation]() for details on installing, running and deploying SPRIGHT. -->

## SIGCOMM artifact evaluation ##
To reproduce the experiment in [our paper](https://dl.acm.org/doi/abs/10.1145/3544216.3544259), please refer to commit [98434fd](https://github.com/ucr-serverless/spright/tree/98434fd1e4fb9498308151e863975ff6883d5bf7).

