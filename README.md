# PALLADIUM

## Installation guideline (on Cloudlab) ##

This guideline is mainly for deploying PALLADIUM on [NSF Cloudlab](https://www.cloudlab.us/). 


First, clone palladium-gateway to your machine and update the git submodule RDMA\_lib.
```
git clone git@github.com:ucr-serverless/palladium-gateway.git
cd palladium-gateway
git submodule update --init --recursive
```


Our development environment is Cloudlab node type c6525-25g
Refer to [Cloudlab machine type](https://docs.cloudlab.us/hardware.html) page for more detail.


Follow steps below to set up palladium-gateway dependencies and get ready to run:

- [Setup the DOCA environment on DPU](https://docs.nvidia.com/doca/sdk/nvidia+doca+installation+guide+for+linux/index.html)
- [Installing PALLADIUM dependencies](/docs/install-dependencies.md)
- remember to call `git submodule update --init --recursive` to pull RDMA\_lib
- build the RDMA_lib
    ```
    cd RDMA_lib
    meson setup build --reconfigure
    ninja -C build/ -v
    ```
- setup palladium-gateway with `meson setup build`

- compile binaries with `ninja -C build/ -v`

- [Change cfg file](/docs/change-cfg-file.md)

## run with dummy function chain

On node 1


