# PALLADIUM

## Installation guideline (on Cloudlab) ##

This guideline is mainly for deploying PALLADIUM on [NSF Cloudlab](https://www.cloudlab.us/). 


First, clone palladium-gateway to your machine and update the git submodule RDMA_lib.
```
git clone git@github.com:ucr-serverless/palladium-gateway.git
git submodule update --init --recursive
```

Our development environment is Cloudlab node type c6525-25g
Refer to [Cloudlab machine type](https://docs.cloudlab.us/hardware.html) page for more detail.

Follow steps below to set up palladium-gateway dependencies and get ready to run:

- [Install the RDMA driver](docs/install-RDMA-driver.md)
- [Installing PALLADIUM dependencies](/docs/install-dependencies.md)
- Compile palladium-gateway with `make all`
- [Change cfg file](/docs/change-cfg-file.md)



