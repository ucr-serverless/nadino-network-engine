# install RDMA driver and ibverb library

## install on host (CPU)

To compile palladium-gateway, [OFED driver](https://network.nvidia.com/products/infiniband-drivers/linux/mlnx_ofed/) for Mallonox RDMA device on the device is needed. (only CX4 above is supported in palladium-gateway)

Please refer to the installation instruction to install the OFED driver for your system.

For ubuntu 22.04, there is an handy script in RDMA_lib that download OFED driver and install it.

**Please verify the content of the script and use it on your own risk**
**There is no guarantee for the script**

```
cd palladium-gateway/
bash RDMA_lib/scripts/install_ofed_driver.sh
```
