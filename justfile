update:
    git pull --recurse-submodules
    cd RDMA_lib && git checkout main
init:
    git submodule update --init --recursive
ir:
    bash RDMA_lib/scripts/install_ofed_driver.sh

