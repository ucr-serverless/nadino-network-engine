update:
    git pull --recurse-submodules
    cd RDMA_lib && git fetch
init:
    git submodule update --init --recursive
ir:
    bash RDMA_lib/scripts/install_ofed_driver.sh
reset_main:
    git fetch
    git reset --hard origin/main

