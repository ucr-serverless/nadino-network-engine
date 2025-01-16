build:
    ninja -C build/ -v
update:
    git submodule update --remote
    git pull --recurse-submodules
    ninja -C build/
init:
    git submodule update --init --recursive
ir:
    bash RDMA_lib/scripts/install_ofed_driver.sh
reset_main:
    git fetch
    git reset --hard origin/main
format:
    ninja -C build/ clang-format
gs:
    git status
gl:
    git log --all --graph
rdma:
    cd RDMA_lib && meson setup build --reconfigure && ninja -C build/ -v
doca:
    cd DOCA_lib && meson setup build --reconfigure && ninja -C buils/ -v
debug:
    meson setup build --buildtype=debug
    ninja -C build/ -v
list_dev:
    /opt/mellanox/doca/tools/doca_caps --list-devs


