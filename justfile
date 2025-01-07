build:
    ninja -C build/ -v
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
lc:
    ln build/compile_commands.json compile_commands.json
format:
    ninja -C build/ clang-format
gs:
    git status
gl:
    git log --all --graph
rdma:
    cd RDMA_lib && meson setup build --reconfigure && ninja -C build/ -v
debug:
    meson setup build --buildtype=debug
    ninja -C build/ -v


