#/bin/bash
# This script can be run with non-root user

echo "Installing libbpf"
cd

git clone --single-branch https://github.com/libbpf/libbpf.git
cd libbpf
git switch --detach v0.6.0
cd src
make -j $(nproc)
sudo make install
echo "/usr/lib64/" | sudo tee -a /etc/ld.so.conf
sudo ldconfig
sudo cp libbpf.so.0.6.0 /lib/x86_64-linux-gnu/
sudo ln -sf /lib/x86_64-linux-gnu/libbpf.so.0.6.0 /lib/x86_64-linux-gnu/libbpf.so.0
cd ../..

arch=$(uname -m)

if [[ "$arch" == "aarch64" ]]; then
    echo "This is a 64-bit ARM architecture. Assume it is DPU, skip the DPDK installation"
    echo "Set up hugepages"
    sudo sysctl -w vm.nr_hugepages=400
elif [[ "$arch" == "x86_64" ]]; then
    echo "This is not an ARM architecture. Detected architecture: $arch"
    echo "Installing DPDK"
    cd
    # Perform actions for other architectures
    git clone --single-branch git://dpdk.org/dpdk
    cd dpdk
    git switch --detach v21.11
    meson build
    cd build
    ninja
    sudo ninja install
    sudo ldconfig
    cd ../..
    echo "Set up hugepages"
    sudo sysctl -w vm.nr_hugepages=32768
fi





