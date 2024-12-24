#/bin/bash
# This script can be run with non-root user
arch=$(uname -m)

if ldconfig -p | grep -q libbpf; then
    echo "libbpf is installed."
else
    echo "libbpf is not installed."
    read -p "There are no libbpf detected, do you want to download and install the libbpf?" input
    if [[ "$input" != "y" ]]; then
        exit 1
    fi
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
    if [[ "$arch" == "aarch64" ]]; then
        echo "This is a 64-bit ARM architecture. Assume it is DPU, skip the ebpf lib link"
    elif [[ "$arch" == "x86_64" ]]; then
        sudo cp libbpf.so.0.6.0 /lib/x86_64-linux-gnu/
        sudo ln -sf /lib/x86_64-linux-gnu/libbpf.so.0.6.0 /lib/x86_64-linux-gnu/libbpf.so.0
    fi

    cd ../..
fi



if [[ "$arch" == "aarch64" ]]; then
    echo "This is a 64-bit ARM architecture. Assume it is DPU, skip the DPDK installation"
    echo "Set up hugepages"
    sudo sysctl -w vm.nr_hugepages=400
elif [[ "$arch" == "x86_64" ]]; then
    echo "This is not an ARM architecture. Detected architecture: $arch"
    if pkg-config --exists libdpdk; then
        echo "dpdk found by pkg-config."

        # Get the prefix of dpdk using pkg-config
        DPDK_PATH=$(pkg-config --variable=prefix libdpdk)

        # Check if the path contains /opt/mellanox/dpdk
        if [[ $DPDK_PATH == *"/opt/mellanox/dpdk"* ]]; then
            echo "dpdk is from /opt/mellanox/dpdk."
            exit(0)
        else
            echo "dpdk is not from /opt/mellanox/dpdk. It is located at: $DPDK_PATH"
            exit(0)
        fi
    else
        echo "dpdk not found by pkg-config."
    fi
    read -p "There are no libdpdk detected, do you want to download and install the dpdk?" input
    if [[ "$input" != "y" ]]; then
        exit 1
    fi
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





