#/bin/bash
# This script can be run with non-root user

sudo apt update && sudo apt install -y flex bison build-essential dwarves libssl-dev libelf-dev \
                    libnuma-dev pkg-config python3-pip python3-pyelftools \
                    libconfig-dev golang clang uuid-dev sysstat clang-format libglib2.0-dev apache2-utils cmake libjson-c-dev gdb libstdc++-12-dev nlohmann-json3-dev

sudo pip3 install meson ninja

curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin

# Add ~/.local/bin to PATH in bashrc and/or zshrc
add_to_path() {
    local rc_file="$1"
    local line='export PATH="$HOME/.local/bin:$PATH"'

    if [[ -f "$rc_file" ]]; then
        if ! grep -q '.local/bin' "$rc_file"; then
            echo "" >> "$rc_file"
            echo "# Added by just installer" >> "$rc_file"
            echo "$line" >> "$rc_file"
            echo "Added PATH entry to $rc_file"
        else
            echo "$rc_file already has .local/bin in PATH, skipping"
        fi
    fi
}

add_to_path "$HOME/.bashrc"
add_to_path "$HOME/.zshrc"

# Apply to current session
export PATH="$HOME/.local/bin:$PATH"

echo "just $(just --version) installed successfully"
echo "Restart your shell or run: source ~/.bashrc"
# cd /mydata # Use the extended disk with enough space
#
# wget --no-hsts https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.16.tar.xz
# tar -xf linux-5.16.tar.xz
# cd linux-5.16
# make olddefconfig
# scripts/config --set-str SYSTEM_TRUSTED_KEYS ""
# scripts/config --set-str SYSTEM_REVOCATION_KEYS ""
# make -j $(nproc)
# find -name *.ko -exec strip --strip-unneeded {} +
# sudo make modules_install -j $(nproc)
# sudo make install
# cd ..
#
# sudo reboot
