# BlueField-2 DPU Setup Guide for CloudLab

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture and Modes of Operation](#architecture-and-modes-of-operation)
3. [Prerequisites](#prerequisites)
4. [Host-Side Setup](#host-side-setup)
5. [DPU Image Installation](#dpu-image-installation)
6. [Connecting to the DPU](#connecting-to-the-dpu)
7. [DPU Initial Configuration](#dpu-initial-configuration)
8. [Firmware Management](#firmware-management)
9. [Network Configuration](#network-configuration)
10. [CloudLab-Specific Setup](#cloudlab-specific-setup)
11. [Post-Configuration Verification](#post-configuration-verification)
12. [Troubleshooting](#troubleshooting)
13. [References](#references)

---

## Overview

The NVIDIA BlueField-2 is a Data Processing Unit (DPU) / SmartNIC that combines:
- **8 ARM Cortex-A72 cores** for offloaded processing
- **ConnectX-6 Dx network controller** for high-performance networking
- Ability to run a full Linux OS independently from the host

The DPU can offload complex functions from the host CPU, including networking, storage, and security operations.

### Key Interfaces

| Interface | Description |
|-----------|-------------|
| `tmfifo_net0` | Internal PCIe-based communication channel between host and DPU (rshim) |
| `oob_net0` | Out-of-band management interface |
| `p0`, `p1` | Physical uplink ports (external network) |
| `pf0hpf`, `pf1hpf` | Host Physical Function representors |
| `enp3s0f0s0` | Scalable Function (SF) interface on DPU |

---

## Architecture and Modes of Operation

BlueField-2 supports multiple operational modes:

For our usage, we should make sure DPU is under ECPF mode; if it is not, refer to the troubleshooting to change its mode.

### 1. Separated Host Mode (Legacy)
- Host and ARM CPUs operate independently
- Both share the NIC but manage their own functions
- No centralized traffic control

### 2. Embedded CPU Function Ownership (ECPF) Mode
- **Recommended mode for most use cases**
- All host communications route through the SmartNIC ARM cores
- Provides centralized control via Open vSwitch (OVS)
- Uses representors to map host functions to DPU interfaces

### 3. Restricted Mode
- Limited ARM CPU access for specific use cases

### Network Representors (ECPF Mode)

In ECPF mode, the DPU uses kernel representors connected to an embedded switch (E-Switch):

- **Uplink representors:** `p0`, `p1` (physical ports)
- **PF representors:** `pf0hpf`, `pf1hpf` (host physical functions)
- **SF representors:** `en3f<X>pf<Y>sf<Z>` (scalable functions)

---

## Prerequisites

- CloudLab node with BlueField-2 DPU installed
- Host running Ubuntu 22.04 (or compatible OS)
- Root/sudo access on the host
- DOCA SDK package (version 2.10 recommended for NADINO)

---

## Host-Side Setup

### Step 1: Verify DPU Installation

```bash
lspci | grep -i mell
```

Expected output:
```
04:00.0 Ethernet controller: Mellanox Technologies MT42822 BlueField-2 integrated ConnectX-6 Dx network controller (rev 01)
04:00.1 Ethernet controller: Mellanox Technologies MT42822 BlueField-2 integrated ConnectX-6 Dx network controller (rev 01)
04:00.2 DMA controller: Mellanox Technologies MT42822 BlueField-2 SoC Management Interface (rev 01)
```

### Step 2: Install DOCA Host Packages

Download the appropriate DOCA version from [NVIDIA DOCA Downloads](https://developer.nvidia.com/doca-downloads).

```bash
# Example for DOCA 2.9.0 on Ubuntu 22.04 (adjust version as needed)
wget https://www.mellanox.com/downloads/DOCA/DOCA_v2.9.0/host/doca-host_2.9.0-129000-24.10-ubuntu2204_amd64.deb
sudo dpkg -i doca-host_2.9.0-129000-24.10-ubuntu2204_amd64.deb
sudo apt-get update
sudo apt-get -y install doca-all
```

### Step 3: Load Drivers and Initialize MST

Run these commands after installation and after every host reboot:

```bash
# Restart OpenIB driver (may take several minutes)
sudo /etc/init.d/openibd restart

# Initialize Mellanox Software Tools
sudo mst restart
```

### Step 4: Enable and Configure rshim

The rshim (Remote SHell Interface Module) provides host-to-DPU communication.

```bash
# Enable and start rshim service
sudo systemctl enable --now rshim

# Verify rshim device exists
ls /dev/rshim0

# Query DPU system information
sudo bash -c 'echo DISPLAY_LEVEL 2 > /dev/rshim0/misc'
sudo cat /dev/rshim0/misc
```

**Reference:** [Host-Side Interface Configuration](https://docs.nvidia.com/networking/display/bluefielddpuosv470/host-side+interface+configuration)

---

## DPU Image Installation

### Step 1: Download BFB Image

Download the appropriate BFB (BlueField Boot) image:

```bash
wget https://content.mellanox.com/BlueField/BFBs/Ubuntu22.04/bf-bundle-2.10.0-147_25.01_ubuntu-22.04_prod.bfb
```

### Step 2: Install BFB Image via rshim

```bash
# Install pv for progress monitoring
sudo apt install pv

# Flash the BFB image (replace <N> with your rshim number, typically 0)
sudo bfb-install --rshim rshim<N> --bfb <image_path.bfb>
```

### Step 3: Monitor Installation Progress

```bash
sudo cat /dev/rshim0/misc
```

Wait until installation completes. The DPU will reboot automatically.

**Troubleshooting rshim:** [rshim Troubleshooting Guide](https://docs.nvidia.com/networking/display/bluefielddpuosv385/rshim+troubleshooting+and+how-tos)

---

## Connecting to the DPU

### Method 1: Via tmfifo (IPv4)

Configure the host-side tmfifo interface:

```bash
# Temporary configuration
sudo ifconfig tmfifo_net0 192.168.100.1/24

# SSH to DPU (default credentials: ubuntu/ubuntu)
ssh ubuntu@192.168.100.2
```

**Persistent Configuration (Netplan):**

Create or edit `/etc/netplan/99-tmfifo.yaml`:

```yaml
network:
  version: 2
  ethernets:
    tmfifo_net0:
      dhcp4: false
      addresses:
        - 192.168.100.1/24
      routes:
        - to: 192.168.100.0/24
          via: 192.168.100.1
```

Apply with: `sudo netplan apply`


### Default Credentials

- **Username:** ubuntu
- **Password:** ubuntu

---

## DPU Initial Configuration

### Change Password

On first login, you'll be forced to change the password. To allow weaker passwords:

```bash
# Edit password quality configuration
sudo vim /etc/security/pwquality.conf
```

Add these lines:

```text
minlen=6
dictcheck=0
```

Then set new password
```bash
sudo passwd ubuntu
```

### Configure SSH Key Authentication

On the host:

```bash
# Generate SSH key
ssh-keygen -t ed25519

# Copy key to DPU
ssh-copy-id ubuntu@192.168.100.2
```

# Add SSH config for convenience (~/.ssh/config)
```text
Host dpu
    HostName 192.168.100.2
    User ubuntu
```

### Change Hostname

```bash
sudo hostnamectl set-hostname new-hostname

# Update /etc/hosts
sudo vim /etc/hosts
# Change: 127.0.1.1 old-hostname -> 127.0.1.1 new-hostname

# Verify
hostnamectl
```

---

## Firmware Management

*NOTE*: Normally you do not need to update the firmware!!!

### Check Current Firmware Version

```bash
# On DPU
sudo bfvcheck

# On host
sudo mst start
sudo mst status
sudo flint -d /dev/mst/mt<device>_pciconf0 query
```

The PSID appears after "Board ID" (e.g., `MT_0000000559`).

### Identify Your Adapter

Use the [Firmware Identification Tool](https://network.nvidia.com/support/firmware/identification/)

Download firmware from [BlueField-2 Firmware](https://network.nvidia.com/support/firmware/bluefield2/)

### Flash Firmware

```bash
# Flash firmware
sudo flint -d /dev/mst/mt41686_pciconf0 -i <firmware_file.bin> burn

# Verify
sudo flint -d /dev/mst/mt41686_pciconf0 q
```

> **Important:** Some older firmware versions cannot be directly updated to the latest. Update gradually, one LTS version at a time. See [this forum post](https://forums.developer.nvidia.com/t/upgrade-bluefield-2-firmware-failed-with-bad-parameters/308461/4) for details.

### Apply Firmware Update (Reset Required)

For soft reset:
```bash
mlxfwreset
```

If soft reset fails, perform hard power cycle:

1. Shutdown DPU: `sudo shutdown -h now` (from DPU)
2. Verify DPU is off (from host):
   ```bash
   sudo bash -c 'echo DISPLAY_LEVEL 2 > /dev/rshim0/misc'
   sudo cat /dev/rshim0/misc
   # Look for: INFO[BL31]: System Off
   ```
3. Shutdown host: `sudo shutdown -h now`
4. Physically power on the server
5. Verify firmware update: `sudo bfvcheck` (from DPU)

**Reference:** [BlueField Reset Procedures](https://docs.nvidia.com/doca/sdk/nvidia+bluefield+reset+and+reboot+procedures/index.html)

---

## Network Configuration

### DPU Network Interfaces

Use Scalable Functions (SF) for host-DPU communication, not OVS representors:

```bash
# Show SF representor mapping
sudo mlnx-sf -a show

# Show OVS configuration
ovs-vsctl show
```

---

## CloudLab-Specific Setup

### Host Interface Identification

On CloudLab, the DPU interface appears as `enp128s0f0np0` (Scalable Function 0).

### DPU IP Assignment

Assign IPs to SF interfaces on DPU:

*NOTE*: DPU should have the same IP subnet with host interfaces.

```bash
# On DPU (adjust IP per node)
sudo ip addr add 10.10.1.10/24 dev enp3s0f0s0
```

Then try ping host IP/other DPU IP.



### Enable Internet Access via Host (NAT)

The DPU on cloudlab r7525 nodes does not have out-of-band interface connected, so DPU access network through host intermediary.

**On Host:**

```bash
# Enable IP forwarding (temporary)
sudo sysctl -w net.ipv4.ip_forward=1

# Enable IP forwarding (permanent)
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Find internet-facing interface
ip route | grep default
# Example output: default via X.X.X.X dev eno1

# Configure NAT (replace eno1 with your interface)
sudo iptables -t nat -A POSTROUTING -o eno1 -j MASQUERADE

# Make iptables rules persistent
sudo apt-get install iptables-persistent
sudo netfilter-persistent save
```

**On DPU:**

Configure DNS in `/etc/resolv.conf`:

```
nameserver 8.8.8.8
nameserver 8.8.4.4
```

> **Note:** After this, DPU can ping `8.8.8.8`. DNS resolution requires the nameserver entries above.

---

## Post-Configuration Verification

### Check OVS Status

```bash
systemctl status openvswitch-switch.service
ovs-vsctl show
```

### Verify Network Connectivity

```bash
# From DPU
ping 8.8.8.8
ping www.google.com
```

### Handle Automatic Updates

If `apt update` fails due to ongoing automatic updates:

```bash
ps aux | grep unattended
# Wait for the process to complete before running apt commands
```

---

## Troubleshooting

### No VFs on Host Side

Normally after the fresh installation of DPU, host can not see VFs (interfaces), a reboot will usually solve this issue.

But there are also potential other issues (not applicable to cloudlab)
**Causes:**
- Firmware incompatibility with software
- SR-IOV not enabled in host BIOS

**Solutions:**
1. Manually update firmware (see [Firmware Management](#firmware-management))
2. Enable SR-IOV in BIOS settings

### No OVS Interfaces on DPU

**Cause:** DPU may be in Separated Host mode instead of ECPF mode.

**Diagnosis:**
```bash
mlxconfig -d /dev/mst/mtXXXXX_pciconf0 q | grep -i internal_cpu_model
```

If output shows `SEPARATED_HOST(0)`, switch to ECPF mode.

**Reference:** [BlueField Modes of Operation](https://docs.nvidia.com/doca/sdk/nvidia+bluefield+modes+of+operation/index.html)

### rshim Device Not Appearing

```bash
# Check rshim service status
systemctl status rshim

# Enable and start if needed
sudo systemctl enable rshim
sudo systemctl start rshim

# Verify device
ls /dev/rshim*
```

### DPU Boot Takes Too Long

ES2 (Engineering Sample 2) units may take up to 10 minutes to boot. The DPU boots independently of the host.

---

## References

- [NVIDIA DOCA Downloads](https://developer.nvidia.com/doca-downloads)
- [Host-Side Interface Configuration](https://docs.nvidia.com/networking/display/bluefielddpuosv470/host-side+interface+configuration)
- [rshim Troubleshooting](https://docs.nvidia.com/networking/display/bluefielddpuosv385/rshim+troubleshooting+and+how-tos)
- [BlueField Reset Procedures](https://docs.nvidia.com/doca/sdk/nvidia+bluefield+reset+and+reboot+procedures/index.html)
- [BlueField Modes of Operation](https://docs.nvidia.com/doca/sdk/nvidia+bluefield+modes+of+operation/index.html)
- [BlueField-2 Firmware Downloads](https://network.nvidia.com/support/firmware/bluefield2/)
- [Configuring NVIDIA BlueField2 SmartNIC (Insu Jang)](https://insujang.github.io/2022-01-06/configuring-nvidia-bluefield2-smartnic/)
