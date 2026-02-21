# Creating a CloudLab Cluster

This project is tested on CloudLab [`r7525`](https://docs.cloudlab.us/hardware.html) nodes
using the customized [dpu-same-lan](https://www.cloudlab.us/p/KKProjects/dpu-same-lan) network
profile, which provisions worker nodes and BlueField-2 DPUs on the same LAN.

## Steps

1. Log in to [CloudLab](https://www.cloudlab.us/) and go to **Experiments → Start Experiment**.

2. Select the **dpu-same-lan** profile (or the standard **small-lan** profile for CNE-only
   experiments).

3. On the parameterization page:
   - Set the number of nodes as needed (typically 2 worker nodes + ingress node)
   - Set the OS image to **Ubuntu 22.04**
   - Select **r7525** as the node type
   - Check **Temp Filesystem Max Space** to maximize disk space
   - Keep the temporary filesystem mount point as **/mydata**

4. Wait for the cluster to initialize (5–10 minutes).

5. Extend the working directory on each node:

   ```bash
   sudo chown -R $(id -u):$(id -g) /mydata
   cd /mydata
   export MYMOUNT=/mydata
   ```

6. Clone the repository and follow [README.md](../README.md) for installation.

## Hardware Notes

- Each `r7525` node has dual Mellanox ConnectX-6 NICs and a BlueField-2 DPU.
- The DPU runs its own Ubuntu image and is reachable via the host's management interface.
- Refer to the [CloudLab hardware page](https://docs.cloudlab.us/hardware.html) for full specs.
