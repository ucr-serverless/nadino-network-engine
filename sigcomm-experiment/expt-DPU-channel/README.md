# DPU channel latency measurement

First, we should build a binary individually on Host and DPU side for them to communicate.

Second, we should invoke the python script to run the experiment.

To let pkg-config find doca libraries, we need to add the path to the `PKG_CONFIG_PATH`.
Normally it is already included in the variable.
We can check by `echo $PKG_CONFIG_PATH`.

If the `$PKG_CONFIG_PATH` is not set, we should manually set it with the following steps.

If you are on Host, the doca library is located at `/opt/mellanox/doca/lib/x86_64-linux-gnu/`.
We should export with

```bash
export PKG_CONFIG_PATH=/opt/mellanox/doca/lib/x86_64-linux-gnu/pkgconfig/:$PKG_CONFIG_PATH
```

If you are on DPU, the doca library is located at `/opt/mellanox/doca/lib/x86_64-linux-gnu/`.
We should export with

```bash
export PKG_CONFIG_PATH=/opt/mellanox/doca/lib/aarch64-linux-gnu/pkgconfig/:$PKG_CONFIG_PATH
```

We can run this code snippet to test if we set it correct or not.

```bash
if pkg-config --exists doca-argp; then
    echo "doca-argp is installed."
else
    echo "doca-argp is not installed."
fi

```

Then we can compile the code with

```bash
meson setup build
ninja -C build/

```

We can verify the compiled binary with `./build/DPU_channel -h`
