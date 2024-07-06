## Troubleshooting

1. When you run any SPRIGHT component, you got
```
error while loading shared libraries: libbpf.so.0: cannot open shared object file: No such file or directory
```

Solutions: This may happen when you use Ubuntu 22, which has the libbpf 0.5.0 pre-installed. You need to re-link the `/lib/x86_64-linux-gnu/libbpf.so.0` to `libbpf.so.0.6.0`
```bash
# Assume you have executed the libbpf installation script
cd /path/to/your/directory/of/libbpf/src

# Copy libbpf.so.0.6.0 to /lib/x86_64-linux-gnu/
sudo cp libbpf.so.0.6.0 /lib/x86_64-linux-gnu/

# Re-link libbpf.so.0
sudo ln -sf /lib/x86_64-linux-gnu/libbpf.so.0.6.0 /lib/x86_64-linux-gnu/libbpf.so.0
```