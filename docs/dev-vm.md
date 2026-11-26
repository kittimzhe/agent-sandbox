# The development VM

The BPF side of the tree builds and runs on `sandbox-dev`, a Lima VM on
the macOS host. This page records how it is put together and the facts
the Makefile and the loader rely on. Recreate it with:

```sh
limactl start --tty=false --name=sandbox-dev .lima-images/sandbox-dev.yaml
```

The template installs the toolchain with apt at first boot and shares
the project tree read-only; the guest never writes the share, and
artifacts come out with `limactl cp`.

## Facts the code relies on

| Fact | Value | Why it matters |
|---|---|---|
| Kernel | 7.0.0-43-generic (Ubuntu 26.04 arm64) | bleeding edge: the tree targets current kernels, no fallback |
| BPF LSM | active (`lsm=` lists `bpf`) | the LSM hooks the sandbox attaches are live |
| Kernel BTF | `/sys/kernel/btf/vmlinux` | **kernel 7.0 renamed the 5.x/6.x `vfs` to `vmlinux`**; `bpf/gen-vmlinux.sh` handles both |
| cgroup v2 | mounted, controllers: cpuset cpu io memory hugetlb pids rdma misc dmem | the scope is a cgroup v2 subtree |
| Toolchain | go 1.26.8, clang 21.1.8, bpftool 7.7.0 | clang ≥ 18 with the BPF target; `-mcpu=v4` instructions |
| Config | `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y` | LSM attachment and CO-RE relocations |

## Host ↔ guest file flow

The share is read-only from the guest (a Lima/vz virtiofs quirk), so
the flow is one-directional by design:

- host edits files; the guest compiles them in place from the share;
- artifacts the guest produces (objects, skeletons, logs) go to the
  guest's `$HOME` and come out with `limactl cp sandbox-dev:… .`;
- `bpf/vmlinux.h` is generated inside the guest and copied out; it is
  git-ignored, because a stale one defeats CO-RE.
