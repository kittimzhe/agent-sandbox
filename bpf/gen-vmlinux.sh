#!/bin/sh
# bpf/gen-vmlinux.sh -- regenerate bpf/vmlinux.h from the running kernel.
#
# vmlinux.h is generated, never committed: it is 4 MB of the running
# kernel's own types, and a stale one is worse than none, because the
# CO-RE relocations would resolve against the wrong layout. Run this on
# the development VM after every kernel update.
#
#   limactl shell sandbox-dev -- sh -c \
#     'bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h'
#   limactl cp sandbox-dev:/tmp/vmlinux.h bpf/vmlinux.h
#
# Kernel 7.0 moved the vmlinux BTF from /sys/kernel/btf/vfs, where 5.x
# and 6.x keep it, to /sys/kernel/btf/vmlinux; the script names the
# file that exists.
set -eu

if [ -r /sys/kernel/btf/vmlinux ]; then
	bpftool btf dump file /sys/kernel/btf/vmlinux format c
elif [ -r /sys/kernel/btf/vfs ]; then
	bpftool btf dump file /sys/kernel/btf/vfs format c
else
	echo "no BTF in sysfs: is CONFIG_DEBUG_INFO_BTF set?" >&2
	exit 1
fi
