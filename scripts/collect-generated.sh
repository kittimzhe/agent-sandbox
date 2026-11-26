#!/bin/sh
# scripts/collect-generated.sh -- copy the bpf2go objects out of the VM.
#
# Run on the macOS host after scripts/guest-build.sh: the guest builds
# in its own copy (the share is read-only there), so the generated
# loaders and objects come back here, to be committed with the change
# that touched the programs. CI checks the committed files; forgetting
# this step is what a failing go vet on linux usually means.
set -eu

LIMA_HOME=${LIMA_HOME:-/Users/mengzhe/project/.lima}
PATH="/Users/mengzhe/project/.tools/lima/bin:$PATH"
dest=$(cd "$(dirname "$0")/.." && pwd)/internal/loader

for f in \
    count_exec_arm64_bpfel.go count_exec_arm64_bpfel.o \
    count_exec_x86_bpfel.go count_exec_x86_bpfel.o \
    policy_exec_arm64_bpfel.go policy_exec_arm64_bpfel.o \
    policy_exec_x86_bpfel.go policy_exec_x86_bpfel.o \
    policy_file_arm64_bpfel.go policy_file_arm64_bpfel.o \
    policy_file_x86_bpfel.go policy_file_x86_bpfel.o
do
    limactl cp "sandbox-dev:/home/mengzhe.guest/build/internal/loader/$f" "$dest/$f"
done
ls -la "$dest" | tail -n +2
echo "collected; commit them with the change that touched the programs"
