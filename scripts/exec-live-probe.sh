#!/bin/bash
# Live dump of the exec tables while a strict sleep runs.
set -u
B=/home/mengzhe.guest/build/agent-sandbox
sudo "$B" run --policy /tmp/sleep-exact.yaml -- /bin/sleep 8 &
RUNPID=$!
sleep 2
echo "--- check_exec program ---"
sudo bpftool prog show | grep -A2 check_exec | head -4
echo "--- exec_exact map ---"
ids=$(sudo bpftool map show | grep exec_exact | cut -d: -f1)
for m in $ids; do
    echo "map id $m:"
    sudo bpftool map dump id "$m" | head -6
done
echo "--- trace ---"
timeout 2 sudo cat /sys/kernel/tracing/trace_pipe | grep bprm | head -3
wait $RUNPID
