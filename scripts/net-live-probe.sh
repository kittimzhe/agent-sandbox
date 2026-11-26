#!/bin/bash
# Live probe: run the sandbox in the background, dump the net maps
# while the scope is alive.
set -u
B=/home/mengzhe.guest/build/agent-sandbox
sudo "$B" run --policy /tmp/net5.yaml -- /usr/bin/python3 /tmp/retry_probe.py &
RUNPID=$!
sleep 3
echo "--- programs named check_connect ---"
sudo bpftool prog show | grep -A1 check_connect
echo "--- net maps ---"
ids=$(sudo bpftool map show | grep -E 'net_allow|net_deny' | cut -d: -f1)
for m in $ids; do
    echo "map id $m:"
    sudo bpftool map dump id "$m" | head -8
done
wait $RUNPID
