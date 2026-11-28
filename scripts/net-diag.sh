#!/bin/bash
# The final diagnostic: one run, three views at once -- the program's
# printk of its lookup key, the trie's stored bytes, the counters that
# say which branch fired.
set -u
B=/home/mengzhe.guest/build/agent-sandbox
D=/tmp/agent-sandbox-e2e

cat > "$D/sleep-probe.py" <<'EOF'
import socket, time
s = socket.socket(); s.settimeout(2)
try:
    s.connect(("1.1.1.1", 443)); print("RESULT: CONNECT-OK (trie missed)")
except Exception as e:
    print("RESULT:", e)
time.sleep(8)
EOF
# Fresh policy, fresh signature: nothing left over from earlier runs.
cat > "$D/final.yaml" <<'EOF'
name: final
scope:
  cgroup: /sys/fs/cgroup/agent-sandbox-e2e
exec:
  allow:
    - /usr/bin/python3
net:
  allow:
    - tcp/443
  deny_cidr:
    - 1.1.1.1/32
EOF
sudo "$B" sign --key "$D/op.key" "$D/final.yaml" >/dev/null
echo "trace cleared"; sudo sh -c 'echo > /sys/kernel/tracing/trace'

sudo "$B" run --policy "$D/final.yaml" --public "$D/op.pub" -- /usr/bin/python3 "$D/sleep-probe.py" &
RUNPID=$!
sleep 3
echo "=== program's key (printk) ==="
sudo cat /sys/kernel/tracing/trace_pipe 2>/dev/null | grep cidr | head -2
echo "=== trie stored bytes ==="
TRIE=$(sudo bpftool map show | grep net_deny_cidr | cut -d: -f1 | head -1)
sudo bpftool map dump id "$TRIE" 2>&1 | head -8
echo "=== counters ==="
for m in $(sudo bpftool map show | grep -E 'net_allowed|net_denied' | cut -d: -f1); do
    sudo bpftool map dump id "$m" 2>/dev/null | head -4
done
wait $RUNPID
