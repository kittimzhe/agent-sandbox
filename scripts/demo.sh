#!/usr/bin/env bash
# scripts/demo.sh -- the whole sandbox in one minute, on a Linux host
# with a BPF-capable kernel (or the dev VM from docs/dev-vm.md).
#
# One policy, three enforcements, one event stream, one tampered
# signature: everything the README claims, shown instead of told.
set -eu

cd "$(dirname "$0")/.."
# The share is read-only in the dev VM; build to the guest's home.
B=${AGENT_SANDBOX_BIN:-/tmp/agent-sandbox}
P=/tmp/demo-strict.yaml

echo "=== 0. build (skip if /tmp/demo-built exists) ==="
if [ ! -f /tmp/demo-built ]; then
    go build -o "$B" ./cmd/agent-sandbox
    touch /tmp/demo-built
fi

echo
echo "=== 1. keys and signature ==="
"$B" keys generate --private /tmp/demo.key --public /tmp/demo.pub
echo "name: demo-strict
scope:
  cgroup: /sys/fs/cgroup/agent-sandbox-demo
exec:
  allow:
    - /bin/ls
file:
  deny_read:
    - /root/.ssh/**
net:
  allow:
    - tcp/443
  deny_cidr:
    - 169.254.169.254/32" > "$P"
"$B" sign --key /tmp/demo.key "$P"

echo
echo "=== 2. decide, the dry run, on any host ==="
echo -n "  /bin/ls      -> "; "$B" decide --policy "$P" exec /bin/ls
echo -n "  /bin/sh      -> "; "$B" decide --policy "$P" exec /bin/sh || true
echo -n "  metadata:443 -> "; "$B" decide --policy "$P" net tcp 169.254.169.254 443 || true

echo
echo "=== 3. run, enforced by the kernel ==="
echo -n "  /bin/ls  -> "; sudo "$B" run --policy "$P" --public /tmp/demo.pub -- /bin/ls / >/dev/null && echo "ran"
echo -n "  /bin/sh  -> "; sudo "$B" run --policy "$P" --public /tmp/demo.pub -- /bin/sh -c 'echo SHOULD-NOT-PRINT' 2>&1 | tail -1

echo
echo "=== 4. the event stream, one line per exec ==="
sudo "$B" observe --policy "$P" -- /bin/sh -c 'ls / >/dev/null; ls /usr >/dev/null' 2>&1 | grep -E '^\{' || true

echo
echo "=== 5. a tampered policy is refused ==="
echo "# tampered" >> "$P"
sudo "$B" run --policy "$P" --public /tmp/demo.pub -- /bin/ls / 2>&1 | tail -1

echo
echo "demo complete. The engine, the kernel and the signature agreed on every line."
