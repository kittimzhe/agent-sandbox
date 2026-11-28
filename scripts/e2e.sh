#!/usr/bin/env bash
# scripts/e2e.sh -- assert, not show: every claim of the README, one script.
#
# The manual matrices the tree was verified with across its development,
# frozen into assertions: exec semantics, file direction, net order,
# the signature chain, the event stream. Run as root on a Linux host
# with a BPF-capable kernel (the dev VM of docs/dev-vm.md is one):
#
#   sudo bash scripts/e2e.sh
#
# A denial is asserted on its errno text -- "Operation not permitted"
# for the exec and net hooks, "Permission denied" for file -- because
# only that distinguishes a refusal by the policy from a refusal by
# the network: a connect the LSM never blocked can still come back
# refused by whatever the packets found. The CIDR-first case is built
# to need no unreachable address: it refuses 1.1.1.1, which the same
# policy allows by port, so the refusal can only come from the CIDR.
#
# The file policies allow both /bin/* and /usr/bin/*: on a usrmerge
# system a shell resolves cat to /usr/bin/cat, and a policy that only
# allows /bin/* would deny the exec for a reason the case is not
# about.
set -u

# The suite builds the binary it asserts with. It finds the repo by
# looking for go.mod from the script's own directory, falling back to
# the dev VM's shared checkout -- and a failed build exits, never
# falls back to a stale binary: a net enforcement bisect left
# disabled once stayed green to every manual check because a stale
# /tmp binary answered for the fresh tree.
B=${AGENT_SANDBOX_BIN:-/tmp/agent-sandbox}
D=/tmp/agent-sandbox-e2e
REPO=${E2E_REPO:-}
if [ -z "$REPO" ]; then
    REPO=$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)
    [ -f "$REPO/go.mod" ] || REPO=/Users/mengzhe/project/agent-sandbox
fi
cd "$REPO" || exit 1
go build -o "$B" ./cmd/agent-sandbox || exit 1
pass=0; fail=0; failed=()

t() { # t <name> <want-rc> <stderr-must-contain> <cmd...>
    local name=$1 want=$2 needle=$3; shift 3
    local out rc
    out=$("$@" 2>&1); rc=$?
    if [ "$rc" = "$want" ] && { [ -z "$needle" ] || printf '%s' "$out" | grep -qi "$needle"; }; then
        pass=$((pass+1)); printf 'ok   %s\n' "$name"
    else
        fail=$((fail+1)); failed+=("$name")
        printf 'FAIL %s\n     want rc=%s needle=%q\n     got  rc=%s: %s\n' \
            "$name" "$want" "$needle" "$rc" "$(printf '%s' "$out" | tail -2 | tr '\n' ' ')"
    fi
}

mkdir -p "$D"
# Fixtures: a two-level tree for the one-level rule, an ssh dir with a
# file, a keypair, and a direct-connect probe that prints its errno.
sudo mkdir -p /opt/app/lib /root/.ssh
printf '#!/bin/sh\necho tool-ran\n' > /opt/app/tool;  chmod +x /opt/app/tool
printf '#!/bin/sh\necho lib-ran\n'  > /opt/app/lib/x; chmod +x /opt/app/lib/x
echo known_hosts > /root/.ssh/known_hosts
mkdir -p /etc/agent-sandbox-e2e
cat > "$D/probe.py" <<'EOF'
import socket, sys
kind = sys.argv[3] if len(sys.argv) > 3 else "tcp"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM)
s.settimeout(4)
try:
    s.connect((sys.argv[1], int(sys.argv[2]))); print("CONNECT-OK")
except Exception as e:
    print("FAIL:", e)
    sys.exit(1)  # a denied connect is a failed connect, not a printed one
EOF

pol() { cat > "$D/$1"; }

pol exec-strict.yaml <<'EOF'
name: e2e-exec
scope:
  cgroup: /sys/fs/cgroup/agent-sandbox-e2e
exec:
  allow:
    - /bin/ls
EOF
pol exec-star.yaml <<'EOF'
name: e2e-star
scope:
  cgroup: /sys/fs/cgroup/agent-sandbox-e2e
exec:
  allow:
    - /bin/*
    - /usr/bin/*
EOF
pol exec-depth.yaml <<'EOF'
name: e2e-depth
scope:
  cgroup: /sys/fs/cgroup/agent-sandbox-e2e
exec:
  allow:
    - /opt/app/*
EOF
pol file.yaml <<'EOF'
name: e2e-file
scope:
  cgroup: /sys/fs/cgroup/agent-sandbox-e2e
exec:
  allow:
    - /bin/*
    - /usr/bin/*
file:
  deny_read:
    - /root/.ssh/**
  deny_write:
    - /etc/agent-sandbox-e2e/**
EOF
pol read-only.yaml <<'EOF'
name: e2e-read
scope:
  cgroup: /sys/fs/cgroup/agent-sandbox-e2e
exec:
  allow:
    - /bin/*
    - /usr/bin/*
file:
  deny_read:
    - /root/.ssh/**
EOF
pol net.yaml <<'EOF'
name: e2e-net
scope:
  cgroup: /sys/fs/cgroup/agent-sandbox-e2e
exec:
  allow:
    - /usr/bin/python3
net:
  allow:
    - tcp/443
    - udp/53
EOF
pol net-cidr.yaml <<'EOF'
name: e2e-cidr
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
# Unsigned on purpose: the signature case needs a policy with no .sig.
pol unsigned.yaml <<'EOF'
name: e2e-unsigned
scope:
  cgroup: /sys/fs/cgroup/agent-sandbox-e2e
exec:
  allow:
    - /bin/*
EOF

"$B" keys generate --private "$D/op.key" --public "$D/op.pub" >/dev/null
for p in exec-strict exec-star exec-depth file read-only net net-cidr; do
    "$B" sign --key "$D/op.key" "$D/$p.yaml" >/dev/null
done
echo "## exec"
t "exact allow runs"                             0 "" "$B" run --policy "$D/exec-strict.yaml" --public "$D/op.pub" -- /bin/ls /
t "unlisted exec is EPERM"                       1 "Operation not permitted" "$B" run --policy "$D/exec-strict.yaml" --public "$D/op.pub" -- /bin/sh -c true
t "a longer name sharing the prefix stays denied" 1 "Operation not permitted" \
    sh -c "cp /bin/true /bin/e2e-lsx; $B run --policy '$D/exec-strict.yaml' --public '$D/op.pub' -- /bin/e2e-lsx; rc=\$?; rm -f /bin/e2e-lsx; exit \$rc"
t "one level: a component below runs"            0 "" "$B" run --policy "$D/exec-depth.yaml" --public "$D/op.pub" -- /opt/app/tool
t "one level: a second / is EPERM"               1 "Operation not permitted" "$B" run --policy "$D/exec-depth.yaml" --public "$D/op.pub" -- /opt/app/lib/x

echo "## file"
t "deny_read refuses the read"                   1 "Permission denied" "$B" run --policy "$D/file.yaml" --public "$D/op.pub" -- /bin/sh -c 'cat /root/.ssh/known_hosts'
t "an unlisted read runs"                        0 "" "$B" run --policy "$D/file.yaml" --public "$D/op.pub" -- /bin/sh -c 'cat /etc/hostname' >/dev/null
t "deny_write refuses the write"                 1 "Permission denied" "$B" run --policy "$D/file.yaml" --public "$D/op.pub" -- /bin/sh -c 'echo x > /etc/agent-sandbox-e2e/marker'
t "an unlisted write runs"                       0 "" "$B" run --policy "$D/file.yaml" --public "$D/op.pub" -- /bin/sh -c "echo x > $D/w" >/dev/null
t "a read rule does not refuse a write"          0 "" "$B" run --policy "$D/read-only.yaml" --public "$D/op.pub" -- /bin/sh -c "echo x > $D/w2" >/dev/null

echo "## net"
t "an allowed port connects"                     0 "CONNECT-OK"   "$B" run --policy "$D/net.yaml" --public "$D/op.pub" -- /usr/bin/python3 "$D/probe.py" 1.1.1.1 443
t "an unlisted port is EPERM"                    1 "Operation not permitted" "$B" run --policy "$D/net.yaml" --public "$D/op.pub" -- /usr/bin/python3 "$D/probe.py" 1.1.1.1 8080
t "an allowed udp port connects"                 0 "CONNECT-OK"   "$B" run --policy "$D/net.yaml" --public "$D/op.pub" -- /usr/bin/python3 "$D/probe.py" 1.1.1.1 53 udp
t "the CIDR refuses before the allow"            1 "Operation not permitted" "$B" run --policy "$D/net-cidr.yaml" --public "$D/op.pub" -- /usr/bin/python3 "$D/probe.py" 1.1.1.1 443

echo "## signature"
t "an unsigned policy is refused"                1 "no signature" "$B" run --policy "$D/unsigned.yaml" --public "$D/op.pub" -- /bin/true
t "a tampered policy is refused"                 1 "does not match" \
    sh -c "echo '# tampered' >> '$D/net-cidr.yaml'; $B run --policy '$D/net-cidr.yaml' --public '$D/op.pub' -- /bin/true; rc=\$?; sed -i '/# tampered/d' '$D/net-cidr.yaml'; exit \$rc"

echo "## event stream"
t "the stream counts the execs it saw"           0 "3 exec events" \
    sh -c "$B observe --policy '$D/exec-star.yaml' -- /bin/sh -c 'ls / >/dev/null; ls /usr >/dev/null' 2>&1 | grep -E 'exec events'"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
if [ "$fail" -gt 0 ]; then
    printf 'failed: %s\n' "${failed[*]}"
    exit 1
fi
rm -rf "$D" /opt/app /root/.ssh/known_hosts /etc/agent-sandbox-e2e
exit 0
