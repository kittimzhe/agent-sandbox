# agent-sandbox

An eBPF sandbox for AI agent processes on Linux. Give an agent process
tree a policy: what it may execute, what it may open, where it may
connect. Everything the kernel reports or refuses comes out as one JSON
event per line.

**Status: the kernel side runs.** `observe` loads a BPF program
(tracepoint `sched/sched_process_exec`, compiled with `-mcpu=v4`),
attaches it, runs a command inside a cgroup v2 scope, and reports the
exec count of the scope — no enforcement yet, that is M1. See
[DESIGN.md](DESIGN.md) for the architecture and what this
deliberately does not do (no kernel patches, no TPM, no daemon).

## The policy file

Three defaults ship in [policy/defaults/](policy/defaults/) —
`agent-web`, `agent-dev` and `agent-ci` — as a copy-and-edit starting
point. A strict subset of YAML, parsed by hand with no YAML library: unknown
keys, missing required keys and malformed values are errors with line
numbers, never defaults. A path pattern may end in `*` (one component)
or `**` (any number); a `*` anywhere else is refused, because the
kernel side matches by prefix and a pattern it cannot enforce must not
parse.

```yaml
name: agent-web

scope:
  cgroup: /sys/fs/cgroup/agent-sandbox   # the process tree to sandbox

exec:
  allow:
    - /usr/bin/*

file:
  deny_read:
    - /root/.ssh/**

net:
  allow:
    - tcp/443
  deny_cidr:
    - 169.254.169.254/32   # cloud metadata endpoint
```

## Development

Requires Go 1.26+. The packages under `internal/` are platform-neutral
and test anywhere:

```sh
go test ./...
go run ./cmd/agent-sandbox validate policy.yaml
go run ./cmd/agent-sandbox decide --policy policy.yaml exec /usr/bin/python3
```

`decide` prints the decision for one access as JSON and exits 1 when
refused — the dry-run of observe mode, on any host:

```sh
$ go run ./cmd/agent-sandbox decide --policy policy.yaml net tcp 169.254.169.254 443
{"allowed":false,"rule":"net.deny_cidr[0]"}
```

`observe` needs a Linux host with a BPF-capable kernel; the tree
carries a Lima VM template that sets one up (see
[docs/dev-vm.md](docs/dev-vm.md)):

```sh
sudo agent-sandbox observe --policy policy.yaml -- /bin/sh -c 'ls /'
# observing /bin/sh -c ls / in /sys/fs/cgroup/agent-sandbox
# 2 execs in the scope
```

## Related

- [shirudo](https://github.com/shirudo-dev/shirudo) — the kernel-side
  signed-BPF platform this project studies and borrows its discipline
  from (strict parsing, hand-rolled formats, documented tradeoffs).
  agent-sandbox is the lightweight, single-host counterpart for agent
  processes.
