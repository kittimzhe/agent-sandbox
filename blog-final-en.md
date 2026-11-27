# Sandboxing AI Agent processes with eBPF: design notes and seven lessons the kernel taught me

*Repo: [github.com/kittimzhe/agent-sandbox](https://github.com/kittimzhe/agent-sandbox) · 37+ commits, CI green · one command loads four BPF programs: an exec-counting tracepoint and three LSM hooks (exec, file, net) enforced from one policy file.*

## Why now

Two things in late 2026 turned "agent process sandbox" from optional into necessary. Agents run real tasks in production — editing files, calling APIs, executing shell tools. And in November, OpenAI and Cisco open-sourced [shirudo](https://github.com/shirudo-dev/shirudo), which made "agent-driven security" an official direction. But shirudo answers a different question: *who may load BPF into the kernel*. It needs a custom kernel (five patches not in mainline yet) and a TPM 2.0. The question a team running agents has is plainer:

> This agent process tree — what may it read, write, connect to, and execute?

The existing tools don't answer it: Tetragon and KubeArmor are cluster/container platforms with a deployment surface to match; seccomp is too crude; prompt-level "constraints" are not a security boundary. What was missing is a single-host, lightweight sandbox shaped for an agent process tree. That is agent-sandbox: one command loads four BPF programs from a policy file — a strict subset of YAML, parsed by hand, with line-numbered errors and no defaults.

```console
$ sudo agent-sandbox run --policy agent-web.yaml -- /bin/sh -c 'ls /'
running /bin/sh -c ls / in /sys/fs/cgroup/agent-sandbox under agent-web

$ sudo agent-sandbox run --policy strict.yaml -- /bin/sh -c true
operation not permitted        # refused inside the kernel, by an LSM program
```

## The boundary with shirudo, stated honestly

shirudo's trust chain: signed BPF loader → kernel-sealed keyring → TPM measurement register → offline-verifiable attestation. Root cannot load unsigned BPF, cannot tamper with the record.

agent-sandbox does none of that, and the consequence is written where the code lives: **root can unload our programs and edit our policy**. It defends against *agent overreach* — prompt injection that curls the internal network or reads `~/.ssh` — which happens every day, not against a root compromise, whose cost is another order of magnitude. shirudo's AGENTS.md has a line I copied into my own code comments: *a policy that reads differently from what its author wrote is a sandbox that enforces the wrong rules.*

## Seven lessons the kernel taught me

### 1. An fentry program that loads is not an fentry program that runs

My first counter attached `fentry/do_execve`. It loaded. It counted zero. kallsyms showed why: `do_execve` is gone — kernel 7.0 inlined it — and `bprm_execve` survives only as a dead out-of-line copy that ftrace can attach and no one will ever call. The baseline counter now uses the tracepoint `sched/sched_process_exec`, alive on every kernel; fentry stays for M1's LSM hooks, where the exact function matters and the kernel is pinned. On a bleeding-edge kernel, "attached" and "fires" are two different claims, and kallsyms and BTF do not always agree.

### 2. The verifier's budget: 1,000,001 processed instructions is a real limit

The first exec policy walked every rule byte by byte (64 rules × 64 bytes). The verifier refused it: `Processed 1000001 insn`. The fix was to let the kernel do the matching: a `BPF_MAP_TYPE_LPM_TRIE` lookup is O(prefix depth) inside the kernel, one map lookup replacing the whole outer loop. The verifier pays for every possible path; choosing a data structure *is* budgeting the verifier.

### 3. An LPM bit-prefix cannot say "equal" — a security bug born and fixed

A policy allowing only `/bin/ls` also allowed `/bin/lsx`. LPM matches by bit prefix, and the longest match would have shadowed a shorter rule that applied. The fix is two tables: exact rules in a hash (equality, O(1)), prefix rules in the trie with their trailing slash. Let one structure stand in for two semantics and the hole you get is on the allow side. My user-space matcher's fuzzer had caught the same over-match shape earlier (`Compile("/*")` returning the rule that matches everything); the bug grew back in the kernel table.

### 4. `bpf_probe_read_kernel_str` guarantees the NUL, not the tail

The eeriest one: LPM tests passed, exact-hash lookups all missed, and a dump of the map showed the right bytes. The buffer was `char path[64];` — uninitialized. The helper writes the string and its NUL and nothing else; the remaining 56 bytes were stack garbage, and the exact key compares all sixty-four. `char path[MAX_PREFIX] = {};` fixed it. In the file program the same bug was a deny-direction security hole: the opens that should have been refused were allowed. Read the helper's guarantee word by word, and when two lookups behave differently, look where their semantics divide — here, prefixlen counting only the prefix bits.

### 5. The verifier knows sockaddr is 16 bytes; it does not know you wanted 28

Reading `sin6_addr` byte by byte was refused: `access beyond struct sockaddr at off 17`. The hook's ctx pointer is bounded by the generic `struct sockaddr`. The reads go through `BPF_CORE_READ_INTO`, whose size comes from the field itself.

### 6. Kernel 7.0's verifier rule: no arithmetic on a maybe-null pointer

`BPF_CORE_READ(sock, sk->sk_protocol)` was refused: pointer arithmetic on a trusted-or-null pointer, null-check it first. Two steps: read the pointer, check it, read the field. Old kernels forgive; new kernels refuse precisely, and the error message teaches the fix.

### 7. The address family is not the protocol

The net allow table never matched. After bisecting with the net program disabled, absolute paths, and a direct connect probe, the bug was mine: I had encoded `family == AF_INET ? 1 : 2` as the tcp/udp value — AF_INET *is* 2, so every v4 connect looked up the UDP entry. The protocol lives in `sock->sk->sk_protocol`, a different dimension than the family. Semantic mistakes that happen to compile are the hardest to see; design the test matrix over the semantic dimensions (protocol × family), not over the code paths.

## What is built and verified

- **Scope**: cgroup v2 with a shim — the process moves *itself* into the cgroup before its first exec. No window, no PID race.
- **Exec** (`lsm/bprm_check_security`): exact-hash plus LPM two-table, six-case semantic matrix.
- **File** (`lsm/file_open`): deny_read and deny_write, direction asymmetry locked by tests — a read rule says nothing about writes.
- **Net** (`lsm/socket_connect`): refused CIDRs first (v4 in its mapped form, so a v6 address sharing bytes is not a match), allow list second.
- **Asymmetric defaults**: exec and net are allow-lists (the unnamed is refused — an agent doing something the policy does not name is the whole threat), file is a deny-list (nobody writes a policy of every readable file). Every verdict names its rule: `exec.allow[1]`, `net.deny_cidr[0]`, `default deny`.
- **Signatures, honestly scoped**: Ed25519 detached signature, verified against the pinned public key before a single rule reaches the kernel; unsigned policies refuse. The package comment says what it is honest about: it stops a policy edited in transit or by mistake, and says nothing about root. shirudo closes that boundary with kernel patches, a sealed keyring and a TPM; that is a different product, and this is not it.
- **The event stream**: a ringbuf record per exec, drained as NDJSON, with a drop counter so a partial stream says so. The first `Read` blocked forever on an empty ring — a ringbuf reader is blocking, and nothing was left to unblock it; the fix is a timer that closes the reader once the ring goes quiet.
- **One compiler, two tables, one parity suite**: the engine and the kernel tables are built from the same compiled rules, and the parity tests lock the three sides together (engine verdict ↔ kernel-table mirror ↔ expectation), 14 cases green on a real kernel. Writing them, both failures were the test author's, not the code's — the engine and the kernel agreed with each other and with the design, against my case table. That is the parity suite doing its job.

## The other seven lessons: three turns inside a 300k-line C repository

The kernel was not the only teacher. I spent a week as a contributor to shirudo, and the turns came faster there than the verifier refusals did.

**The first PR was adopted.** I fixed a roll-up bug in xtop (by-image tree positions mixing sequences from different trees), 47 CI checks went green, and then John Fastabend — a maintainer — closed my PR with "pushed some updates here": he continued from my change in his own PR, my types and comments intact, with a ranking refinement on top, and merged it into main. Not a rejection; an adoption, just through the maintainer's hands.

**The second PR lost a two-minute race.** I root-caused another issue (`upatch map --json` failing on a map without a decoder), wrote the fix, and opened a PR — then found that someone had posted the same root cause **two minutes** before me, the community had converged on a different path (the reporter adding a decoder, a clearer error message merged separately), and the maintainers closed the issue. My PR had become a pre-emptive implementation of a design the maintainers had explicitly left to themselves. I left a comment acknowledging the convergence and accepting closure. When you lose a race, the graceful note says more about you than the code did.

**The third turn, discipline saved me.** A cross-layer schema question (xtop's drill-down pulling findings from a different build of the same image) — I wrote a design comment: two implementation paths, the search semantics, a request for the maintainers' direction. Then I waited. The next day an implementation PR appeared, taking the path I had named second, semantics matching my note. Had I implemented my preferred path directly, it would have been another head-on collision. Three turns, one rule: **in a fast repository, comment the design first, wait for the direction, then implement.** It does not win races; it keeps you from losing them twice.

## What is left

- OTLP export (NDJSON covers the demo; OTLP is the operator's integration)
- Kernel-side inputs for the fuzz targets on match and event
- Publishing the parity cases as a compatibility contract between releases

*Everything above is implemented and tested; nothing in the post is claimed that a test did not pass first. The repo is [github.com/kittimzhe/agent-sandbox](https://github.com/kittimzhe/agent-sandbox) — `sh scripts/demo.sh` shows the whole story in a minute.*
