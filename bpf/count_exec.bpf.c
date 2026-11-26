// The first BPF program of the tree: count execs by cgroup.
//
// One tracepoint hook on sched_process_exec, one map the loader
// reads. It observes only — the policy engine gates nothing yet — but
// it proves the whole path the sandbox depends on: clang compiles for
// the BPF ISA, the loader relocates the types against the running
// kernel, the verifier accepts the program, and events reach user
// space. Everything after this builds on these four steps.
//
// The hook is the tracepoint, not an fentry: the baseline counter
// must run on every kernel the tree supports, and kernel 7.0 inlines
// the exec path (do_execve is gone, bprm_execve survives only as a
// dead out-of-line copy), so a tracepoint is the hook that is alive
// everywhere. fentry stays for M1's policy hooks, where the target
// kernel is pinned and the exact function matters.
//
// The cgroup id is the sandbox's scope key: bpf_get_current_cgroup_id
// returns the id of the v2 cgroup the task belongs to, which the
// runtime put in the sandbox map.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);   /* cgroup id */
	__type(value, __u64); /* exec count */
} exec_counts SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int count_exec(void *ctx)
{
	__u64 cgroup = bpf_get_current_cgroup_id();
	__u64 *n;
	__u64 one = 1;

	// The first exec of a cgroup creates its entry; a hash map does
	// not grow one by itself.
	n = bpf_map_lookup_elem(&exec_counts, &cgroup);
	if (n)
		__sync_fetch_and_add(n, 1);
	else
		bpf_map_update_elem(&exec_counts, &cgroup, &one, BPF_ANY);
	return 0;
}
