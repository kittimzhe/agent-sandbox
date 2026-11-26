// The exec event stream: one record per exec inside the scope.
//
// The counter map says how many execs a scope had; the ring buffer
// says which. A record carries the facts a reader needs to name the
// exec — the binary, the pid, the cgroup — and the kernel time it
// happened, which orders events even when the wall clock steps. The
// reader in user space turns records into the event package's NDJSON.
//
// The buffer is reserved, never allocated after the fact: a ringbuf
// reservation that fails is an event dropped, counted in dropped, so
// the reader knows the stream is partial rather than trusting it
// whole.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "Dual BSD/GPL";

/* The record the reader parses. Fixed size, no pointers: the kernel
   hands out eight-byte-aligned slices of the ring. */
struct exec_event {
	__u64 cgroup;
	__u64 ktime;
	__u32 pid;
	__u32 ppid;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MiB, one page aligned */
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u64);
	__type(value, __u8);
} scoped_cgroups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u64);
	__type(value, __u64);
} dropped SEC(".maps");

static __always_inline void bump(void *m, __u64 cgroup)
{
	__u64 *n = bpf_map_lookup_elem(m, &cgroup);
	__u64 one = 1;

	if (n)
		__sync_fetch_and_add(n, 1);
	else
		bpf_map_update_elem(m, &cgroup, &one, BPF_ANY);
}

SEC("tracepoint/sched/sched_process_exec")
int emit_exec(void *ctx)
{
	struct exec_event *e;
	__u64 cgroup = bpf_get_current_cgroup_id();
	__u8 *in_scope;

	in_scope = bpf_map_lookup_elem(&scoped_cgroups, &cgroup);
	if (!in_scope)
		return 0; /* not ours */

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bump(&dropped, cgroup);
		return 0; /* the reader learns the stream is partial */
	}
	e->cgroup = cgroup;
	e->ktime = bpf_ktime_get_ns();
	e->pid = (__u32)bpf_get_current_pid_tgid();
	e->ppid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}
