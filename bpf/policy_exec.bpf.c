// The exec policy: one BPF LSM program and the maps the loader fills.
//
// The hook is bprm_check_security, the LSM hook every execve crosses
// after the binary is found and before the new program runs. It looks
// the task's cgroup up in the scope map: a task outside the sandbox
// passes untouched. A task inside checks two tables:
//
//   - exec_exact, a hash of whole paths. An exact rule is equality,
//     and equality is what a hash lookup is; a bit-prefix trie cannot
//     say it ("/bin/ls" as a prefix also matches "/bin/lsx", and the
//     trie's longest match would shadow a shorter rule that applies).
//
//   - exec_rules, an LPM trie of directory prefixes: a OneLevel rule
//     plus the check that the rest of the path carries no second '/',
//     which this program does in one bounded pass; a Recursive rule
//     matches everything below its prefix, whose trailing '/' is part
//     of the key so a name that only shares the prefix is not a match.
//
// A hit in either table allows; neither names the path and the exec
// is refused with EPERM. The loader builds both tables and refuses
// what they cannot hold, so what the kernel enforces is what the
// policy wrote.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

/* How many rules the table holds, and how long a prefix may be. The
   loader refuses a policy that does not fit; LPM does not grow. */
#define MAX_RULES 64
#define MAX_PREFIX 64

/* match.Kind, mirrored; Exact lives in its own table. */
#define KIND_ONE_LEVEL 1
#define KIND_RECURSIVE 2

/* The refusal the LSM hook returns; vmlinux.h does not name errno
   values, so the number is the kernel's own. */
#define EPERM 1

struct path_key {
	__u8 data[MAX_PREFIX];
};

struct rule_key {
	__u32 prefixlen; /* bits */
	__u8 data[MAX_PREFIX];
};

struct rule {
	__u8 kind;
	__u8 plen; /* the rule's own prefix, in bytes */
	__u8 pad[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_RULES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct rule_key);
	__type(value, struct rule);
} exec_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RULES);
	__type(key, struct path_key);
	__type(value, __u8);
} exec_exact SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u64);  /* cgroup id */
	__type(value, __u8); /* present */
} scoped_cgroups SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(check_exec, struct linux_binprm *bprm, int ret)
{
	/* The path buffer starts zeroed: bpf_probe_read_kernel_str
	   guarantees the NUL, not the tail, and the exact key compares
	   all sixty-four bytes. */
	char path[MAX_PREFIX] = {};
	struct path_key exact = {};
	struct rule_key key = {};
	struct rule *r;
	const char *filename;
	__u64 cgroup;
	__u8 *hit;
	__u8 *in_scope;
	int len, i;

	if (ret)
		return ret;

	cgroup = bpf_get_current_cgroup_id();
	in_scope = bpf_map_lookup_elem(&scoped_cgroups, &cgroup);
	if (!in_scope)
		return 0; /* not ours */

	filename = bprm->filename;
	len = bpf_probe_read_kernel_str(path, sizeof(path), filename);
	if (len <= 1)
		return -EPERM; /* unreadable path: refuse, never allow */
	len--; /* bpf_probe_read_kernel_str counts the NUL */

	/* An exact rule is equality: the whole path is the key. */
	for (i = 0; i < MAX_PREFIX; i++)
		exact.data[i] = path[i];
	hit = bpf_map_lookup_elem(&exec_exact, &exact);
	if (hit)
		return 0;

	/* A prefix rule: the trie returns the longest prefix the path
	   starts with. */
	key.prefixlen = (__u32)len * 8;
	for (i = 0; i < MAX_PREFIX; i++)
		key.data[i] = path[i];
	r = bpf_map_lookup_elem(&exec_rules, &key);
	if (!r)
		return -EPERM;

	if (r->kind == KIND_ONE_LEVEL) {
		/* One component below the prefix: the rest of the path,
		   after the rule's '/', carries no second '/'. The rule's
		   own length comes in the value; the lookup key carries
		   the path's. */
		int rest0 = (int)r->plen + 1;

		for (i = rest0; i < len; i++) {
			if (path[i] == '/')
				return -EPERM;
		}
	}
	return 0;
}
