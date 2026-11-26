// The file policy: one BPF LSM program over file_open.
//
// The hook is file_open, crossed by every open(2) before the kernel
// hands the descriptor out. It looks the task's cgroup up in the
// scope map — outside the sandbox, untouched — and checks the path
// against two tables: deny_read for opens without write intent,
// deny_write for opens with it. A rule that names a path for reads
// says nothing about writes, the same asymmetry the engine states.
//
// The path comes from bpf_d_path, which renders the dentry the way
// /proc would; the match is the same two tables the exec side uses:
// exact rules in hashes, prefix rules in an LPM trie with the rule's
// own trailing '/', one bounded pass for the one-level depth. A
// refusal is EACCES, the errno an open reports for a permission the
// subject does not hold.
//
// FMODE_READ and FMODE_WRITE are macros, not BTF types, so the file
// carries their values with the kernel's own comment.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "Dual BSD/GPL";

/* fs.h: the file access mode bits, stable since forever. */
#define FMODE_READ 0x1
#define FMODE_WRITE 0x2

/* The refusal for an open the policy refuses. */
#define EACCES 13

#define MAX_RULES 64
#define MAX_PREFIX 64

/* match.Kind, mirrored; Exact lives in its own table. */
#define KIND_ONE_LEVEL 1
#define KIND_RECURSIVE 2

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
} deny_read SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_RULES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct rule_key);
	__type(value, struct rule);
} deny_write SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RULES);
	__type(key, struct path_key);
	__type(value, __u8);
} deny_read_exact SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RULES);
	__type(key, struct path_key);
	__type(value, __u8);
} deny_write_exact SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u64);  /* cgroup id */
	__type(value, __u8); /* present */
} scoped_cgroups SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(check_file, struct file *file)
{
	struct path_key lookup = {};
	struct rule_key rkey = {};
	struct rule *r;
	__u8 *hit;
	/* The path buffer starts zeroed: bpf_d_path guarantees the NUL,
	   not the tail, and the exact key compares all sixty-four
	   bytes. */
	char path[MAX_PREFIX] = {};
	__u64 cgroup;
	__u8 *in_scope;
	__u32 mode;
	void *hash, *rules;
	int len, is_write, i;

	cgroup = bpf_get_current_cgroup_id();
	in_scope = bpf_map_lookup_elem(&scoped_cgroups, &cgroup);
	if (!in_scope)
		return 0; /* not ours */

	mode = BPF_CORE_READ(file, f_mode);
	is_write = mode & FMODE_WRITE;
	hash = is_write ? (void *)&deny_write_exact : (void *)&deny_read_exact;
	rules = is_write ? (void *)&deny_write : (void *)&deny_read;

	len = bpf_d_path(&file->f_path, path, sizeof(path));
	if (len < 0 || len <= 1)
		return 0; /* nothing to compare: allow, the tables are empty of it */
	if (len > MAX_PREFIX)
		len = MAX_PREFIX;
	len--; /* bpf_d_path counts the NUL */

	/* An exact rule is equality: the whole path is the key. */
	for (i = 0; i < MAX_PREFIX; i++)
		lookup.data[i] = path[i];
	hit = bpf_map_lookup_elem(hash, &lookup);
	if (hit)
		return -EACCES;

	/* A prefix rule: the trie returns the longest prefix the path
	   starts with. */
	rkey.prefixlen = (__u32)len * 8;
	for (i = 0; i < MAX_PREFIX; i++)
		rkey.data[i] = path[i];
	r = bpf_map_lookup_elem(rules, &rkey);
	if (!r)
		return 0;

	if (r->kind == KIND_ONE_LEVEL) {
		/* One component below the prefix: the rest of the path
		   carries no second '/'. A OneLevel rule that names the
		   prefix itself is the caller's to allow. */
		int rest0 = (int)r->plen + 1;

		if (rest0 > len)
			return 0; /* the path is the prefix directory */
		for (i = rest0; i < len; i++) {
			if (path[i] == '/')
				return -EACCES;
		}
	}
	return -EACCES;
}
