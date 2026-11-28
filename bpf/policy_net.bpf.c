// The net policy: one BPF LSM program over socket_connect.
//
// The hook is socket_connect, crossed by every connect(2) before the
// kernel dials. It looks the task's cgroup up in the scope map —
// outside the sandbox, untouched — then walks the same order the
// engine states: a refused CIDR is refused first, an allow entry
// (protocol and port) is consulted second, and what neither names is
// refused with EPERM. The tables hold IPv4 and IPv6 in one LPM trie
// each, keyed by the family the address carries.
//
// The order test in internal/decision is the spec this program
// implements: the parity the kernel side owes the user side.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "Dual BSD/GPL";

/* in.h: address families and the sockaddrs a connect carries. */
#define AF_INET 2
#define AF_INET6 10

/* The refusal for a connect the policy refuses. */
#define EPERM 1

#define MAX_ENTRIES 128
#define IPV6_LEN 16

/* One allow entry: the port, and whether the protocol is tcp (1),
   udp (2) or any (0). */
struct allow {
	__u16 port;
	__u8 proto;
	__u8 pad[5];
};

/* deny_cidr, one LPM trie over both families. */
struct cidr_key {
	__u32 prefixlen; /* bits */
	__u8 data[IPV6_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct cidr_key);
	__type(value, __u8);
} net_deny_cidr SEC(".maps");

/* allow, a hash of port and protocol. The key packs the protocol in
   the high byte so any/443, tcp/443 and udp/443 are distinct. */
struct allow_key {
	__u16 port;
	__u8 proto;
	__u8 pad[5];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct allow_key);
	__type(value, __u8);
} net_allow SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u64);  /* cgroup id */
	__type(value, __u8); /* present */
} scoped_cgroups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u64);
} connect_counts SEC(".maps");

/* The refused and allowed counts, for the event stream to read: the
   policy is printed with its own verdicts. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u64);
	__type(value, __u64);
} net_denied SEC(".maps");

/* Diagnostic counters: the trie lookup's path, counted per cgroup,
   because printk loses messages and the counters never do. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u64);
	__type(value, __u64);
} cidr_lookups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u64);
	__type(value, __u64);
} cidr_hits SEC(".maps");

/* The scope probes: the cgroup id every in-scope-family connect
   carried, and the ones the scope map accepted. The gap between them
   is the poisoning this suite chased. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u64);
	__type(value, __u64);
} scope_probes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u64);
	__type(value, __u64);
} scope_hits SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u64);
	__type(value, __u64);
} net_allowed SEC(".maps");

static __always_inline void bump(void *m, __u64 cgroup)
{
	__u64 *n = bpf_map_lookup_elem(m, &cgroup);
	__u64 one = 1;

	if (n)
		__sync_fetch_and_add(n, 1);
	else
		bpf_map_update_elem(m, &cgroup, &one, BPF_ANY);
}

/* The cidr key for the address, v4 mapped into the low bytes. */
static __always_inline void fill_cidr(struct cidr_key *k, __u8 *addr,
				      int alen, int bits)
{
	__builtin_memcpy(k->data, addr, alen);
	k->prefixlen = bits;
}

SEC("lsm/socket_connect")
int BPF_PROG(check_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	struct cidr_key ck = {};
	struct allow_key ak = {};
	__u64 cgroup;
	__u8 *in_scope;
	__u8 *denied;
	__u8 addr[IPV6_LEN] = {};
	int family, bits, i;
	__u16 port;
	__u8 proto;
	if (ret)
		return ret;

	cgroup = bpf_get_current_cgroup_id();
	bump(&scope_probes, cgroup);
	in_scope = bpf_map_lookup_elem(&scoped_cgroups, &cgroup);
	if (!in_scope)
		return 0; /* not ours */
	bump(&scope_hits, cgroup);

	family = BPF_CORE_READ(address, sa_family);
	if (family == AF_INET) {
		/* v4 rides the v6 trie in its mapped form, ::ffff:a.b.c.d,
		   so a v6 address that shares v4's first bytes is not a
		   match. The reads go through the CO-RE helpers, whose
		   sizes come from the fields: the verifier only knows the
		   generic sockaddr's 16 bytes, and a byte loop past them
		   is an access beyond. INTO reads into the storage it is
		   given -- a __u8 slot would take one byte and leave the
		   address 1.1.0.0, so the four bytes go through a __be32
		   first, network order straight into the mapped form. */
		struct sockaddr_in *in4 = (struct sockaddr_in *)address;
		__be32 a4;

		BPF_CORE_READ_INTO(&a4, in4, sin_addr.s_addr);
		__builtin_memcpy(&addr[12], &a4, 4);
		port = __builtin_bswap16(BPF_CORE_READ(in4, sin_port));
		bits = 128;
	} else if (family == AF_INET6) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)address;

		BPF_CORE_READ_INTO(&addr, in6, sin6_addr);
		port = __builtin_bswap16(BPF_CORE_READ(in6, sin6_port));
		bits = 128;
	} else {
		return 0; /* unix and the rest are not ours */
	}

	/* The CIDR refusals run before the allow list: a refused
	   address is refused whatever port it carries. */
	ck.prefixlen = bits;
	for (i = 0; i < IPV6_LEN; i++)
		ck.data[i] = addr[i];
	bump(&cidr_lookups, cgroup);
	denied = bpf_map_lookup_elem(&net_deny_cidr, &ck);
	if (denied) {
		bump(&cidr_hits, cgroup);
		bump(&net_denied, cgroup);
		return -EPERM;
	}

	/* The allow list: the entry for this port and protocol, or
	   any's. The protocol is the socket's, not the address family:
	   family says v4 or v6, sk_protocol says tcp or udp. The sock
	   is null-checked before its fields are read; kernel 7.0's
	   verifier does not allow the arithmetic on a maybe-null. */
	ak.port = port;
	ak.proto = 0;
	if (bpf_map_lookup_elem(&net_allow, &ak))
		goto allowed;
	struct sock *sk = BPF_CORE_READ(sock, sk);

	if (sk) {
		proto = BPF_CORE_READ(sk, sk_protocol);
		ak.proto = proto;
		if (bpf_map_lookup_elem(&net_allow, &ak))
			goto allowed;
	}
	bump(&net_denied, cgroup);
	return -EPERM;

allowed:
	bump(&net_allowed, cgroup);
	bump(&connect_counts, cgroup);
	return 0;
}
