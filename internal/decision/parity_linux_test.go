//go:build linux

package decision

import (
	"net/netip"
	"os"
	"testing"

	"github.com/kittimzhe/agent-sandbox/internal/loader"
	"github.com/kittimzhe/agent-sandbox/internal/policy"
)

// The parity cases: the same policy, decided by the engine and
// enforced by the kernel tables, must agree. The engine runs
// anywhere; the kernel side needs a BPF-capable Linux host, which the
// skips below name. A verdict the two sides disagree on is a bug in
// one of them, and this suite is how it is found.

func mustEngineK(t *testing.T, text string) (*Engine, *policy.Policy) {
	t.Helper()
	p, err := policy.Parse(text)
	if err != nil {
		t.Fatalf("policy.Parse() error = %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return e, p
}

// scopeID returns the cgroup id of a cgroup v2 path, creating it
// first if needed.
func scopeID(t *testing.T, path string) uint64 {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir cgroup: %v", err)
	}
	id, err := loader.CgroupID(path)
	if err != nil {
		t.Fatalf("cgroup id: %v", err)
	}
	return id
}

// TestParityExec replays the engine's exec verdicts against the
// kernel's exec tables over one policy. The kernel mirror
// (Enforcement.KernelAllows) reads the same tables the hook reads, so
// a mismatch between engine and mirror says the compiler served two
// different rules, and a mismatch between mirror and program (seen
// with AGENT_SANDBOX_DEBUG_TABLES and an actual exec) says the
// program diverged from its own tables.
func TestParityExec(t *testing.T) {
	if !loader.KernelProbe() {
		t.Skip("no BPF-capable kernel on this host")
	}
	e, _ := mustEngineK(t, `name: parity
scope:
  cgroup: /sys/fs/cgroup/agent-sandbox-parity
exec:
  allow:
    - /bin/sh
    - /bin/*
    - /usr/bin/python3
`)
	ef, err := loader.LoadPolicy(e.ExecRules(), scopeID(t, "/sys/fs/cgroup/agent-sandbox-parity"))
	if err != nil {
		t.Fatalf("LoadPolicy() error = %v", err)
	}
	defer ef.Close()

	cases := []struct {
		path    string
		allowed bool
	}{
		{"/bin/sh", true},          // exact
		{"/bin/ls", true},          // one level
		{"/bin/lsx", true},         // one level: any one component below /bin
		{"/bin/sh/sub", false},     // exact is exact
		{"/bin/sub/ls", false},     // one level refuses a second '/'
		{"/usr/bin/python3", true}, // exact
		{"/usr/bin/pip", false},    // nothing names it
		{"relative", false},        // never
	}
	for _, tc := range cases {
		engine := e.Exec(tc.path).Allowed
		kernel := ef.KernelAllows(tc.path)
		if engine != kernel || engine != tc.allowed {
			t.Errorf("%s: engine=%v kernel=%v want %v", tc.path, engine, kernel, tc.allowed)
		}
	}
}

// TestParityNet replays the engine's net verdicts against the kernel
// net tables: the CIDR refusals run before the allow list, the entry
// for the protocol or any matches, and what neither names is refused.
func TestParityNet(t *testing.T) {
	if !loader.KernelProbe() {
		t.Skip("no BPF-capable kernel on this host")
	}
	e, p := mustEngineK(t, `name: parity-net
scope:
  cgroup: /sys/fs/cgroup/agent-sandbox-parity
exec:
  allow:
    - /bin/*
net:
  allow:
    - tcp/443
    - any/53
  deny_cidr:
    - 169.254.169.254/32
`)
	ne, err := loader.LoadNetPolicy(&p.Net, scopeID(t, "/sys/fs/cgroup/agent-sandbox-parity"))
	if err != nil {
		t.Fatalf("LoadNetPolicy() error = %v", err)
	}
	defer ne.Close()

	cases := []struct {
		proto   string
		addr    string
		port    uint16
		allowed bool
	}{
		{"tcp", "93.184.216.34", 443, true},
		{"udp", "1.1.1.1", 53, true},           // any/53
		{"tcp", "1.1.1.1", 53, true},           // any/53, tcp
		{"tcp", "1.1.1.1", 8080, false},        // nothing names it
		{"tcp", "169.254.169.254", 443, false}, // the CIDR refuses first
		{"udp", "169.254.169.254", 53, false},  // the CIDR beats any
		{"tcp", "2001:db8::1", 443, true},      // tcp/443 is not address-scoped
		{"udp", "2001:db8::1", 53, true},       // any/53, either family
	}
	for _, tc := range cases {
		addr := netip.MustParseAddr(tc.addr)
		engine := e.Net(tc.proto, addr, tc.port).Allowed
		kernel := ne.KernelAllows(tc.proto, addr, tc.port)
		if engine != kernel || engine != tc.allowed {
			t.Errorf("%s %s:%d: engine=%v kernel=%v want %v",
				tc.proto, tc.addr, tc.port, engine, kernel, tc.allowed)
		}
	}
}
