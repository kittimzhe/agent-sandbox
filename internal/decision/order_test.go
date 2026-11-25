package decision

import (
	"net/netip"
	"testing"

	"github.com/kittimzhe/agent-sandbox/internal/policy"
)

// These tests are the order the kernel programs must implement, named
// here so the BPF side has one behavior to match: the CIDR refusals
// run before the allow list, the first matching allow entry wins, and
// a file rule is read-only or write-only, never both. When the BPF
// side arrives, its parity test replays these cases against the
// kernel and the engine and requires the same verdicts.

func TestOrderCIDRBeforeAllow(t *testing.T) {
	// 443 is allowed and the address is inside a refused CIDR: the
	// refusal decides.
	p, err := policy.Parse(`name: x
scope:
  cgroup: /x
exec:
  allow:
    - /bin/*
net:
  allow:
    - tcp/443
  deny_cidr:
    - 10.0.0.0/8
`)
	if err != nil {
		t.Fatalf("policy.Parse() error = %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	v := e.Net("tcp", netip.MustParseAddr("10.1.2.3"), 443)
	if v.Allowed || v.Rule != "net.deny_cidr[0]" {
		t.Errorf("the CIDR did not decide before the allow list: %+v", v)
	}
	// The same address outside the CIDR takes the allow list.
	v = e.Net("tcp", netip.MustParseAddr("11.1.2.3"), 443)
	if !v.Allowed || v.Rule != "net.allow[0]" {
		t.Errorf("an address outside the CIDR was not allowed: %+v", v)
	}
}

func TestFirstMatchingAllowWins(t *testing.T) {
	p, err := policy.Parse(`name: x
scope:
  cgroup: /x
exec:
  allow:
    - /bin/sh
    - /bin/*
`)
	if err != nil {
		t.Fatalf("policy.Parse() error = %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// /bin/sh matches entry 0 exactly and entry 1 by its star; the
	// report names 0, so a policy author can find the line.
	if v := e.Exec("/bin/sh"); v.Rule != "exec.allow[0]" {
		t.Errorf("/bin/sh decided by %+v, want entry 0", v)
	}
	if v := e.Exec("/bin/ls"); v.Rule != "exec.allow[1]" {
		t.Errorf("/bin/ls decided by %+v, want entry 1", v)
	}
}

func TestFileRulesAreDirectional(t *testing.T) {
	p, err := policy.Parse(`name: x
scope:
  cgroup: /x
exec:
  allow:
    - /bin/*
file:
  deny_read:
    - /secrets/**
  deny_write:
    - /state/**
`)
	if err != nil {
		t.Fatalf("policy.Parse() error = %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// A read rule refuses reads, not writes, and the other way round:
	// the kernel side checks one list per direction, so a rule the
	// policy names for one direction must not leak into the other.
	if v := e.File("/secrets/k", false); v.Allowed {
		t.Errorf("a denied read was allowed: %+v", v)
	}
	if v := e.File("/secrets/k", true); !v.Allowed {
		t.Errorf("a read rule refused a write: %+v", v)
	}
	if v := e.File("/state/k", true); v.Allowed {
		t.Errorf("a denied write was allowed: %+v", v)
	}
	if v := e.File("/state/k", false); !v.Allowed {
		t.Errorf("a write rule refused a read: %+v", v)
	}
}

// A deny list refuses only what it names; everything else proceeds,
// including a path that shares a prefix with a refused one.
func TestDenyIsNotPrefixOverreach(t *testing.T) {
	p, err := policy.Parse(`name: x
scope:
  cgroup: /x
exec:
  allow:
    - /bin/*
file:
  deny_read:
    - /root/.ssh/authorized_keys
`)
	if err != nil {
		t.Fatalf("policy.Parse() error = %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if v := e.File("/root/.ssh/authorized_keys", false); v.Allowed {
		t.Errorf("the named file was readable: %+v", v)
	}
	if v := e.File("/root/.ssh/authorized_keys2", false); !v.Allowed {
		t.Errorf("a file the rule does not name was refused: %+v", v)
	}
	if v := e.File("/root/.ssh/config", false); !v.Allowed {
		t.Errorf("a sibling file was refused: %+v", v)
	}
}
