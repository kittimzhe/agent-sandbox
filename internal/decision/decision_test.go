package decision

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/kittimzhe/agent-sandbox/internal/policy"
)

func mustEngine(t *testing.T, text string) *Engine {
	t.Helper()
	p, err := policy.Parse(text)
	if err != nil {
		t.Fatalf("policy.Parse() error = %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return e
}

const demo = `name: demo
scope:
  cgroup: /sys/fs/cgroup/agent-sandbox
exec:
  allow:
    - /usr/bin/*
    - /bin/ls
file:
  deny_read:
    - /root/.ssh/**
  deny_write:
    - /etc/**
net:
  allow:
    - tcp/443
    - any/53
  deny_cidr:
    - 169.254.169.254/32
`

func TestExec(t *testing.T) {
	e := mustEngine(t, demo)
	cases := []struct {
		path    string
		allowed bool
		rule    string
	}{
		{"/usr/bin/python3", true, "exec.allow[0]"},
		{"/bin/ls", true, "exec.allow[1]"},
		{"/usr/bin/sub/x", false, "default deny"},
		{"/bin/sh", false, "default deny"},
		{"/opt/tool", false, "default deny"},
	}
	for _, tc := range cases {
		got := e.Exec(tc.path)
		if got.Allowed != tc.allowed || got.Rule != tc.rule {
			t.Errorf("Exec(%q) = %+v, want allowed=%v rule=%q", tc.path, got, tc.allowed, tc.rule)
		}
	}
}

func TestFile(t *testing.T) {
	e := mustEngine(t, demo)
	cases := []struct {
		path    string
		write   bool
		allowed bool
		rule    string
	}{
		{"/root/.ssh/id_ed25519", false, false, "file.deny_read[0]"},
		{"/root/.ssh/id_ed25519", true, true, ""},
		{"/etc/hosts", true, false, "file.deny_write[0]"},
		{"/etc/hosts", false, true, ""},
		{"/var/log/x", true, true, ""},
		{"/var/log/x", false, true, ""},
	}
	for _, tc := range cases {
		got := e.File(tc.path, tc.write)
		if got.Allowed != tc.allowed || got.Rule != tc.rule {
			t.Errorf("File(%q, write=%v) = %+v, want allowed=%v rule=%q", tc.path, tc.write, got, tc.allowed, tc.rule)
		}
	}
}

func TestNet(t *testing.T) {
	e := mustEngine(t, demo)
	metadata := netip.MustParseAddr("169.254.169.254")
	public := netip.MustParseAddr("93.184.216.34")
	dns := netip.MustParseAddr("1.1.1.1")

	cases := []struct {
		proto   string
		addr    netip.Addr
		port    uint16
		allowed bool
		rule    string
	}{
		{"tcp", public, 443, true, "net.allow[0]"},
		{"udp", dns, 53, true, "net.allow[1]"},
		{"tcp", dns, 53, true, "net.allow[1]"},
		{"udp", public, 123, false, "default deny"},
		// The CIDR is refused before the allow list: port 443 inside it
		// does not help.
		{"tcp", metadata, 443, false, "net.deny_cidr[0]"},
		{"tcp", metadata, 80, false, "net.deny_cidr[0]"},
	}
	for _, tc := range cases {
		got := e.Net(tc.proto, tc.addr, tc.port)
		if got.Allowed != tc.allowed || got.Rule != tc.rule {
			t.Errorf("Net(%s, %s, %d) = %+v, want allowed=%v rule=%q",
				tc.proto, tc.addr, tc.port, got, tc.allowed, tc.rule)
		}
	}
}

func TestEmptyListsKeepDefaults(t *testing.T) {
	e := mustEngine(t, "name: x\nscope:\n  cgroup: /x\nexec:\n  allow:\n    - /bin/*\n")
	if got := e.File("/anything", true); !got.Allowed {
		t.Errorf("no file rules denies everything: %+v", got)
	}
	if got := e.Net("tcp", netip.MustParseAddr("1.2.3.4"), 80); got.Allowed {
		t.Errorf("no net rules allows everything: %+v", got)
	}
}

func TestNewRejectsBadPattern(t *testing.T) {
	p, err := policy.Parse("name: x\nscope:\n  cgroup: /x\nexec:\n  allow:\n    - /home/*/.ssh/**\n")
	if err != nil {
		t.Fatalf("policy.Parse() error = %v", err)
	}
	_, err = New(p)
	if err == nil || !strings.Contains(err.Error(), "cannot enforce") {
		t.Errorf("New() error = %v, want it to contain %q", err, "cannot enforce")
	}
	if err == nil || !strings.Contains(err.Error(), "exec.allow") {
		t.Errorf("New() error = %v, want it to name the list", err)
	}
}
