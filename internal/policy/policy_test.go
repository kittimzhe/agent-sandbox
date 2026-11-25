package policy

import (
	"strings"
	"testing"
)

const full = `# agent-web: a policy for an agent that only talks HTTPS.
name: agent-web

scope:
  cgroup: /sys/fs/cgroup/agent-sandbox

exec:
  allow:
    - /usr/bin/*
    - /bin/*

file:
  deny_read:
    - /home/*/.ssh/**
    - /home/*/.gnupg/**
  deny_write:
    - /etc/**

net:
  allow:
    - tcp/443
    - tcp/80
    - udp/53
  deny_cidr:
    - 169.254.169.254/32
`

func TestParseFull(t *testing.T) {
	p, err := Parse(full)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if p.Name != "agent-web" {
		t.Errorf("Name = %q, want agent-web", p.Name)
	}
	if p.Scope.Cgroup != "/sys/fs/cgroup/agent-sandbox" {
		t.Errorf("Scope.Cgroup = %q", p.Scope.Cgroup)
	}
	wantAllow := []string{"/usr/bin/*", "/bin/*"}
	if len(p.Exec.Allow) != len(wantAllow) {
		t.Fatalf("Exec.Allow = %v, want %v", p.Exec.Allow, wantAllow)
	}
	for i, s := range wantAllow {
		if p.Exec.Allow[i] != s {
			t.Errorf("Exec.Allow[%d] = %q, want %q", i, p.Exec.Allow[i], s)
		}
	}
	if len(p.File.DenyRead) != 2 || len(p.File.DenyWrite) != 1 {
		t.Errorf("File lists = %v / %v", p.File.DenyRead, p.File.DenyWrite)
	}
	if len(p.Net.Allow) != 3 {
		t.Fatalf("Net.Allow = %v", p.Net.Allow)
	}
	if got := p.Net.Allow[0]; got.Proto != "tcp" || got.Port != 443 {
		t.Errorf("Net.Allow[0] = %+v, want tcp/443", got)
	}
	if got := p.Net.Allow[2]; got.Proto != "udp" || got.Port != 53 {
		t.Errorf("Net.Allow[2] = %+v, want udp/53", got)
	}
	if len(p.Net.DenyCIDR) != 1 || p.Net.DenyCIDR[0].String() != "169.254.169.254/32" {
		t.Errorf("Net.DenyCIDR = %v", p.Net.DenyCIDR)
	}
}

func TestParseMinimal(t *testing.T) {
	p, err := Parse("name: bare\nscope:\n  cgroup: /run/cg/x\nexec:\n  allow:\n    - /bin/ls\n")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if p.Name != "bare" || p.File.DenyRead != nil || p.Net.Allow != nil {
		t.Errorf("minimal policy = %+v", p)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{"missing name", "scope:\n  cgroup: /x\nexec:\n  allow:\n    - /bin/ls\n", "name is required"},
		{"missing cgroup", "name: x\nexec:\n  allow:\n    - /bin/ls\n", "scope.cgroup is required"},
		{"relative cgroup", "name: x\nscope:\n  cgroup: cg/x\nexec:\n  allow:\n    - /bin/ls\n", "absolute path"},
		{"empty exec allow", "name: x\nscope:\n  cgroup: /x\n", "refuses every exec"},
		{"unknown top key", "name: x\nmode: observe\n", "unknown key"},
		{"unknown file key", "name: x\nscope:\n  cgroup: /x\nexec:\n  allow:\n    - /bin/ls\nfile:\n  deny:\n    - /etc\n", "unknown key"},
		{"bad net entry", "name: x\nscope:\n  cgroup: /x\nexec:\n  allow:\n    - /bin/ls\nnet:\n  allow:\n    - tcp/https\n", "bad port"},
		{"bad protocol", "name: x\nscope:\n  cgroup: /x\nexec:\n  allow:\n    - /bin/ls\nnet:\n  allow:\n    - sctp/22\n", "bad protocol"},
		{"bad cidr", "name: x\nscope:\n  cgroup: /x\nexec:\n  allow:\n    - /bin/ls\nnet:\n  deny_cidr:\n    - 169.254.0.0\n", "bad CIDR"},
		{"tab indent", "name: x\nscope:\n\tcgroup: /x\n", "spaces, not tabs"},
		{"odd indent", "name: x\nscope:\n   cgroup: /x\n", "multiple of two"},
		{"stray indent", "name: x\n  cgroup: /x\n", "unexpected indent"},
		{"list before key", "name: x\nscope:\n  cgroup: /x\nexec:\n  - /bin/ls\n", "outside a key"},
		{"scalar on block key", "name: x\nscope: /x\n", "block, not a value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.text)
			if err == nil {
				t.Fatalf("Parse() = nil error, want one containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Parse() error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestParseErrorHasLineNumber(t *testing.T) {
	_, err := Parse("# comment line\n\nname: x\nmode: observe\n")
	if err == nil || !strings.Contains(err.Error(), "line 4") {
		t.Errorf("Parse() error = %v, want it to name line 4", err)
	}
}
