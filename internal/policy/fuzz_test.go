package policy

import (
	"strings"
	"testing"
)

// FuzzParse drives the parser with arbitrary input. It must never
// panic, never hang, and a valid parse must always round-trip the
// parts the policy carries: this is the parser that reads a file an
// operator or a pipeline wrote, so garbage in gets a clean error, and
// a policy that parses is a policy the engine can build.
func FuzzParse(f *testing.F) {
	seeds := []string{
		full,
		"name: x\nscope:\n  cgroup: /x\nexec:\n  allow:\n    - /bin/*\n",
		"name: x\nmode: observe\n",
		"name: x\nscope:\n  cgroup: /x\nexec:\n  allow:\n    - /home/*/.ssh/**\n",
		"name: x\nscope:\n\tcgroup: /x\n",
		"name: x\nscope:\n  cgroup: /x\nexec:\n  allow:\n    - /bin/ls\nnet:\n  allow:\n    - tcp/https\n",
		"",
		"\n\n\n",
		"# comment only\n",
		"name: x\nscope:\n  cgroup: /x\nexec:\n  allow:\n    - -\n    -\nfile:\n  deny_read:\n    - /a\n    -\n",
		"name: x\nscope:\n  cgroup: /x\nnet:\n  deny_cidr:\n    - 1.2.3.4/33\n",
		"name: ~\nscope:\n  cgroup: ~\n",
		"name: x\nscope:\n  cgroup: /x\nexec:\n  allow:\n    - a:b\n",
		"- a\n- b\n",
		"a:\n b:\n  c: d\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		p, err := Parse(text)
		if err != nil {
			return
		}
		// A policy that parsed must be complete by the parser's own
		// rules, or a later build sees what validate refused.
		if p.Name == "" || p.Scope.Cgroup == "" || len(p.Exec.Allow) == 0 {
			t.Fatalf("Parse(%q) accepted an incomplete policy: %+v", text, p)
		}
		// The parsed values must come from the input, not from
		// anywhere else: every list entry is a non-empty substring
		// of the input.
		for _, s := range p.Exec.Allow {
			if s == "" || !strings.Contains(text, s) {
				t.Fatalf("Parse(%q) invented exec.allow entry %q", text, s)
			}
		}
		for _, s := range append(append([]string{}, p.File.DenyRead...), p.File.DenyWrite...) {
			if s == "" || !strings.Contains(text, s) {
				t.Fatalf("Parse(%q) invented a file entry %q", text, s)
			}
		}
		if !strings.Contains(text, p.Scope.Cgroup) {
			t.Fatalf("Parse(%q) invented scope.cgroup %q", text, p.Scope.Cgroup)
		}
	})
}
