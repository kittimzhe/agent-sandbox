package match

import (
	"strings"
	"testing"
)

func TestCompile(t *testing.T) {
	cases := []struct {
		pattern string
		prefix  string
		kind    Kind
	}{
		{"/usr/bin/ls", "/usr/bin/ls", Exact},
		{"/usr/bin/*", "/usr/bin", OneLevel},
		{"/home/alice/.ssh/**", "/home/alice/.ssh", Recursive},
		{"/etc/**", "/etc", Recursive},
		{"/", "", Recursive},
	}
	for _, tc := range cases {
		r, err := Compile(tc.pattern)
		if err != nil {
			t.Fatalf("Compile(%q) error = %v", tc.pattern, err)
		}
		if r.Prefix() != tc.prefix || r.Kind() != tc.kind {
			t.Errorf("Compile(%q) = %q, %v; want %q, %v", tc.pattern, r.Prefix(), r.Kind(), tc.prefix, tc.kind)
		}
		if got := r.Pattern(); got != tc.pattern {
			t.Errorf("Pattern() = %q, want %q", got, tc.pattern)
		}
	}
}

func TestCompileRejects(t *testing.T) {
	cases := []struct {
		pattern string
		want    string
	}{
		{"", "empty"},
		{"usr/bin/*", "absolute"},
		{"/usr//bin/*", "empty component"},
		{"/usr/*/bin", "cannot enforce"},
		{"/u*sr/bin", "cannot enforce"},
		{"/usr/bin**/x", "cannot enforce"},
		{"/home/*/.ssh/**", "cannot enforce"},
	}
	for _, tc := range cases {
		_, err := Compile(tc.pattern)
		if err == nil {
			t.Errorf("Compile(%q) = nil error, want %q", tc.pattern, tc.want)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Compile(%q) error = %q, want it to contain %q", tc.pattern, err, tc.want)
		}
	}
}

func TestMatchExact(t *testing.T) {
	r := mustCompile(t, "/usr/bin/ls")
	yes := []string{"/usr/bin/ls"}
	no := []string{"/usr/bin/lsx", "/usr/bin/ls/x", "/usr/bin", "usr/bin/ls", ""}
	for _, p := range yes {
		if !r.Match(p) {
			t.Errorf("Match(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if r.Match(p) {
			t.Errorf("Match(%q) = true, want false", p)
		}
	}
}

func TestMatchOneLevel(t *testing.T) {
	r := mustCompile(t, "/usr/bin/*")
	yes := []string{"/usr/bin/ls", "/usr/bin/7z", "/usr/bin/x.elf"}
	no := []string{"/usr/bin", "/usr/bin/", "/usr/bin/sub/ls", "/usr/local/bin/ls"}
	for _, p := range yes {
		if !r.Match(p) {
			t.Errorf("Match(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if r.Match(p) {
			t.Errorf("Match(%q) = true, want false", p)
		}
	}
}

func TestMatchRecursive(t *testing.T) {
	r := mustCompile(t, "/etc/**")
	// Recursive covers zero components, so the prefix itself matches.
	yes := []string{"/etc", "/etc/passwd", "/etc/ssl/private/k.pem"}
	no := []string{"/etc/", "/etcx", "/home/x"}
	for _, p := range yes {
		if !r.Match(p) {
			t.Errorf("Match(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if r.Match(p) {
			t.Errorf("Match(%q) = true, want false", p)
		}
	}
}

func TestRootPatternMatchesEverything(t *testing.T) {
	r := mustCompile(t, "/")
	for _, p := range []string{"/", "/usr/bin/ls", "/anything"} {
		if !r.Match(p) {
			t.Errorf("Match(%q) = false, want true", p)
		}
	}
	if r.Match("") || r.Match("etc/passwd") {
		t.Errorf("the root pattern matched a relative path")
	}
}

func TestKindStrings(t *testing.T) {
	if Exact.String() != "exact" || OneLevel.String() != "one level" || Recursive.String() != "recursive" {
		t.Errorf("kind strings = %q, %q, %q", Exact, OneLevel, Recursive)
	}
}

func mustCompile(t *testing.T, pattern string) Rule {
	t.Helper()
	r, err := Compile(pattern)
	if err != nil {
		t.Fatalf("Compile(%q) error = %v", pattern, err)
	}
	return r
}
