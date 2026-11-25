package match

import (
	"strings"
	"testing"
)

// FuzzCompile drives the pattern compiler with arbitrary input: it
// never panics, a compiled rule's Pattern is the pattern it compiled,
// and Match never allows a path the rule's prefix does not name. The
// compiler is the gate the kernel side relies on, so what it rejects
// is as important as what it takes.
func FuzzCompile(f *testing.F) {
	for _, s := range [][2]string{
		{"/usr/bin/ls", "/usr/bin/ls"}, {"/usr/bin/*", "/usr/bin/ls"}, {"/etc/**", "/etc/passwd"},
		{"/", "/anything"}, {"/*", "/x"}, {"/**", "/x/y"},
		{"/usr/*/bin", "/usr/a/bin"}, {"/home/*/.ssh/**", "/home/alice/.ssh/k"},
		{"usr/bin/*", "usr/bin/ls"}, {"", ""}, {"//", "//"}, {"/a//b", "/a/b"},
		{"/usr/bin**/x", "/usr/bin/y/x"}, {"/u*sr", "/usr"}, {"/x/", "/x/"}, {"/x/*", "/x/"},
		{"/*/*", "/a/b"}, {"/**/**", "/a"}, {"/root/.ssh/id_ed25519", "/root/.ssh/id_ed25519"},
		{"/" + strings.Repeat("a", 300) + "/*", "/" + strings.Repeat("a", 300) + "/b"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, path string) {
		r, err := Compile(pattern)
		if err != nil {
			return
		}
		// A rule spells itself back as the pattern it compiled.
		if got := r.Prefix(); got != "" && !strings.HasPrefix(pattern, got) {
			t.Fatalf("Compile(%q).Prefix() = %q, which the pattern does not start with", pattern, got)
		}
		// A rule spells itself back as a pattern that compiles to
		// itself: the spelling is canonical, and "/**" and "/" are
		// one and the same rule.
		canonical, err := Compile(r.Pattern())
		if err != nil {
			t.Fatalf("Compile(%q).Pattern() = %q does not compile: %v", pattern, r.Pattern(), err)
		}
		if canonical != r {
			t.Fatalf("Compile(%q).Pattern() = %q, which compiles to a different rule", pattern, r.Pattern())
		}
		// An exact rule matches only its own prefix; a star rule never
		// matches a shorter or unrelated path.
		if r.Match(path) {
			if r.Kind() == Exact && path != r.Prefix() {
				t.Fatalf("exact rule %q matched %q", pattern, path)
			}
			if !strings.HasPrefix(path, r.Prefix()) {
				t.Fatalf("rule %q matched %q outside its prefix", pattern, path)
			}
		}
	})
}
