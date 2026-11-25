// Package match compiles a policy path pattern into a rule and matches
// paths against it.
//
// A pattern is an absolute path whose last component may be `*` or
// `**`: `*` stands for exactly one component, `**` for any number of
// components, zero included. A `*` anywhere but at the end, a relative
// path or an empty component is rejected: the kernel side of the
// sandbox matches by prefix, and a pattern it cannot enforce must fail
// to load rather than match more, or less, than it appears to. A
// policy for a home directory names it: `/home/alice/.ssh/**`, not a
// wildcard over every user's home.
//
// Match is the same decision the kernel makes. It is used by the
// tests, by observe mode's accounting, and by anything that needs to
// explain a decision in user space. Paths are canonical: absolute,
// without `.` or `..`, and without a trailing slash but the root's.
package match

import (
	"fmt"
	"strings"
)

// Kind says how many components a rule's star stands for.
type Kind uint8

const (
	// Exact matches the prefix and nothing more.
	Exact Kind = iota
	// OneLevel matches one component below the prefix.
	OneLevel
	// Recursive matches any number of components below the prefix,
	// zero included.
	Recursive
)

func (k Kind) String() string {
	switch k {
	case Exact:
		return "exact"
	case OneLevel:
		return "one level"
	case Recursive:
		return "recursive"
	}
	return "kind" + fmt.Sprint(uint8(k))
}

// Rule is a compiled pattern.
type Rule struct {
	// prefix is the pattern with its star removed, without a trailing
	// slash; empty for the root pattern "/".
	prefix string
	kind   Kind
}

// Compile turns a pattern into a rule.
func Compile(pattern string) (Rule, error) {
	if pattern == "" {
		return Rule{}, fmt.Errorf("empty pattern")
	}
	if !strings.HasPrefix(pattern, "/") {
		return Rule{}, fmt.Errorf("pattern %q is not an absolute path", pattern)
	}
	if pattern == "/" {
		return Rule{prefix: "", kind: Recursive}, nil
	}
	if strings.Contains(pattern, "//") {
		return Rule{}, fmt.Errorf("pattern %q has an empty component", pattern)
	}
	kind := Exact
	body := pattern
	switch {
	case strings.HasSuffix(pattern, "/**"):
		kind, body = Recursive, pattern[:len(pattern)-3]
	case strings.HasSuffix(pattern, "/*"):
		kind, body = OneLevel, pattern[:len(pattern)-2]
	}
	if strings.Contains(body, "*") {
		return Rule{}, fmt.Errorf("pattern %q has a '*' the kernel side cannot enforce: it may only end a path", pattern)
	}
	return Rule{prefix: body, kind: kind}, nil
}

// Match reports whether the path satisfies the rule. A relative or
// empty path matches nothing.
func (r Rule) Match(path string) bool {
	if path == "" || !strings.HasPrefix(path, "/") {
		return false
	}
	// The root pattern matches every absolute path. A star under the
	// root falls through to the component count like any other.
	if r.prefix == "" && r.kind == Recursive {
		return true
	}
	if path == r.prefix {
		// Exact is its match; Recursive's star stands for zero or
		// more components, zero included; OneLevel's stands for one,
		// so the bare prefix is not its match.
		return r.kind == Exact || r.kind == Recursive
	}
	if !strings.HasPrefix(path, r.prefix+"/") {
		return false
	}
	rest := path[len(r.prefix)+1:]
	if rest == "" { // a trailing slash names no component
		return false
	}
	switch r.kind {
	case OneLevel:
		return !strings.Contains(rest, "/")
	case Recursive:
		return true
	}
	return false // Exact and path != prefix
}

// Kind is how the rule matches below its prefix.
func (r Rule) Kind() Kind { return r.kind }

// Prefix is the literal part of the pattern, without the star.
func (r Rule) Prefix() string { return r.prefix }

// Pattern is the rule spelled as a pattern again, for reports.
func (r Rule) Pattern() string {
	switch r.kind {
	case Recursive:
		if r.prefix == "" {
			return "/"
		}
		return r.prefix + "/**"
	case OneLevel:
		return r.prefix + "/*"
	}
	return r.prefix
}
