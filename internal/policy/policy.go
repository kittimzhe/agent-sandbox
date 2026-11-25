// Package policy parses and validates the sandbox policy file.
//
// The file format is a strict subset of YAML, parsed here by hand: two
// spaces of indent per level, `key:` opens a block, `key: value` sets a
// scalar, and a list is one `- value` per line under its key. Comments
// are whole lines starting with `#`. An unknown key, a missing required
// key or a malformed value is an error, never a default: a policy that
// reads differently from what its author wrote is a sandbox that
// enforces the wrong rules.
//
// Only what the M0 release needs is parsed. Keys a newer runtime will
// grow are rejected until they are implemented, so a policy written for
// one fails here instead of silently losing its rules.
package policy

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Policy is the whole file.
type Policy struct {
	Name  string
	Scope Scope
	Exec  ExecRules
	File  FileRules
	Net   NetRules
}

// Scope names the cgroup v2 subtree the policy applies to. Processes
// the runtime moves into it are sandboxed; nothing else is.
type Scope struct {
	Cgroup string
}

// ExecRules constrain what binaries a sandboxed process may execute.
type ExecRules struct {
	Allow []string
}

// FileRules constrain what a sandboxed process may open.
type FileRules struct {
	DenyRead  []string
	DenyWrite []string
}

// NetRules constrain what a sandboxed process may connect to.
type NetRules struct {
	// Allow holds `tcp/443`, `udp/53` or `any/22` entries.
	Allow []NetAllow
	// DenyCIDR holds CIDRs refused before the allow list is consulted,
	// for a link-local metadata endpoint an allow entry would cover.
	DenyCIDR []netip.Prefix
}

// NetAllow is one protocol and port a process may connect to.
type NetAllow struct {
	Proto string // "tcp", "udp" or "any"
	Port  uint16
}

// Parse reads a whole policy file.
func Parse(text string) (*Policy, error) {
	lines, err := scanLines(text)
	if err != nil {
		return nil, err
	}
	p := &Policy{}
	for i := 0; i < len(lines); i++ {
		ln := lines[i]
		if ln.indent != 0 {
			return nil, fmt.Errorf("line %d: unexpected indent at the top level", ln.number)
		}
		key, value, ok := cutKey(ln.text)
		if !ok {
			return nil, fmt.Errorf("line %d: expected `key:` or `key: value`", ln.number)
		}
		if value != "" {
			switch key {
			case "name":
				p.Name = value
			case "scope", "exec", "file", "net":
				return nil, fmt.Errorf("line %d: %s takes a block, not a value", ln.number, key)
			default:
				return nil, fmt.Errorf("line %d: unknown key %q", ln.number, key)
			}
			continue
		}
		if key != "name" && key != "scope" && key != "exec" && key != "file" && key != "net" {
			return nil, fmt.Errorf("line %d: unknown key %q", ln.number, key)
		}
		// A block: gather the following, indented lines.
		var block []line
		for i+1 < len(lines) && lines[i+1].indent > 0 {
			i++
			block = append(block, lines[i])
		}
		if err := setBlock(p, key, block); err != nil {
			return nil, err
		}
	}
	if err := validate(p); err != nil {
		return nil, err
	}
	return p, nil
}

func setBlock(p *Policy, key string, block []line) error {
	switch key {
	case "scope":
		return parseScope(&p.Scope, block)
	case "exec":
		return parseExec(&p.Exec, block)
	case "file":
		return parseFile(&p.File, block)
	case "net":
		return parseNet(&p.Net, block)
	}
	return fmt.Errorf("unknown key %q", key)
}

func parseScope(s *Scope, block []line) error {
	for _, ln := range block {
		key, value, ok := cutKey(ln.text)
		if !ok || value == "" {
			return fmt.Errorf("line %d: scope takes `cgroup: <path>`", ln.number)
		}
		if key != "cgroup" {
			return fmt.Errorf("line %d: unknown scope key %q", ln.number, key)
		}
		s.Cgroup = value
	}
	return nil
}

// parseListBlock walks a block whose keys are list names and whose
// `- value` lines feed the list the last key named. feed reports one
// entry; listKey says which keys start a list.
func parseListBlock(block []line, listKey func(string) bool, feed func(key, entry string, n int) error) error {
	current := ""
	for _, ln := range block {
		if strings.HasPrefix(ln.text, "- ") {
			if current == "" {
				return fmt.Errorf("line %d: list entry outside a key", ln.number)
			}
			if err := feed(current, strings.TrimSpace(ln.text[2:]), ln.number); err != nil {
				return err
			}
			continue
		}
		key, value, ok := cutKey(ln.text)
		if !ok || value != "" {
			return fmt.Errorf("line %d: expected `<list>:` or `- <entry>`", ln.number)
		}
		if !listKey(key) {
			return fmt.Errorf("line %d: unknown key %q", ln.number, key)
		}
		current = key
	}
	return nil
}

func parseExec(e *ExecRules, block []line) error {
	return parseListBlock(block,
		func(key string) bool { return key == "allow" },
		func(key, entry string, n int) error {
			if entry == "" {
				return fmt.Errorf("line %d: empty exec.allow entry", n)
			}
			e.Allow = append(e.Allow, entry)
			return nil
		})
}

func parseFile(f *FileRules, block []line) error {
	return parseListBlock(block,
		func(key string) bool { return key == "deny_read" || key == "deny_write" },
		func(key, entry string, n int) error {
			if entry == "" {
				return fmt.Errorf("line %d: empty file.%s entry", n, key)
			}
			switch key {
			case "deny_read":
				f.DenyRead = append(f.DenyRead, entry)
			case "deny_write":
				f.DenyWrite = append(f.DenyWrite, entry)
			}
			return nil
		})
}

func parseNet(n *NetRules, block []line) error {
	return parseListBlock(block,
		func(key string) bool { return key == "allow" || key == "deny_cidr" },
		func(key, entry string, num int) error {
			if entry == "" {
				return fmt.Errorf("line %d: empty net.%s entry", num, key)
			}
			if key == "deny_cidr" {
				prefix, err := netip.ParsePrefix(entry)
				if err != nil {
					return fmt.Errorf("line %d: bad CIDR %q: %v", num, entry, err)
				}
				n.DenyCIDR = append(n.DenyCIDR, prefix)
				return nil
			}
			proto, port, ok := strings.Cut(entry, "/")
			if !ok {
				return fmt.Errorf("line %d: bad net allow %q, want tcp/443, udp/53 or any/22", num, entry)
			}
			p, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return fmt.Errorf("line %d: bad port in %q", num, entry)
			}
			switch proto {
			case "tcp", "udp", "any":
				n.Allow = append(n.Allow, NetAllow{Proto: proto, Port: uint16(p)})
				return nil
			}
			return fmt.Errorf("line %d: bad protocol in %q, want tcp, udp or any", num, entry)
		})
}

func validate(p *Policy) error {
	var errs []error
	if p.Name == "" {
		errs = append(errs, fmt.Errorf("name is required"))
	}
	if p.Scope.Cgroup == "" {
		errs = append(errs, fmt.Errorf("scope.cgroup is required"))
	} else if !strings.HasPrefix(p.Scope.Cgroup, "/") {
		errs = append(errs, fmt.Errorf("scope.cgroup must be an absolute path, got %q", p.Scope.Cgroup))
	}
	if len(p.Exec.Allow) == 0 {
		errs = append(errs, fmt.Errorf("exec.allow must list at least one path: an empty allow list refuses every exec"))
	}
	return joinErrs(errs)
}

func joinErrs(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Error()
	}
	return fmt.Errorf("%s", strings.Join(msgs, "; "))
}

// line is one non-blank, non-comment line of the file: the text
// without indent and trailing blanks, the indent in two-space steps,
// and the 1-based number it had, for errors.
type line struct {
	indent int
	text   string
	number int
}

// scanLines strips comments and blank lines and records indents.
func scanLines(text string) ([]line, error) {
	var out []line
	for i, raw := range strings.Split(text, "\n") {
		n := i + 1
		lead := raw[:len(raw)-len(strings.TrimLeft(raw, " \t"))]
		if strings.Contains(lead, "\t") {
			return nil, fmt.Errorf("line %d: indent with spaces, not tabs", n)
		}
		trimmed := raw[len(lead):]
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(trimmed)
		if indent%2 != 0 {
			return nil, fmt.Errorf("line %d: indent must be a multiple of two spaces", n)
		}
		out = append(out, line{indent: indent / 2, text: strings.TrimRight(trimmed, " "), number: n})
	}
	return out, nil
}

func cutKey(text string) (key, value string, ok bool) {
	i := strings.Index(text, ":")
	if i < 0 {
		return "", "", false
	}
	return text[:i], strings.TrimSpace(text[i+1:]), true
}
