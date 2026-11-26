// Package decision turns a policy into the decisions the sandbox makes.
//
// The engine is what the kernel programs will implement; it lives in
// user space so that observe mode, the tests and any report can make
// the same decision the kernel would and name the rule that made it.
// When the BPF side arrives, its behavior is checked against this one.
//
// The defaults are asymmetric, on purpose. Exec is an allow list and
// net an allow list with CIDRs refused first: an agent that executes
// or connects to what the policy does not name is the sandbox's whole
// point, so the unnamed is refused. File is a deny list: the tree is
// readable and writable except for what the policy names, because
// listing every file an agent may read is not a policy anyone writes.
//
// A decision names the rule that made it, as `exec.allow[1]`,
// `file.deny_read[0]`, `net.allow[2]` or `net.deny_cidr[0]`, or the
// default it fell back to. The names are the policy author's index
// into their own lists, and events carry them unchanged.
package decision

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/kittimzhe/agent-sandbox/internal/match"
	"github.com/kittimzhe/agent-sandbox/internal/policy"
)

// Verdict is a decision and the rule that made it.
type Verdict struct {
	// Allowed says the access proceeds. A deny in observe mode is
	// reported but not enforced.
	Allowed bool
	// Rule names the policy entry that decided, or the default:
	// "default deny" when nothing matched an allow list, "" when
	// nothing matched a deny list and the default is allow.
	Rule string
}

// Engine is a compiled policy.
type Engine struct {
	execAllow     []match.Rule
	fileDenyRead  []match.Rule
	fileDenyWrite []match.Rule
	netAllow      []policy.NetAllow
	netDenyCIDR   []netip.Prefix
}

// New compiles a policy into an engine. An engine is immutable once
// built; a policy change builds a new one.
func New(p *policy.Policy) (*Engine, error) {
	e := &Engine{
		netAllow:    p.Net.Allow,
		netDenyCIDR: p.Net.DenyCIDR,
	}
	for _, pattern := range p.Exec.Allow {
		r, err := match.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("exec.allow %q: %w", pattern, err)
		}
		e.execAllow = append(e.execAllow, r)
	}
	for _, list := range []struct {
		name     string
		patterns []string
		dst      *[]match.Rule
	}{
		{"file.deny_read", p.File.DenyRead, &e.fileDenyRead},
		{"file.deny_write", p.File.DenyWrite, &e.fileDenyWrite},
	} {
		for _, pattern := range list.patterns {
			r, err := match.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("%s %q: %w", list.name, pattern, err)
			}
			*list.dst = append(*list.dst, r)
		}
	}
	return e, nil
}

// Exec decides whether a sandboxed task may execute a binary.
func (e *Engine) Exec(path string) Verdict {
	for i, r := range e.execAllow {
		if r.Match(path) {
			return Verdict{Allowed: true, Rule: "exec.allow[" + strconv.Itoa(i) + "]"}
		}
	}
	return Verdict{Allowed: false, Rule: "default deny"}
}

// File decides whether a sandboxed task may open a path. A read is
// checked against deny_read and a write against deny_write, and a
// write-only rule does not refuse a read of the same path.
func (e *Engine) File(path string, write bool) Verdict {
	denies := e.fileDenyRead
	list := "file.deny_read"
	if write {
		denies = e.fileDenyWrite
		list = "file.deny_write"
	}
	for i, r := range denies {
		if r.Match(path) {
			return Verdict{Allowed: false, Rule: list + "[" + strconv.Itoa(i) + "]"}
		}
	}
	return Verdict{Allowed: true}
}

// ExecRules is the compiled exec table, in policy order: what the
// kernel side fills its own table with, so one compiler backs both.
func (e *Engine) ExecRules() []match.Rule {
	return e.execAllow
}

// FileDenyRead is the compiled deny_read table.
func (e *Engine) FileDenyRead() []match.Rule {
	return e.fileDenyRead
}

// FileDenyWrite is the compiled deny_write table.
func (e *Engine) FileDenyWrite() []match.Rule {
	return e.fileDenyWrite
}

// Net decides whether a sandboxed task may connect to an address.
// A CIDR the policy refuses is refused before the allow list, so a
// port an allow entry names is still refused inside that CIDR.
func (e *Engine) Net(proto string, addr netip.Addr, port uint16) Verdict {
	for i, prefix := range e.netDenyCIDR {
		if prefix.Contains(addr) {
			return Verdict{Allowed: false, Rule: "net.deny_cidr[" + strconv.Itoa(i) + "]"}
		}
	}
	for i, allow := range e.netAllow {
		if allow.Port != port {
			continue
		}
		if allow.Proto == "any" || allow.Proto == proto {
			return Verdict{Allowed: true, Rule: "net.allow[" + strconv.Itoa(i) + "]"}
		}
	}
	return Verdict{Allowed: false, Rule: "default deny"}
}
