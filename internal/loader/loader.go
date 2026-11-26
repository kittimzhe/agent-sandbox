// Package loader loads and attaches the sandbox's BPF programs.
//
// The programs are compiled from ../bpf by bpf2go at go:generate time,
// with the flags the tree pins: -mcpu=v4 for the instruction set the
// tree writes against, -g so the verifier's logs and the JIT's line
// info name our source lines. The generated loader handles the
// endianness of the build host; the programs themselves are CO-RE, so
// one object runs on every kernel whose types the relocations resolve.
//
//go:build linux

package loader

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -cflags "-mcpu=v4 -O2 -g -I../../bpf" count_exec ../../bpf/count_exec.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -cflags "-mcpu=v4 -O2 -g -I../../bpf" policy_exec ../../bpf/policy_exec.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -cflags "-mcpu=v4 -O2 -g -I../../bpf" policy_file ../../bpf/policy_file.bpf.c

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/kittimzhe/agent-sandbox/internal/match"
	"golang.org/x/sys/unix"
)

// Counters is the loaded count_exec program and its map.
type Counters struct {
	Obj  count_execObjects
	Link link.Link
}

// LoadCounters loads the exec counter and attaches it to do_execve.
func LoadCounters() (*Counters, error) {
	obj := &count_execObjects{}
	if err := loadCount_execObjects(obj, nil); err != nil {
		return nil, fmt.Errorf("load count_exec: %w", err)
	}
	// A tracepoint attaches by name: the kernel owns the ABI, so the
	// baseline counter runs on every kernel, inlined exec paths or
	// not. M1's policy hooks attach by BTF id instead, where the
	// target kernel is pinned.
	l, err := link.Tracepoint("sched", "sched_process_exec", obj.CountExec, nil)
	if err != nil {
		obj.Close()
		return nil, fmt.Errorf("attach fentry/do_execve: %w", err)
	}
	return &Counters{Obj: *obj, Link: l}, nil
}

// Close detaches and frees the program and its map.
func (c *Counters) Close() error {
	if c == nil {
		return nil
	}
	err := c.Link.Close()
	if err2 := c.Obj.Close(); err == nil {
		err = err2
	}
	return err
}

// Counts reads the per-cgroup exec counts as a copy.
func (c *Counters) Counts() (map[uint64]uint64, error) {
	out := map[uint64]uint64{}
	var key, val uint64
	it := c.Obj.ExecCounts.Iterate()
	for it.Next(&key, &val) {
		out[key] = val
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// CountOf reads one cgroup's count; a cgroup with no execs reads 0.
func (c *Counters) CountOf(cgroupID uint64) (uint64, error) {
	var n uint64
	err := c.Obj.ExecCounts.Lookup(cgroupID, &n)
	if errors.Is(err, ebpf.ErrKeyNotExist) || errors.Is(err, unix.ENOENT) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return n, nil
}

// The kernel's rule table. The C side pins the sizes; the loader
// refuses a policy that does not fit, never truncates one.
const (
	maxRules  = 64
	maxPrefix = 64
)

// ruleKind mirrors the C constants in policy_exec.bpf.c.
const (
	kindExact = 0
	kindOne   = 1
	kindRec   = 2
)

type cRule struct {
	Kind uint8
	Plen uint8 // the rule's own prefix, in bytes
	_    [6]byte
}

type cKey struct {
	PrefixLen uint32 // bits
	Data      [maxPrefix]byte
}

type cPath struct {
	Data [maxPrefix]byte
}

// Enforcement is the loaded LSM program with its maps filled.
type Enforcement struct {
	Obj  *policy_execObjects
	Link link.Link
}

// LoadPolicy loads the LSM program and fills its maps from the
// compiled rules: one LPM key per rule, and the scope cgroup the task
// must sit in. Recursive and one-level rules carry the trailing '/'
// in their key — a name that only shares the prefix must not match.
// The maps are pinned by no one; the program lives only as long as
// the runtime does.
func LoadPolicy(rules []match.Rule, scopeCgroupID uint64) (*Enforcement, error) {
	if len(rules) > maxRules {
		return nil, fmt.Errorf("%d exec rules, the kernel table holds %d", len(rules), maxRules)
	}
	obj := &policy_execObjects{}
	if err := loadPolicy_execObjects(obj, nil); err != nil {
		return nil, fmt.Errorf("load policy_exec: %w", err)
	}
	fail := func(err error) (*Enforcement, error) {
		obj.Close()
		return nil, err
	}
	for i, r := range rules {
		prefix := r.Prefix()
		if r.Kind() != match.Exact {
			// A glob's prefix is the directory: keep its slash, so
			// /bin/** does not match /binutils. match drops it.
			prefix += "/"
		}
		if len(prefix) > maxPrefix {
			return fail(fmt.Errorf("rule %d (%q) does not fit the kernel table: a key holds %d bytes", i, r.Pattern(), maxPrefix))
		}
		if r.Kind() == match.Exact {
			// Equality is a hash lookup on the whole path: a bit
			// prefix would also match a longer name that shares it.
			var pk cPath
			copy(pk.Data[:], prefix)
			if err := obj.ExecExact.Update(&pk, uint8(1), ebpf.UpdateAny); err != nil {
				return fail(fmt.Errorf("rule %d: %w", i, err))
			}
			continue
		}
		var (
			key cKey
			val cRule
		)
		key.PrefixLen = uint32(len(prefix)) * 8
		copy(key.Data[:], prefix)
		switch r.Kind() {
		case match.OneLevel:
			val.Kind = kindOne
		case match.Recursive:
			val.Kind = kindRec
		}
		val.Plen = uint8(len(prefix))
		if err := obj.ExecRules.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return fail(fmt.Errorf("rule %d: %w", i, err))
		}
	}
	// The rest of the table stays empty: LPM matches only what the
	// loader put in.
	if err := obj.ScopedCgroups.Update(scopeCgroupID, uint8(1), ebpf.UpdateAny); err != nil {
		return fail(fmt.Errorf("scope cgroup: %w", err))
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: obj.CheckExec})
	if err != nil {
		return fail(fmt.Errorf("attach lsm/bprm_check_security: %w", err))
	}
	return &Enforcement{Obj: obj, Link: l}, nil
}

// Close detaches and frees the program and its maps.
func (e *Enforcement) Close() error {
	if e == nil {
		return nil
	}
	err := e.Link.Close()
	if err2 := e.Obj.Close(); err == nil {
		err = err2
	}
	return err
}

// FileEnforcement is the loaded file_open program with the deny
// tables filled.
type FileEnforcement struct {
	Obj  *policy_fileObjects
	Link link.Link
}

// fillFileTables writes one direction's rules into its two tables.
func fillFileTables(rules []match.Rule, lpm, hash *ebpf.Map, dir string) error {
	for i, r := range rules {
		prefix := r.Prefix()
		if r.Kind() != match.Exact {
			prefix += "/"
		}
		if len(prefix) > maxPrefix {
			return fmt.Errorf("%s rule %d (%q) does not fit the kernel table: a key holds %d bytes", dir, i, r.Pattern(), maxPrefix)
		}
		if r.Kind() == match.Exact {
			var pk cPath
			copy(pk.Data[:], prefix)
			if err := hash.Update(&pk, uint8(1), ebpf.UpdateAny); err != nil {
				return fmt.Errorf("%s rule %d: %w", dir, i, err)
			}
			continue
		}
		var (
			key cKey
			val cRule
		)
		key.PrefixLen = uint32(len(prefix)) * 8
		copy(key.Data[:], prefix)
		if r.Kind() == match.OneLevel {
			val.Kind = kindOne
		} else {
			val.Kind = kindRec
		}
		val.Plen = uint8(len(prefix))
		if err := lpm.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("%s rule %d: %w", dir, i, err)
		}
	}
	return nil
}

// LoadFilePolicy loads the file_open program and fills the deny
// tables from the policy's two lists.
func LoadFilePolicy(denyRead, denyWrite []match.Rule, scopeCgroupID uint64) (*FileEnforcement, error) {
	if len(denyRead) > maxRules {
		return nil, fmt.Errorf("%d file.deny_read rules, the kernel table holds %d", len(denyRead), maxRules)
	}
	if len(denyWrite) > maxRules {
		return nil, fmt.Errorf("%d file.deny_write rules, the kernel table holds %d", len(denyWrite), maxRules)
	}
	obj := &policy_fileObjects{}
	if err := loadPolicy_fileObjects(obj, nil); err != nil {
		return nil, fmt.Errorf("load policy_file: %w", err)
	}
	fail := func(err error) (*FileEnforcement, error) {
		obj.Close()
		return nil, err
	}
	if err := fillFileTables(denyRead, obj.DenyRead, obj.DenyReadExact, "file.deny_read"); err != nil {
		return fail(err)
	}
	if err := fillFileTables(denyWrite, obj.DenyWrite, obj.DenyWriteExact, "file.deny_write"); err != nil {
		return fail(err)
	}
	if err := obj.ScopedCgroups.Update(scopeCgroupID, uint8(1), ebpf.UpdateAny); err != nil {
		return fail(fmt.Errorf("scope cgroup: %w", err))
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: obj.CheckFile})
	if err != nil {
		return fail(fmt.Errorf("attach lsm/file_open: %w", err))
	}
	return &FileEnforcement{Obj: obj, Link: l}, nil
}

// Close detaches and frees the program and its maps.
func (f *FileEnforcement) Close() error {
	if f == nil {
		return nil
	}
	err := f.Link.Close()
	if err2 := f.Obj.Close(); err == nil {
		err = err2
	}
	return err
}
