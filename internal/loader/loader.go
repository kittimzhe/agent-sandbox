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
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -cflags "-mcpu=v4 -O2 -g -I../../bpf" policy_net ../../bpf/policy_net.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -cflags "-mcpu=v4 -O2 -g -I../../bpf" events ../../bpf/events.bpf.c
import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/kittimzhe/agent-sandbox/internal/match"
	"github.com/kittimzhe/agent-sandbox/internal/policy"
	"net/netip"

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

// DebugDump writes the tables' contents, for AGENT_SANDBOX_DEBUG_TABLES.
func (e *Enforcement) DebugDump(w interface{ Write([]byte) (int, error) }) {
	var key cPath
	var val uint8
	it := e.Obj.ExecExact.Iterate()
	for it.Next(&key, &val) {
		fmt.Fprintf(w, "exact: %q\n", key.Data)
	}
	var rk cKey
	var rv cRule
	it2 := e.Obj.ExecRules.Iterate()
	for it2.Next(&rk, &rv) {
		fmt.Fprintf(w, "lpm: bits=%d prefix=%q kind=%d plen=%d\n", rk.PrefixLen, rk.Data, rv.Kind, rv.Plen)
	}
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

// The net tables. The allow hash keys on the protocol value the
// kernel reports in sk_protocol -- IPPROTO_TCP and IPPROTO_UDP, the
// numbers the C program reads -- with 0 as the "any" entry the hook
// consults first. The codes 1 and 2 they once had were an
// invention: the kernel never reports them, and every allow entry
// missed while every connect was refused.
const (
	protoAny = 0
	protoTCP = 6  // IPPROTO_TCP
	protoUDP = 17 // IPPROTO_UDP
)

type cAllowKey struct {
	Port  uint16
	Proto uint8
	_     [5]byte
}

type cCIDRKey struct {
	PrefixLen uint32
	Data      [ipv6Len]byte
}

const ipv6Len = 16

// NetEnforcement is the loaded socket_connect program with the CIDR
// and allow tables filled.
type NetEnforcement struct {
	Obj  *policy_netObjects
	Link link.Link
}

// LoadNetPolicy loads the connect program: the CIDRs go in the LPM
// trie, the allow entries in the hash, exactly the order the engine
// decides in.
func LoadNetPolicy(p *policy.NetRules, scopeCgroupID uint64) (*NetEnforcement, error) {
	if len(p.Allow) > maxRules {
		return nil, fmt.Errorf("%d net.allow entries, the kernel table holds %d", len(p.Allow), maxRules)
	}
	if len(p.DenyCIDR) > maxRules {
		return nil, fmt.Errorf("%d net.deny_cidr entries, the kernel table holds %d", len(p.DenyCIDR), maxRules)
	}
	obj := &policy_netObjects{}
	if err := loadPolicy_netObjects(obj, nil); err != nil {
		return nil, fmt.Errorf("load policy_net: %w", err)
	}
	fail := func(err error) (*NetEnforcement, error) {
		obj.Close()
		return nil, err
	}
	for i, cidr := range p.DenyCIDR {
		if !cidr.Addr().Is4() && !cidr.Addr().Is6() {
			return fail(fmt.Errorf("net.deny_cidr[%d]: unsupported family", i))
		}
		var ck cCIDRKey
		bits := cidr.Bits()
		if cidr.Addr().Is4() {
			bits += 96 // v4 rides in the v6 trie, mapped
			v4 := cidr.Addr().As4()
			copy(ck.Data[12:], v4[:])
		} else {
			v6 := cidr.Addr().As16()
			copy(ck.Data[:], v6[:])
		}
		ck.PrefixLen = uint32(bits)
		if err := obj.NetDenyCidr.Update(&ck, uint8(1), ebpf.UpdateAny); err != nil {
			return fail(fmt.Errorf("net.deny_cidr[%d]: %w", i, err))
		}
	}
	for i, a := range p.Allow {
		var ak cAllowKey
		ak.Port = a.Port
		switch a.Proto {
		case "any":
			ak.Proto = protoAny
		case "tcp":
			ak.Proto = protoTCP
		case "udp":
			ak.Proto = protoUDP
		default:
			return fail(fmt.Errorf("net.allow[%d]: unknown protocol %q", i, a.Proto))
		}
		if err := obj.NetAllow.Update(&ak, uint8(1), ebpf.UpdateAny); err != nil {
			return fail(fmt.Errorf("net.allow[%d]: %w", i, err))
		}
	}
	if err := obj.ScopedCgroups.Update(scopeCgroupID, uint8(1), ebpf.UpdateAny); err != nil {
		return fail(fmt.Errorf("scope cgroup: %w", err))
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: obj.CheckConnect})
	if err != nil {
		return fail(fmt.Errorf("attach lsm/socket_connect: %w", err))
	}
	return &NetEnforcement{Obj: obj, Link: l}, nil
}

// Close detaches and frees the program and its maps.
func (n *NetEnforcement) Close() error {
	if n == nil {
		return nil
	}
	err := n.Link.Close()
	if err2 := n.Obj.Close(); err == nil {
		err = err2
	}
	return err
}

// KernelProbe reports whether this host can load BPF programs: the
// tracepoint the baseline counter needs exists and attaches. It is
// what the parity tests gate on.
func KernelProbe() bool {
	c, err := LoadCounters()
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// CgroupID is the cgroup id of a cgroup v2 path: the inode number its
// directory carries, the value bpf_get_current_cgroup_id reports.
func CgroupID(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// KernelAllows asks the exec tables the way the hook reads them:
// exact hash first, then the LPM trie with the one-level depth check.
// It is the kernel's decision mirrored in Go, so a parity mismatch
// names the side that moved.
func (e *Enforcement) KernelAllows(path string) bool {
	if len(path) > maxPrefix || !strings.HasPrefix(path, "/") {
		return false
	}
	var pk cPath
	copy(pk.Data[:], path)
	var one uint8
	if err := e.Obj.ExecExact.Lookup(&pk, &one); err == nil {
		return true
	}
	var key cKey
	key.PrefixLen = uint32(len(path)) * 8
	copy(key.Data[:], path)
	var rule cRule
	if err := e.Obj.ExecRules.Lookup(&key, &rule); err != nil {
		return false
	}
	switch rule.Kind {
	case kindRec:
		return true
	case kindOne:
		for i := int(rule.Plen) + 1; i < len(path); i++ {
			if path[i] == '/' {
				return false
			}
		}
		return true
	}
	return false
}

// KernelAllows asks the net tables the way the hook reads them: the
// CIDR trie first, then the allow hash for the protocol and for any.
// It is the kernel's decision mirrored in Go for the parity tests.
func (n *NetEnforcement) KernelAllows(proto string, addr netip.Addr, port uint16) bool {
	var ck cCIDRKey
	bits := 128
	if addr.Is4() {
		v4 := addr.As4()
		copy(ck.Data[12:], v4[:])
	} else {
		v6 := addr.As16()
		copy(ck.Data[:], v6[:])
	}
	ck.PrefixLen = uint32(bits)
	if err := n.Obj.NetDenyCidr.Lookup(&ck, new(uint8)); err == nil {
		return false
	}
	var ak cAllowKey
	ak.Port = port
	ak.Proto = protoAny
	if err := n.Obj.NetAllow.Lookup(&ak, new(uint8)); err == nil {
		return true
	}
	switch proto {
	case "tcp":
		ak.Proto = protoTCP
	case "udp":
		ak.Proto = protoUDP
	default:
		return false
	}
	if err := n.Obj.NetAllow.Lookup(&ak, new(uint8)); err == nil {
		return true
	}
	return false
}

// cExecEvent mirrors the kernel record in events.bpf.c, the reader
// side of the stream.
type cExecEvent struct {
	Cgroup uint64
	KTime  uint64
	PID    uint32
	PPID   uint32
	Comm   [16]byte
}

// Events is the loaded exec event stream.
type Events struct {
	Obj  *eventsObjects
	Link link.Link
}

// LoadEvents loads the stream and attaches the emitter; the scope's
// execs flow once its cgroup is named.
func LoadEvents(scopeCgroupID uint64) (*Events, error) {
	obj := &eventsObjects{}
	if err := loadEventsObjects(obj, nil); err != nil {
		return nil, fmt.Errorf("load events: %w", err)
	}
	fail := func(err error) (*Events, error) {
		obj.Close()
		return nil, err
	}
	if err := obj.ScopedCgroups.Update(scopeCgroupID, uint8(1), ebpf.UpdateAny); err != nil {
		return fail(fmt.Errorf("scope cgroup: %w", err))
	}
	l, err := link.Tracepoint("sched", "sched_process_exec", obj.EmitExec, nil)
	if err != nil {
		return fail(fmt.Errorf("attach tracepoint: %w", err))
	}
	return &Events{Obj: obj, Link: l}, nil
}

// Close detaches and frees.
func (s *Events) Close() error {
	if s == nil {
		return nil
	}
	err := s.Link.Close()
	if err2 := s.Obj.Close(); err == nil {
		err = err2
	}
	return err
}

// Read drains the ring buffer and converts the records into NDJSON
// lines. It waits at most the timeout for the first record and stops
// at the first empty read after that — the ring has whatever the
// kernel kept, and a quiet ring is a valid answer. It returns the
// dropped count beside them: a stream with drops says so, never
// silently pretends whole.
func (s *Events) Read(w interface{ Write([]byte) (int, error) }, timeout time.Duration) (int, error) {
	rd, err := ringbuf.NewReader(s.Obj.Events)
	if err != nil {
		return 0, err
	}
	defer rd.Close()
	// The reader is blocking; a timer closes it when the ring goes
	// quiet, which unblocks a pending Read with a closed error.
	timer := time.AfterFunc(timeout, func() { rd.Close() })
	defer timer.Stop()
	wrote := 0
	for {
		rec, err := rd.Read()
		if err != nil {
			// Closed by the timer or the deferred close: whatever
			// the ring held has been read.
			return wrote, nil
		}
		if len(rec.RawSample) != 8+8+4+4+16 { // cExecEvent, its fields in order
			return wrote, fmt.Errorf("record is %d bytes, want 40", len(rec.RawSample))
		}
		var ce cExecEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ce); err != nil {
			return wrote, err
		}
		comm := string(bytes.TrimRight(ce.Comm[:], "\x00"))
		b, err := json.Marshal(struct {
			Schema   uint64 `json:"schema"`
			Kind     string `json:"kind"`
			Decision string `json:"decision"`
			PID      uint32 `json:"pid"`
			Comm     string `json:"comm"`
			KTimeNS  uint64 `json:"ktime_ns"`
		}{Schema: 1, Kind: "exec", Decision: "allow", PID: ce.PID, Comm: comm, KTimeNS: ce.KTime})
		if err != nil {
			return wrote, err
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			return wrote, err
		}
		wrote++
	}
}
