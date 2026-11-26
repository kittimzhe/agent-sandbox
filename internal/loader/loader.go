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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf -cflags "-mcpu=v4 -O2 -g -I../../bpf" count_exec ../../bpf/count_exec.bpf.c

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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
