//go:build linux

package main

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

type cidrKey struct {
	PrefixLen uint32
	Data      [16]byte
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LPMTrie,
		KeySize:    4 + 16,
		ValueSize:  1,
		MaxEntries: 64,
		Flags:      0x1, // BPF_F_NO_PREALLOC, required by the trie
	})
	if err != nil {
		log.Fatal("create: ", err)
	}
	defer m.Close()

	store := cidrKey{PrefixLen: 128}
	copy(store.Data[12:], []byte{1, 1, 1, 1})
	if err := m.Update(&store, uint8(1), ebpf.UpdateAny); err != nil {
		log.Fatal("update: ", err)
	}

	probe := cidrKey{PrefixLen: 128}
	copy(probe.Data[12:], []byte{1, 1, 1, 1})
	var v uint8
	err = m.Lookup(&probe, &v)
	fmt.Printf("lookup same-struct: err=%v value=%d\n", err, v)

	// The exact bytes the BPF program constructs: prefixlen from
	// bits=128, data from a zeroed 16-byte array with sin_addr at
	// [12:16].
	var raw [20]byte
	raw[0] = 128 // little-endian prefixlen, single byte suffices
	raw[16], raw[17], raw[18], raw[19] = 1, 1, 1, 1
	err = m.Lookup(unsafeBytes(raw), &v)
	fmt.Printf("lookup raw-bytes:   err=%v value=%d\n", err, v)

	// A /32-in-v4 style: what a 32-bit prefixlen key would say.
	short := cidrKey{PrefixLen: 32}
	copy(short.Data[12:], []byte{1, 1, 1, 1})
	err = m.Lookup(&short, &v)
	fmt.Printf("lookup plen=32:     err=%v value=%d\n", err, v)
}

func unsafeBytes(b [20]byte) *[20]byte { return &b }
