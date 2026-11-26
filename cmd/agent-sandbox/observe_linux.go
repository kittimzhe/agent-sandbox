// The Linux-only half of the command: the shim dispatch and the
// observe command that loads the programs and runs the scope.

//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/kittimzhe/agent-sandbox/internal/loader"
	"github.com/kittimzhe/agent-sandbox/internal/scope"
)

func init() {
	observeCmd = observe
	scopeShim = shimDispatch
}

// shimDispatch handles the scope shim's argv, if this process is one.
func shimDispatch(argv []string) (bool, error) {
	if len(argv) == 0 || argv[0] != scope.ScopeMarker {
		return false, nil
	}
	return true, scope.RunShim(argv)
}

// observe runs a command under the policy's scope with the kernel
// observing: the BPF programs report what happens, the decisions are
// printed as they would be, but nothing is enforced yet.
func observe(args []string) error {
	var policyFile string
	var command []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--policy" {
			if i+1 >= len(args) {
				return fmt.Errorf("--policy needs a file")
			}
			policyFile = args[i+1]
			i++
			continue
		}
		if args[i] == "--" {
			command = args[i+1:]
			break
		}
		return fmt.Errorf("usage: agent-sandbox observe --policy <file> -- <command> [args...]")
	}
	if policyFile == "" || len(command) == 0 {
		return fmt.Errorf("usage: agent-sandbox observe --policy <file> -- <command> [args...]")
	}
	p, _, err := loadPolicy(policyFile)
	if err != nil {
		return err
	}
	counters, err := loader.LoadCounters()
	if err != nil {
		return err
	}
	defer counters.Close()
	sc, err := scope.Open(p.Scope.Cgroup)
	if err != nil {
		return err
	}
	selfExe, err := os.Executable()
	if err != nil {
		sc.Close()
		return err
	}
	fmt.Fprintf(os.Stderr, "observing %s in %s\n", strings.Join(command, " "), sc.Path)
	cmd, err := sc.RunScoped(selfExe, command)
	if err != nil {
		sc.Close()
		return err
	}
	// The scope cgroup's id is the inode number of its directory, the
	// value bpf_get_current_cgroup_id reports to the programs.
	id, err := cgroupID(sc.Path)
	if err != nil {
		cmd.Wait()
		sc.Close()
		return err
	}
	werr := cmd.Wait()
	n, err := counters.CountOf(id)
	if err != nil {
		sc.Close()
		return fmt.Errorf("read counters: %w", err)
	}
	if rerr := sc.Close(); rerr != nil {
		fmt.Fprintf(os.Stderr, "remove cgroup: %v\n", rerr)
	}
	// While the map is still open, name every key it holds: an empty
	// or unexpected key says the hook did not fire where the scope
	// expected it to.
	if all, derr := counters.Counts(); derr == nil {
		fmt.Fprintf(os.Stderr, "map: %v (scope id %d)\n", all, id)
	}
	fmt.Fprintf(os.Stderr, "%d execs in the scope\n", n)
	return werr
}

// cgroupID reads the cgroup's id as the kernel's cgroup id: the inode
// number of the cgroup directory in the v2 filesystem.
func cgroupID(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("stat cgroup: %w", err)
	}
	return st.Ino, nil
}
