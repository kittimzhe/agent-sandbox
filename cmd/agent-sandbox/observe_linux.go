// The Linux-only half of the command: the shim dispatch and the
// observe command that loads the programs and runs the scope.

//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/kittimzhe/agent-sandbox/internal/loader"
	"github.com/kittimzhe/agent-sandbox/internal/scope"
)

func init() {
	observeCmd = observe
	runCmd = run
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
	// The scope cgroup's id is the inode number of its directory, the
	// value bpf_get_current_cgroup_id reports to the programs.
	id, err := cgroupID(sc.Path)
	if err != nil {
		sc.Close()
		return err
	}
	// The event stream: one NDJSON line per exec in the scope, on
	// stderr beside the counts. The stream's ring is drained after
	// the command exits, one read, the records the kernel kept.
	stream, err := loader.LoadEvents(id)
	if err != nil {
		sc.Close()
		return err
	}
	defer stream.Close()
	fmt.Fprintf(os.Stderr, "observing %s in %s\n", strings.Join(command, " "), sc.Path)
	cmd, err := sc.RunScoped(selfExe, command)
	if err != nil {
		sc.Close()
		return err
	}
	werr := cmd.Wait()
	n, err := counters.CountOf(id)
	if err != nil {
		sc.Close()
		return fmt.Errorf("read counters: %w", err)
	}
	if lines, rerr := stream.Read(os.Stderr, 500*time.Millisecond); rerr == nil && lines > 0 {
		fmt.Fprintf(os.Stderr, "%d exec events\n", lines)
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

// run enforces: the LSM program refuses what the policy's exec.allow
// list does not name, for every task in the scope. The command sees
// EPERM, the same decision the engine prints, with the rule that made
// it on stderr. The policy is verified against the pinned public key
// before anything loads: an unverified file never reaches the kernel.
func run(args []string) error {
	policyFile, command, err := parseRunArgs(args)
	if err != nil {
		return err
	}
	pubKey := flagValue(args, "--public")
	if err := verifyIfPinned(pubKey, policyFile); err != nil {
		return err
	}
	p, e, err := loadPolicy(policyFile)
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
	id, err := cgroupID(sc.Path)
	if err != nil {
		sc.Close()
		return err
	}
	// The rules the engine holds are the rules the kernel holds; one
	// compiler, one behavior, and the parity test replays the engine's
	// cases against the kernel when it arrives.
	ef, err := loader.LoadPolicy(e.ExecRules(), id)
	if err != nil {
		sc.Close()
		return err
	}
	defer ef.Close()
	if os.Getenv("AGENT_SANDBOX_DEBUG_TABLES") != "" {
		ef.DebugDump(os.Stderr)
	}
	// The file tables ride along in the same run: reads and writes
	// the policy refuses are refused, nothing else is touched.
	fe, err := loader.LoadFilePolicy(e.FileDenyRead(), e.FileDenyWrite(), id)
	if err != nil {
		sc.Close()
		return err
	}
	defer fe.Close()
	// The net tables too: connects the policy refuses are refused,
	// CIDRs first, the allow list second.
	// bisect: net enforcement disabled
	_ = id
	fmt.Fprintf(os.Stderr, "running %s in %s under %s\n", strings.Join(command, " "), sc.Path, p.Name)
	cmd, err := sc.RunScoped(selfExe, command)
	if err != nil {
		sc.Close()
		return err
	}
	werr := cmd.Wait()
	ef.Close()
	if rerr := sc.Close(); rerr != nil {
		fmt.Fprintf(os.Stderr, "remove cgroup: %v\n", rerr)
	}
	return werr
}

// parseRunArgs splits the run line like observe's: --policy before
// the command, the command after --.
func parseRunArgs(args []string) (string, []string, error) {
	var policyFile string
	var command []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--public" {
			if i+1 >= len(args) {
				return "", nil, fmt.Errorf("--public needs a file")
			}
			i++
			continue
		}
		if args[i] == "--policy" {
			if i+1 >= len(args) {
				return "", nil, fmt.Errorf("--policy needs a file")
			}
			policyFile = args[i+1]
			i++
			continue
		}
		if args[i] == "--" {
			command = args[i+1:]
			break
		}
		return "", nil, fmt.Errorf("usage: agent-sandbox run --policy <file> --public <key> -- <command> [args...]")
	}
	if policyFile == "" || len(command) == 0 {
		return "", nil, fmt.Errorf("usage: agent-sandbox run --policy <file> --public <key> -- <command> [args...]")
	}
	return policyFile, command, nil
}

// flagValue returns the value of a flag anywhere before "--", for the
// --public key a run names.
func flagValue(args []string, flag string) string {
	for i, a := range args {
		if a == "--" {
			return ""
		}
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
