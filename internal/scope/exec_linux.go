//go:build linux

package scope

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// ScopeMarker is the argv[1] that tells a fresh agent-sandbox process
// it is a scope shim: it moves itself into the cgroup named in the
// environment and execs the command that follows. Only the shim does
// the move, and it does it before the exec, so the command and every
// child it spawns are born inside the scope.
const ScopeMarker = "--agent-sandbox-scope-shim--"

// CgroupEnv is the environment variable that carries the cgroup path
// into the shim.
const CgroupEnv = "AGENT_SANDBOX_CGROUP"

// RunScoped starts the command inside the scope. The runtime stays
// alive as the parent: it waits for the shim, which has already
// entered the cgroup by the time the command execs, so there is no
// window where the command runs outside.
func (s *Scope) RunScoped(selfExe string, args []string) (*exec.Cmd, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command to run")
	}
	if args[0] == ScopeMarker {
		return nil, fmt.Errorf("the command must not be the scope shim")
	}
	cmd := exec.Command(selfExe, append([]string{ScopeMarker, s.Path}, args...)...)
	cmd.Env = append(os.Environ(), CgroupEnv+"="+s.Path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", args[0], err)
	}
	return cmd, nil
}

// RunShim is what main calls when argv[1] is the marker: move into
// the cgroup and exec the command. It returns only on error, and the
// error is printed by the caller before a nonzero exit.
func RunShim(argv []string) error {
	if len(argv) < 3 {
		return fmt.Errorf("shim: expected <cgroup> <command> [args...]")
	}
	cgroup := argv[1]
	if cgroup != os.Getenv(CgroupEnv) {
		return fmt.Errorf("shim: cgroup argument does not match the environment")
	}
	pid := os.Getpid()
	if err := os.WriteFile(cgroup+"/cgroup.procs", []byte(fmt.Sprint(pid)), 0o644); err != nil {
		return fmt.Errorf("shim: enter cgroup: %w", err)
	}
	command := argv[2:]
	return syscall.Exec(command[0], command, os.Environ())
}
