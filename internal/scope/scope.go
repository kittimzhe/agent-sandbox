//go:build linux

package scope

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Scope is one cgroup v2 subtree the runtime sandboxes.
type Scope struct {
	// Path is the cgroup's absolute path in the host mount.
	Path string
	dir  *os.File
}

// Open creates the cgroup if it is not there and returns a handle.
// The caller holds it for the run and releases it with Close.
func Open(path string) (*Scope, error) {
	if !filepath.IsAbs(path) || strings.Contains(path, "..") {
		return nil, fmt.Errorf("cgroup path %q must be absolute without ..", path)
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, fmt.Errorf("create cgroup: %w", err)
	}
	// The controllers the children need are enabled by writing the
	// subtree control file; an empty one is fine for now, the kernel
	// programs scope by id, not by controller.
	return &Scope{Path: path}, nil
}

// Enter moves a process into the scope. The process is identified by
// its pid; a running command re-execs after the runtime writes its
// pid, so the exec happens inside.
func (s *Scope) Enter(pid int) error {
	procs := filepath.Join(s.Path, "cgroup.procs")
	if err := os.WriteFile(procs, []byte(fmt.Sprint(pid)), 0o644); err != nil {
		return fmt.Errorf("move pid %d into %s: %w", pid, s.Path, err)
	}
	return nil
}

// Close removes the cgroup. It fails if processes are still inside;
// a caller waits for its command first.
func (s *Scope) Close() error {
	return os.Remove(s.Path)
}
