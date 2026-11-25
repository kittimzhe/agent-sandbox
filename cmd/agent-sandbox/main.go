// Command agent-sandbox runs a sandboxed process tree under a policy.
//
// Today it validates a policy file; run and observe need a Linux host
// with a BPF kernel and are not implemented yet.
package main

import (
	"fmt"
	"os"

	"github.com/kittimzhe/agent-sandbox/internal/match"
	"github.com/kittimzhe/agent-sandbox/internal/policy"
)

const usage = `agent-sandbox — an eBPF sandbox for AI agent processes

Usage:

  agent-sandbox validate <policy-file>
      Check a policy file: parse it and compile every path pattern.

  agent-sandbox run --policy <file> -- <command> [args...]
      (Linux, not implemented yet) Run a command under the policy.

  agent-sandbox observe --policy <file> -- <command> [args...]
      (Linux, not implemented yet) Run with the policy dry-run.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "validate":
		err = validate(os.Args[2:])
	case "run", "observe":
		fmt.Fprintf(os.Stderr, "%s needs a Linux host with a BPF kernel; it is not implemented yet\n", os.Args[1])
		os.Exit(2)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// summary counts the rules a policy compiles to.
type summary struct {
	execAllow, fileDenyRead, fileDenyWrite, netAllow, netDenyCIDR int
}

func validate(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: agent-sandbox validate <policy-file>")
	}
	file := args[0]
	text, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	p, err := policy.Parse(string(text))
	if err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	s, err := compilePatterns(p)
	if err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	fmt.Printf("%s: %d exec allow, %d file deny_read, %d file deny_write, %d net allow, %d net deny_cidr; every pattern compiles to a prefix rule\n",
		p.Name, s.execAllow, s.fileDenyRead, s.fileDenyWrite, s.netAllow, s.netDenyCIDR)
	return nil
}

func compilePatterns(p *policy.Policy) (summary, error) {
	s := summary{}
	for _, pattern := range p.Exec.Allow {
		if _, err := match.Compile(pattern); err != nil {
			return s, fmt.Errorf("exec.allow %q: %w", pattern, err)
		}
		s.execAllow++
	}
	for _, list := range []struct {
		name     string
		patterns []string
		count    *int
	}{
		{"file.deny_read", p.File.DenyRead, &s.fileDenyRead},
		{"file.deny_write", p.File.DenyWrite, &s.fileDenyWrite},
	} {
		for _, pattern := range list.patterns {
			if _, err := match.Compile(pattern); err != nil {
				return s, fmt.Errorf("%s %q: %w", list.name, pattern, err)
			}
			*list.count++
		}
	}
	s.netAllow = len(p.Net.Allow)
	s.netDenyCIDR = len(p.Net.DenyCIDR)
	return s, nil
}
