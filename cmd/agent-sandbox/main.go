// Command agent-sandbox runs a sandboxed process tree under a policy.
//
// Today it validates a policy file and prints the decision for one
// access; run and observe need a Linux host with a BPF kernel and are
// not implemented yet.
package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/kittimzhe/agent-sandbox/internal/decision"
	"github.com/kittimzhe/agent-sandbox/internal/policy"
)

const usage = `agent-sandbox — an eBPF sandbox for AI agent processes

Usage:

  agent-sandbox validate <policy-file>
      Check a policy file: parse it and compile every path pattern.

  agent-sandbox decide --policy <file> exec <path>
  agent-sandbox decide --policy <file> file <path> [read|write]
  agent-sandbox decide --policy <file> net <proto> <addr> <port>
      Print the decision the policy makes for one access, and the rule
      that made it. The dry-run of observe mode, on any host.

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
	case "decide":
		err = decide(os.Args[2:])
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

// loadPolicy reads, parses and compiles a policy file.
func loadPolicy(file string) (*policy.Policy, *decision.Engine, error) {
	text, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, err
	}
	p, err := policy.Parse(string(text))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", file, err)
	}
	e, err := decision.New(p)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", file, err)
	}
	return p, e, nil
}

func validate(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: agent-sandbox validate <policy-file>")
	}
	p, _, err := loadPolicy(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("%s: %d exec allow, %d file deny_read, %d file deny_write, %d net allow, %d net deny_cidr; every pattern compiles to a prefix rule\n",
		p.Name, len(p.Exec.Allow), len(p.File.DenyRead), len(p.File.DenyWrite), len(p.Net.Allow), len(p.Net.DenyCIDR))
	return nil
}

// decide prints the decision for one access as JSON, so a script or a
// test harness consumes it without parsing prose.
func decide(args []string) error {
	rest := args
	var file string
	for len(rest) > 0 {
		if rest[0] != "--policy" {
			break
		}
		if len(rest) < 2 {
			return fmt.Errorf("--policy needs a file")
		}
		file, rest = rest[1], rest[2:]
	}
	if file == "" {
		return fmt.Errorf("usage: agent-sandbox decide --policy <file> exec|file|net ...")
	}
	_, e, err := loadPolicy(file)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return fmt.Errorf("what to decide: exec <path> | file <path> [read|write] | net <proto> <addr> <port>")
	}
	var v decision.Verdict
	switch rest[0] {
	case "exec":
		if len(rest) != 2 {
			return fmt.Errorf("usage: decide --policy <file> exec <path>")
		}
		v = e.Exec(rest[1])
	case "file":
		if len(rest) < 2 || len(rest) > 3 {
			return fmt.Errorf("usage: decide --policy <file> file <path> [read|write]")
		}
		write := len(rest) == 3 && rest[2] == "write"
		if len(rest) == 3 && rest[2] != "write" && rest[2] != "read" {
			return fmt.Errorf("mode %q is read or write", rest[2])
		}
		v = e.File(rest[1], write)
	case "net":
		if len(rest) != 4 {
			return fmt.Errorf("usage: decide --policy <file> net <proto> <addr> <port>")
		}
		addr, err := netip.ParseAddr(rest[2])
		if err != nil {
			return fmt.Errorf("bad address %q: %w", rest[2], err)
		}
		port, err := strconv.ParseUint(rest[3], 10, 16)
		if err != nil {
			return fmt.Errorf("bad port %q", rest[3])
		}
		v = e.Net(strings.ToLower(rest[1]), addr, uint16(port))
	default:
		return fmt.Errorf("unknown access kind %q, want exec, file or net", rest[0])
	}
	verdict := struct {
		Allowed bool   `json:"allowed"`
		Rule    string `json:"rule"`
	}{Allowed: v.Allowed, Rule: v.Rule}
	b, err := json.Marshal(verdict)
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	if !v.Allowed {
		os.Exit(1)
	}
	return nil
}
