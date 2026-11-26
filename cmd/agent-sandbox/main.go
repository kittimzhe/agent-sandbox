// Command agent-sandbox runs a sandboxed process tree under a policy.
//
// validate and decide run anywhere; observe loads the BPF programs and
// watches a command under the policy's scope, on a Linux host with a
// BPF-capable kernel; run, which enforces, is M1.
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
      (M1) Run a command under the policy, enforced by the kernel.

  agent-sandbox observe --policy <file> -- <command> [args...]
      (Linux) Run a command under the policy's scope with the kernel
      watching: the exec counts of the scope, no enforcement yet.
`

// The Linux build replaces both: observeCmd with the real observe,
// scopeShim with the shim dispatch. A darwin build keeps the stubs, so
// validate and decide still build and run on a development host.
var (
	observeCmd = func(args []string) error {
		return fmt.Errorf("observe needs a Linux host with a BPF kernel")
	}
	runCmd = func(args []string) error {
		return fmt.Errorf("run needs a Linux host with a BPF kernel")
	}
	scopeShim = func(argv []string) (bool, error) { return false, nil }
)

func main() {
	// The scope shim runs before anything else: it exists only to
	// move itself into a cgroup and exec the command.
	if handled, err := scopeShim(os.Args[1:]); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(126)
		}
		return // unreachable: the shim execs
	}
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
	case "observe":
		err = observeCmd(os.Args[2:])
	case "run":
		err = runCmd(os.Args[2:])
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

// request is one access to decide, parsed from the command line.
type request struct {
	kind  string // "exec", "file" or "net"
	path  string // exec and file
	write bool   // file
	proto string // net, lower case
	addr  netip.Addr
	port  uint16
}

// parseDecideArgs splits the decide command line into the policy file
// and the access it names.
func parseDecideArgs(args []string) (string, request, error) {
	rest := args
	var file string
	for len(rest) > 0 {
		if rest[0] != "--policy" {
			break
		}
		if len(rest) < 2 {
			return "", request{}, fmt.Errorf("--policy needs a file")
		}
		file, rest = rest[1], rest[2:]
	}
	if file == "" {
		return "", request{}, fmt.Errorf("usage: agent-sandbox decide --policy <file> exec|file|net ...")
	}
	if len(rest) == 0 {
		return "", request{}, fmt.Errorf("what to decide: exec <path> | file <path> [read|write] | net <proto> <addr> <port>")
	}
	req := request{kind: rest[0]}
	switch req.kind {
	case "exec":
		if len(rest) != 2 {
			return "", request{}, fmt.Errorf("usage: decide --policy <file> exec <path>")
		}
		req.path = rest[1]
	case "file":
		if len(rest) < 2 || len(rest) > 3 {
			return "", request{}, fmt.Errorf("usage: decide --policy <file> file <path> [read|write]")
		}
		req.path = rest[1]
		if len(rest) == 3 {
			if rest[2] != "read" && rest[2] != "write" {
				return "", request{}, fmt.Errorf("mode %q is read or write", rest[2])
			}
			req.write = rest[2] == "write"
		}
	case "net":
		if len(rest) != 4 {
			return "", request{}, fmt.Errorf("usage: decide --policy <file> net <proto> <addr> <port>")
		}
		addr, err := netip.ParseAddr(rest[2])
		if err != nil {
			return "", request{}, fmt.Errorf("bad address %q: %w", rest[2], err)
		}
		port, err := strconv.ParseUint(rest[3], 10, 16)
		if err != nil {
			return "", request{}, fmt.Errorf("bad port %q", rest[3])
		}
		req.proto = strings.ToLower(rest[1])
		req.addr = addr
		req.port = uint16(port)
	default:
		return "", request{}, fmt.Errorf("unknown access kind %q, want exec, file or net", req.kind)
	}
	return file, req, nil
}

// decide prints the decision for one access as JSON, so a script or a
// test harness consumes it without parsing prose.
func decide(args []string) error {
	file, req, err := parseDecideArgs(args)
	if err != nil {
		return err
	}
	_, e, err := loadPolicy(file)
	if err != nil {
		return err
	}
	var v decision.Verdict
	switch req.kind {
	case "exec":
		v = e.Exec(req.path)
	case "file":
		v = e.File(req.path, req.write)
	case "net":
		v = e.Net(req.proto, req.addr, req.port)
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
