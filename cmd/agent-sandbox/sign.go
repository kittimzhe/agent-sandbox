package main

import (
	"fmt"

	"github.com/kittimzhe/agent-sandbox/internal/sig"
)

// signCmd writes the detached signature of a policy file. Platform
// neutral: signing happens on the operator host, whatever it runs.
func signCmd(args []string) error {
	var key, file string
	for i := 0; i < len(args); i++ {
		if args[i] == "--key" {
			if i+1 >= len(args) {
				return fmt.Errorf("--key needs a file")
			}
			key = args[i+1]
			i++
			continue
		}
		if file != "" {
			return fmt.Errorf("usage: agent-sandbox sign --key <private-key> <policy-file>")
		}
		file = args[i]
	}
	if key == "" || file == "" {
		return fmt.Errorf("usage: agent-sandbox sign --key <private-key> <policy-file>")
	}
	if err := sig.Sign(key, file); err != nil {
		return err
	}
	fmt.Printf("signed %s -> %s.sig\n", file, file)
	return nil
}

// keysCmd makes the signing keypair. Platform neutral, same as sign.
func keysCmd(args []string) error {
	if len(args) == 0 || args[0] != "generate" {
		return fmt.Errorf("usage: agent-sandbox keys generate --private <file> --public <file>")
	}
	var priv, pub string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--private":
			if i+1 >= len(args) {
				return fmt.Errorf("--private needs a file")
			}
			priv = args[i+1]
			i++
		case "--public":
			if i+1 >= len(args) {
				return fmt.Errorf("--public needs a file")
			}
			pub = args[i+1]
			i++
		default:
			return fmt.Errorf("unknown argument %q", args[i])
		}
	}
	if priv == "" || pub == "" {
		return fmt.Errorf("keys generate needs --private and --public")
	}
	if err := sig.GenerateKey(priv, pub, "default"); err != nil {
		return err
	}
	fmt.Printf("wrote %s (keep it private) and %s (pin this in the runtime)\n", priv, pub)
	return nil
}

// verifyIfPinned checks the policy's signature when a public key was
// given; without one it refuses, so enforcement never runs on an
// unverified file by accident.
func verifyIfPinned(pub, policyFile string) error {
	if pub == "" {
		return fmt.Errorf("--public is required: the policy is what the kernel enforces, and it is verified against the key that signed it")
	}
	return sig.Verify(pub, policyFile)
}
