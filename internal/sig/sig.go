// Package sig signs and verifies policy files.
//
// A policy is an instruction to the kernel: what a process tree may
// do. Whoever edits it changes what the sandbox enforces, so the
// runtime checks that the file it loads is the file its operator
// signed. The scheme is one detached signature per policy: the
// operator signs the exact bytes with an Ed25519 key, and `run` and
// `observe` verify those bytes against the public key pinned in their
// configuration before a single rule reaches the kernel.
//
// What this is honest about: the check is user space, and the runtime
// itself is not covered. It stops a policy that was edited in transit
// or by mistake — the common case, an operator's script or a CI job
// that touched the file — and says nothing about root, who can change
// the runtime, the key, or the kernel. shirudo closes that boundary
// with kernel patches, a sealed keyring and a TPM; that is a
// different product, and this is not it.
package sig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Signature is one detached signature over the policy's exact bytes.
type Signature struct {
	// KeyID names the key that signed, so an operator with more
	// than one can tell them apart at a glance.
	KeyID string `json:"key_id"`
	// Sig is the base64 Ed25519 signature over the file's bytes.
	Sig string `json:"sig"`
}

// GenerateKey makes a keypair and writes the private and the public
// halves as base64 text files. The private half signs; the public
// half is what a runtime pins.
func GenerateKey(privPath, pubPath, keyID string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}
	if err := os.WriteFile(privPath, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
		return err
	}
	return os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(pub)), 0o644)
}

func readKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(trimSpace(b))
	if err != nil {
		return nil, fmt.Errorf("%s: bad key encoding: %w", path, err)
	}
	if len(raw) != ed25519.PublicKeySize && len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s: %d bytes, want an Ed25519 public (%d) or private (%d) key", path, len(raw), ed25519.PublicKeySize, ed25519.PrivateKeySize)
	}
	return raw, nil
}

func trimSpace(b []byte) string {
	out := b
	for len(out) > 0 && (out[len(out)-1] == '\n' || out[len(out)-1] == '\r' || out[len(out)-1] == ' ' || out[len(out)-1] == '\t') {
		out = out[:len(out)-1]
	}
	for len(out) > 0 && (out[0] == '\n' || out[0] == '\r' || out[0] == ' ' || out[0] == '\t') {
		out = out[1:]
	}
	return string(out)
}

// Sign reads a policy file and writes its detached signature next to
// it: <path>.sig, JSON, with the key that signed named.
func Sign(privPath, policyPath string) error {
	privRaw, err := readKey(privPath)
	if err != nil {
		return err
	}
	if len(privRaw) != ed25519.PrivateKeySize {
		return fmt.Errorf("%s: is a public key; signing needs the private half", privPath)
	}
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ed25519.PrivateKey(privRaw), data)
	out, err := json.Marshal(Signature{
		KeyID: "default",
		Sig:   base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		return err
	}
	return os.WriteFile(policyPath+".sig", out, 0o644)
}

// ErrUnsigned is what a caller sees when the policy has no signature
// next to it. A missing signature is an error, never a pass: an
// unsigned policy looks exactly like a signed one until the day it
// matters.
var ErrUnsigned = errors.New("policy has no signature; sign it with agent-sandbox sign and pin the public key")

// Verify checks the signature beside a policy file against the pinned
// public key. The check is over the exact bytes on disk, so a policy
// edited after signing fails here.
func Verify(pubPath, policyPath string) error {
	pubRaw, err := readKey(pubPath)
	if err != nil {
		return err
	}
	if len(pubRaw) != ed25519.PublicKeySize {
		return fmt.Errorf("%s: is not a public key", pubPath)
	}
	sigRaw, err := os.ReadFile(policyPath + ".sig")
	if os.IsNotExist(err) {
		return ErrUnsigned
	}
	if err != nil {
		return err
	}
	var s Signature
	if err := json.Unmarshal(sigRaw, &s); err != nil {
		return fmt.Errorf("%s.sig: %w", policyPath, err)
	}
	sig, err := base64.StdEncoding.DecodeString(s.Sig)
	if err != nil {
		return fmt.Errorf("%s.sig: bad signature encoding: %w", policyPath, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%s.sig: %d bytes, want %d", policyPath, len(sig), ed25519.SignatureSize)
	}
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), data, sig) {
		return fmt.Errorf("%s: signature does not match the file; it was edited after signing, or signed by another key", policyPath)
	}
	return nil
}
