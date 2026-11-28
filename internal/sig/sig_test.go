package sig

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setup(t *testing.T) (priv, pub, policy string, data []byte) {
	t.Helper()
	dir := t.TempDir()
	priv = filepath.Join(dir, "sign.key")
	pub = filepath.Join(dir, "sign.pub")
	policy = filepath.Join(dir, "policy.yaml")
	data = []byte("name: demo\nscope:\n  cgroup: /x\nexec:\n  allow:\n    - /bin/*\n")
	if err := os.WriteFile(policy, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := GenerateKey(priv, pub, "default"); err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv, pub, policy, _ := setup(t)
	if err := Sign(priv, policy); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if err := Verify(pub, policy); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestVerifyFailsAfterEdit(t *testing.T) {
	priv, pub, policy, _ := setup(t)
	if err := Sign(priv, policy); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if err := os.WriteFile(policy, []byte("name: edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := Verify(pub, policy)
	if err == nil {
		t.Fatal("Verify() accepted an edited policy")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error = %q, want the mismatch wording", err)
	}
}

func TestVerifyUnsignedIsAnError(t *testing.T) {
	_, pub, policy, _ := setup(t)
	err := Verify(pub, policy)
	if err == nil {
		t.Fatal("Verify() accepted an unsigned policy")
	}
	if err != ErrUnsigned {
		t.Errorf("error = %v, want ErrUnsigned", err)
	}
}

func TestVerifyWithWrongKey(t *testing.T) {
	priv, _, policy, _ := setup(t)
	dir := t.TempDir()
	other := filepath.Join(dir, "other.pub")
	if err := GenerateKey(filepath.Join(dir, "other.key"), other, "default"); err != nil {
		t.Fatal(err)
	}
	if err := Sign(priv, policy); err != nil {
		t.Fatal(err)
	}
	if err := Verify(other, policy); err == nil {
		t.Fatal("Verify() accepted a signature from another key")
	}
}

func TestSignWithPublicKeyRefused(t *testing.T) {
	_, pub, policy, _ := setup(t)
	err := Sign(pub, policy)
	if err == nil {
		t.Fatal("Sign() accepted a public key")
	}
	if !strings.Contains(err.Error(), "private half") {
		t.Errorf("error = %q, want the public-key wording", err)
	}
}

func TestTamperedSignatureRefused(t *testing.T) {
	priv, pub, policy, _ := setup(t)
	if err := Sign(priv, policy); err != nil {
		t.Fatal(err)
	}
	sigPath := policy + ".sig"
	raw, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	var s Signature
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	b, err := base64.StdEncoding.DecodeString(s.Sig)
	if err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0xff // a flipped bit: still 64 bytes, no longer the signature
	s.Sig = base64.StdEncoding.EncodeToString(b)
	tampered, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(tampered, raw) {
		t.Fatal("the tampering changed nothing")
	}
	if err := os.WriteFile(sigPath, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, policy); err == nil {
		t.Fatal("Verify() accepted a tampered signature")
	}
}
