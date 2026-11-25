package defaults

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/kittimzhe/agent-sandbox/internal/decision"
	"github.com/kittimzhe/agent-sandbox/internal/policy"
)

// Every default must parse, compile, and decide the accesses its
// comment promises: the defaults are the fixture the engine's behavior
// is stated against, so a rule that cannot hold is a bug here, not in
// the operator's copy.
func TestDefaults(t *testing.T) {
	for name, text := range All {
		p, err := policy.Parse(text)
		if err != nil {
			t.Fatalf("%s: policy.Parse() error = %v", name, err)
		}
		if p.Name != name {
			t.Errorf("%s: Name = %q", name, p.Name)
		}
		e, err := decision.New(p)
		if err != nil {
			t.Fatalf("%s: decision.New() error = %v", name, err)
		}
		// Every default keeps the operator's keys and the cloud
		// metadata endpoint out.
		if v := e.File("/root/.ssh/id_ed25519", false); v.Allowed {
			t.Errorf("%s: /root/.ssh readable: %+v", name, v)
		}
		if !strings.Contains(e.Net("tcp", mustAddr(t, "169.254.169.254"), 443).Rule, "deny_cidr") {
			t.Errorf("%s: the metadata endpoint is not refused: %+v", name,
				e.Net("tcp", mustAddr(t, "169.254.169.254"), 443))
		}
		if v := e.Exec("/bin/ls"); !v.Allowed {
			t.Errorf("%s: /bin/ls refused: %+v", name, v)
		}
	}
}

// The names a user passes on the command line must match the map.
func TestNames(t *testing.T) {
	for _, name := range []string{"agent-web", "agent-dev", "agent-ci"} {
		if _, ok := All[name]; !ok {
			t.Errorf("All lacks %s", name)
		}
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad address %q: %v", s, err)
	}
	return addr
}
