package event

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var received = time.Unix(1_795_000_000, 123_000_000).UTC()

func execEvent() *Event {
	return &Event{
		Seq: 7, Kind: KindExec, Decision: DecisionDeny, Rule: "exec.allow[0]",
		PID: 4242, CgroupID: 99, KTimeNS: 1_795_000_000_000_000_123, Received: received,
		Exec: &Exec{Binary: "/bin/sh", Argv: []string{"sh", "-c", "curl", "evil"}},
	}
}

func TestJSONRoundTrip(t *testing.T) {
	for _, e := range []*Event{
		execEvent(),
		{Kind: KindFile, Decision: DecisionAllow, PID: 1, File: &File{Path: "/etc/hosts", Write: false}},
		{Kind: KindNet, Decision: DecisionObserve, Rule: "net.allow[1]", Net: &Net{Proto: "tcp", Addr: "10.0.0.9", Port: 443}},
	} {
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}
		var back Event
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		if back.Kind != e.Kind || back.Decision != e.Decision || back.PID != e.PID {
			t.Errorf("round trip lost fields: %+v -> %+v", e, &back)
		}
	}
}

func TestJSONShape(t *testing.T) {
	b, err := execEvent().MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatalf("the JSON is not an object: %v", err)
	}
	for _, key := range []string{"schema", "seq", "kind", "decision", "pid", "cgroup_id", "ktime_ns", "received", "exec"} {
		if _, ok := fields[key]; !ok {
			t.Errorf("JSON lacks %q: %s", key, b)
		}
	}
	if fields["kind"] != "exec" || fields["decision"] != "deny" {
		t.Errorf("kind/decision not spelled out: %s", b)
	}
	if v, _ := fields["schema"].(float64); v != Schema {
		t.Errorf("schema = %v, want %d", fields["schema"], Schema)
	}
	if _, ok := fields["file"]; ok {
		t.Errorf("exec event carries a file payload: %s", b)
	}
}

func TestWriteJSONIsNDJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, execEvent()); err != nil {
		t.Fatalf("WriteJSON() error = %v", err)
	}
	if err := WriteJSON(&buf, &Event{Kind: KindFile, Decision: DecisionAllow, PID: 2, File: &File{Path: "/x"}}); err != nil {
		t.Fatalf("WriteJSON() error = %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), buf.String())
	}
	for i, l := range lines {
		if !json.Valid([]byte(l)) {
			t.Errorf("line %d is not JSON: %q", i, l)
		}
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		e    Event
		want string
	}{
		{"zero kind", Event{}, "kind is zero"},
		{"exec without payload", Event{Kind: KindExec}, "without exec payload"},
		{"exec with net payload", Event{Kind: KindExec, Exec: &Exec{Binary: "/bin/ls"}, Net: &Net{Proto: "tcp"}}, "another payload"},
		{"file without payload", Event{Kind: KindFile, Exec: &Exec{}}, "without file payload"},
		{"net without payload", Event{Kind: KindNet, File: &File{}}, "without net payload"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := json.Marshal(&tc.e)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Marshal() error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestUnmarshalUnknowns(t *testing.T) {
	base := `{"schema":1,"kind":"exec","decision":"allow","pid":1,"exec":{"binary":"/bin/ls"}}`
	for _, bad := range []string{
		strings.Replace(base, `"exec"`, `"fork"`, 1),
		strings.Replace(base, `"allow"`, `"maybe"`, 1),
		strings.Replace(base, `"exec"`, `"file"`, 1),
	} {
		var e Event
		if err := json.Unmarshal([]byte(bad), &e); err == nil {
			t.Errorf("Unmarshal(%s) = nil error, want one", bad)
		}
	}
}

func TestKindDecisionStrings(t *testing.T) {
	if KindExec.String() != "exec" || KindNet.String() != "net" {
		t.Errorf("kind strings = %q, %q", KindExec, KindNet)
	}
	if DecisionAllow.String() != "allow" || DecisionObserve.String() != "observe" {
		t.Errorf("decision strings = %q, %q", DecisionAllow, DecisionObserve)
	}
	// Unknown values keep a readable spelling instead of the empty
	// string, so a recording from a newer schema degrades loudly.
	if Kind(9).String() == "" || Decision(9).String() == "" {
		t.Errorf("unknown kind/decision rendered empty")
	}
}
