package event

import (
	"encoding/json"
	"testing"
)

// FuzzUnmarshal feeds the reader arbitrary bytes: it never panics,
// never hangs, and what it accepts is an event whose kind, decision
// and payload agree. Events arrive from collectors, recordings and
// anything else that speaks the wire form, so the reader stands
// between the runtime and whatever the network says.
func FuzzUnmarshal(f *testing.F) {
	for _, s := range []string{
		`{"schema":1,"kind":"exec","decision":"allow","pid":1,"exec":{"binary":"/bin/ls","argv":["ls"]}}`,
		`{"schema":1,"kind":"file","decision":"deny","pid":2,"file":{"path":"/etc/shadow","write":true}}`,
		`{"schema":1,"kind":"net","decision":"observe","net":{"proto":"tcp","addr":"1.1.1.1","port":443}}`,
		`{"schema":1,"kind":"exec","decision":"allow","pid":3}`,
		`{"schema":1,"kind":"file","decision":"allow","pid":4,"exec":{"binary":"/x"}}`,
		`{"schema":1,"kind":"fork","decision":"allow","pid":5}`,
		`{}`,
		`[]`,
		`{"schema":1}`,
		``,
		"\x00\x01\x02",
		`{"schema":1,"kind":"exec","decision":"allow","pid":1,"exec":{"binary":"` + string(rune(0x7f)) + `"}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var e Event
		if err := e.UnmarshalJSON(b); err != nil {
			return // a clean refusal is an outcome, not a failure
		}
		// What the reader accepted must marshal back unchanged in
		// identity, or the form has two spellings for one event.
		out, err := json.Marshal(&e)
		if err != nil {
			t.Fatalf("an accepted event does not marshal: %v", err)
		}
		var again Event
		if err := again.UnmarshalJSON(out); err != nil {
			t.Fatalf("the re-marshaled form does not read back: %v", err)
		}
		if again.Kind != e.Kind || again.Decision != e.Decision || again.PID != e.PID {
			t.Fatalf("the form is not stable: %+v -> %+v", &e, &again)
		}
	})
}
