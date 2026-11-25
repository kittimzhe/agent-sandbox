// Package event defines what the kernel programs report and how the
// user space side of the runtime writes it out.
//
// An event is one decision the sandbox made, or observed, about one
// syscall by a sandboxed task: the kind of access, the decision, the
// rule that made it, and the kernel-side facts that identify the task.
// The JSON form is one line per event (NDJSON), with snake_case keys
// and a schema version, so a consumer can tell old recordings from new
// ones before it parses the rest.
//
// Events come from the BPF ring buffer, where a record is a fixed
// layout chosen for the verifier rather than for a reader, so decoding
// lives beside the loader (Linux) and this package only defines the
// in-memory shape and the output. KTimeNS is the kernel's monotonic
// clock at the event, which orders events even when the wall clock
// steps; Received is the user space arrival time.
package event

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"
)

// Schema is the version of the JSON form of an event.
const Schema = 1

// Kind is the kind of access an event reports.
type Kind uint8

const (
	KindExec Kind = iota + 1
	KindFile
	KindNet
)

func (k Kind) String() string {
	switch k {
	case KindExec:
		return "exec"
	case KindFile:
		return "file"
	case KindNet:
		return "net"
	}
	return "kind" + strconv.Itoa(int(k))
}

// Decision is what the sandbox did with the access.
type Decision uint8

const (
	// DecisionAllow is an access the policy allows.
	DecisionAllow Decision = iota + 1
	// DecisionDeny is an access the policy refused: the syscall
	// returned EPERM and the task saw it.
	DecisionDeny
	// DecisionObserve is an access reported in observe mode, where
	// nothing is refused and the policy is dry-run against the traffic.
	DecisionObserve
)

func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "allow"
	case DecisionDeny:
		return "deny"
	case DecisionObserve:
		return "observe"
	}
	return "decision" + strconv.Itoa(int(d))
}

// Exec is a task calling execve.
type Exec struct {
	Binary string   `json:"binary"`
	Argv   []string `json:"argv"`
}

// File is a task opening a path.
type File struct {
	Path  string `json:"path"`
	Write bool   `json:"write"`
}

// Net is a task connecting out.
type Net struct {
	Proto string `json:"proto"`
	Addr  string `json:"addr"`
	Port  uint16 `json:"port"`
}

// Event is one reported access. Exactly one of Exec, File and Net is
// set, matching Kind.
type Event struct {
	Seq      uint64 // ring buffer record number, assigned by the loader
	Kind     Kind
	Decision Decision
	// Rule names the policy entry that decided, for a reader matching
	// events back to the policy they came from.
	Rule     string
	PID      uint32
	CgroupID uint64
	KTimeNS  uint64
	Received time.Time

	Exec *Exec `json:"exec,omitempty"`
	File *File `json:"file,omitempty"`
	Net  *Net  `json:"net,omitempty"`
}

// jsonEvent is the wire form; its fields are explicit so that a
// renamed Go field cannot silently change the format.
type jsonEvent struct {
	Schema   uint64    `json:"schema"`
	Seq      uint64    `json:"seq"`
	Kind     string    `json:"kind"`
	Decision string    `json:"decision"`
	Rule     string    `json:"rule,omitempty"`
	PID      uint32    `json:"pid"`
	CgroupID uint64    `json:"cgroup_id"`
	KTimeNS  uint64    `json:"ktime_ns"`
	Received time.Time `json:"received"`
	Exec     *Exec     `json:"exec,omitempty"`
	File     *File     `json:"file,omitempty"`
	Net      *Net      `json:"net,omitempty"`
}

func (e *Event) MarshalJSON() ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(jsonEvent{
		Schema:   Schema,
		Seq:      e.Seq,
		Kind:     e.Kind.String(),
		Decision: e.Decision.String(),
		Rule:     e.Rule,
		PID:      e.PID,
		CgroupID: e.CgroupID,
		KTimeNS:  e.KTimeNS,
		Received: e.Received,
		Exec:     e.Exec,
		File:     e.File,
		Net:      e.Net,
	})
}

func (e *Event) UnmarshalJSON(b []byte) error {
	var j jsonEvent
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	e.Seq = j.Seq
	e.Rule = j.Rule
	e.PID = j.PID
	e.CgroupID = j.CgroupID
	e.KTimeNS = j.KTimeNS
	e.Received = j.Received
	e.Exec = j.Exec
	e.File = j.File
	e.Net = j.Net
	switch j.Kind {
	case "exec":
		e.Kind = KindExec
	case "file":
		e.Kind = KindFile
	case "net":
		e.Kind = KindNet
	default:
		return fmt.Errorf("unknown kind %q", j.Kind)
	}
	switch j.Decision {
	case "allow":
		e.Decision = DecisionAllow
	case "deny":
		e.Decision = DecisionDeny
	case "observe":
		e.Decision = DecisionObserve
	default:
		return fmt.Errorf("unknown decision %q", j.Decision)
	}
	return e.validate()
}

func (e *Event) validate() error {
	if e.Kind == 0 {
		return fmt.Errorf("event kind is zero")
	}
	switch e.Kind {
	case KindExec:
		if e.Exec == nil {
			return fmt.Errorf("exec event without exec payload")
		}
		if e.File != nil || e.Net != nil {
			return fmt.Errorf("exec event with another payload")
		}
	case KindFile:
		if e.File == nil {
			return fmt.Errorf("file event without file payload")
		}
		if e.Exec != nil || e.Net != nil {
			return fmt.Errorf("file event with another payload")
		}
	case KindNet:
		if e.Net == nil {
			return fmt.Errorf("net event without net payload")
		}
		if e.Exec != nil || e.File != nil {
			return fmt.Errorf("net event with another payload")
		}
	}
	return nil
}

// WriteJSON writes one event as a line. It returns the bytes written
// so a caller can count them without another marshal.
func WriteJSON(w io.Writer, e *Event) error {
	b, err := e.MarshalJSON()
	if err != nil {
		return err
	}
	if _, err := w.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}
