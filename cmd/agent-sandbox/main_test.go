package main

import (
	"net/netip"
	"testing"
)

func TestParseDecideArgs(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		file    string
		request request
		wantErr string
	}{
		{
			name:    "exec",
			args:    []string{"--policy", "p.yaml", "exec", "/usr/bin/ls"},
			file:    "p.yaml",
			request: request{kind: "exec", path: "/usr/bin/ls"},
		},
		{
			name:    "file read defaults",
			args:    []string{"--policy", "p.yaml", "file", "/etc/hosts"},
			file:    "p.yaml",
			request: request{kind: "file", path: "/etc/hosts", write: false},
		},
		{
			name:    "file write",
			args:    []string{"--policy", "p.yaml", "file", "/etc/hosts", "write"},
			file:    "p.yaml",
			request: request{kind: "file", path: "/etc/hosts", write: true},
		},
		{
			name:    "net with proto case",
			args:    []string{"--policy", "p.yaml", "net", "TCP", "1.1.1.1", "443"},
			file:    "p.yaml",
			request: request{kind: "net", proto: "tcp", addr: netip.MustParseAddr("1.1.1.1"), port: 443},
		},
		{name: "missing policy", args: []string{"exec", "/x"}, wantErr: "usage"},
		{name: "policy without file", args: []string{"--policy"}, wantErr: "needs a file"},
		{name: "nothing to decide", args: []string{"--policy", "p.yaml"}, wantErr: "what to decide"},
		{name: "unknown kind", args: []string{"--policy", "p.yaml", "ptrace", "1"}, wantErr: "unknown access kind"},
		{name: "exec without path", args: []string{"--policy", "p.yaml", "exec"}, wantErr: "usage"},
		{name: "bad mode", args: []string{"--policy", "p.yaml", "file", "/x", "both"}, wantErr: "read or write"},
		{name: "bad address", args: []string{"--policy", "p.yaml", "net", "tcp", "not-an-addr", "443"}, wantErr: "bad address"},
		{name: "bad port", args: []string{"--policy", "p.yaml", "net", "tcp", "1.1.1.1", "https"}, wantErr: "bad port"},
		{name: "port out of range", args: []string{"--policy", "p.yaml", "net", "tcp", "1.1.1.1", "65536"}, wantErr: "bad port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file, req, err := parseDecideArgs(tc.args)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("parseDecideArgs(%v) = nil error, want %q", tc.args, tc.wantErr)
				}
				if !contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDecideArgs(%v) error = %v", tc.args, err)
			}
			if file != tc.file {
				t.Errorf("file = %q, want %q", file, tc.file)
			}
			if req.kind != tc.request.kind || req.path != tc.request.path ||
				req.write != tc.request.write || req.proto != tc.request.proto ||
				req.port != tc.request.port || req.addr != tc.request.addr {
				t.Errorf("request = %+v, want %+v", req, tc.request)
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
