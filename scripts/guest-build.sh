#!/bin/sh
# scripts/guest-build.sh -- build, vet and test inside the dev VM.
#
# The project share is read-only from the guest, so the tree is copied
# to the guest's home first and built there: go generate needs to write
# the bpf2go output beside the loader, and the module cache lives in
# the guest. Run from the share inside the VM:
#
#   sh scripts/guest-build.sh
set -eu

dest="$HOME/build"
rm -rf "$dest"
mkdir -p "$dest"
# The git metadata stays behind; vmlinux.h comes along, the compile
# reads it.
tar --exclude=.git -cf - . | tar -xf - -C "$dest"

cd "$dest"
export CGO_ENABLED=0
go generate ./...
go vet ./...
go build ./...
go test ./...

# The binary comes out for limactl cp.
go build -o "$dest/agent-sandbox" ./cmd/agent-sandbox
ls -la "$dest/agent-sandbox"
