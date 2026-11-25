# Development targets. The runtime targets (bpf, image, install) come
# with the Linux side of the tree.

.PHONY: test fuzz vet fmt check

test:
	go test ./...

# 30 s over the parser; raise -fuzztime before a release.
fuzz:
	go test -run '^$$' -fuzz FuzzParse -fuzztime 30s ./internal/policy/

vet:
	go vet ./...

fmt:
	gofmt -l .

check: vet fmt test
