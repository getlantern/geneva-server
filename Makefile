# geneva-server — build, test, and e2e targets.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: build test test-race bench bench-e2e vet lint e2e docker package clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/geneva-server ./cmd/geneva-server

# Unit + packet-level tests. Root-gated integration tests (real nftables) run
# only when invoked as root; otherwise they self-skip.
test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

# Per-packet cost of the engine, with no kernel in the loop. The fastest signal
# when changing the hot path; run bench-e2e for the number that includes NFQUEUE.
bench:
	go test ./internal/engine/ ./internal/nfqueue/ -run '^$$' -bench . -benchmem

# Full data-plane benchmark over docker networking: throughput and sidecar CPU
# per GiB across every sidecar state. Args: GiB per condition, concurrent
# streams.
bench-e2e:
	./bench/run.sh $(GIB) $(STREAMS)

# Full e2e over docker networking (requires docker + a netfilter-capable kernel).
e2e:
	./e2e/run.sh

docker:
	docker build -t geneva-server:$(VERSION) --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) .

# Build the release .deb locally, exactly as the release workflow does, without
# publishing. Useful for checking the package's contents, dependencies and
# maintainer scripts before tagging.
package:
	goreleaser release --snapshot --clean --skip=publish

clean:
	rm -rf bin dist
