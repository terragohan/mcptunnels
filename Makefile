# Binaries go to ./dist (already git-ignored; same layout as the release workflow).

.PHONY: build test lint e2e clean

build:
	go build -o dist/tunneld ./cmd/tunneld
	go build -o dist/mcptunnel ./cmd/mcptunnel

test:
	go test ./... -count=1

# Binary-level end-to-end test: builds both binaries, runs tunneld + mcptunnel
# against a fake upstream (uses ports 8765/8799 on localhost).
e2e:
	bash scripts/e2e.sh

lint:
	go vet ./...
	@test -z "$$(gofmt -l .)"

clean:
	rm -rf dist
