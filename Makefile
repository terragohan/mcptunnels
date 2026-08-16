# Binaries go to ./dist (already git-ignored; same layout as the release workflow).

.PHONY: build test lint clean

build:
	go build -o dist/tunneld ./cmd/tunneld
	go build -o dist/mcptunnel ./cmd/mcptunnel

test:
	go test ./... -count=1

lint:
	go vet ./...
	@test -z "$$(gofmt -l .)"

clean:
	rm -rf dist
