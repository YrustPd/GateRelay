.PHONY: fmt fmt-check test vet build check-config check snapshot-release run

GORELEASER ?= goreleaser
CONFIG ?= config.example.yaml

fmt:
	gofmt -w ./cmd ./internal

fmt-check:
	test -z "$$(gofmt -l ./cmd ./internal)"

test:
	go test ./...

vet:
	go vet ./...

build:
	go build ./cmd/gaterelay

check-config:
	go run ./cmd/gaterelay -config $(CONFIG) -check-config

check: fmt-check test vet build check-config

snapshot-release:
	$(GORELEASER) release --snapshot --clean

run:
	go run ./cmd/gaterelay -config $(CONFIG)
