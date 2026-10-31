.PHONY: all build build-all clean test test-short datasets genbenign benchmark lint gosec fmt fmt-check ci deps help

BIN      := bin
PKG      := ./cmd/drishti
VERSION  ?= 1.1.0-dev
LDFLAGS  := -s -w -X drishti-nexus/internal/version.Version=$(VERSION)

all: build

## Build ────────────────────────────────────────────────────────────────────

build:
	@go build -ldflags="$(LDFLAGS)" -o $(BIN)/drishti$(if $(filter Windows_NT,$(OS)),.exe,) $(PKG)
	@echo "Built $(BIN)/drishti"

build-all:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/drishti-windows-amd64.exe $(PKG)
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/drishti-linux-amd64 $(PKG)
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/drishti-darwin-arm64 $(PKG)

clean:
	@rm -rf $(BIN) dist

deps:
	@go mod download

## Test data & benchmarks ───────────────────────────────────────────────────

# Public datasets (LogHub, OTRF/Mordor) → testdata/datasets/ (gitignored, checksum-pinned)
datasets:
	@bash scripts/fetch-datasets.sh

# Deterministic synthetic benign dataset → testdata/benign/auth_benign.log
genbenign:
	@go run ./cmd/genbenign

# Full benchmark suite → benchmarks/results/latest.json (numbers feed BASELINE.md)
benchmark: genbenign
	@go run ./cmd/benchmark -suite -out benchmarks/results/latest.json

## Quality gates ────────────────────────────────────────────────────────────

test: genbenign
	@go test -count=1 ./...

# Fixtures only; skips the large public datasets
test-short:
	@go test -short -count=1 ./...

fmt:
	@gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

# Install: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.5.0
lint:
	@golangci-lint run ./...

# Install: go install github.com/securego/gosec/v2/cmd/gosec@v2.22.8
gosec:
	@gosec -conf .gosec.json ./...

# Same gates as .github/workflows/ci.yml
ci: fmt-check test lint gosec
	@echo "CI checks passed."

help:
	@echo "make build | build-all | clean | deps"
	@echo "make datasets | genbenign | benchmark"
	@echo "make test | test-short | fmt | fmt-check | lint | gosec | ci"
