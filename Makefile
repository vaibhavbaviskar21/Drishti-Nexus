.PHONY: all build clean test run-tail run-analyze run-serve

# Build for current platform
all: build

build:
	@echo "Building Drishti Nexus..."
	@go build -ldflags="-s -w" -o drishti.exe .
	@echo "Build complete: drishti.exe"

# Build for multiple platforms
build-all:
	@echo "Building for Windows..."
	@GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/drishti-windows-amd64.exe .
	@echo "Building for Linux..."
	@GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/drishti-linux-amd64 .
	@echo "Building for macOS..."
	@GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o dist/drishti-darwin-amd64 .
	@echo "Cross-platform build complete"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -f drishti drishti.exe
	@rm -rf dist/
	@echo "Clean complete"

# Run tests
test:
	@echo "Running tests..."
	@go test ./... -v

# Install dependencies
deps:
	@echo "Downloading dependencies..."
	@go mod download
	@echo "Dependencies installed"

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Example commands
run-tail:
	@./drishti.exe tail test.log

run-analyze:
	@./drishti.exe analyze test.log

run-serve:
	@./drishti.exe serve -port 8080 -log test.log

help:
	@echo "Drishti Nexus - Makefile Commands"
	@echo ""
	@echo "  make build        - Build for current platform"
	@echo "  make build-all    - Build for Windows, Linux, macOS"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make test         - Run tests"
	@echo "  make deps         - Download dependencies"
	@echo "  make fmt          - Format code"
	@echo "  make run-tail     - Run tail command with test.log"
	@echo "  make run-analyze  - Run analyze command with test.log"
	@echo "  make run-serve    - Run web server with test.log"
