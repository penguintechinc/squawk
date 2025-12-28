# Squawk DNS Client (Go) Makefile
#
# Build targets for the Go DNS-over-HTTPS client

# Variables
APP_NAME = squawk-dns-client
VERSION ?= 1.0.0
BUILD_TIME = $(shell date -u +"%Y-%m-%d_%H:%M:%S")
GIT_COMMIT = $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go variables
GOFLAGS = -ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT)"
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

# Directories
BIN_DIR = bin
BUILD_DIR = build
SRC_DIR = cmd/$(APP_NAME)

# Default target
.PHONY: all
all: build

# Build the application
.PHONY: build
build: clean
	@echo "Building $(APP_NAME) v$(VERSION) for $(GOOS)/$(GOARCH)..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) -o $(BIN_DIR)/$(APP_NAME) ./$(SRC_DIR)
	@echo "Build complete: $(BIN_DIR)/$(APP_NAME)"

# Build for multiple platforms
.PHONY: build-all
build-all: clean
	@echo "Building $(APP_NAME) for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	
	# Linux
	@echo "Building for Linux/amd64..."
	@mkdir -p $(BUILD_DIR)/linux-amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $(BUILD_DIR)/linux-amd64/$(APP_NAME) ./$(SRC_DIR)
	
	@echo "Building for Linux/arm64..."
	@mkdir -p $(BUILD_DIR)/linux-arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -o $(BUILD_DIR)/linux-arm64/$(APP_NAME) ./$(SRC_DIR)
	
	# macOS
	@echo "Building for macOS/amd64..."
	@mkdir -p $(BUILD_DIR)/darwin-amd64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -o $(BUILD_DIR)/darwin-amd64/$(APP_NAME) ./$(SRC_DIR)
	
	@echo "Building for macOS/arm64..."
	@mkdir -p $(BUILD_DIR)/darwin-arm64
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -o $(BUILD_DIR)/darwin-arm64/$(APP_NAME) ./$(SRC_DIR)
	
	# Windows
	@echo "Building for Windows/amd64..."
	@mkdir -p $(BUILD_DIR)/windows-amd64
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o $(BUILD_DIR)/windows-amd64/$(APP_NAME).exe ./$(SRC_DIR)
	
	@echo "Build complete. Binaries available in $(BUILD_DIR)/"

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run linting
.PHONY: lint
lint:
	@echo "Running linter..."
	golangci-lint run

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Install the binary
.PHONY: install
install: build
	@echo "Installing $(APP_NAME)..."
	cp $(BIN_DIR)/$(APP_NAME) $(GOPATH)/bin/

# Uninstall the binary
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(APP_NAME)..."
	rm -f $(GOPATH)/bin/$(APP_NAME)

# Create release packages
.PHONY: package
package: build-all
	@echo "Creating release packages..."
	@mkdir -p $(BUILD_DIR)/packages
	
	# Linux packages
	cd $(BUILD_DIR)/linux-amd64 && tar -czf ../packages/$(APP_NAME)-$(VERSION)-linux-amd64.tar.gz $(APP_NAME)
	cd $(BUILD_DIR)/linux-arm64 && tar -czf ../packages/$(APP_NAME)-$(VERSION)-linux-arm64.tar.gz $(APP_NAME)
	
	# macOS packages  
	cd $(BUILD_DIR)/darwin-amd64 && tar -czf ../packages/$(APP_NAME)-$(VERSION)-darwin-amd64.tar.gz $(APP_NAME)
	cd $(BUILD_DIR)/darwin-arm64 && tar -czf ../packages/$(APP_NAME)-$(VERSION)-darwin-arm64.tar.gz $(APP_NAME)
	
	# Windows packages
	cd $(BUILD_DIR)/windows-amd64 && zip -q ../packages/$(APP_NAME)-$(VERSION)-windows-amd64.zip $(APP_NAME).exe
	
	@echo "Packages created in $(BUILD_DIR)/packages/"

# Run the application in development mode
.PHONY: run
run:
	@echo "Running $(APP_NAME) in development mode..."
	go run ./$(SRC_DIR) $(ARGS)

# Run with example configuration
.PHONY: run-example
run-example:
	@echo "Running with example configuration..."
	go run ./$(SRC_DIR) -d example.com -s https://dns.google/resolve -v

# Run forwarder example
.PHONY: run-forwarder
run-forwarder:
	@echo "Running DNS forwarder (requires sudo for port 53)..."
	sudo go run ./$(SRC_DIR) forward -s https://dns.google/resolve -v

# Generate example config
.PHONY: config-example
config-example:
	@echo "Generating example configuration..."
	go run ./$(SRC_DIR) config generate squawk-client.yaml
	@echo "Example configuration created: squawk-client.yaml"

# Security scan
.PHONY: security
security:
	@echo "Running security scan..."
	gosec ./...

# Benchmark tests
.PHONY: bench
bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Show help
.PHONY: help
help:
	@echo "Squawk DNS Client (Go) Build System"
	@echo "=================================="
	@echo ""
	@echo "Available targets:"
	@echo "  build         - Build for current platform"
	@echo "  build-all     - Build for all supported platforms"
	@echo "  deps          - Install dependencies"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  lint          - Run linter"
	@echo "  fmt           - Format code"
	@echo "  clean         - Clean build artifacts"
	@echo "  install       - Install binary to GOPATH"
	@echo "  uninstall     - Remove binary from GOPATH"
	@echo "  package       - Create release packages"
	@echo "  run           - Run in development mode"
	@echo "  run-example   - Run with example configuration"
	@echo "  run-forwarder - Run DNS forwarder (requires sudo)"
	@echo "  config-example- Generate example configuration"
	@echo "  security      - Run security scan"
	@echo "  bench         - Run benchmarks"
	@echo "  help          - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION       - Application version (default: $(VERSION))"
	@echo "  GOOS          - Target OS (default: $(GOOS))"
	@echo "  GOARCH        - Target architecture (default: $(GOARCH))"
	@echo "  ARGS          - Arguments for run target"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make build GOOS=linux GOARCH=amd64"
	@echo "  make run ARGS='-d example.com -s https://dns.google/resolve'"
	@echo "  make package VERSION=1.2.3"