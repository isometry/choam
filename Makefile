.PHONY: build test test-short test-race test-coverage test-coverage-detailed test-package clean install lint fmt deps help

# Build the binary
build:
	go build -o choam ./main.go

# Run all tests
test:
	go test -v ./...

# Run tests with short mode (skip slow tests)
test-short:
	go test -short -v ./...

# Run tests with race detector
test-race:
	go test -race -short ./...

# Run tests with coverage
test-coverage:
	go test -v -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run tests with detailed coverage output
test-coverage-detailed:
	go test -v -coverprofile=coverage.out -covermode=atomic ./...
	@echo "\n=== Coverage by Package ==="
	@go tool cover -func=coverage.out
	@echo "\n=== Total Coverage ==="
	@go tool cover -func=coverage.out | grep total | awk '{print "Total: " $$3}'
	go tool cover -html=coverage.out -o coverage.html
	@echo "HTML report: coverage.html"

# Run tests for a specific package
test-package:
	@if [ -z "$(PKG)" ]; then \
		echo "Usage: make test-package PKG=internal/scan"; \
		exit 1; \
	fi
	go test -v ./$(PKG)/...

# Clean build artifacts
clean:
	rm -f choam coverage.out coverage.html

# Install dependencies
deps:
	go mod download
	go mod tidy

# Format code
fmt:
	go fmt ./...

# Lint code (requires golangci-lint)
lint:
	golangci-lint run

# Install the binary
install:
	go install

# Help
help:
	@echo "Available targets:"
	@echo "  build                  Build the choam binary"
	@echo "  test                   Run all tests"
	@echo "  test-short             Run tests with short mode (skip slow tests)"
	@echo "  test-race              Run tests with race detector"
	@echo "  test-coverage          Run tests with coverage report"
	@echo "  test-coverage-detailed Run tests with detailed coverage breakdown"
	@echo "  test-package           Run tests for specific package (PKG=path)"
	@echo "  clean                  Clean build artifacts"
	@echo "  deps                   Download and tidy dependencies"
	@echo "  fmt                    Format code"
	@echo "  lint                   Lint code (requires golangci-lint)"
	@echo "  install                Install the binary"
	@echo "  help                   Show this help message"
