.PHONY: build test clean install lint fmt

# Build the binary
build:
	go build -o choam cmd/choam/main.go

# Run tests
test:
	go test -v ./...

# Run tests with coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

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
	go install cmd/choam/main.go

# Run example checks
example:
	./choam check --dry-run examples/

# Help
help:
	@echo "Available targets:"
	@echo "  build         Build the choam binary"
	@echo "  test          Run all tests"
	@echo "  test-coverage Run tests with coverage report"
	@echo "  clean         Clean build artifacts"
	@echo "  deps          Download and tidy dependencies"
	@echo "  fmt           Format code"
	@echo "  lint          Lint code (requires golangci-lint)"
	@echo "  install       Install the binary"
	@echo "  example       Run example with dry-run"
	@echo "  help          Show this help message"
