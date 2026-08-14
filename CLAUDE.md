# CLAUDE.md

This file provides guidance to Claude Code when working with this codebase.

## Project Overview

CHOAM is a CLI tool for managing melange build specifications and securing software supply chains in the Chainguard/Wolfi ecosystem. It provides automated dependency updates and vulnerability scanning through a processor-based architecture.

**Core Capabilities:**
- Multi-source update detection (GitHub, Git, release-monitoring.org)
- Security vulnerability scanning with OSV database integration
- Pipeline-based updates with comment-preserving YAML processing
- Supply chain security for container-optimized Linux distributions

**Ecosystem Context:**
- **Melange**: APK package builder that CHOAM manages
- **Wolfi**: Container-optimized Linux distribution using CHOAM
- **OSV database (api.osv.dev)**: Vulnerability data source, queried via the official osv.dev Go bindings
- **omnibump**: Multi-ecosystem (Go/Rust/Java) dependency-bump tooling backing the `bump` command

## Architecture

**Core Layers:**
1. **CLI Layer** (`cmd/`, `main.go`): Cobra-based commands (check, update, bump — with `gobump` retained as an alias)
2. **Processor Layer** (`internal/processor/`): Modern processing architecture with pipeline stages
3. **Service Clients**: GitHub, Git, Anitya integrations with interface-based design
4. **Business Logic**: Update engine, multi-ecosystem bump system, YAML configuration

**Key Architectural Patterns:**
- **Processor Pattern**: Unified processing interface with extensible stage system
- **Interface Segregation**: Clean client interfaces in `internal/*/types.go`
- **Comment-Preserving YAML**: Maintains formatting, comments, and structure
- **Pipeline Composition**: Configurable pipelines (git-checkout, go/build, bump, go/bump)
- **Change Tracking**: Comprehensive tracking with rollback capabilities
- **Security-First Design**: Vulnerability scanning throughout update process

## Essential Navigation Map

### CLI Entry Points
- `main.go:10` - Application bootstrap (Execute command)
- `cmd/root.go:26` - `NewRootCmd()` base command constructor
- `cmd/root.go:58` - `collectMelangeFiles()` YAML discovery
- `cmd/check.go:14` - `NewCheckCmd()` update detection command
- `cmd/update.go:15` - `NewUpdateCmd()` apply updates command
- `cmd/bump.go:16` - `NewBumpCmd()` vulnerability-bump command (`gobump` alias; flags: `--dry-run`, `--format`, `--backup-suffix`, `--no-validate`, `--simulation-timeout`, `--no-stdlib`)
- `cmd/bump.go:41` - `runBump()` vulnerability scan/apply logic

### Core Processing Architecture
- `internal/processor/processor.go:11` - `Processor` interface definition
- `internal/processor/processor.go:76` - `BaseProcessor` struct
- `internal/processor/stages/file.go` - YAML I/O with backup operations
- `internal/processor/stages/validation.go` - Configuration integrity validation
- `internal/processor/stages/epoch.go` - Epoch management and updates

### Vulnerability Bumping (bump)
- `internal/gobump/processor.go` - `NewGoBumpProcessor()` constructor
- `internal/gobump/stages.go` - language-agnostic orchestrator (discovery, analysis, reconcile)
- `internal/gobump/simulate_stage.go` + `internal/simulate/` - bump simulation (proves candidate sets resolve and cover advisories with a real go toolchain)
- `internal/gobump/gopin.go` - `go-package` toolchain pin parsing and raising on `go/build`/`go/install` steps
- `internal/gobump/goversion_fallback.go` - best-effort `go-version` proxy fallback used under `--no-validate`
- `internal/gobump/stdlib.go` + `internal/gobump/stdlib_stage.go` - Go stdlib staleness check and epoch-bump trigger (`--no-stdlib` to disable)
- `internal/gorelease/` - Go release index (latest stable release as-of a time / available now), backed by the module proxy's `golang.org/toolchain` pseudo-module
- `internal/goversion/` - bare Go version comparison/parsing helpers shared across the above
- `internal/git/local.go` - `LastCommitInfo()` last-commit-time/dirty/shallow lookup used by the stdlib staleness idempotency guard
- `internal/ecosystem/` - per-language `Ecosystem` implementations (`golang/`, `rust/`, `java/`) behind a self-registering plugin registry
- `internal/ecosystem/fetcher.go` - remote manifest fetching (go.mod/Cargo.lock/pom.xml)
- `internal/scan/vulnerability.go` - `NewVulnerabilityScanner()` OSV scanner (language-agnostic `ScanPackages`)
- `internal/scan/cache.go` - Vulnerability result caching (ecosystem-qualified keys)

### Service Clients
- `internal/github/client.go` - GitHub API client with rate limiting
- `internal/git/client.go` - Git operations using go-git
- `internal/anitya/client.go` - Release-monitoring.org integration

### YAML & Configuration
- `internal/config/loader.go` - Comment-preserving YAML loader
- `internal/config/renderer.go` - Formatted YAML output
- `internal/types/types.go` - Core data structures and types

### Update Detection & Processing
- `internal/updater/orchestrator.go:33` - `NewOrchestrator()` update coordinator
- `internal/updater/processor.go:24` - `NewUpdaterProcessor()` update processor
- `internal/updater/pipeline.go` - Pipeline composition and execution
- `internal/updater/version.go` - Semantic version comparison and handling
- `internal/updater/filter.go` - Update filtering logic

## Environment Setup

```bash
# Required tokens
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
export ANITYA_TOKEN=your-anitya-token-here

# Go environment
export GO111MODULE=on
export GOPROXY=https://proxy.golang.org,direct
```

## Installation Methods

For development, build from source. For users/deployment:

```bash
# Homebrew (recommended for macOS/Linux)
brew tap isometry/tap
brew install choam

# Go install
go install github.com/isometry/choam@latest

# From source (development)
make deps && make build
```

## Development Workflow

### Building & Dependencies
```bash
make deps          # Install dependencies (go mod download + tidy)
make build         # Build binary (output: ./choam)
make install       # Install binary to $GOPATH/bin
make clean         # Remove build artifacts (choam, coverage.out, coverage.html)
```

### Testing
```bash
# Run all tests
make test          # Run all tests with verbose output

# Run tests with specific options
make test-short    # Skip slow tests (uses -short flag)
make test-race     # Run with race detector

# Coverage reports
make test-coverage          # Generate coverage.html report
make test-coverage-detailed # Show per-package coverage breakdown

# Test specific package
make test-package PKG=internal/scan      # Test just the scan package
make test-package PKG=internal/gobump    # Test just the gobump package

# Direct go test commands
go test -v ./...                         # All tests verbose
go test -run TestVulnerabilityScanner ./internal/scan  # Specific test
go test -short -v ./internal/processor/...             # Package subtree
```

### Code Quality
```bash
make fmt           # Format code (go fmt ./...)
make lint          # Lint code (requires golangci-lint)
make help          # Show all available make targets

# Quick validation before commit
make fmt && make lint && make test
```

### Running CHOAM
```bash
# Check for updates
./choam check ./packages/                 # Check directory
./choam check package.yaml                # Check single file
./choam check --dry-run ./packages/       # Dry run (no API calls)
./choam check --format json ./packages/   # JSON output

# Apply updates
./choam update ./packages/                # Apply available updates
./choam update --force ./packages/        # Force update even if risky

# Fix dependency vulnerabilities via bump pipeline steps
./choam bump ./packages/                  # Scan and fix (simulation needs a go toolchain)
./choam bump --no-validate ./packages/    # Skip simulation (no toolchain required)
./choam bump --no-stdlib ./packages/      # Skip the Go stdlib staleness/epoch-bump check

# Verbosity control (available for all commands)
./choam check -v ./packages/              # Info level
./choam check -vv ./packages/             # Debug level

# Global flags available for all commands
./choam check --http-timeout 30s ./packages/  # Custom HTTP timeout
```

## Common Extension Points

**Adding New Update Sources:**
1. Create client in `internal/newservice/` (client.go, types.go, tests)
2. Implement service interface from types
3. Integrate to `internal/updater/orchestrator.go`
4. Update `internal/config/loader.go` for new config

**Adding Pipeline Stages:**
1. Create stage in `internal/processor/stages/`
2. Implement processor interface
3. Register in pipeline
4. Add tests

**Adding Vulnerability-Bump Ecosystems:**
1. Create `internal/ecosystem/<lang>/` implementing `ecosystem.Ecosystem`, self-registering via `init()`
2. Blank-import it from `internal/gobump/ecosystems.go`
3. Extend `internal/scan/vulnerability.go` if the ecosystem needs its own version comparator

## Critical Development Guidelines

**Code Quality:**
- Run `make lint` before committing (must pass)
- Maintain ≥80% test coverage for new code
- Preserve YAML comments in all YAML operations
- Follow Go conventions (gofmt, interfaces, error handling)

**Security:**
- Validate all external inputs (YAML configs, API responses)
- Use secure HTTP clients with proper timeouts
- Never log API tokens or secrets
- Run `choam bump` on dependency updates

**Performance:**
- Profile before optimizing
- Cache expensive operations (network, file I/O)
- Use streaming for large files
- Implement graceful timeouts on external calls

**Testing:**
- Write tests with new functionality
- Test error conditions thoroughly
- Mock external dependencies via interfaces
- Validate security fixes with known vulnerabilities

## Key Technical Considerations

**YAML Comment Preservation:**
- Critical requirement throughout YAML processing
- Check `internal/config/loader.go` and `renderer.go` for issues
- Test with complex melange files containing varied comment styles

**Processor Pattern:**
- Modern architecture for all new functionality
- Provides change tracking, version management, error handling
- Extensible via pipeline stages

**Vulnerability Scanning:**
- Security is highest priority
- OSV database integration via `internal/scan/vulnerability.go`
- Minimal fix strategy to reduce update impact
- Epoch management tied to actual fixes

## Important Reminders

- **Edit over create**: Always prefer editing existing files over creating new ones
- **Testing**: Run `make lint` and `make test` before considering work complete
- **Navigation**: Use the file:line references in this guide for efficient code navigation
- **Architecture**: Focus on the processor pattern when adding new functionality
- **Security**: Vulnerability scanning is highest priority - treat security issues accordingly
- **YAML preservation**: All YAML operations must maintain formatting and comments
- **Go version**: Project requires Go 1.26.4 or later (match go.mod)
- **Command visibility**: the `bump` command is fully supported and visible in `--help` (`gobump` is kept as a compatibility alias)