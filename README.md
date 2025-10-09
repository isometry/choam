# CHOAM

A Go CLI tool for managing melange build specifications and securing software supply chains. CHOAM detects updates, applies changes, and scans for vulnerabilities in Go dependencies.

## Features

- 🔍 **Update Detection**: Multi-source monitoring (GitHub releases/tags, Git repositories, release-monitoring.org)
- ⚡ **Automated Updates**: Apply version updates with epoch management and SHA256 verification
- 🛡️ **Vulnerability Scanning**: OSV database integration for Go module security analysis (in-development)
- 📊 **Multiple Output Formats**: Table and JSON output for CI/CD integration
- 🏗️ **Comment-Preserving YAML**: Maintains formatting, comments, and structure
- 🔧 **Processor Architecture**: Extensible pipeline stages with change tracking and rollback

## Installation

### From Source

```bash
git clone https://github.com/isometry/choam
cd choam
make build
```

### Using Go Install

```bash
go install github.com/isometry/choam@latest
```

### Using Make

```bash
make deps      # Install dependencies
make build     # Build binary
make install   # Install to $GOPATH/bin
```

## Usage

CHOAM provides three main commands:

### 1. Check for Updates

Detect available updates without making changes:

```bash
# Check single file
choam check py3-authlib.yaml

# Check directory
choam check ./packages/

# JSON output for automation
choam check --format json ./packages/

# Verbose output
choam check -vv ./packages/
```

#### Flags

- `--format, -f`: Output format (table, json)
- `--dry-run`: Show what would be checked without API calls
- `--verbose, -v`: Increase verbosity (-v info, -vv debug)

### 2. Apply Updates

Update package versions, epochs, and checksums:

```bash
# Update files with available updates
choam update ./packages/

# Dry run to preview changes
choam update --dry-run ./packages/

# Create backups
choam update --backup-suffix .bak ./packages/

# Force update (increment epoch even without version change)
choam update --force package.yaml
```

#### Flags

- `--format, -f`: Output format (table, json)
- `--dry-run`: Show what would be changed without writing
- `--backup-suffix`: Create backup files (e.g., `.bak`)
- `--force`: Force update and increment epoch
- `--shared`: Update shared dependencies (default: true)
- `--verbose, -v`: Increase verbosity

### 3. Bump Vulnerable Go Dependencies

⚠️ **Note:** This feature is in-development and not yet stable.

Scan and fix Go module vulnerabilities using go/bump pipelines:

```bash
# Scan for vulnerabilities
choam gobump ./packages/

# Dry run to preview fixes
choam gobump --dry-run ./packages/

# Create backups before fixing
choam gobump --backup-suffix .bak ./packages/
```

#### Flags

- `--format, -f`: Output format (table, json)
- `--dry-run`: Show what would be changed without writing
- `--backup-suffix`: Create backup files
- `--verbose, -v`: Increase verbosity

## Configuration

CHOAM reads standard melange `update:` configurations:

### GitHub Monitor

```yaml
package:
  name: py3-authlib
  version: 1.5.2
  epoch: 0

update:
  enabled: true
  github:
    identifier: lepture/authlib
    strip-prefix: v
    use-tag: false  # Use releases (default) or tags
```

Set `GITHUB_TOKEN` environment variable for authentication and higher rate limits.

### Release Monitor (release-monitoring.org)

```yaml
package:
  name: example-package
  version: 1.0.0

update:
  enabled: true
  release-monitor:
    identifier: 242117
```

Optionally set `ANITYA_TOKEN` environment variable for authentication.

### Git Monitor

```yaml
update:
  enabled: true
  git:
    url: https://github.com/example/repo
    strip-prefix: v
```

## Development

### Building & Testing

```bash
# Development workflow
make deps              # Install dependencies
make build             # Build binary
make test              # Run all tests
make lint              # Lint code

# Testing variants
make test-short        # Skip slow tests
make test-race         # Run with race detector
make test-coverage     # Generate coverage report
make test-package PKG=internal/scan  # Test specific package

# Code quality
make fmt               # Format code
make clean             # Remove artifacts
```

### Project Structure

```
cmd/              CLI commands (check, update, gobump)
internal/
  processor/      Processing pipeline architecture
  updater/        Update detection and application
  gobump/         Go module vulnerability scanning
  scan/           OSV vulnerability scanner
  github/         GitHub API client
  git/            Git operations client
  anitya/         Release monitoring client
  config/         YAML configuration handling
```

## Example Output

### Check Command

```
PACKAGE         CURRENT    LATEST     UPDATE    SOURCE            STATUS
py3-authlib     1.5.2      1.6.3      YES       github-releases   OK
go              1.21.0     1.21.5     YES       github-tags       OK
example         1.0.0      1.0.0      NO        anitya            OK
```

### Update Command

```
PACKAGE         CURRENT    LATEST     UPDATED    EPOCH    STATUS
py3-authlib     1.5.2      1.6.3      YES        0→1      OK
go              1.21.0     1.21.5     YES        0→1      OK
```

### GoBump Command

```
PACKAGE              MODULE                    CURRENT    FIXED      VULNS    EPOCH    STATUS
go-package           github.com/example/vuln   v1.2.0     v1.2.3     2        5→6      FIXED
safe-package         github.com/example/safe   v2.0.0     v2.0.0     0        3        OK
```

## Environment Variables

- `GITHUB_TOKEN`: GitHub personal access token for API authentication
- `ANITYA_TOKEN`: Release monitoring API token
- `LOG_LEVEL`: Log level override (debug, info, warn, error)

## Requirements

- Go 1.24.6 or later
- Optional: `golangci-lint` for linting

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Run `make lint && make test` before committing
5. Submit a pull request

## Related Projects

- [Melange](https://github.com/chainguard-dev/melange) - APK package builder
- [Wolfi](https://github.com/wolfi-dev) - Container-optimized Linux distribution
- [Chainguard](https://www.chainguard.dev/) - Supply chain security platform

## License

MIT License - see LICENSE file for details
