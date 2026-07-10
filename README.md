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

### Using Homebrew

```bash
# Install choam
brew install isometry/tap/choam
```

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
make deps build
make install # Install to $GOPATH/bin
```

## Usage

### Global Flags

All commands support these global flags:

- `--verbose, -v`: Increase verbosity (-v for info, -vv for debug)
- `--http-timeout`: Timeout for HTTP requests (default: 15s)

CHOAM provides two main commands (plus experimental features):

### Check for Updates

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

### Apply Updates

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

### Fix Vulnerabilities

Scan module dependencies for known vulnerabilities and fix them by adding or updating `bump`/`go/bump` pipeline steps, incrementing `package.epoch` when a fix is applied. `gobump` is retained as a command alias for `bump`:

```bash
# Scan and fix (simulation proves the fix set resolves and covers advisories; needs a go toolchain)
choam bump ./packages/

# Dry run to preview changes
choam bump --dry-run ./packages/

# Skip simulation (writes deps without proving resolution/coverage or artifact-reachability filtering; no toolchain required)
choam bump --no-validate ./packages/

# Skip the Go stdlib staleness check (no epoch bump for toolchain-fixed vulnerabilities)
choam bump --no-stdlib ./packages/

# Create backups before fixing
choam bump --backup-suffix .bak ./packages/
```

#### Flags

- `--format, -f`: Output format (table, json, yaml)
- `--dry-run`: Show what would be changed without writing
- `--backup-suffix`: Create backup files (e.g., `.bak`)
- `--no-validate`: Skip bump simulation (writes deps without proving they resolve or cover all advisories, and skips artifact-reachability filtering; go.sum narrowing still applies)
- `--simulation-timeout`: Per-package budget for bump simulation (default: 10m)
- `--no-stdlib`: Skip the Go stdlib staleness check
- `--verbose, -v`: Increase verbosity

#### Go version handling

When simulation proves a candidate dependency set, `bump` also computes the Go language version that set requires and, if it exceeds the module's existing `go`/`toolchain` directive (never lowering an existing value), emits a `go-version: "X"` input into the `bump`/`go/bump` pipeline step. Under `--no-validate`, a best-effort fallback fetches candidate `go.mod` files from the Go module proxy to approximate the same value. Any `go-package` toolchain pin on `go/build`/`go/install` steps that's now too old (e.g. `go-1.24`) is raised to satisfy the requirement (e.g. `go-1.25`); templated or unrecognized pins are left alone with a warning instead of being edited. Raising the pin is about determinism and explicit toolchain intent rather than avoiding a hard build failure: melange builds run with Go's default `GOTOOLCHAIN=auto`, so a too-old installed toolchain auto-downloads a newer release when the module proxy is reachable - only restricted/hermetic environments actually fail. Note: the emitted `go-version` only takes effect once the generic `bump` pipeline exposes a `go-version` input (melange's native `go/bump` already supports it).

#### Stdlib staleness

On by default (`--no-stdlib` to disable). A shipped binary's standard library is always the build toolchain's (the `go-package` input's) stdlib - the module's own `go.mod` directive does not determine it. `bump` therefore assumes a package was built with the latest upstream Go release as of the melange file's last git commit (constrained by any `go-package` pins), then compares OSV `stdlib` advisories at that assumed release against the newest allowed release; when the same run raises a `go-package` pin, the rebuild side uses the raised pin. When a rebuild would fix advisories affecting stdlib packages actually linked into the build artifacts, `package.epoch` is bumped by 1 to force a rebuild - even with zero dependency changes. Advisories a pinned rebuild cannot fix but a newer Go minor would produce an informational raise-the-pin suggestion instead of a bump. Artifact-linked-import filtering only applies when simulation runs; under `--no-validate` findings are unfiltered. The check is skipped automatically for files that are untracked, outside a git repository, or have uncommitted changes (doubling as an idempotency guard so repeated runs don't stack bumps); shallow clones are still checked but produce a warning about possible false negatives.

Both checks are best-effort and fail open: any failure degrades to a skip-with-message rather than aborting the run. They rely on network access to `proxy.golang.org` (the Go release index and the go-version fallback), in addition to the `api.osv.dev` vulnerability scanning CHOAM already uses.

#### Example Output

```
PACKAGE         FOUND  FIXED  RESIDUAL  UNLINKED  BUMPED  STDLIB  OLD EPOCH  NEW EPOCH  STATUS
go-package      2      2      0         0         1       1       5          6          FIXED
stale-package   0      0      0         0         0       2       3          4          STDLIB-REBUILD
safe-package    0      0      0         0         0       -       3          3          NO VULNS

Summary: 3 files processed, 1 with vulnerabilities, 1 fixed, 0 errors (2 advisories found, 2 fixed, 0 residual, 0 in unlinked modules; 1 modules bumped); 2 stdlib-stale
```

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
    use-tag: false # Use releases (default) or tags
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
cmd/              CLI commands (check, update, bump)
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

## Environment Variables

- `GITHUB_TOKEN`: GitHub personal access token for API authentication
- `ANITYA_TOKEN`: Release monitoring API token
- `LOG_LEVEL`: Log level override (debug, info, warn, error)

## Requirements

- Go 1.25.3 or later
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
