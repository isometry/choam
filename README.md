# CHOAM

An idiomatic Go CLI tool for detecting available updates in melange build specification files. CHOAM respects the standard `update:` schema and integrates with GitHub, Git repositories, and release-monitoring.org to check for package updates.

## Features

- 🔍 **Multi-source Update Detection**: Supports GitHub releases/tags, Git repositories, and release-monitoring.org
- 📋 **Respects Update Configuration**: Honors all `update:` schema fields including filters, transforms, and exclusions
- 🚀 **Simple & Fast**: Lightweight implementation with no external dependencies for basic operations
- 📊 **Multiple Output Formats**: Table and JSON output formats for integration with other tools
- 🛡️ **Robust Filtering**: Version filtering, regex patterns, pre-release handling, and version transformations

## Installation

### From Source

```bash
git clone https://github.com/isometry/choam
cd spice
go build -o spice cmd/spice/main.go
```

### Using Go Install

```bash
go install github.com/isometry/choam/cmd/spice@latest
```

## Usage

### Basic Usage

Check a single melange file:
```bash
spice check py3-authlib.yaml
```

Check multiple files:
```bash
spice check go.yaml py3-authlib.yaml
```

Check a directory:
```bash
spice check ./packages/
```

### Output Formats

Table output (default):
```bash
spice check py3-authlib.yaml
```

JSON output for integration:
```bash
spice check --format json py3-authlib.yaml
```

### Options

- `--format, -f`: Output format (`table` or `json`)
- `--dry-run`: Show what would be checked without making API calls
- `--verbose, -v`: Verbose output with additional details

## Configuration

CHOAM reads standard melange `update:` configurations from your melange.yaml files:

### GitHub Monitor (Recommended)

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
```

Note: if `GITHUB_TOKEN` is set, it will be used for authentication.

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

Note: if `ANITYA_TOKEN` is set, it will be used for authentication.

## Update Sources

### 1. GitHub Monitor

Monitors GitHub releases or tags:

- **identifier**: Repository in format `owner/repo`
- **use-tag**: Use Git tags instead of releases
- **tag-filter**: Filter tags containing this string
- **tag-filter-prefix**: Filter tags starting with this prefix

### 2. Release Monitor (Anitya)

Monitors packages via release-monitoring.org:

- **identifier**: Anitya project ID (integer)
- **strip-prefix/strip-suffix**: Clean up version strings

### 3. Git Monitor

Monitors Git repositories directly:

- Requires repository URL configuration
- Supports tag filtering similar to GitHub

## Examples

### Example Output

```
PACKAGE                        CURRENT         LATEST          UPDATE     SOURCE               STATUS
amazon-corretto-11             11.0.28.6.1     11.0.28.6.1     NO         github-tags          MANUAL
py3-authlib                    1.5.2           1.6.3           YES        github-releases      OK
example-package                1.0.0           1.0.0           NO         anitya               OK
```

### Example JSON Output

```json
[
  {
    "package_name": "py3-authlib",
    "current_version": "1.5.2",
    "latest_version": "1.6.3",
    "has_update": true,
    "update_source": "github-releases"
  }
]
```

## Architecture

```
spice/
├── pkg/
│   ├── anitya/          # Release-monitoring.org client
│   ├── github/          # GitHub API client
│   ├── git/             # Git repository client
│   └── updater/         # Core update detection logic
└── cmd/
    └── choam/           # CLI interface
```

### Key Components

- **pkg/anitya**: Simple HTTP client for release-monitoring.org API
- **pkg/github**: GitHub API client for releases and tags
- **pkg/git**: Git client using command-line git for repository monitoring
- **pkg/updater**: Core logic that coordinates all clients and applies update rules

## Development

### Running Tests

```bash
go test ./...
```

### Building

```bash
go build -o spice cmd/spice/main.go
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Related Projects

- [Melange](https://github.com/chainguard-dev/melange) - APK package builder
- [Wolfi](https://github.com/wolfi-dev) - Container-optimized Linux distribution
- [Chainguard](https://www.chainguard.dev/) - Supply chain security platform
