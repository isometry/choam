package updater

import (
	"os"
	"testing"
)

func TestStripVersionAffix(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		pattern  string
		isPrefix bool
		expected string
	}{
		// Simple prefix/suffix cases (no wildcards)
		{
			name:     "simple prefix removal",
			version:  "v1.2.3",
			pattern:  "v",
			isPrefix: true,
			expected: "1.2.3",
		},
		{
			name:     "simple suffix removal",
			version:  "1.2.3-beta",
			pattern:  "-beta",
			isPrefix: false,
			expected: "1.2.3",
		},
		{
			name:     "no match simple prefix",
			version:  "1.2.3",
			pattern:  "v",
			isPrefix: true,
			expected: "1.2.3",
		},

		// Prefix wildcard patterns
		{
			name:     "prefix wildcard - debian/*",
			version:  "debian/11.2.0",
			pattern:  "debian/*",
			isPrefix: true,
			expected: "11.2.0", // Remove shortest match "debian/"
		},
		{
			name:     "prefix wildcard - v*",
			version:  "v1.2.3-beta",
			pattern:  "v*",
			isPrefix: true,
			expected: "1.2.3-beta", // Remove shortest match "v"
		},
		{
			name:     "prefix wildcard with suffix - v*.",
			version:  "v1.2.3.final",
			pattern:  "v*.",
			isPrefix: true,
			expected: "2.3.final", // Remove shortest match "v1."
		},
		{
			name:     "prefix wildcard with suffix - release-*-",
			version:  "release-1.2.3-final",
			pattern:  "release-*-",
			isPrefix: true,
			expected: "final",
		},

		// Suffix wildcard patterns
		{
			name:     "suffix wildcard - *-beta",
			version:  "1.2.3-beta",
			pattern:  "*-beta",
			isPrefix: false,
			expected: "1.2.3", // Remove shortest match "-beta"
		},
		{
			name:     "suffix wildcard - +dfsg-*",
			version:  "1.2.3+dfsg-1",
			pattern:  "+dfsg-*",
			isPrefix: false,
			expected: "1.2.3",
		},
		{
			name:     "suffix wildcard with prefix - +*-debian",
			version:  "1.2.3+ubuntu-debian",
			pattern:  "+*-debian",
			isPrefix: false,
			expected: "1.2.3",
		},

		// Edge cases
		{
			name:     "empty pattern",
			version:  "1.2.3",
			pattern:  "",
			isPrefix: true,
			expected: "1.2.3",
		},
		{
			name:     "empty version",
			version:  "",
			pattern:  "v*",
			isPrefix: true,
			expected: "",
		},
		{
			name:     "pattern doesn't match",
			version:  "1.2.3",
			pattern:  "debian/*",
			isPrefix: true,
			expected: "1.2.3",
		},
		{
			name:     "complex debian package version",
			version:  "1.2.3+dfsg.1-2ubuntu1",
			pattern:  "+dfsg*",
			isPrefix: false,
			expected: "1.2.3",
		},
		{
			name:     "complex pattern with multiple wildcards",
			version:  "v1.2.3-beta",
			pattern:  "v?.*",
			isPrefix: true,
			expected: "2.3-beta", // Remove "v1." (v? matches "v1", .* matches ".")
		},

		// Real-world examples
		{
			name:     "golang version strip",
			version:  "go1.20.5",
			pattern:  "go*",
			isPrefix: true,
			expected: "1.20.5", // Remove shortest match "go"
		},
		{
			name:     "python version strip",
			version:  "Python-3.11.4",
			pattern:  "Python-*",
			isPrefix: true,
			expected: "3.11.4", // Remove shortest match "Python-"
		},
		{
			name:     "kernel version strip",
			version:  "v6.1.35-gentoo",
			pattern:  "*-gentoo",
			isPrefix: false,
			expected: "v6.1.35",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripVersionAffix(tt.version, tt.pattern, tt.isPrefix)
			if result != tt.expected {
				t.Errorf("stripVersionAffix(%q, %q, %v) = %q, want %q",
					tt.version, tt.pattern, tt.isPrefix, result, tt.expected)
			}
		})
	}
}

func TestIsMelangeConfig(t *testing.T) {
	// Create temp files for testing
	tempDir := t.TempDir()

	// Valid melange config
	validConfig := `package:
  name: test-package
  version: 1.0.0

pipeline:
  - uses: fetch`

	validPath := tempDir + "/valid.yaml"
	if err := writeTestFile(validPath, validConfig); err != nil {
		t.Fatal(err)
	}

	// Invalid config (missing required fields)
	invalidConfig := `name: test-package
version: 1.0.0`

	invalidPath := tempDir + "/invalid.yaml"
	if err := writeTestFile(invalidPath, invalidConfig); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		filePath string
		expected bool
	}{
		{
			name:     "valid melange config",
			filePath: validPath,
			expected: true,
		},
		{
			name:     "invalid config",
			filePath: invalidPath,
			expected: false,
		},
		{
			name:     "non-existent file",
			filePath: tempDir + "/nonexistent.yaml",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isMelangeConfig(tt.filePath)
			if result != tt.expected {
				t.Errorf("isMelangeConfig(%q) = %v, want %v", tt.filePath, result, tt.expected)
			}
		})
	}
}

// Helper function to write test files
func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
