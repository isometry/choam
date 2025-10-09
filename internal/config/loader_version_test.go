package config

import (
	"strings"
	"testing"
)

func TestUpdatePackageVersion_QuotedRendering(t *testing.T) {
	loader := NewLoader()

	testYAML := `package:
  name: test-package
  version: 1.2.3
  epoch: 0
  description: Test package

pipeline:
  - uses: fetch
    with:
      uri: https://example.com
`

	tests := []struct {
		name           string
		newVersion     string
		expectedQuoted bool
	}{
		{
			name:           "simple version that looks like float",
			newVersion:     "1.0",
			expectedQuoted: true,
		},
		{
			name:           "semver version",
			newVersion:     "2.0.0",
			expectedQuoted: true,
		},
		{
			name:           "version with prerelease",
			newVersion:     "1.0.0-beta.1",
			expectedQuoted: true,
		},
		{
			name:           "version with build metadata",
			newVersion:     "1.0.0+20130313144700",
			expectedQuoted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updated, err := loader.UpdatePackageVersion([]byte(testYAML), tt.newVersion)
			if err != nil {
				t.Fatalf("UpdatePackageVersion() error = %v", err)
			}

			result := string(updated)

			// Check if version is properly quoted
			quotedVersion := `"` + tt.newVersion + `"`
			if !strings.Contains(result, quotedVersion) {
				t.Errorf("Expected version to be quoted as %s in output:\n%s", quotedVersion, result)
			}

			// Verify the version line specifically
			lines := strings.Split(result, "\n")
			for _, line := range lines {
				if strings.Contains(line, "version:") {
					if !strings.Contains(line, quotedVersion) {
						t.Errorf("Version line does not contain quoted version:\n  got: %s\n  want: version: %s", line, quotedVersion)
					}
					break
				}
			}
		})
	}
}

func TestUpdatePackageVersion_PreservesComments(t *testing.T) {
	loader := NewLoader()

	testYAML := `package:
  name: test-package
  # Important: Keep this version in sync with upstream
  version: 1.2.3
  epoch: 0
  description: Test package
`

	updated, err := loader.UpdatePackageVersion([]byte(testYAML), "2.0.0")
	if err != nil {
		t.Fatalf("UpdatePackageVersion() error = %v", err)
	}

	result := string(updated)

	// Verify comment is preserved
	if !strings.Contains(result, "# Important: Keep this version in sync with upstream") {
		t.Errorf("Comment was not preserved in output:\n%s", result)
	}

	// Verify version is updated and quoted
	if !strings.Contains(result, `version: "2.0.0"`) {
		t.Errorf("Version was not properly updated or quoted:\n%s", result)
	}
}
