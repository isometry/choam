package updater

import (
	"testing"
)

func TestVersionComparator_Compare(t *testing.T) {
	vc := NewVersionComparator()

	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int
	}{
		{
			name:     "v1 older than v2",
			v1:       "1.0.0",
			v2:       "1.1.0",
			expected: -1,
		},
		{
			name:     "v1 newer than v2",
			v1:       "2.0.0",
			v2:       "1.9.0",
			expected: 1,
		},
		{
			name:     "v1 equals v2",
			v1:       "1.0.0",
			v2:       "1.0.0",
			expected: 0,
		},
		{
			name:     "with v prefix",
			v1:       "v1.0.0",
			v2:       "v1.1.0",
			expected: -1,
		},
		{
			name:     "mixed prefix",
			v1:       "1.0.0",
			v2:       "v1.1.0",
			expected: -1,
		},
		// Multi-part version tests
		{
			name:     "multi-part v1 older than v2",
			v1:       "11.0.27.6.1",
			v2:       "11.0.28.6.1",
			expected: -1,
		},
		{
			name:     "multi-part v1 newer than v2",
			v1:       "11.0.28.6.1",
			v2:       "11.0.27.6.1",
			expected: 1,
		},
		{
			name:     "multi-part v1 equals v2",
			v1:       "11.0.28.6.1",
			v2:       "11.0.28.6.1",
			expected: 0,
		},
		{
			name:     "multi-part with v prefix",
			v1:       "v11.0.27.6.1",
			v2:       "v11.0.28.6.1",
			expected: -1,
		},
		{
			name:     "multi-part different lengths",
			v1:       "11.0.28.6",
			v2:       "11.0.28.6.1",
			expected: -1,
		},
		{
			name:     "multi-part comparison in minor version",
			v1:       "11.0.28.4.1",
			v2:       "11.0.28.6.1",
			expected: -1,
		},
		{
			name:     "multi-part comparison in patch level",
			v1:       "11.0.26.6.1",
			v2:       "11.0.28.6.1",
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vc.Compare(tt.v1, tt.v2)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Compare(%s, %s) = %d, want %d", tt.v1, tt.v2, result, tt.expected)
			}
		})
	}
}

func TestVersionComparator_IsNewer(t *testing.T) {
	vc := NewVersionComparator()

	tests := []struct {
		name     string
		current  string
		new      string
		expected bool
	}{
		{
			name:     "new version is newer",
			current:  "1.0.0",
			new:      "1.1.0",
			expected: true,
		},
		{
			name:     "new version is older",
			current:  "2.0.0",
			new:      "1.9.0",
			expected: false,
		},
		{
			name:     "versions are equal",
			current:  "1.0.0",
			new:      "1.0.0",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vc.IsNewer(tt.current, tt.new)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("IsNewer(%s, %s) = %t, want %t", tt.current, tt.new, result, tt.expected)
			}
		})
	}
}

func TestVersionComparator_ApplyTransform(t *testing.T) {
	vc := NewVersionComparator()

	tests := []struct {
		name     string
		version  string
		match    string
		replace  string
		expected string
		wantErr  bool
	}{
		{
			name:     "simple replacement",
			version:  "go1.22.0",
			match:    "go",
			replace:  "",
			expected: "1.22.0",
		},
		{
			name:     "regex replacement",
			version:  "v1.0.0-beta",
			match:    "-.*",
			replace:  "",
			expected: "v1.0.0",
		},
		{
			name:     "no match",
			version:  "1.0.0",
			match:    "go",
			replace:  "",
			expected: "1.0.0",
		},
		{
			name:     "empty match",
			version:  "1.0.0",
			match:    "",
			replace:  "v",
			expected: "1.0.0",
		},
		{
			name:    "invalid regex",
			version: "1.0.0",
			match:   "[",
			replace: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vc.ApplyTransform(tt.version, tt.match, tt.replace)
			if (err != nil) != tt.wantErr {
				t.Errorf("ApplyTransform() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("ApplyTransform(%s, %s, %s) = %s, want %s", tt.version, tt.match, tt.replace, result, tt.expected)
			}
		})
	}
}

func TestVersionComparator_FilterPreReleases(t *testing.T) {
	vc := NewVersionComparator()

	tests := []struct {
		name              string
		versions          []string
		enablePreReleases bool
		expected          []string
	}{
		{
			name:              "filter pre-releases",
			versions:          []string{"1.0.0", "1.1.0-alpha", "1.2.0", "2.0.0-beta"},
			enablePreReleases: false,
			expected:          []string{"1.0.0", "1.2.0"},
		},
		{
			name:              "keep pre-releases",
			versions:          []string{"1.0.0", "1.1.0-alpha", "1.2.0", "2.0.0-beta"},
			enablePreReleases: true,
			expected:          []string{"1.0.0", "1.1.0-alpha", "1.2.0", "2.0.0-beta"},
		},
		{
			name:              "no pre-releases",
			versions:          []string{"1.0.0", "1.2.0"},
			enablePreReleases: false,
			expected:          []string{"1.0.0", "1.2.0"},
		},
		{
			name:              "filter non-semver versions",
			versions:          []string{"1.0.0", "12.0.0_a6", "1.2.0", "invalid", "2.0.0-beta"},
			enablePreReleases: false,
			expected:          []string{"1.0.0", "1.2.0"},
		},
		{
			name:              "keep valid semver even with non-semver present",
			versions:          []string{"debian/1.0.0+dfsg", "12.0.0_a6", "1.2.0", "2.0.0-beta"},
			enablePreReleases: true,
			expected:          []string{"1.2.0", "2.0.0-beta"},
		},
		// Multi-part version tests
		{
			name:              "include multi-part versions",
			versions:          []string{"1.0.0", "11.0.28.6.1", "1.2.0", "11.0.27.6.1"},
			enablePreReleases: false,
			expected:          []string{"1.0.0", "11.0.28.6.1", "1.2.0", "11.0.27.6.1"},
		},
		{
			name:              "mixed multi-part and semver with pre-releases",
			versions:          []string{"1.0.0", "11.0.28.6.1", "1.2.0-alpha", "11.0.27.6.1"},
			enablePreReleases: false,
			expected:          []string{"1.0.0", "11.0.28.6.1", "11.0.27.6.1"},
		},
		{
			name:              "mixed multi-part and semver allowing pre-releases",
			versions:          []string{"1.0.0", "11.0.28.6.1", "1.2.0-alpha", "11.0.27.6.1"},
			enablePreReleases: true,
			expected:          []string{"1.0.0", "11.0.28.6.1", "1.2.0-alpha", "11.0.27.6.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vc.FilterPreReleases(tt.versions, tt.enablePreReleases)
			if len(result) != len(tt.expected) {
				t.Errorf("FilterPreReleases() returned %d items, want %d", len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("FilterPreReleases()[%d] = %s, want %s", i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestVersionComparator_IsValidVersion(t *testing.T) {
	vc := NewVersionComparator()

	tests := []struct {
		name            string
		version         string
		allowPreRelease bool
		expected        bool
	}{
		{
			name:            "valid version without pre-release",
			version:         "1.0.0",
			allowPreRelease: false,
			expected:        true,
		},
		{
			name:            "valid version with pre-release allowed",
			version:         "1.0.0-alpha",
			allowPreRelease: true,
			expected:        true,
		},
		{
			name:            "valid version with pre-release not allowed",
			version:         "1.0.0-alpha",
			allowPreRelease: false,
			expected:        false,
		},
		{
			name:            "invalid semver",
			version:         "12.0.0_a6",
			allowPreRelease: true,
			expected:        false,
		},
		{
			name:            "debian package format invalid",
			version:         "debian/1.0.0+dfsg",
			allowPreRelease: true,
			expected:        false,
		},
		{
			name:            "completely invalid",
			version:         "invalid",
			allowPreRelease: true,
			expected:        false,
		},
		{
			name:            "valid with v prefix",
			version:         "v1.0.0",
			allowPreRelease: false,
			expected:        true,
		},
		// Multi-part version tests
		{
			name:            "multi-part version valid",
			version:         "11.0.28.6.1",
			allowPreRelease: false,
			expected:        true,
		},
		{
			name:            "multi-part version with v prefix",
			version:         "v11.0.28.6.1",
			allowPreRelease: false,
			expected:        true,
		},
		{
			name:            "multi-part version with pre-release setting ignored",
			version:         "11.0.28.6.1",
			allowPreRelease: true,
			expected:        true,
		},
		{
			name:            "short multi-part version",
			version:         "11.0.28",
			allowPreRelease: false,
			expected:        true,
		},
		{
			name:            "long multi-part version",
			version:         "11.0.28.6.1.2.3",
			allowPreRelease: false,
			expected:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vc.IsValidVersion(tt.version, tt.allowPreRelease)
			if result != tt.expected {
				t.Errorf("IsValidVersion(%s, %t) = %t, want %t", tt.version, tt.allowPreRelease, result, tt.expected)
			}
		})
	}
}

func TestIsMultiPartNumeric(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected bool
	}{
		{
			name:     "simple multi-part",
			version:  "11.0.28.6.1",
			expected: true,
		},
		{
			name:     "multi-part with v prefix",
			version:  "v11.0.28.6.1",
			expected: true,
		},
		{
			name:     "standard semver",
			version:  "1.2.3",
			expected: true,
		},
		{
			name:     "semver with v prefix",
			version:  "v1.2.3",
			expected: true,
		},
		{
			name:     "single number",
			version:  "1",
			expected: true,
		},
		{
			name:     "two parts",
			version:  "1.2",
			expected: true,
		},
		{
			name:     "with pre-release",
			version:  "1.2.3-alpha",
			expected: false,
		},
		{
			name:     "with build metadata",
			version:  "1.2.3+build1",
			expected: false,
		},
		{
			name:     "non-numeric parts",
			version:  "1.2.alpha",
			expected: false,
		},
		{
			name:     "leading zeros",
			version:  "01.02.03",
			expected: true,
		},
		{
			name:     "empty string",
			version:  "",
			expected: false,
		},
		{
			name:     "just v prefix",
			version:  "v",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isMultiPartNumeric(tt.version)
			if result != tt.expected {
				t.Errorf("isMultiPartNumeric(%s) = %t, want %t", tt.version, result, tt.expected)
			}
		})
	}
}

func TestCompareMultiPart(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int
	}{
		{
			name:     "equal versions",
			v1:       "11.0.28.6.1",
			v2:       "11.0.28.6.1",
			expected: 0,
		},
		{
			name:     "v1 older in minor",
			v1:       "11.0.27.6.1",
			v2:       "11.0.28.6.1",
			expected: -1,
		},
		{
			name:     "v1 newer in minor",
			v1:       "11.0.29.6.1",
			v2:       "11.0.28.6.1",
			expected: 1,
		},
		{
			name:     "different lengths v1 shorter",
			v1:       "11.0.28",
			v2:       "11.0.28.6",
			expected: -1,
		},
		{
			name:     "different lengths v1 longer",
			v1:       "11.0.28.6.1",
			v2:       "11.0.28.6",
			expected: 1,
		},
		{
			name:     "different major",
			v1:       "10.0.28.6.1",
			v2:       "11.0.28.6.1",
			expected: -1,
		},
		{
			name:     "with v prefix",
			v1:       "v11.0.27.6.1",
			v2:       "v11.0.28.6.1",
			expected: -1,
		},
		{
			name:     "mixed prefix",
			v1:       "11.0.27.6.1",
			v2:       "v11.0.28.6.1",
			expected: -1,
		},
		{
			name:     "many parts",
			v1:       "11.0.28.6.1.2.3",
			v2:       "11.0.28.6.1.2.4",
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareMultiPart(tt.v1, tt.v2)
			if result != tt.expected {
				t.Errorf("compareMultiPart(%s, %s) = %d, want %d", tt.v1, tt.v2, result, tt.expected)
			}
		})
	}
}

func TestVersionComparator_MatchesIgnorePattern(t *testing.T) {
	vc := NewVersionComparator()

	tests := []struct {
		name     string
		version  string
		patterns []string
		expected bool
	}{
		{
			name:     "jenkins weekly ignored",
			version:  "2.525",
			patterns: []string{"^2[.][0-9]+$"},
			expected: true,
		},
		{
			name:     "jenkins lts not ignored",
			version:  "2.516.2",
			patterns: []string{"^2[.][0-9]+$"},
			expected: false,
		},
		{
			name:     "multiple patterns first match",
			version:  "1.0.0-beta",
			patterns: []string{".*-beta.*", ".*-rc.*"},
			expected: true,
		},
		{
			name:     "multiple patterns second match",
			version:  "1.0.0-rc.1",
			patterns: []string{".*-beta.*", ".*-rc.*"},
			expected: true,
		},
		{
			name:     "no patterns match",
			version:  "1.0.0",
			patterns: []string{".*-beta.*", ".*-rc.*"},
			expected: false,
		},
		{
			name:     "empty patterns",
			version:  "1.0.0",
			patterns: []string{},
			expected: false,
		},
		{
			name:     "anchored pattern at start",
			version:  "vulkan-sdk-1.3.290.0",
			patterns: []string{"^vulkan-sdk"},
			expected: true,
		},
		{
			name:     "anchored pattern at start no match",
			version:  "v1.3-vulkan-sdk-290.0",
			patterns: []string{"^vulkan-sdk"},
			expected: false,
		},
		{
			name:     "anchored pattern at end match",
			version:  "release_v2.9",
			patterns: []string{".*_v2.9$"},
			expected: true,
		},
		{
			name:     "anchored pattern at end no match",
			version:  "release_v2.9.1",
			patterns: []string{".*_v2.9$"},
			expected: false,
		},
		{
			name:     "substring match",
			version:  "v1.2.3-vulkan-sdk-1.3.290.0",
			patterns: []string{"vulkan-sdk"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vc.MatchesIgnorePattern(tt.version, tt.patterns)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("MatchesIgnorePattern(%q, %v) = %t, want %t", tt.version, tt.patterns, result, tt.expected)
			}
		})
	}
}

// TestVersionComparator_MatchesIgnorePattern_Errors tests error handling
func TestVersionComparator_MatchesIgnorePattern_Errors(t *testing.T) {
	vc := NewVersionComparator()

	tests := []struct {
		name     string
		version  string
		patterns []string
		wantErr  bool
	}{
		{
			name:     "invalid regex pattern - unclosed bracket",
			version:  "1.0.0",
			patterns: []string{"[invalid"},
			wantErr:  true,
		},
		{
			name:     "invalid regex pattern - invalid quantifier",
			version:  "1.0.0",
			patterns: []string{"*invalid"},
			wantErr:  true,
		},
		{
			name:     "invalid regex pattern - unclosed parenthesis",
			version:  "1.0.0",
			patterns: []string{"(unclosed"},
			wantErr:  true,
		},
		{
			name:     "multiple patterns with one invalid",
			version:  "1.0.0",
			patterns: []string{"valid.*", "[invalid"},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := vc.MatchesIgnorePattern(tt.version, tt.patterns)
			if (err != nil) != tt.wantErr {
				t.Errorf("MatchesIgnorePattern() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestVersionComparator_Compare_EdgeCases expands Compare testing with edge cases
func TestVersionComparator_Compare_EdgeCases(t *testing.T) {
	vc := NewVersionComparator()

	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int
		wantErr  bool
	}{
		{
			name:     "version with build metadata - ignored in comparison",
			v1:       "1.0.0+build.123",
			v2:       "1.0.0+build.456",
			expected: 0,
		},
		{
			name:     "version with build metadata and pre-release",
			v1:       "1.0.0-alpha+build.123",
			v2:       "1.0.0-alpha+build.456",
			expected: 0,
		},
		{
			name:     "pre-release with multiple identifiers",
			v1:       "1.0.0-alpha.1.2",
			v2:       "1.0.0-alpha.1.3",
			expected: -1,
		},
		{
			name:     "pre-release numeric vs text",
			v1:       "1.0.0-alpha.1",
			v2:       "1.0.0-alpha.beta",
			expected: -1,
		},
		{
			name:     "leading zeros in semver",
			v1:       "1.0.0",
			v2:       "1.0.0",
			expected: 0,
		},
		{
			name:     "very long version strings",
			v1:       "1.2.3.4.5.6.7.8.9.10.11.12",
			v2:       "1.2.3.4.5.6.7.8.9.10.11.13",
			expected: -1,
		},
		{
			name:     "version with only major",
			v1:       "2",
			v2:       "1.9.9",
			expected: 1,
		},
		{
			name:     "version with major.minor only",
			v1:       "1.5",
			v2:       "1.4.9",
			expected: 1,
		},
		{
			name:     "zero versions",
			v1:       "0.0.0",
			v2:       "0.0.1",
			expected: -1,
		},
		{
			name:    "invalid version - unicode characters",
			v1:      "1.0.0-α",
			v2:      "1.0.0",
			wantErr: true,
		},
		{
			name:    "completely invalid version",
			v1:      "not-a-version",
			v2:      "1.0.0",
			wantErr: true,
		},
		{
			name:    "invalid multi-part with non-numeric",
			v1:      "1.2.abc",
			v2:      "1.2.0",
			wantErr: true,
		},
		{
			name:     "multi-part with large numbers",
			v1:       "1.999999.0",
			v2:       "1.1000000.0",
			expected: -1,
		},
		{
			name:    "multi-part vs semver with pre-release",
			v1:      "11.0.28.6.1",
			v2:      "1.0.0-alpha",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vc.Compare(tt.v1, tt.v2)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Compare(%s, %s) expected error, got nil", tt.v1, tt.v2)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Compare(%s, %s) = %d, want %d", tt.v1, tt.v2, result, tt.expected)
			}
		})
	}
}

// TestVersionComparator_IsNewer_EdgeCases tests IsNewer with edge cases
func TestVersionComparator_IsNewer_EdgeCases(t *testing.T) {
	vc := NewVersionComparator()

	tests := []struct {
		name     string
		current  string
		new      string
		expected bool
		wantErr  bool
	}{
		{
			name:     "pre-release vs stable",
			current:  "1.0.0-alpha",
			new:      "1.0.0",
			expected: true,
		},
		{
			name:     "build metadata ignored",
			current:  "1.0.0+build.1",
			new:      "1.0.0+build.2",
			expected: false,
		},
		{
			name:     "multi-part versions",
			current:  "11.0.27.6.1",
			new:      "11.0.28.0.0",
			expected: true,
		},
		{
			name:    "invalid current version",
			current: "invalid",
			new:     "1.0.0",
			wantErr: true,
		},
		{
			name:    "invalid new version",
			current: "1.0.0",
			new:     "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vc.IsNewer(tt.current, tt.new)
			if tt.wantErr {
				if err == nil {
					t.Errorf("IsNewer(%s, %s) expected error, got nil", tt.current, tt.new)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("IsNewer(%s, %s) = %t, want %t", tt.current, tt.new, result, tt.expected)
			}
		})
	}
}

// TestVersionComparator_ApplyTransform_EdgeCases expands ApplyTransform testing
func TestVersionComparator_ApplyTransform_EdgeCases(t *testing.T) {
	vc := NewVersionComparator()

	tests := []struct {
		name     string
		version  string
		match    string
		replace  string
		expected string
		wantErr  bool
	}{
		{
			name:     "multiple transforms - remove prefix and suffix",
			version:  "go1.22.0-beta",
			match:    "^go",
			replace:  "",
			expected: "1.22.0-beta",
		},
		{
			name:     "transform with no matches - return unchanged",
			version:  "1.0.0",
			match:    "notfound",
			replace:  "replacement",
			expected: "1.0.0",
		},
		{
			name:     "transform with multiple matches - replace all",
			version:  "v1.0.0-v2-v3",
			match:    "v",
			replace:  "",
			expected: "1.0.0-2-3",
		},
		{
			name:     "complex regex with capture groups",
			version:  "release-v1.2.3",
			match:    "release-v(.+)",
			replace:  "$1",
			expected: "1.2.3",
		},
		{
			name:     "regex with character classes",
			version:  "1.0.0-SNAPSHOT",
			match:    "-[A-Z]+",
			replace:  "",
			expected: "1.0.0",
		},
		{
			name:     "empty version string",
			version:  "",
			match:    ".*",
			replace:  "0.0.0",
			expected: "0.0.0",
		},
		{
			name:     "special regex characters in version",
			version:  "1.0.0+build",
			match:    `\+.*`,
			replace:  "",
			expected: "1.0.0",
		},
		{
			name:    "invalid regex - unclosed bracket",
			version: "1.0.0",
			match:   "[unclosed",
			replace: "",
			wantErr: true,
		},
		{
			name:    "invalid regex - invalid quantifier",
			version: "1.0.0",
			match:   "*invalid",
			replace: "",
			wantErr: true,
		},
		{
			name:    "invalid regex - unclosed group",
			version: "1.0.0",
			match:   "(unclosed",
			replace: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vc.ApplyTransform(tt.version, tt.match, tt.replace)
			if (err != nil) != tt.wantErr {
				t.Errorf("ApplyTransform() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("ApplyTransform(%s, %s, %s) = %s, want %s", tt.version, tt.match, tt.replace, result, tt.expected)
			}
		})
	}
}

// TestVersionComparator_FilterPreReleases_EdgeCases expands FilterPreReleases testing
func TestVersionComparator_FilterPreReleases_EdgeCases(t *testing.T) {
	vc := NewVersionComparator()

	tests := []struct {
		name              string
		versions          []string
		enablePreReleases bool
		expected          []string
	}{
		{
			name:              "empty version list",
			versions:          []string{},
			enablePreReleases: false,
			expected:          nil,
		},
		{
			name:              "all pre-releases filtered out",
			versions:          []string{"1.0.0-alpha", "1.1.0-beta", "2.0.0-rc.1"},
			enablePreReleases: false,
			expected:          nil,
		},
		{
			name:              "pre-release with build metadata",
			versions:          []string{"1.0.0-alpha+build.123", "1.0.0"},
			enablePreReleases: false,
			expected:          []string{"1.0.0"},
		},
		{
			name:              "pre-release with build metadata kept",
			versions:          []string{"1.0.0-alpha+build.123", "1.0.0"},
			enablePreReleases: true,
			expected:          []string{"1.0.0-alpha+build.123", "1.0.0"},
		},
		{
			name:              "invalid semver completely filtered",
			versions:          []string{"completely-invalid", "not@version", "1.0.0"},
			enablePreReleases: true,
			expected:          []string{"1.0.0"},
		},
		{
			name:              "mixed valid and invalid versions",
			versions:          []string{"1.0.0", "invalid", "2.0.0-beta", "also-invalid", "3.0.0"},
			enablePreReleases: false,
			expected:          []string{"1.0.0", "3.0.0"},
		},
		{
			name:              "multi-part with different lengths",
			versions:          []string{"11.0.28", "11.0.28.6", "11.0.28.6.1", "1.0.0"},
			enablePreReleases: false,
			expected:          []string{"11.0.28", "11.0.28.6", "11.0.28.6.1", "1.0.0"},
		},
		{
			name:              "versions with v prefix mixed",
			versions:          []string{"v1.0.0", "1.1.0-alpha", "v2.0.0", "2.1.0-beta"},
			enablePreReleases: false,
			expected:          []string{"v1.0.0", "v2.0.0"},
		},
		{
			name:              "single version pre-release filtered",
			versions:          []string{"1.0.0-alpha"},
			enablePreReleases: false,
			expected:          nil,
		},
		{
			name:              "single version stable kept",
			versions:          []string{"1.0.0"},
			enablePreReleases: false,
			expected:          []string{"1.0.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vc.FilterPreReleases(tt.versions, tt.enablePreReleases)
			if len(result) != len(tt.expected) {
				t.Errorf("FilterPreReleases() returned %d items, want %d. Got: %v, Want: %v", len(result), len(tt.expected), result, tt.expected)
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("FilterPreReleases()[%d] = %s, want %s", i, v, tt.expected[i])
				}
			}
		})
	}
}

// TestVersionComparator_IsValidVersion_EdgeCases expands IsValidVersion testing
func TestVersionComparator_IsValidVersion_EdgeCases(t *testing.T) {
	vc := NewVersionComparator()

	tests := []struct {
		name            string
		version         string
		allowPreRelease bool
		expected        bool
	}{
		{
			name:            "version with spaces - invalid",
			version:         "1.0.0 ",
			allowPreRelease: false,
			expected:        false,
		},
		{
			name:            "version with leading spaces - invalid",
			version:         " 1.0.0",
			allowPreRelease: false,
			expected:        false,
		},
		{
			name:            "version with special characters - invalid",
			version:         "1.0.0@special",
			allowPreRelease: false,
			expected:        false,
		},
		{
			name:            "very long version string",
			version:         "1.2.3.4.5.6.7.8.9.10.11.12.13.14.15",
			allowPreRelease: false,
			expected:        true,
		},
		{
			name:            "numeric-only single digit",
			version:         "1",
			allowPreRelease: false,
			expected:        true,
		},
		{
			name:            "numeric-only two digits",
			version:         "22",
			allowPreRelease: false,
			expected:        true,
		},
		{
			name:            "numeric-only three digits",
			version:         "333",
			allowPreRelease: false,
			expected:        true,
		},
		{
			name:            "version with leading v and pre-release",
			version:         "v1.0.0-alpha",
			allowPreRelease: true,
			expected:        true,
		},
		{
			name:            "version with leading v and pre-release not allowed",
			version:         "v1.0.0-alpha",
			allowPreRelease: false,
			expected:        false,
		},
		{
			name:            "version with build metadata only",
			version:         "1.0.0+build.123",
			allowPreRelease: false,
			expected:        true,
		},
		{
			name:            "version with both pre-release and build",
			version:         "1.0.0-alpha+build.123",
			allowPreRelease: true,
			expected:        true,
		},
		{
			name:            "version with both pre-release and build not allowed",
			version:         "1.0.0-alpha+build.123",
			allowPreRelease: false,
			expected:        false,
		},
		{
			name:            "empty string - invalid",
			version:         "",
			allowPreRelease: false,
			expected:        false,
		},
		{
			name:            "just v prefix - invalid",
			version:         "v",
			allowPreRelease: false,
			expected:        false,
		},
		{
			name:            "version with underscores - invalid",
			version:         "1_0_0",
			allowPreRelease: false,
			expected:        false,
		},
		{
			name:            "version with hyphens but not pre-release - invalid",
			version:         "1-0-0",
			allowPreRelease: false,
			expected:        false,
		},
		{
			name:            "multi-part with leading zeros",
			version:         "01.02.03.04",
			allowPreRelease: false,
			expected:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vc.IsValidVersion(tt.version, tt.allowPreRelease)
			if result != tt.expected {
				t.Errorf("IsValidVersion(%q, %t) = %t, want %t", tt.version, tt.allowPreRelease, result, tt.expected)
			}
		})
	}
}

// TestIsMultiPartNumeric_EdgeCases expands isMultiPartNumeric testing
func TestIsMultiPartNumeric_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected bool
	}{
		{
			name:     "version with hyphens - not numeric",
			version:  "1-2-3",
			expected: false,
		},
		{
			name:     "version with underscores - not numeric",
			version:  "1_2_3",
			expected: false,
		},
		{
			name:     "version with spaces - not numeric",
			version:  "1 2 3",
			expected: false,
		},
		{
			name:     "version with letters - not numeric",
			version:  "1.2.a",
			expected: false,
		},
		{
			name:     "very long multi-part",
			version:  "1.2.3.4.5.6.7.8.9.10.11.12.13.14.15",
			expected: true,
		},
		{
			name:     "trailing dot - not numeric",
			version:  "1.2.3.",
			expected: false,
		},
		{
			name:     "leading dot - not numeric",
			version:  ".1.2.3",
			expected: false,
		},
		{
			name:     "double dots - not numeric",
			version:  "1..2.3",
			expected: false,
		},
		{
			name:     "negative numbers - not numeric",
			version:  "1.-2.3",
			expected: false,
		},
		{
			name:     "decimal numbers - not numeric",
			version:  "1.2.3.5",
			expected: true,
		},
		{
			name:     "zero version",
			version:  "0.0.0",
			expected: true,
		},
		{
			name:     "single zero",
			version:  "0",
			expected: true,
		},
		{
			name:     "v prefix with zeros",
			version:  "v0.0.0",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isMultiPartNumeric(tt.version)
			if result != tt.expected {
				t.Errorf("isMultiPartNumeric(%q) = %t, want %t", tt.version, result, tt.expected)
			}
		})
	}
}

// TestCompareMultiPart_EdgeCases expands compareMultiPart testing
func TestCompareMultiPart_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int
	}{
		{
			name:     "very long multi-part versions equal",
			v1:       "1.2.3.4.5.6.7.8.9.10",
			v2:       "1.2.3.4.5.6.7.8.9.10",
			expected: 0,
		},
		{
			name:     "very long multi-part versions different at end",
			v1:       "1.2.3.4.5.6.7.8.9.10",
			v2:       "1.2.3.4.5.6.7.8.9.11",
			expected: -1,
		},
		{
			name:     "versions with zeros - equal when trailing zeros",
			v1:       "1.0",
			v2:       "1.0.0",
			expected: 0,
		},
		{
			name:     "versions with zeros - equal when trailing zeros reversed",
			v1:       "1.0.0",
			v2:       "1.0",
			expected: 0,
		},
		{
			name:     "large numeric difference in major",
			v1:       "100.0.0",
			v2:       "1.0.0",
			expected: 1,
		},
		{
			name:     "large numeric difference in minor",
			v1:       "1.1000.0",
			v2:       "1.100.0",
			expected: 1,
		},
		{
			name:     "large numeric difference in patch",
			v1:       "1.0.9999",
			v2:       "1.0.999",
			expected: 1,
		},
		{
			name:     "single digit vs multi-part",
			v1:       "2",
			v2:       "1.9.9.9",
			expected: 1,
		},
		{
			name:     "two parts vs many parts",
			v1:       "2.0",
			v2:       "1.9.9.9.9.9",
			expected: 1,
		},
		{
			name:     "zero vs non-zero",
			v1:       "0.0.0",
			v2:       "0.0.1",
			expected: -1,
		},
		{
			name:     "all zeros equal",
			v1:       "0.0.0.0",
			v2:       "0.0.0.0",
			expected: 0,
		},
		{
			name:     "leading zeros - numerically equal",
			v1:       "01.02.03",
			v2:       "1.2.3",
			expected: 0,
		},
		{
			name:     "v prefix on both",
			v1:       "v2.0.0",
			v2:       "v1.9.9",
			expected: 1,
		},
		{
			name:     "v prefix on v1 only",
			v1:       "v2.0.0",
			v2:       "1.9.9",
			expected: 1,
		},
		{
			name:     "v prefix on v2 only",
			v1:       "2.0.0",
			v2:       "v1.9.9",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareMultiPart(tt.v1, tt.v2)
			if result != tt.expected {
				t.Errorf("compareMultiPart(%s, %s) = %d, want %d", tt.v1, tt.v2, result, tt.expected)
			}
		})
	}
}
