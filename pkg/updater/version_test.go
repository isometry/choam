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
