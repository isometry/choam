package goversion

import (
	"testing"
)

func TestCompare(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected int // -1, 0, or +1
	}{
		// Valid version comparisons
		{name: "1.24 < 1.25", a: "1.24", b: "1.25", expected: -1},
		{name: "1.25 > 1.24", a: "1.25", b: "1.24", expected: +1},
		{name: "1.24 == 1.24", a: "1.24", b: "1.24", expected: 0},
		{name: "1.9 < 1.24 (semver trap)", a: "1.9", b: "1.24", expected: -1},
		{name: "1.24 < 1.24.1", a: "1.24", b: "1.24.1", expected: -1},
		{name: "1.24.1 < 1.25rc1", a: "1.24.1", b: "1.25rc1", expected: -1},
		{name: "1.25rc1 > 1.25", a: "1.25rc1", b: "1.25", expected: +1},
		{name: "1.24.5 > 1.24.1", a: "1.24.5", b: "1.24.1", expected: +1},
		{name: "1.24.5 == 1.24.5", a: "1.24.5", b: "1.24.5", expected: 0},
		{name: "1.25rc1 == 1.25rc1", a: "1.25rc1", b: "1.25rc1", expected: 0},

		// Invalid inputs: invalid < valid
		{name: "invalid(empty) < valid", a: "", b: "1.24", expected: -1},
		{name: "valid > invalid(empty)", a: "1.24", b: "", expected: +1},
		{name: "invalid(go-prefixed) < valid", a: "go1.24", b: "1.24", expected: -1},
		{name: "valid > invalid(go-prefixed)", a: "1.24", b: "go1.24", expected: +1},
		{name: "invalid(v-prefixed) < valid", a: "v1.24", b: "1.24", expected: -1},
		{name: "valid > invalid(v-prefixed)", a: "1.24", b: "v1.24", expected: +1},
		{name: "invalid(banana) < valid", a: "banana", b: "1.24", expected: -1},
		{name: "valid > invalid(banana)", a: "1.24", b: "banana", expected: +1},

		// Invalid == invalid
		{name: "invalid(empty) == invalid(empty)", a: "", b: "", expected: 0},
		{name: "invalid(go-prefixed) == invalid(banana)", a: "go1.24", b: "banana", expected: 0},
		{name: "invalid(v-prefixed) == invalid(empty)", a: "v1.24", b: "", expected: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compare(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestMax(t *testing.T) {
	tests := []struct {
		name     string
		versions []string
		expected string
	}{
		// Single element
		{name: "single valid", versions: []string{"1.24"}, expected: "1.24"},
		{name: "single invalid", versions: []string{""}, expected: ""},
		{name: "single invalid banana", versions: []string{"banana"}, expected: ""},

		// Mixed valid/invalid
		{name: "valid and invalid", versions: []string{"1.24", ""}, expected: "1.24"},
		{name: "multiple valid and invalid", versions: []string{"1.24", "", "1.25", "banana"}, expected: "1.25"},
		{name: "invalid before valid", versions: []string{"", "1.24", "banana"}, expected: "1.24"},

		// All invalid
		{name: "all invalid", versions: []string{"", "banana", "go1.24"}, expected: ""},
		{name: "all invalid empty", versions: []string{""}, expected: ""},

		// All valid
		{name: "all valid", versions: []string{"1.24", "1.25", "1.24.5"}, expected: "1.25"},
		{name: "all valid rc versions", versions: []string{"1.25rc1", "1.24", "1.25rc2"}, expected: "1.25rc2"},
		{name: "all valid equal", versions: []string{"1.24", "1.24", "1.24"}, expected: "1.24"},

		// Empty input
		{name: "no arguments", versions: []string{}, expected: ""},

		// Complex cases
		{name: "1.9, 1.24, 1.25", versions: []string{"1.9", "1.24", "1.25"}, expected: "1.25"},
		{name: "1.24.1, 1.25rc1, 1.25", versions: []string{"1.24.1", "1.25rc1", "1.25"}, expected: "1.25rc1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Max(tt.versions...)
			if got != tt.expected {
				t.Errorf("Max(%v) = %q, want %q", tt.versions, got, tt.expected)
			}
		})
	}
}

func TestMinor(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		// Valid versions
		{name: "simple version", version: "1.24", expected: "1.24"},
		{name: "patch version", version: "1.24.5", expected: "1.24"},
		{name: "rc version", version: "1.25rc1", expected: "1.25"},
		{name: "rc2 version", version: "1.25rc2", expected: "1.25"},
		{name: "1.9", version: "1.9", expected: "1.9"},
		{name: "1.9.3", version: "1.9.3", expected: "1.9"},
		{name: "1.24.1", version: "1.24.1", expected: "1.24"},
		{name: "1.25.10", version: "1.25.10", expected: "1.25"},

		// Invalid versions
		{name: "empty", version: "", expected: ""},
		{name: "go-prefixed", version: "go1.24", expected: ""},
		{name: "v-prefixed", version: "v1.24", expected: ""},
		{name: "invalid", version: "banana", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Minor(tt.version)
			if got != tt.expected {
				t.Errorf("Minor(%q) = %q, want %q", tt.version, got, tt.expected)
			}
		})
	}
}

func TestIsValid(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected bool
	}{
		// Valid versions
		{name: "simple version", version: "1.24", expected: true},
		{name: "patch version", version: "1.24.5", expected: true},
		{name: "rc version", version: "1.25rc1", expected: true},
		{name: "rc2 version", version: "1.25rc2", expected: true},
		{name: "1.9", version: "1.9", expected: true},
		{name: "1.9.3", version: "1.9.3", expected: true},
		{name: "1.24.1", version: "1.24.1", expected: true},
		{name: "1.25.10", version: "1.25.10", expected: true},

		// Invalid versions
		{name: "empty", version: "", expected: false},
		{name: "go-prefixed", version: "go1.24", expected: false},
		{name: "v-prefixed", version: "v1.24", expected: false},
		{name: "invalid", version: "banana", expected: false},
		{name: "only major", version: "1", expected: true},
		{name: "too many components", version: "1.24.5.6", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValid(tt.version)
			if got != tt.expected {
				t.Errorf("IsValid(%q) = %v, want %v", tt.version, got, tt.expected)
			}
		})
	}
}
