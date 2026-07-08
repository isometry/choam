// Package goversion provides comparison helpers for bare Go language/directive version strings
// as they appear in go.mod `go` directives and melange `go-version` inputs (e.g., "1.24", "1.24.5", "1.25rc1").
// These functions operate on bare version strings without "v" or "go" prefixes.
package goversion

import (
	"go/version"
	"strings"
)

// Compare compares two bare Go directive versions (e.g. "1.24", "1.24.5",
// "1.25rc1"). It returns -1, 0, or +1. Invalid versions sort below all
// valid versions; two invalid versions compare equal.
func Compare(a, b string) int {
	aValid := IsValid(a)
	bValid := IsValid(b)

	// Both invalid: equal
	if !aValid && !bValid {
		return 0
	}
	// Invalid < valid
	if !aValid {
		return -1
	}
	if !bValid {
		return +1
	}

	// Both valid: use stdlib version.Compare with "go" prefix
	result := version.Compare("go"+a, "go"+b)
	return result
}

// Max returns the highest of the given versions, ignoring invalid or empty
// entries. It returns "" when no valid version is present.
func Max(vs ...string) string {
	var maxVer string
	for _, v := range vs {
		if !IsValid(v) {
			continue
		}
		if maxVer == "" || Compare(v, maxVer) > 0 {
			maxVer = v
		}
	}
	return maxVer
}

// Minor returns the major.minor language version of v (e.g. "1.25.3" ->
// "1.25", "1.25rc1" -> "1.25"). It returns "" for invalid input.
func Minor(v string) string {
	if !IsValid(v) {
		return ""
	}
	// Use stdlib version.Lang which returns the major.minor part with "go" prefix
	lang := version.Lang("go" + v)
	// Strip the "go" prefix
	return strings.TrimPrefix(lang, "go")
}

// IsValid reports whether v is a valid bare Go directive version.
func IsValid(v string) bool {
	// Empty string is invalid
	if v == "" {
		return false
	}
	// Don't allow go- or v-prefixed strings
	if strings.HasPrefix(v, "go") || strings.HasPrefix(v, "v") {
		return false
	}
	// Use stdlib version.IsValid with "go" prefix
	return version.IsValid("go" + v)
}
