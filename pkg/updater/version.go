package updater

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// VersionComparator handles version comparison logic
type VersionComparator struct {
	verbose bool
}

// NewVersionComparator creates a new version comparator
func NewVersionComparator() *VersionComparator {
	return &VersionComparator{verbose: false}
}

// SetVerbose sets the verbose flag for debugging output
func (vc *VersionComparator) SetVerbose(verbose bool) {
	vc.verbose = verbose
}

// isMultiPartNumeric checks if a version consists only of numbers and dots
func isMultiPartNumeric(version string) bool {
	// Remove 'v' prefix if present
	v := strings.TrimPrefix(version, "v")
	// Check if it's purely numeric parts separated by dots
	pattern := `^\d+(\.\d+)*$`
	matched, _ := regexp.MatchString(pattern, v)
	return matched
}

// compareMultiPart compares multi-part numeric versions
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareMultiPart(v1, v2 string) int {
	// Remove 'v' prefix if present
	v1 = strings.TrimPrefix(v1, "v")
	v2 = strings.TrimPrefix(v2, "v")

	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := max(len(parts2), len(parts1))

	for i := range maxLen {
		p1, p2 := 0, 0
		if i < len(parts1) {
			p1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			p2, _ = strconv.Atoi(parts2[i])
		}
		if p1 != p2 {
			if p1 < p2 {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Compare compares two versions, returning:
// -1 if v1 < v2
//
//	0 if v1 == v2
//	1 if v1 > v2
func (vc *VersionComparator) Compare(v1, v2 string) (int, error) {
	// Try SemVer first
	version1 := vc.normalizeVersion(v1)
	version2 := vc.normalizeVersion(v2)

	sv1, err1 := semver.NewVersion(version1)
	sv2, err2 := semver.NewVersion(version2)

	// If both parse as SemVer, use SemVer comparison
	if err1 == nil && err2 == nil {
		return sv1.Compare(sv2), nil
	}

	// If both are multi-part numeric, use multi-part comparison
	if isMultiPartNumeric(v1) && isMultiPartNumeric(v2) {
		return compareMultiPart(v1, v2), nil
	}

	// Otherwise, return the original error
	if err1 != nil {
		return 0, fmt.Errorf("parsing version %s: %w", v1, err1)
	}
	return 0, fmt.Errorf("parsing version %s: %w", v2, err2)
}

// IsNewer returns true if newVersion is newer than currentVersion
func (vc *VersionComparator) IsNewer(currentVersion, newVersion string) (bool, error) {
	result, err := vc.Compare(currentVersion, newVersion)
	if err != nil {
		return false, err
	}
	return result < 0, nil
}

// normalizeVersion ensures version has proper format for semver parsing
func (vc *VersionComparator) normalizeVersion(version string) string {
	// If version already starts with 'v', return as-is
	if strings.HasPrefix(version, "v") {
		return version
	}

	// Add 'v' prefix for semver compatibility
	return "v" + version
}

// ApplyTransform applies a regex-based transformation to a version string
func (vc *VersionComparator) ApplyTransform(version, match, replace string) (string, error) {
	if match == "" {
		return version, nil
	}

	regex, err := regexp.Compile(match)
	if err != nil {
		return version, fmt.Errorf("compiling regex %s: %w", match, err)
	}

	return regex.ReplaceAllString(version, replace), nil
}

// MatchesIgnorePattern checks if a version matches any of the ignore patterns
func (vc *VersionComparator) MatchesIgnorePattern(version string, patterns []string) (bool, error) {
	return vc.matchesIgnorePatternVerbose(version, patterns, vc.verbose)
}

// matchesIgnorePatternVerbose checks if a version matches any of the ignore patterns with optional verbose output
func (vc *VersionComparator) matchesIgnorePatternVerbose(version string, patterns []string, verbose bool) (bool, error) {
	for _, pattern := range patterns {
		matched, err := regexp.MatchString(pattern, version)
		if err != nil {
			return false, fmt.Errorf("matching pattern %s: %w", pattern, err)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "[DEBUG]     Pattern %q vs %q: %v\n", pattern, version, matched)
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

// IsValidVersion checks if a version is valid semver and handles pre-release filtering
func (vc *VersionComparator) IsValidVersion(version string, allowPreRelease bool) bool {
	// First, check if it's a valid multi-part numeric version
	if isMultiPartNumeric(version) {
		// Multi-part numeric versions don't have pre-release concept
		return true
	}

	// Otherwise, check SemVer validity
	normalized := vc.normalizeVersion(version)
	sv, err := semver.NewVersion(normalized)
	if err != nil {
		return false
	}

	// If pre-releases not allowed, exclude versions with pre-release tags
	if !allowPreRelease && sv.Prerelease() != "" {
		return false
	}

	return true
}

// FilterPreReleases filters out pre-release versions unless enabled
func (vc *VersionComparator) FilterPreReleases(versions []string, enablePreReleases bool) []string {
	var filtered []string
	for _, version := range versions {
		// Multi-part numeric versions pass through (no pre-release concept)
		if isMultiPartNumeric(version) {
			filtered = append(filtered, version)
			continue
		}

		// For SemVer versions, apply pre-release filtering
		normalized := vc.normalizeVersion(version)
		sv, err := semver.NewVersion(normalized)
		if err != nil {
			continue // Skip invalid SemVer
		}

		if enablePreReleases || sv.Prerelease() == "" {
			filtered = append(filtered, version)
		}
	}

	return filtered
}
