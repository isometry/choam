package updater

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

var yamlExtensions = []string{".yaml", ".yml"}

// isYAMLFile checks if a filename has a YAML extension
func isYAMLFile(filename string) bool {
	lowerName := strings.ToLower(filename)
	for _, ext := range yamlExtensions {
		if strings.HasSuffix(lowerName, ext) {
			return true
		}
	}
	return false
}

// stripVersionAffix removes a prefix or suffix from a version string using proper glob patterns.
// Uses Go's standard path.Match for correct glob pattern matching.
//
// For prefix patterns (isPrefix=true):
//   - Finds the shortest match and removes it from the beginning
//
// For suffix patterns (isPrefix=false):
//   - Finds the shortest match and removes it from the end
//
// Returns the original string if pattern doesn't match or is empty.
func stripVersionAffix(version, pattern string, isPrefix bool) string {
	if pattern == "" {
		return version
	}

	// Handle simple cases without wildcards
	if !strings.Contains(pattern, "*") {
		if isPrefix {
			return strings.TrimPrefix(version, pattern)
		}
		return strings.TrimSuffix(version, pattern)
	}

	if isPrefix {
		// For prefix patterns, find the shortest matching prefix
		return stripPrefixWithGlob(version, pattern)
	} else {
		// For suffix patterns, find the shortest matching suffix
		return stripSuffixWithGlob(version, pattern)
	}
}

// stripPrefixWithGlob removes a prefix that matches a glob pattern
func stripPrefixWithGlob(version, pattern string) string {
	// Try progressively longer prefixes until we find a match
	for i := 1; i <= len(version); i++ {
		prefix := version[:i]
		matched, err := path.Match(pattern, prefix)
		if err != nil {
			return version // Invalid pattern
		}
		if matched {
			// Return everything after the matched prefix
			return version[i:]
		}
	}
	return version // No match found
}

// stripSuffixWithGlob removes a suffix that matches a glob pattern
func stripSuffixWithGlob(version, pattern string) string {
	// Try progressively longer suffixes until we find a match
	for i := 1; i <= len(version); i++ {
		suffix := version[len(version)-i:]
		matched, err := path.Match(pattern, suffix)
		if err != nil {
			return version // Invalid pattern
		}
		if matched {
			// Return everything before the matched suffix
			return version[:len(version)-i]
		}
	}
	return version // No match found
}

// isMelangeConfig performs a quick check to see if a file is a melange config
func isMelangeConfig(filePath string) bool {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}

	contentStr := string(content)
	// Look for melange-specific fields
	return strings.Contains(contentStr, "package:") &&
		(strings.Contains(contentStr, "pipeline:") || strings.Contains(contentStr, "update:"))
}

// findMelangeFiles finds all YAML files in a directory that appear to be melange configs
func findMelangeFiles(dirPath string) ([]string, error) {
	var files []string

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if isYAMLFile(name) {
			fullPath := filepath.Join(dirPath, name)

			// Quick check if it looks like a melange config
			if isMelangeConfig(fullPath) {
				files = append(files, fullPath)
			}
		}
	}

	return files, nil
}
