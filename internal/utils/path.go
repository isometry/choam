package utils

import "strings"

// IsLocalPath determines if a path is a local filesystem path
// This is used by both go/bump analysis and vulnerability scanning
// to identify local module replacements that should be treated specially
func IsLocalPath(path string) bool {
	return path == "" ||
		strings.HasPrefix(path, ".") ||
		strings.HasPrefix(path, "/") ||
		strings.Contains(path, "\\") // Windows paths
}
