package updater

import (
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	melange "chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/cond"
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
// Optimized to read only the first part of the file for efficiency
func isMelangeConfig(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Log the error but don't fail the function
			// since this is just a cleanup operation
			slog.Debug("Failed to close file", "error", err, "file", filePath)
		}
	}()

	// Read only the first 1KB to check for melange markers
	buffer := make([]byte, 1024)
	n, err := file.Read(buffer)
	if err != nil && n == 0 {
		return false
	}

	contentStr := string(buffer[:n])
	// Look for melange-specific fields in the beginning of the file
	hasPackage := strings.Contains(contentStr, "package:")
	hasMarker := strings.Contains(contentStr, "pipeline:") || strings.Contains(contentStr, "update:")

	return hasPackage && hasMarker
}

// createVariableLookup creates a VariableLookupFunction that handles melange variable substitution
// Supports standard variables, config vars, and var-transforms
func createVariableLookup(cfg *melange.Configuration, version string) cond.VariableLookupFunction {
	return func(key string) (string, error) {
		// Handle standard melange variables
		switch key {
		case "package.version":
			return version, nil
		case "package.full-version":
			return version, nil
		case "package.name":
			if cfg != nil {
				return cfg.Package.Name, nil
			}
			return "", fmt.Errorf("package name not available")
		case "package.epoch":
			if cfg != nil {
				return fmt.Sprintf("%d", cfg.Package.Epoch), nil
			}
			return "0", nil
		}

		// Handle vars.* variables from config
		if cfg != nil && strings.HasPrefix(key, "vars.") {
			varName := strings.TrimPrefix(key, "vars.")
			
			// First check direct vars
			if value, ok := cfg.Vars[varName]; ok {
				return value, nil
			}

			// Then check var-transforms
			for _, transform := range cfg.VarTransforms {
				if transform.To == varName {
					// Recursively resolve the 'from' variable first
					fromValue, err := cond.Subst(transform.From, createVariableLookup(cfg, version))
					if err != nil {
						return "", fmt.Errorf("resolving transform source %q: %w", transform.From, err)
					}

					// Apply the regex transformation
					re, err := regexp.Compile(transform.Match)
					if err != nil {
						return "", fmt.Errorf("compiling transform regex %q: %w", transform.Match, err)
					}

					return re.ReplaceAllString(fromValue, transform.Replace), nil
				}
			}
		}

		return "", fmt.Errorf("variable %q not defined", key)
	}
}

// substituteVariables performs template variable substitution using melange's cond.Subst
// This replaces our custom implementation with melange's battle-tested logic
func substituteVariables(template, version string) string {
	return substituteVariablesWithConfig(template, version, nil)
}

// substituteVariablesWithConfig performs template variable substitution with full melange config support
func substituteVariablesWithConfig(template, version string, cfg *melange.Configuration) string {
	lookupFn := createVariableLookup(cfg, version)
	result, err := cond.Subst(template, lookupFn)
	if err != nil {
		// Fallback to original template if substitution fails
		// This maintains backward compatibility
		slog.Debug("Variable substitution failed", "template", template, "error", err)
		return template
	}
	return result
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
