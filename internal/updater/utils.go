package updater

import (
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"chainguard.dev/melange/pkg/cond"
	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/utils"
)

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
	// For simple cases without wildcards, use faster string operations
	if !strings.Contains(pattern, "*") && !strings.Contains(pattern, "?") {
		return strings.TrimPrefix(version, pattern)
	}

	// For patterns with wildcards, find the shortest match by trying progressively longer prefixes
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
	// For simple cases without wildcards, use faster string operations
	if !strings.Contains(pattern, "*") && !strings.Contains(pattern, "?") {
		return strings.TrimSuffix(version, pattern)
	}

	// For patterns with wildcards, find the shortest match by trying progressively longer suffixes
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
		// Handle standard melange variables first (most common case)
		if value, ok := resolveStandardVariable(key, cfg, version); ok {
			return value, nil
		}

		// Handle vars.* variables from config
		if cfg != nil && strings.HasPrefix(key, "vars.") {
			return resolveVarsVariable(key, cfg, version)
		}

		return "", fmt.Errorf("variable %q not defined", key)
	}
}

// resolveStandardVariable handles built-in melange variables
func resolveStandardVariable(key string, cfg *melange.Configuration, version string) (string, bool) {
	switch key {
	case "package.version", "package.full-version":
		return version, true
	case "package.name":
		if cfg != nil {
			return cfg.Package.Name, true
		}
		return "", false
	case "package.epoch":
		if cfg != nil {
			return fmt.Sprintf("%d", cfg.Package.Epoch), true
		}
		return "0", true
	}
	return "", false
}

// resolveVarsVariable handles vars.* variables including transforms
func resolveVarsVariable(key string, cfg *melange.Configuration, version string) (string, error) {
	varName := strings.TrimPrefix(key, "vars.")

	// Check direct vars first (most common case)
	if value, ok := cfg.Vars[varName]; ok {
		return value, nil
	}

	// Check var-transforms
	for _, transform := range cfg.VarTransforms {
		if transform.To != varName {
			continue
		}

		// Found matching transform - apply it
		fromValue, err := cond.Subst(transform.From, createVariableLookup(cfg, version))
		if err != nil {
			return "", fmt.Errorf("resolving transform source %q: %w", transform.From, err)
		}

		re, err := regexp.Compile(transform.Match)
		if err != nil {
			return "", fmt.Errorf("compiling transform regex %q: %w", transform.Match, err)
		}

		return re.ReplaceAllString(fromValue, transform.Replace), nil
	}

	return "", fmt.Errorf("variable %q not defined", key)
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
		if utils.IsYAMLFile(name) {
			fullPath := filepath.Join(dirPath, name)

			// Quick check if it looks like a melange config
			if isMelangeConfig(fullPath) {
				files = append(files, fullPath)
			}
		}
	}

	return files, nil
}
