package updater

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	melangeConfig "github.com/isometry/choam/pkg/config"
)

// SharedUpdater handles updates to packages with shared dependencies
type SharedUpdater struct{}

// NewSharedUpdater creates a new shared updater
func NewSharedUpdater() *SharedUpdater {
	return &SharedUpdater{}
}

// UpdateSharedDependencies updates packages that depend on the updated package
func (su *SharedUpdater) UpdateSharedDependencies(ctx context.Context, updatedFilePath, updatedPackageName string, opts *ApplyOptions) ([]string, error) {
	var results []string

	// Get directory containing the updated package
	dir := filepath.Dir(updatedFilePath)

	// Find all melange files in the same directory
	melangeFiles, err := findMelangeFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("finding melange files in %s: %w", dir, err)
	}

	// Check each file for dependencies on the updated package
	for _, filePath := range melangeFiles {
		// Skip the file we just updated
		if filePath == updatedFilePath {
			continue
		}

		updated, err := su.updateDependentPackage(filePath, updatedPackageName, opts)
		if err != nil {
			results = append(results, fmt.Sprintf("Error updating %s: %v", filepath.Base(filePath), err))
			continue
		}

		if updated {
			results = append(results, fmt.Sprintf("Updated epoch for %s", filepath.Base(filePath)))
		}
	}

	return results, nil
}

// updateDependentPackage checks if a package depends on the updated package and updates it
func (su *SharedUpdater) updateDependentPackage(filePath, updatedPackageName string, opts *ApplyOptions) (bool, error) {
	loader := melangeConfig.NewLoader()

	// Load the file to check for dependencies
	_, originalContent, err := loader.LoadWithPreservation(filePath)
	if err != nil {
		return false, fmt.Errorf("loading file %s: %w", filePath, err)
	}

	// Check if this package depends on the updated package
	depends, err := su.dependsOn(originalContent, updatedPackageName)
	if err != nil {
		return false, fmt.Errorf("checking dependencies: %w", err)
	}

	if !depends {
		return false, nil // No dependency found
	}

	// Increment epoch for the dependent package
	updatedContent, err := loader.IncrementEpoch(originalContent)
	if err != nil {
		return false, fmt.Errorf("incrementing epoch: %w", err)
	}

	// Save the updated file if not in dry run mode
	if !opts.DryRun {
		if err := loader.SaveWithBackup(filePath, updatedContent); err != nil {
			return false, fmt.Errorf("saving updated file: %w", err)
		}
	}

	return true, nil
}

// dependsOn checks if a package configuration depends on another package
func (su *SharedUpdater) dependsOn(yamlContent []byte, packageName string) (bool, error) {
	// Split content once to avoid repeated string operations
	lines := strings.Split(string(yamlContent), "\n")

	// Check various ways a package might depend on another:

	// 1. Runtime dependencies
	if su.checkInSection(lines, "runtime:", packageName) {
		return true, nil
	}

	// 2. Build dependencies
	if su.checkInSection(lines, "dependencies:", packageName) {
		return true, nil
	}

	// 3. Pipeline references (like go/bump with specific module)
	if su.checkInPipelines(lines, packageName) {
		return true, nil
	}

	// 4. Environment or variable references
	if su.checkInVariables(lines, packageName) {
		return true, nil
	}

	return false, nil
}

// checkInSection checks if a package is referenced in a specific YAML section
// Uses pre-split lines to avoid repeated string operations
func (su *SharedUpdater) checkInSection(lines []string, sectionName, packageName string) bool {
	inSection := false
	sectionIndent := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check if we're entering the target section
		if strings.HasPrefix(trimmed, sectionName) {
			inSection = true
			sectionIndent = len(line) - len(strings.TrimLeft(line, " \t"))
			continue
		}

		if inSection {
			currentIndent := len(line) - len(strings.TrimLeft(line, " \t"))

			// If we're at the same or less indentation level and it's not empty/comment, we've left the section
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") && currentIndent <= sectionIndent {
				inSection = false
				continue
			}

			// Check for package references in this section
			if strings.Contains(trimmed, packageName) {
				return true
			}
		}
	}

	return false
}

// checkInPipelines checks if a package is referenced in pipeline configurations
// Uses pre-split lines to avoid repeated string operations
func (su *SharedUpdater) checkInPipelines(lines []string, packageName string) bool {
	inPipeline := false
	pipelineIndent := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check if we're entering pipeline section
		if strings.HasPrefix(trimmed, "pipeline:") {
			inPipeline = true
			pipelineIndent = len(line) - len(strings.TrimLeft(line, " \t"))
			continue
		}

		if inPipeline {
			currentIndent := len(line) - len(strings.TrimLeft(line, " \t"))

			// If we're at the same or less indentation and not empty/comment, check if we left pipelines
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") && currentIndent <= pipelineIndent {
				// This might be the start of a new top-level section
				if !strings.HasPrefix(trimmed, "-") && strings.Contains(trimmed, ":") {
					inPipeline = false
					continue
				}
			}

			// Check for package references in pipeline steps
			if strings.Contains(trimmed, packageName) {
				return true
			}
		}
	}

	return false
}

// checkInVariables checks if a package is referenced in variables or environment sections
// Uses pre-split lines to avoid repeated string operations
func (su *SharedUpdater) checkInVariables(lines []string, packageName string) bool {
	variableSections := []string{"vars:", "environment:"}

	for _, section := range variableSections {
		if su.checkInSection(lines, section, packageName) {
			return true
		}
	}

	return false
}

// GetSharedDependencies analyzes a directory to find which packages have shared dependencies
func (su *SharedUpdater) GetSharedDependencies(dirPath string) (map[string][]string, error) {
	dependencies := make(map[string][]string)

	// Find all melange files
	melangeFiles, err := findMelangeFiles(dirPath)
	if err != nil {
		return nil, fmt.Errorf("finding melange files: %w", err)
	}

	// Cache file contents to avoid reading twice
	fileContents := make(map[string][]byte)
	packageNames := make([]string, 0, len(melangeFiles))
	fileToPackage := make(map[string]string)

	// Read all files once and extract package names
	for _, filePath := range melangeFiles {
		content, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		fileContents[filePath] = content

		loader := melangeConfig.NewLoader()
		name, _, _, err := loader.GetPackageInfo(content)
		if err != nil {
			continue
		}

		packageNames = append(packageNames, name)
		fileToPackage[filePath] = name
	}

	// Check dependencies between packages using cached content
	for _, filePath := range melangeFiles {
		packageName := fileToPackage[filePath]
		content, ok := fileContents[filePath]
		if !ok {
			continue
		}

		var deps []string
		for _, otherPackage := range packageNames {
			if otherPackage == packageName {
				continue
			}

			depends, err := su.dependsOn(content, otherPackage)
			if err != nil {
				continue
			}

			if depends {
				deps = append(deps, otherPackage)
			}
		}

		if len(deps) > 0 {
			dependencies[packageName] = deps
		}
	}

	return dependencies, nil
}
