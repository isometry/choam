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
	return su.checkAllDependencies(lines, packageName), nil
}

// checkAllDependencies checks all possible dependency types in one pass through the lines
func (su *SharedUpdater) checkAllDependencies(lines []string, packageName string) bool {
	inRuntime := false
	inDependencies := false
	inPipeline := false
	inVariables := false

	runtimeIndent := 0
	dependenciesIndent := 0
	pipelineIndent := 0
	variablesIndent := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		currentIndent := len(line) - len(strings.TrimLeft(line, " \t"))

		// Check section starts
		switch {
		case strings.HasPrefix(trimmed, "runtime:"):
			inRuntime = true
			runtimeIndent = currentIndent
		case strings.HasPrefix(trimmed, "dependencies:"):
			inDependencies = true
			dependenciesIndent = currentIndent
		case strings.HasPrefix(trimmed, "pipeline:"):
			inPipeline = true
			pipelineIndent = currentIndent
		case strings.HasPrefix(trimmed, "vars:") || strings.HasPrefix(trimmed, "environment:"):
			inVariables = true
			variablesIndent = currentIndent
		}

		// Reset section flags if we've left the section
		if inRuntime && currentIndent <= runtimeIndent && !strings.HasPrefix(trimmed, "runtime:") && strings.Contains(trimmed, ":") {
			inRuntime = false
		}
		if inDependencies && currentIndent <= dependenciesIndent && !strings.HasPrefix(trimmed, "dependencies:") && strings.Contains(trimmed, ":") {
			inDependencies = false
		}
		if inPipeline && currentIndent <= pipelineIndent && !strings.HasPrefix(trimmed, "-") && strings.Contains(trimmed, ":") && !strings.HasPrefix(trimmed, "pipeline:") {
			inPipeline = false
		}
		if inVariables && currentIndent <= variablesIndent && strings.Contains(trimmed, ":") && !strings.HasPrefix(trimmed, "vars:") && !strings.HasPrefix(trimmed, "environment:") {
			inVariables = false
		}

		// Check for package name in active sections
		if (inRuntime || inDependencies || inPipeline || inVariables) && strings.Contains(trimmed, packageName) {
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
