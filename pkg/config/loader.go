package config

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"chainguard.dev/melange/pkg/config"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// Loader handles loading and saving melange configurations while preserving YAML structure
type Loader struct{}

// NewLoader creates a new config loader
func NewLoader() *Loader {
	return &Loader{}
}

// LoadWithPreservation loads a melange config while preserving YAML structure and comments
func (l *Loader) LoadWithPreservation(path string) (*config.Configuration, []byte, error) {
	// Read the original YAML content
	originalContent, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading file %s: %w", path, err)
	}

	// Parse the configuration using melange's parser for validation
	cfg, err := config.ParseConfiguration(context.Background(), path)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing melange configuration %s: %w", path, err)
	}

	return cfg, originalContent, nil
}

// UpdateField updates a specific field in the YAML while preserving structure
func (l *Loader) UpdateField(yamlContent []byte, path, newValue string) ([]byte, error) {
	yamlPath, err := yaml.PathString(path)
	if err != nil {
		return nil, fmt.Errorf("creating YAML path %s: %w", path, err)
	}

	// Parse YAML to AST with comments preserved
	file, err := parser.ParseBytes(yamlContent, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	// Use ReplaceWithReader to update the field
	err = yamlPath.ReplaceWithReader(file, strings.NewReader(newValue))
	if err != nil {
		return nil, fmt.Errorf("updating field %s: %w", path, err)
	}

	// Convert back to bytes with formatting preserved
	return []byte(file.String()), nil
}

// UpdateIntField updates an integer field in the YAML
func (l *Loader) UpdateIntField(yamlContent []byte, path string, newValue int64) ([]byte, error) {
	return l.UpdateField(yamlContent, path, fmt.Sprintf("%d", newValue))
}

// UpdatePackageVersion updates the package version (epoch handling moved to EpochApplier)
func (l *Loader) UpdatePackageVersion(yamlContent []byte, newVersion string) ([]byte, error) {
	// Update version
	updated, err := l.UpdateField(yamlContent, "$.package.version", newVersion)
	if err != nil {
		return nil, fmt.Errorf("updating package version: %w", err)
	}

	// Epoch handling is now centralized in EpochApplier
	return updated, nil
}

// IncrementEpoch increments the epoch field by 1
func (l *Loader) IncrementEpoch(yamlContent []byte) ([]byte, error) {
	// Parse to get current epoch
	var parsed map[string]any
	if err := yaml.Unmarshal(yamlContent, &parsed); err != nil {
		return nil, fmt.Errorf("parsing YAML to get current epoch: %w", err)
	}

	currentEpoch := int64(0)
	if pkg, ok := parsed["package"].(map[string]any); ok {
		if epoch, ok := pkg["epoch"].(int); ok {
			currentEpoch = int64(epoch)
		} else if epoch, ok := pkg["epoch"].(int64); ok {
			currentEpoch = epoch
		}
	}

	return l.UpdateIntField(yamlContent, "$.package.epoch", currentEpoch+1)
}

// SetEpoch sets the epoch field to a specific value
func (l *Loader) SetEpoch(yamlContent []byte, newEpoch int64) ([]byte, error) {
	return l.UpdateIntField(yamlContent, "$.package.epoch", newEpoch)
}

// UpdatePipelineField updates a field within a specific pipeline
func (l *Loader) UpdatePipelineField(yamlContent []byte, pipelineIndex int, field, newValue string) ([]byte, error) {
	path := fmt.Sprintf("$.pipeline[%d].with.%s", pipelineIndex, field)
	return l.UpdateField(yamlContent, path, newValue)
}

// FindPipelinesByUse finds pipeline indices that use a specific pipeline type
func (l *Loader) FindPipelinesByUse(yamlContent []byte, useType string) ([]int, error) {
	var parsed map[string]any
	if err := yaml.Unmarshal(yamlContent, &parsed); err != nil {
		return nil, fmt.Errorf("parsing YAML to find pipelines: %w", err)
	}

	var indices []int
	if pipeline, ok := parsed["pipeline"].([]any); ok {
		for i, step := range pipeline {
			if stepMap, ok := step.(map[string]any); ok {
				if uses, ok := stepMap["uses"].(string); ok && uses == useType {
					indices = append(indices, i)
				}
			}
		}
	}

	return indices, nil
}

// GetPipelineWithField gets the with field map for a specific pipeline
func (l *Loader) GetPipelineWithField(yamlContent []byte, pipelineIndex int) (map[string]string, error) {
	var parsed map[string]any
	if err := yaml.Unmarshal(yamlContent, &parsed); err != nil {
		return nil, fmt.Errorf("parsing YAML to get pipeline with field: %w", err)
	}

	if pipeline, ok := parsed["pipeline"].([]any); ok {
		if pipelineIndex < len(pipeline) {
			if stepMap, ok := pipeline[pipelineIndex].(map[string]any); ok {
				if withField, ok := stepMap["with"].(map[string]any); ok {
					result := make(map[string]string)
					for k, v := range withField {
						if str, ok := v.(string); ok {
							result[k] = str
						}
					}
					return result, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("pipeline at index %d not found or has no with field", pipelineIndex)
}

// SaveWithBackup saves the updated YAML content to file with backup
func (l *Loader) SaveWithBackup(path string, content []byte) error {
	return l.Save(path, content, ".bak")
}

// Save saves the updated YAML content to file, optionally creating a backup
// backupSuffix: suffix for backup files (empty = no backup)
// Returns error if save failed, nil if no changes needed or save successful
func (l *Loader) Save(path string, content []byte, backupSuffix string) error {
	// Read the current content to compare
	currentContent, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading current file %s: %w", path, err)
	}

	// Check if content has actually changed
	if bytes.Equal(currentContent, content) {
		// No changes needed
		return nil
	}

	// Create backup if suffix is provided
	if backupSuffix != "" {
		backupPath := path + backupSuffix
		if err := l.copyFile(path, backupPath); err != nil {
			return fmt.Errorf("creating backup %s: %w", backupPath, err)
		}
	}

	// Write updated content
	if err := os.WriteFile(path, content, 0644); err != nil {
		return fmt.Errorf("writing updated file %s: %w", path, err)
	}

	return nil
}

// ValidateUpdatedConfig validates that the updated YAML is still valid
func (l *Loader) ValidateUpdatedConfig(content []byte, tempPath string) error {
	// Write to temp file for validation
	if err := os.WriteFile(tempPath, content, 0644); err != nil {
		return fmt.Errorf("writing temp file for validation: %w", err)
	}
	defer func() { _ = os.Remove(tempPath) }()

	// Try to parse with melange
	_, err := config.ParseConfiguration(context.Background(), tempPath)
	if err != nil {
		return fmt.Errorf("validation failed - updated config is invalid: %w", err)
	}

	return nil
}

// copyFile copies a file from src to dst
func (l *Loader) copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = sourceFile.Close() }()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = destFile.Close() }()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// GetPackageInfo extracts package name and version from YAML content
func (l *Loader) GetPackageInfo(yamlContent []byte) (name, version string, epoch int64, err error) {
	var parsed map[string]any
	if err := yaml.Unmarshal(yamlContent, &parsed); err != nil {
		return "", "", 0, fmt.Errorf("parsing YAML to get package info: %w", err)
	}

	if pkg, ok := parsed["package"].(map[string]any); ok {
		if n, ok := pkg["name"].(string); ok {
			name = n
		}
		if v, ok := pkg["version"].(string); ok {
			version = v
		}
		if e, ok := pkg["epoch"].(int); ok {
			epoch = int64(e)
		} else if e, ok := pkg["epoch"].(int64); ok {
			epoch = e
		}
	}

	return name, version, epoch, nil
}

// GetGoBumpDeps extracts the deps field from a go/bump pipeline
func (l *Loader) GetGoBumpDeps(yamlContent []byte, pipelineIndex int) ([]string, error) {
	withFields, err := l.GetPipelineWithField(yamlContent, pipelineIndex)
	if err != nil {
		return nil, fmt.Errorf("getting pipeline with fields: %w", err)
	}

	deps, ok := withFields["deps"]
	if !ok {
		return []string{}, nil // No deps field
	}

	// Split deps by any whitespace (spaces, tabs, newlines)
	whitespaceRegex := regexp.MustCompile(`\s+`)
	parts := whitespaceRegex.Split(deps, -1)

	var result []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}

	return result, nil
}

// UpdateGoBumpDeps updates the deps field in a go/bump pipeline
func (l *Loader) UpdateGoBumpDeps(yamlContent []byte, pipelineIndex int, newDeps []string) ([]byte, error) {
	if len(newDeps) == 0 {
		// Empty deps - remove the entire go/bump pipeline step
		return l.RemovePipelineStep(yamlContent, pipelineIndex)
	} else {
		// Use block scalar format with |- for any deps (even single dep)
		path := fmt.Sprintf("$.pipeline[%d].with.deps", pipelineIndex)
		depsString := strings.Join(newDeps, "\n")

		// Use the block scalar update function
		return l.UpdateFieldWithBlockScalar(yamlContent, path, depsString)
	}
}

// RemovePipelineStep removes a single pipeline step by index while preserving formatting
func (l *Loader) RemovePipelineStep(yamlContent []byte, pipelineIndex int) ([]byte, error) {
	// Parse YAML to AST with comments preserved
	file, err := parser.ParseBytes(yamlContent, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	// Get the pipeline array using path
	yamlPath, err := yaml.PathString("$.pipeline")
	if err != nil {
		return nil, fmt.Errorf("creating pipeline path: %w", err)
	}

	node, err := yamlPath.FilterFile(file)
	if err != nil {
		return yamlContent, nil // Pipeline not found, return unchanged
	}

	// Check if it's a sequence node (array)
	seqNode, ok := node.(*ast.SequenceNode)
	if !ok {
		return yamlContent, nil // Not a sequence, return unchanged
	}

	// Check if index is valid
	if pipelineIndex < 0 || pipelineIndex >= len(seqNode.Values) {
		return yamlContent, nil // Invalid index, return unchanged
	}

	// Remove the pipeline step by creating new slice without the item at pipelineIndex
	newValues := make([]ast.Node, 0, len(seqNode.Values)-1)
	for i, value := range seqNode.Values {
		if i != pipelineIndex {
			newValues = append(newValues, value)
		}
	}
	seqNode.Values = newValues

	// Return the AST string representation with formatting preserved
	return []byte(file.String()), nil
}

// InsertPipelineStep inserts a new pipeline step at the specified index
func (l *Loader) InsertPipelineStep(yamlContent []byte, pipelineIndex int, pipelineStep map[string]any) ([]byte, error) {
	// Parse YAML to AST with comments preserved
	file, err := parser.ParseBytes(yamlContent, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	// Get the pipeline array using path
	yamlPath, err := yaml.PathString("$.pipeline")
	if err != nil {
		return nil, fmt.Errorf("creating pipeline path: %w", err)
	}

	node, err := yamlPath.FilterFile(file)
	if err != nil {
		return nil, fmt.Errorf("pipeline not found: %w", err)
	}

	// Check if it's a sequence node (array)
	seqNode, ok := node.(*ast.SequenceNode)
	if !ok {
		return nil, fmt.Errorf("pipeline is not a sequence")
	}

	// Convert the pipeline step to YAML node
	stepYAML, err := yaml.Marshal(pipelineStep)
	if err != nil {
		return nil, fmt.Errorf("marshaling pipeline step: %w", err)
	}

	stepNode, err := parser.ParseBytes(stepYAML, 0)
	if err != nil {
		return nil, fmt.Errorf("parsing pipeline step: %w", err)
	}

	// Extract the document node contents
	var stepASTNode ast.Node
	if len(stepNode.Docs) > 0 {
		stepASTNode = stepNode.Docs[0].Body
	} else {
		return nil, fmt.Errorf("invalid pipeline step structure")
	}

	// Insert the new step at the specified index
	if pipelineIndex < 0 {
		pipelineIndex = 0
	}
	if pipelineIndex > len(seqNode.Values) {
		pipelineIndex = len(seqNode.Values)
	}

	// Create new slice with the inserted item
	newValues := make([]ast.Node, 0, len(seqNode.Values)+1)
	newValues = append(newValues, seqNode.Values[:pipelineIndex]...)
	newValues = append(newValues, stepASTNode)
	newValues = append(newValues, seqNode.Values[pipelineIndex:]...)
	seqNode.Values = newValues

	// Return the AST string representation with formatting preserved
	return []byte(file.String()), nil
}
