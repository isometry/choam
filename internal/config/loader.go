package config

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
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
	// Update version using quoted string to ensure proper YAML rendering
	// This prevents values like "1.0" from being rendered as numbers
	updated, err := l.UpdateFieldAsQuotedString(yamlContent, "$.package.version", newVersion)
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

// RemovePipelineWithField removes a single field from a pipeline step's with
// map, preserving the rest of the step and surrounding formatting.
func (l *Loader) RemovePipelineWithField(yamlContent []byte, pipelineIndex int, field string) ([]byte, error) {
	withPath, err := yaml.PathString(fmt.Sprintf("$.pipeline[%d].with", pipelineIndex))
	if err != nil {
		return nil, fmt.Errorf("creating with path: %w", err)
	}

	file, err := parser.ParseBytes(yamlContent, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	node, err := withPath.FilterFile(file)
	if err != nil {
		// No with field - nothing to remove.
		return yamlContent, nil
	}

	mapping, ok := node.(*ast.MappingNode)
	if !ok {
		return yamlContent, nil
	}

	filtered := make([]*ast.MappingValueNode, 0, len(mapping.Values))
	for _, mv := range mapping.Values {
		if mv.Key.GetToken().Value == field {
			continue
		}
		filtered = append(filtered, mv)
	}
	if len(filtered) == len(mapping.Values) {
		// Field not present - nothing to remove.
		return yamlContent, nil
	}
	mapping.Values = filtered

	return []byte(file.String()), nil
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

// whitespaceRegex splits block-scalar or space-separated pipeline field values
// (deps, modroot) into their individual entries.
var whitespaceRegex = regexp.MustCompile(`\s+`)

// splitWhitespaceList splits a string on any whitespace (spaces, tabs, newlines),
// discarding empty entries.
func splitWhitespaceList(value string) []string {
	parts := whitespaceRegex.Split(value, -1)
	var result []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// GetGoBumpDeps extracts the deps field from a bump or go/bump pipeline
func (l *Loader) GetGoBumpDeps(yamlContent []byte, pipelineIndex int) ([]string, error) {
	withFields, err := l.GetPipelineWithField(yamlContent, pipelineIndex)
	if err != nil {
		return nil, fmt.Errorf("getting pipeline with fields: %w", err)
	}

	deps, ok := withFields["deps"]
	if !ok {
		return []string{}, nil // No deps field
	}

	return splitWhitespaceList(deps), nil
}

// GetBumpReplaces extracts the replaces field ("old=new@version" entries) from
// a bump or go/bump pipeline step.
func (l *Loader) GetBumpReplaces(yamlContent []byte, pipelineIndex int) ([]string, error) {
	withFields, err := l.GetPipelineWithField(yamlContent, pipelineIndex)
	if err != nil {
		return nil, fmt.Errorf("getting pipeline with fields: %w", err)
	}

	replaces, ok := withFields["replaces"]
	if !ok {
		return []string{}, nil // No replaces field
	}

	return splitWhitespaceList(replaces), nil
}

// bumpActions are the pipeline "uses" values that perform Go dependency bumps.
// "bump" is the modern, language-agnostic omnibump wrapper (supports a
// multi-valued modroot); "go/bump" is the legacy, single-modroot wrapper.
var bumpActions = []string{"bump", "go/bump"}

// BumpStep describes a bump or go/bump pipeline step and its parsed with-fields.
type BumpStep struct {
	Index     int      // pipeline index
	Action    string   // "bump" or "go/bump"
	Language  string   // parsed with.language entry ("" when absent)
	GoVersion string   // parsed with.go-version entry ("" when absent)
	Modroots  []string // parsed with.modroot entries; defaults to ["."] when absent
	Deps      []string // parsed with.deps entries ("module@version")
	Replaces  []string // parsed with.replaces entries ("old=new@version")
}

// FindBumpSteps finds all bump and go/bump pipeline steps, in pipeline order,
// with their modroot and deps fields parsed.
func (l *Loader) FindBumpSteps(yamlContent []byte) ([]BumpStep, error) {
	var steps []BumpStep

	for _, action := range bumpActions {
		indices, err := l.FindPipelinesByUse(yamlContent, action)
		if err != nil {
			return nil, fmt.Errorf("finding %s pipelines: %w", action, err)
		}

		for _, idx := range indices {
			modroots, err := l.GetBumpModroots(yamlContent, idx)
			if err != nil {
				return nil, fmt.Errorf("getting modroot for pipeline[%d]: %w", idx, err)
			}

			deps, err := l.GetGoBumpDeps(yamlContent, idx)
			if err != nil {
				return nil, fmt.Errorf("getting deps for pipeline[%d]: %w", idx, err)
			}

			replaces, err := l.GetBumpReplaces(yamlContent, idx)
			if err != nil {
				return nil, fmt.Errorf("getting replaces for pipeline[%d]: %w", idx, err)
			}

			var language, goVersion string
			if withFields, err := l.GetPipelineWithField(yamlContent, idx); err == nil {
				language = withFields["language"]
				goVersion = withFields["go-version"]
			}

			steps = append(steps, BumpStep{
				Index:     idx,
				Action:    action,
				Language:  language,
				GoVersion: goVersion,
				Modroots:  modroots,
				Deps:      deps,
				Replaces:  replaces,
			})
		}
	}

	sort.Slice(steps, func(i, j int) bool { return steps[i].Index < steps[j].Index })

	return steps, nil
}

// GetBumpModroots extracts the modroot field from a bump/go-bump pipeline step.
// When the field is absent, it defaults to ["."], matching the pipeline's own
// default (the current directory).
func (l *Loader) GetBumpModroots(yamlContent []byte, pipelineIndex int) ([]string, error) {
	withFields, err := l.GetPipelineWithField(yamlContent, pipelineIndex)
	if err != nil {
		return nil, fmt.Errorf("getting pipeline with fields: %w", err)
	}

	modroot, ok := withFields["modroot"]
	if !ok || strings.TrimSpace(modroot) == "" {
		return []string{"."}, nil
	}

	return splitWhitespaceList(modroot), nil
}

// UpdateGoBumpDeps updates the deps field in a go/bump pipeline
func (l *Loader) UpdateGoBumpDeps(yamlContent []byte, pipelineIndex int, newDeps []string) ([]byte, error) {
	return l.UpdateGoBumpStep(yamlContent, pipelineIndex, newDeps, nil, "")
}

// UpdateGoBumpStep updates a bump/go-bump step's deps, replaces and
// go-version fields in place. Both deps and replaces empty removes the whole
// step; deps empty with replaces present keeps the step (gobump accepts a
// replaces-only invocation) and removes just the deps field; an empty
// replaces list removes just that field. goVersion == "" leaves any existing
// go-version field untouched (it is never removed by this call); a non-empty
// goVersion upserts go-version as a quoted scalar so it can never round-trip
// as a YAML float.
func (l *Loader) UpdateGoBumpStep(yamlContent []byte, pipelineIndex int, deps, replaces []string, goVersion string) ([]byte, error) {
	if len(deps) == 0 && len(replaces) == 0 {
		return l.RemovePipelineStep(yamlContent, pipelineIndex)
	}

	var err error
	if len(deps) == 0 {
		yamlContent, err = l.RemovePipelineWithField(yamlContent, pipelineIndex, "deps")
	} else {
		path := fmt.Sprintf("$.pipeline[%d].with.deps", pipelineIndex)
		yamlContent, err = l.UpdateFieldWithBlockScalar(yamlContent, path, strings.Join(deps, "\n"))
	}
	if err != nil {
		return nil, fmt.Errorf("updating deps for pipeline[%d]: %w", pipelineIndex, err)
	}

	if len(replaces) == 0 {
		yamlContent, err = l.RemovePipelineWithField(yamlContent, pipelineIndex, "replaces")
	} else {
		yamlContent, err = l.UpsertPipelineWithBlockScalar(yamlContent, pipelineIndex, "replaces", strings.Join(replaces, "\n"))
	}
	if err != nil {
		return nil, fmt.Errorf("updating replaces for pipeline[%d]: %w", pipelineIndex, err)
	}

	if goVersion != "" {
		yamlContent, err = l.UpsertPipelineWithQuotedString(yamlContent, pipelineIndex, "go-version", goVersion)
		if err != nil {
			return nil, fmt.Errorf("updating go-version for pipeline[%d]: %w", pipelineIndex, err)
		}
	}

	return yamlContent, nil
}

// goPackagePinActions are the pipeline "uses" values that accept a
// with.go-package pin (the go toolchain version a build/install step
// compiles with).
var goPackagePinActions = map[string]bool{"go/build": true, "go/install": true}

// GoPackagePin locates one go/build|go/install step's with.go-package value.
type GoPackagePin struct {
	Path       string // goccy yaml path, e.g. "$.pipeline[3].with.go-package" or "$.subpackages[2].pipeline[0].with.go-package"
	Subpackage string // subpackage name for messages; "" for top-level
	Value      string // raw string value (possibly templated)
}

// FindGoPackagePins walks the top-level pipeline and every subpackage's
// pipeline for go/build and go/install steps carrying a string
// with.go-package pin, returning one GoPackagePin per pin found - in
// top-level-then-subpackage, then pipeline order. Steps without a go-package
// field are not returned; there's nothing to edit. Each pin's Path is a
// goccy yaml path directly usable with UpdateField to rewrite it in place.
func (l *Loader) FindGoPackagePins(yamlContent []byte) ([]GoPackagePin, error) {
	var parsed map[string]any
	if err := yaml.Unmarshal(yamlContent, &parsed); err != nil {
		return nil, fmt.Errorf("parsing YAML to find go-package pins: %w", err)
	}

	var pins []GoPackagePin
	collectGoPackagePins(&pins, parsed["pipeline"], "$", "")

	if subpackages, ok := parsed["subpackages"].([]any); ok {
		for i, sp := range subpackages {
			spMap, ok := sp.(map[string]any)
			if !ok {
				continue
			}
			name, _ := spMap["name"].(string)
			collectGoPackagePins(&pins, spMap["pipeline"], fmt.Sprintf("$.subpackages[%d]", i), name)
		}
	}

	return pins, nil
}

// collectGoPackagePins appends a GoPackagePin for every go/build|go/install
// step in pipeline (the raw, unmarshalled `pipeline:` sequence value) that
// carries a string with.go-package, using pathPrefix (e.g. "$" or
// "$.subpackages[2]") to build each pin's editable yaml path.
func collectGoPackagePins(pins *[]GoPackagePin, pipeline any, pathPrefix, subpackage string) {
	steps, ok := pipeline.([]any)
	if !ok {
		return
	}
	for i, step := range steps {
		stepMap, ok := step.(map[string]any)
		if !ok {
			continue
		}
		uses, _ := stepMap["uses"].(string)
		if !goPackagePinActions[uses] {
			continue
		}
		withField, ok := stepMap["with"].(map[string]any)
		if !ok {
			continue
		}
		value, ok := withField["go-package"].(string)
		if !ok {
			continue
		}
		*pins = append(*pins, GoPackagePin{
			Path:       fmt.Sprintf("%s.pipeline[%d].with.go-package", pathPrefix, i),
			Subpackage: subpackage,
			Value:      value,
		})
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

	// Remove the pipeline step, keeping any comments on the remaining steps intact
	removeSequenceValue(seqNode, pipelineIndex)

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

	// Insert the new step, keeping any comments on the surrounding steps intact
	insertSequenceValue(seqNode, pipelineIndex, stepASTNode)

	// Return the AST string representation with formatting preserved
	return []byte(file.String()), nil
}
