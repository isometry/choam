package updater

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"chainguard.dev/melange/pkg/config"
	melangeConfig "github.com/isometry/choam/pkg/config"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// GoBumpUpdater handles optimization of go/bump pipeline steps
type GoBumpUpdater struct {
	httpClient *http.Client
}

// NewGoBumpUpdater creates a new go/bump pipeline updater
func NewGoBumpUpdater(httpClient *http.Client) *GoBumpUpdater {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &GoBumpUpdater{
		httpClient: httpClient,
	}
}

// BumpAnalysis represents the analysis result for a single bump
type BumpAnalysis struct {
	Module      string
	BumpVersion string
	GoModVersion string
	Action      string // "keep", "remove-noop", "remove-downgrade", "remove-missing"
	Reason      string
}

// UpdateGoBumpPipelines processes all go/bump pipelines and optimizes them
func (gbu *GoBumpUpdater) UpdateGoBumpPipelines(ctx context.Context, yamlContent []byte, cfg *config.Configuration, updateResult *UpdateResult) ([]byte, []string, error) {
	if !updateResult.HasUpdate {
		return yamlContent, nil, nil
	}

	loader := melangeConfig.NewLoader()
	var updatesApplied []string
	currentContent := yamlContent

	// Find all go/bump pipelines
	goBumpIndices, err := loader.FindPipelinesByUse(yamlContent, "go/bump")
	if err != nil {
		return yamlContent, nil, fmt.Errorf("finding go/bump pipelines: %w", err)
	}

	if len(goBumpIndices) == 0 {
		return yamlContent, nil, nil // No go/bump pipelines found
	}

	// Check if there's a git-checkout pipeline to get repository info
	repoURL, tag, err := gbu.extractRepositoryInfo(yamlContent, cfg, updateResult.LatestVersion)
	if err != nil {
		return yamlContent, nil, fmt.Errorf("extracting repository info: %w", err)
	}

	if repoURL == "" {
		// No repository info available, report that go/bump analysis was skipped
		for i := len(goBumpIndices) - 1; i >= 0; i-- {
			index := goBumpIndices[i]
			updatesApplied = append(updatesApplied, 
				fmt.Sprintf("pipeline[%d].with.deps (go/bump skipped - no git-checkout found)", index))
		}
		return yamlContent, updatesApplied, nil
	}

	// Process go/bump pipelines in reverse order to handle index changes
	for i := len(goBumpIndices) - 1; i >= 0; i-- {
		index := goBumpIndices[i]
		
		// Get pipeline configuration including modroot
		withFields, err := loader.GetPipelineWithField(currentContent, index)
		if err != nil {
			updatesApplied = append(updatesApplied, 
				fmt.Sprintf("pipeline[%d].with.deps (go/bump failed - config error)", index))
			continue // Skip this pipeline but continue with others
		}
		
		// Extract modroot (default to "." if not specified)
		modroot := withFields["modroot"]
		if modroot == "" {
			modroot = "."
		}
		
		// Build path to go.mod based on modroot
		goModPath := "go.mod"
		if modroot != "." && modroot != "" {
			goModPath = modroot + "/go.mod"
		}
		
		// Fetch go.mod for this specific pipeline
		goModContent, err := gbu.fetchGoMod(ctx, repoURL, tag, goModPath)
		if err != nil {
			// Report error for this specific pipeline
			updatesApplied = append(updatesApplied, 
				fmt.Sprintf("pipeline[%d].with.deps (go/bump check skipped - %s)", index, err.Error()))
			continue // Skip this pipeline but continue with others
		}
		
		// Parse go.mod for this pipeline
		requirements, err := gbu.parseGoMod(goModContent)
		if err != nil {
			// Report parse error for this specific pipeline
			updatesApplied = append(updatesApplied, 
				fmt.Sprintf("pipeline[%d].with.deps (go.mod parse failed - %s)", index, err.Error()))
			continue // Skip this pipeline but continue with others
		}
		
		// Get current deps from the pipeline
		deps, err := loader.GetGoBumpDeps(currentContent, index)
		if err != nil {
			updatesApplied = append(updatesApplied, 
				fmt.Sprintf("pipeline[%d].with.deps (go/bump failed - deps error)", index))
			continue // Skip this pipeline but continue with others
		}

		// Analyze and filter bumps
		analysis, filteredDeps := gbu.analyzeBumps(deps, requirements)
		
		if len(filteredDeps) == 0 {
			// Remove entire go/bump pipeline
			currentContent, err = loader.RemovePipelineStep(currentContent, index)
			if err != nil {
				return yamlContent, updatesApplied, fmt.Errorf("removing go/bump pipeline[%d]: %w", index, err)
			}
			updatesApplied = append(updatesApplied, fmt.Sprintf("removed pipeline[%d] (go/bump - all bumps obsolete)", index))
		} else if len(filteredDeps) < len(deps) {
			// Update deps with filtered list
			currentContent, err = loader.UpdateGoBumpDeps(currentContent, index, filteredDeps)
			if err != nil {
				return yamlContent, updatesApplied, fmt.Errorf("updating go/bump deps for pipeline[%d]: %w", index, err)
			}
			
			removedCount := len(deps) - len(filteredDeps)
			updatesApplied = append(updatesApplied, fmt.Sprintf("pipeline[%d].with.deps (removed %d obsolete bumps)", index, removedCount))
		}
		// else: No changes needed, don't add to updatesApplied
		
		// Log analysis for debugging if needed
		for _, a := range analysis {
			if a.Action != "keep" {
				// Could add verbose logging here
				_ = a
			}
		}
	}

	return currentContent, updatesApplied, nil
}

// extractRepositoryInfo extracts repository URL and tag from git-checkout pipeline
func (gbu *GoBumpUpdater) extractRepositoryInfo(yamlContent []byte, cfg *config.Configuration, newVersion string) (string, string, error) {
	loader := melangeConfig.NewLoader()
	
	// Find git-checkout pipelines
	gitCheckoutIndices, err := loader.FindPipelinesByUse(yamlContent, "git-checkout")
	if err != nil {
		return "", "", fmt.Errorf("finding git-checkout pipelines: %w", err)
	}
	
	if len(gitCheckoutIndices) == 0 {
		return "", "", nil // No git-checkout found
	}
	
	// Use the first git-checkout pipeline
	withFields, err := loader.GetPipelineWithField(yamlContent, gitCheckoutIndices[0])
	if err != nil {
		return "", "", fmt.Errorf("getting git-checkout with fields: %w", err)
	}
	
	repository, ok := withFields["repository"]
	if !ok {
		return "", "", nil
	}
	
	tag, ok := withFields["tag"]
	if !ok {
		return "", "", nil
	}
	
	// Expand variables in tag (e.g., v${{package.version}})
	expandedTag := gbu.expandVariables(tag, newVersion)
	
	return repository, expandedTag, nil
}

// expandVariables expands template variables in strings
func (gbu *GoBumpUpdater) expandVariables(input string, version string) string {
	// Simple variable expansion for package.version
	result := input
	result = strings.ReplaceAll(result, "${{package.version}}", version)
	return result
}

// fetchGoMod fetches go.mod content from a git repository
func (gbu *GoBumpUpdater) fetchGoMod(ctx context.Context, repoURL, tag, goModPath string) ([]byte, error) {
	// Convert GitHub repository URL to raw content URL
	rawURL, err := gbu.buildRawURL(repoURL, tag, goModPath)
	if err != nil {
		return nil, fmt.Errorf("building raw URL: %w", err)
	}
	
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	
	resp, err := gbu.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching go.mod: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusNotFound:
			return nil, fmt.Errorf("go.mod not found at %s", goModPath)
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("authentication required for private repository")
		case http.StatusForbidden:
			return nil, fmt.Errorf("access denied (check token permissions or rate limit)")
		case http.StatusTooManyRequests:
			return nil, fmt.Errorf("GitHub API rate limit exceeded")
		default:
			return nil, fmt.Errorf("failed to fetch go.mod: HTTP %d", resp.StatusCode)
		}
	}
	
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	
	return content, nil
}

// buildRawURL converts a GitHub repository URL to raw content URL
func (gbu *GoBumpUpdater) buildRawURL(repoURL, tag, filepath string) (string, error) {
	// Ensure filepath doesn't start with /
	filepath = strings.TrimPrefix(filepath, "/")
	
	// Handle GitHub URLs
	githubPattern := regexp.MustCompile(`https://github\.com/([^/]+)/([^/]+)`)
	matches := githubPattern.FindStringSubmatch(repoURL)
	
	if len(matches) == 3 {
		owner := matches[1]
		repo := matches[2]
		return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, tag, filepath), nil
	}
	
	return "", fmt.Errorf("unsupported repository URL format: %s", repoURL)
}

// parseGoMod parses go.mod content and extracts module requirements
func (gbu *GoBumpUpdater) parseGoMod(content []byte) (map[string]string, error) {
	modFile, err := modfile.Parse("go.mod", content, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod: %w", err)
	}
	
	requirements := make(map[string]string)
	for _, req := range modFile.Require {
		requirements[req.Mod.Path] = req.Mod.Version
	}
	
	return requirements, nil
}

// analyzeBumps analyzes each bump and determines whether to keep or remove it
func (gbu *GoBumpUpdater) analyzeBumps(deps []string, requirements map[string]string) ([]BumpAnalysis, []string) {
	var analysis []BumpAnalysis
	var filteredDeps []string
	
	for _, dep := range deps {
		dep = strings.TrimSpace(dep)
		if dep == "" {
			continue
		}
		
		// Parse module@version
		parts := strings.Split(dep, "@")
		if len(parts) != 2 {
			// Malformed dep, keep it as is
			filteredDeps = append(filteredDeps, dep)
			analysis = append(analysis, BumpAnalysis{
				Module:      dep,
				BumpVersion: "",
				GoModVersion: "",
				Action:      "keep",
				Reason:      "malformed dependency, keeping as-is",
			})
			continue
		}
		
		module := parts[0]
		bumpVersion := parts[1]
		
		goModVersion, exists := requirements[module]
		if !exists {
			// Module not in go.mod, remove the bump
			analysis = append(analysis, BumpAnalysis{
				Module:       module,
				BumpVersion:  bumpVersion,
				GoModVersion: "",
				Action:       "remove-missing",
				Reason:       "module not in go.mod",
			})
			continue
		}
		
		// Compare versions using semver
		cmp := semver.Compare(bumpVersion, goModVersion)
		
		var action, reason string
		switch {
		case cmp > 0:
			action = "keep"
			reason = "bump needed"
			filteredDeps = append(filteredDeps, dep)
		case cmp == 0:
			action = "remove-noop"
			reason = "same version as go.mod"
		case cmp < 0:
			action = "remove-downgrade"
			reason = "would downgrade from go.mod version"
		}
		
		analysis = append(analysis, BumpAnalysis{
			Module:       module,
			BumpVersion:  bumpVersion,
			GoModVersion: goModVersion,
			Action:       action,
			Reason:       reason,
		})
	}
	
	return analysis, filteredDeps
}