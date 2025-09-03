package updater

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"chainguard.dev/melange/pkg/config"
	melangeConfig "github.com/isometry/choam/pkg/config"
	"github.com/isometry/choam/pkg/scan"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// GoBumpUpdater handles optimization of go/bump pipeline steps
type GoBumpUpdater struct {
	httpClient           *http.Client
	vulnerabilityScanner *scan.VulnerabilityScanner
}

// NewGoBumpUpdater creates a new go/bump pipeline updater
func NewGoBumpUpdater(httpClient *http.Client) *GoBumpUpdater {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &GoBumpUpdater{
		httpClient:           httpClient,
		vulnerabilityScanner: scan.NewVulnerabilityScanner(httpClient),
	}
}

// BumpAnalysis represents the analysis result for a single bump
type BumpAnalysis struct {
	Module       string
	BumpVersion  string
	GoModVersion string
	Action       string // "keep", "remove-noop", "remove-downgrade", "remove-missing"
	Reason       string
}

// SecurityUpdateResult represents the result of security scanning and updates
type SecurityUpdateResult struct {
	Content        []byte   `json:"-"` // Updated YAML content
	UpdatesApplied []string `json:"updates_applied"`
}

// UpdateGoBumpPipelines processes all go/bump pipelines and optimizes them
func (gbu *GoBumpUpdater) UpdateGoBumpPipelines(ctx context.Context, updateContext *UpdateContext, cfg *config.Configuration, updateResult *UpdateResult, securityScan bool) error {
	// Skip if no update and no security scan requested
	if !updateResult.HasUpdate && !securityScan {
		return nil
	}

	loader := melangeConfig.NewLoader()

	// Get repository info needed for processing
	repoURL, tag, err := gbu.extractRepositoryInfo(updateContext.CurrentContent, cfg, updateResult.LatestVersion)
	if err != nil {
		return fmt.Errorf("extracting repository info: %w", err)
	}

	// Process go/bump pipelines
	err = gbu.processGoBumpPipelines(ctx, loader, updateContext, repoURL, tag)
	if err != nil {
		return err
	}

	// Handle security scanning
	if securityScan {
		err = gbu.processSecurityScanning(ctx, updateContext, repoURL, tag)
		if err != nil {
			updateContext.UpdateMessages = append(updateContext.UpdateMessages, fmt.Sprintf("security scan failed: %v", err))
		}
	}

	return nil
}

// processGoBumpPipelines handles the main go/bump pipeline processing logic
func (gbu *GoBumpUpdater) processGoBumpPipelines(ctx context.Context, loader *melangeConfig.Loader, updateContext *UpdateContext, repoURL, tag string) error {
	// Find all go/bump pipelines
	goBumpIndices, err := loader.FindPipelinesByUse(updateContext.CurrentContent, "go/bump")
	if err != nil {
		return fmt.Errorf("finding go/bump pipelines: %w", err)
	}

	if repoURL == "" {
		// No repository info available, report that go/bump analysis was skipped
		skippedMessages := gbu.reportSkippedPipelines(goBumpIndices)
		updateContext.UpdateMessages = append(updateContext.UpdateMessages, skippedMessages...)
		return nil
	}

	// Process go/bump pipelines in reverse order to handle index changes
	for i := len(goBumpIndices) - 1; i >= 0; i-- {
		index := goBumpIndices[i]
		update, newContent, err := gbu.processSingleGoBumpPipeline(ctx, loader, updateContext.CurrentContent, index, repoURL, tag)

		if err != nil {
			return err
		}

		updateContext.CurrentContent = newContent
		if update != "" {
			updateContext.AddGoBumpUpdate(update)
		}
	}

	return nil
}

// reportSkippedPipelines creates update messages for skipped pipelines
func (gbu *GoBumpUpdater) reportSkippedPipelines(goBumpIndices []int) []string {
	var updates []string
	for i := len(goBumpIndices) - 1; i >= 0; i-- {
		index := goBumpIndices[i]
		updates = append(updates,
			fmt.Sprintf("pipeline[%d].with.deps (go/bump skipped - no git-checkout found)", index))
	}
	return updates
}

// processSingleGoBumpPipeline processes a single go/bump pipeline
func (gbu *GoBumpUpdater) processSingleGoBumpPipeline(ctx context.Context, loader *melangeConfig.Loader, yamlContent []byte, index int, repoURL, tag string) (string, []byte, error) {
	// Get pipeline configuration including modroot
	withFields, err := loader.GetPipelineWithField(yamlContent, index)
	if err != nil {
		return fmt.Sprintf("pipeline[%d].with.deps (go/bump failed - config error)", index), yamlContent, nil
	}

	// Extract modroot and build go.mod path
	goModPath := gbu.buildGoModPath(withFields["modroot"])

	// Fetch and parse go.mod
	requirements, err := gbu.fetchAndParseGoMod(ctx, repoURL, tag, goModPath)
	if err != nil {
		return fmt.Sprintf("pipeline[%d].with.deps (go/bump check skipped - %s)", index, err.Error()), yamlContent, nil
	}

	// Get current deps from the pipeline
	deps, err := loader.GetGoBumpDeps(yamlContent, index)
	if err != nil {
		return fmt.Sprintf("pipeline[%d].with.deps (go/bump failed - deps error)", index), yamlContent, nil
	}

	// Analyze and update deps
	return gbu.updatePipelineDeps(loader, yamlContent, index, deps, requirements)
}

// buildGoModPath constructs the go.mod path based on modroot
func (gbu *GoBumpUpdater) buildGoModPath(modroot string) string {
	if modroot == "" || modroot == "." {
		return "go.mod"
	}
	return modroot + "/go.mod"
}

// fetchAndParseGoMod fetches and parses go.mod content
func (gbu *GoBumpUpdater) fetchAndParseGoMod(ctx context.Context, repoURL, tag, goModPath string) (map[string]string, error) {
	goModContent, err := gbu.fetchGoMod(ctx, repoURL, tag, goModPath)
	if err != nil {
		return nil, err
	}

	return gbu.parseGoMod(goModContent)
}

// updatePipelineDeps analyzes deps and updates the pipeline accordingly
func (gbu *GoBumpUpdater) updatePipelineDeps(loader *melangeConfig.Loader, yamlContent []byte, index int, deps []string, requirements map[string]string) (string, []byte, error) {
	// Analyze and filter bumps
	_, filteredDeps := gbu.analyzeBumps(deps, requirements)

	if len(filteredDeps) == 0 {
		// Remove entire go/bump pipeline
		updatedContent, err := loader.RemovePipelineStep(yamlContent, index)
		if err != nil {
			return "", yamlContent, fmt.Errorf("removing go/bump pipeline[%d]: %w", index, err)
		}
		return fmt.Sprintf("removed pipeline[%d] (go/bump - all bumps obsolete)", index), updatedContent, nil

	} else if len(filteredDeps) < len(deps) {
		// Update deps with filtered list
		updatedContent, err := loader.UpdateGoBumpDeps(yamlContent, index, filteredDeps)
		if err != nil {
			return "", yamlContent, fmt.Errorf("updating go/bump deps for pipeline[%d]: %w", index, err)
		}

		removedCount := len(deps) - len(filteredDeps)
		return fmt.Sprintf("pipeline[%d].with.deps (removed %d obsolete bumps)", index, removedCount), updatedContent, nil
	}

	// No changes needed
	return "", yamlContent, nil
}

// processSecurityScanning handles security scanning and updates
func (gbu *GoBumpUpdater) processSecurityScanning(ctx context.Context, updateContext *UpdateContext, repoURL, tag string) error {
	if repoURL == "" {
		updateContext.UpdateMessages = append(updateContext.UpdateMessages, "security scan skipped - no git-checkout found")
		return nil
	}

	loader := melangeConfig.NewLoader()
	
	// Check if this is actually a Go project (has go/build pipeline)
	goBuildIndices, _ := loader.FindPipelinesByUse(updateContext.CurrentContent, "go/build")
	if len(goBuildIndices) == 0 {
		updateContext.UpdateMessages = append(updateContext.UpdateMessages, "security scan skipped - not a Go project (no go/build pipeline)")
		return nil
	}

	// Check if there are actually go/bump pipelines in the YAML
	goBumpIndices, _ := loader.FindPipelinesByUse(updateContext.CurrentContent, "go/bump")
	needToInsert := len(goBumpIndices) == 0

	return gbu.handleSecurityScanning(ctx, updateContext, repoURL, tag, needToInsert)
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
	expandedTag := substituteVariables(tag, newVersion)

	return repository, expandedTag, nil
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
				Module:       dep,
				BumpVersion:  "",
				GoModVersion: "",
				Action:       "keep",
				Reason:       "malformed dependency, keeping as-is",
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

// handleSecurityScanning performs security scanning and applies security updates
func (gbu *GoBumpUpdater) handleSecurityScanning(ctx context.Context, updateContext *UpdateContext, repoURL, tag string, needToInsertGoBump bool) error {
	// Fetch go.mod content
	goModContent, err := gbu.fetchGoMod(ctx, repoURL, tag, "go.mod")
	if err != nil {
		return fmt.Errorf("fetching go.mod for security scan: %w", err)
	}

	// Perform vulnerability scan
	scanResult, err := gbu.vulnerabilityScanner.ScanGoMod(ctx, goModContent)
	if err != nil {
		return fmt.Errorf("scanning go.mod for vulnerabilities: %w", err)
	}

	if scanResult.Error != "" {
		return fmt.Errorf("security scan error: %s", scanResult.Error)
	}

	// Check if we found any security bumps
	if !scanResult.HasSecurityBumps() {
		updateContext.UpdateMessages = append(updateContext.UpdateMessages, "security scan completed - no vulnerabilities found")
		return nil
	}

	loader := melangeConfig.NewLoader()

	// Set security fixes information in the update context
	criticalCount := scanResult.GetCriticalCount()
	highCount := scanResult.GetHighCount()
	totalVulns := len(scanResult.Vulnerabilities)

	// This call will mark security fixes and set the vulnerability counts
	updateContext.SetSecurityFixes(len(scanResult.SecurityBumps), totalVulns, criticalCount, highCount)

	// If we need to insert a go/bump pipeline, do it now
	if needToInsertGoBump {
		// Find the position to insert go/bump step (after git-checkout)
		gitCheckoutIndices, err := loader.FindPipelinesByUse(updateContext.CurrentContent, "git-checkout")
		if err != nil {
			return fmt.Errorf("finding git-checkout pipeline for insertion: %w", err)
		}

		insertPosition := 0
		if len(gitCheckoutIndices) > 0 {
			insertPosition = gitCheckoutIndices[0] + 1
		}

		// Process security bumps through mergeDeps to deduplicate and normalize
		processedDeps := gbu.mergeDeps([]string{}, scanResult.SecurityBumps)

		// Insert the go/bump pipeline step with processed deps
		updateContext.CurrentContent, err = loader.InsertGoBumpPipelineStep(updateContext.CurrentContent, insertPosition, processedDeps)

		if err != nil {
			return fmt.Errorf("inserting go/bump pipeline step: %w", err)
		}

		// Add insertion message
		updateContext.AddGoBumpUpdate(fmt.Sprintf("inserted pipeline[%d] (go/bump with %d security fixes)", insertPosition, len(processedDeps)))
		
		// Mark that security fixes were actually applied
		updateContext.MarkSecurityFixesApplied()
	} else {
		// Add security bumps to existing go/bump pipeline(s)
		goBumpIndices, err := loader.FindPipelinesByUse(updateContext.CurrentContent, "go/bump")
		if err != nil {
			return fmt.Errorf("finding go/bump pipelines for security updates: %w", err)
		}

		if len(goBumpIndices) > 0 {
			// Add to the first go/bump pipeline found
			index := goBumpIndices[0]

			// Get existing deps
			existingDeps, err := loader.GetGoBumpDeps(updateContext.CurrentContent, index)
			if err != nil {
				return fmt.Errorf("getting existing go/bump deps: %w", err)
			}

			// Merge security bumps with existing deps (avoid duplicates)
			mergedDeps := gbu.mergeDeps(existingDeps, scanResult.SecurityBumps)

			// Check if deps actually changed by comparing normalized content
			depsChanged := gbu.haveDepsChanged(existingDeps, mergedDeps)

			if !depsChanged {
				// No actual changes needed
				return nil
			}

			// Update the pipeline with merged deps
			updateContext.CurrentContent, err = loader.UpdateGoBumpDeps(updateContext.CurrentContent, index, mergedDeps)
			if err != nil {
				return fmt.Errorf("updating go/bump deps with security fixes: %w", err)
			}

			// Add update message
			addedCount := len(mergedDeps) - len(existingDeps)
			if addedCount > 0 {
				updateContext.AddGoBumpUpdate(fmt.Sprintf("pipeline[%d].with.deps (added %d security fixes)", index, addedCount))
			} else {
				updateContext.AddGoBumpUpdate(fmt.Sprintf("pipeline[%d].with.deps (updated security fixes)", index))
			}
			
			// Mark that security fixes were actually applied
			updateContext.MarkSecurityFixesApplied()
		}
	}

	return nil
}

// mergeDeps merges security bumps with existing deps, avoiding duplicates and keeping highest version per module
func (gbu *GoBumpUpdater) mergeDeps(existingDeps, securityBumps []string) []string {
	// Use a map to track highest version for each module
	moduleVersions := make(map[string]string) // module path -> highest version

	// Process all deps, keeping the highest version for each module
	allDeps := append(existingDeps, securityBumps...)
	for _, dep := range allDeps {
		dep = strings.TrimSpace(dep)
		if dep == "" {
			continue
		}

		// Normalize by removing +incompatible suffix first
		normalizedDep := strings.TrimSuffix(dep, "+incompatible")
		
		// Parse module@version
		parts := strings.Split(normalizedDep, "@")
		if len(parts) != 2 {
			// Invalid format, skip
			continue
		}
		
		modulePath := parts[0]
		version := parts[1]
		
		// Check if we already have a version for this module
		if existingVersion, exists := moduleVersions[modulePath]; exists {
			// Compare versions and keep the highest
			if semver.Compare(version, existingVersion) > 0 {
				moduleVersions[modulePath] = version
			}
		} else {
			// First time seeing this module
			moduleVersions[modulePath] = version
		}
	}

	// Convert map back to slice in module@version format
	mergedDeps := make([]string, 0, len(moduleVersions))
	for modulePath, version := range moduleVersions {
		mergedDeps = append(mergedDeps, fmt.Sprintf("%s@%s", modulePath, version))
	}

	// Sort for stability and consistency
	slices.Sort(mergedDeps)

	return mergedDeps
}

// haveDepsChanged compares two dependency lists to see if content actually changed after normalization
func (gbu *GoBumpUpdater) haveDepsChanged(existing, merged []string) bool {
	// Normalize both lists for comparison
	existingNormalized := make(map[string]bool)
	for _, dep := range existing {
		dep = strings.TrimSpace(dep)
		if dep != "" {
			normalizedDep := strings.TrimSuffix(dep, "+incompatible")
			existingNormalized[normalizedDep] = true
		}
	}

	mergedNormalized := make(map[string]bool)
	for _, dep := range merged {
		dep = strings.TrimSpace(dep)
		if dep != "" {
			normalizedDep := strings.TrimSuffix(dep, "+incompatible")
			mergedNormalized[normalizedDep] = true
		}
	}

	// Compare the normalized sets
	if len(existingNormalized) != len(mergedNormalized) {
		return true
	}

	for dep := range existingNormalized {
		if !mergedNormalized[dep] {
			return true
		}
	}

	return false
}
