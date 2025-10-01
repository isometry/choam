package gobump

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/config"
	"github.com/isometry/choam/internal/processor"
	"github.com/isometry/choam/internal/processor/stages"
	"github.com/isometry/choam/internal/scan"
)

// VulnerabilityChecker checks for Go module vulnerabilities
type VulnerabilityChecker struct {
	processor.BaseStage
	Analyzer *Analyzer
}

func NewVulnerabilityChecker(analyzer *Analyzer) *VulnerabilityChecker {
	return &VulnerabilityChecker{
		BaseStage: processor.BaseStage{
			StageName:        "vulnerability_check",
			StageDescription: "Check for Go module vulnerabilities",
		},
		Analyzer: analyzer,
	}
}

func (v *VulnerabilityChecker) Check(ctx context.Context, p processor.Processor) error {
	gp, ok := p.(*GoBumpProcessor)
	if !ok {
		return fmt.Errorf("expected GoBumpProcessor, got %T", p)
	}

	// Perform vulnerability analysis directly
	analysis, err := v.checkVulnerabilities(ctx, gp)
	if err != nil {
		return fmt.Errorf("checking vulnerabilities: %w", err)
	}

	gp.VulnerabilityAnalysis = analysis

	// Note: SecurityFixes are added by the applier when actual changes are made,
	// not during the check phase. This ensures the count reflects real changes.

	if analysis.VulnerabilitiesFound == 0 {
		gp.AddMessage("No vulnerabilities found")
	} else {
		gp.AddMessage(fmt.Sprintf("Found %d vulnerabilities", analysis.VulnerabilitiesFound))
	}

	return nil
}

// GoBumpApplier applies go/bump pipeline changes
type GoBumpApplier struct {
	processor.BaseStage
	Analyzer *Analyzer
}

func NewGoBumpApplier(analyzer *Analyzer) *GoBumpApplier {
	return &GoBumpApplier{
		BaseStage: processor.BaseStage{
			StageName:        "gobump_apply",
			StageDescription: "Apply go/bump pipeline changes",
		},
		Analyzer: analyzer,
	}
}

func (g *GoBumpApplier) ShouldRun(ctx context.Context, p processor.Processor) (bool, error) {
	gp, ok := p.(*GoBumpProcessor)
	if !ok {
		return false, fmt.Errorf("expected GoBumpProcessor, got %T", p)
	}

	// Only run if vulnerabilities were found and there are actions to apply
	if gp.VulnerabilityAnalysis == nil {
		return false, nil
	}

	return gp.VulnerabilityAnalysis.VulnerabilitiesFound > 0 &&
		len(gp.VulnerabilityAnalysis.BumpActions) > 0, nil
}

func (g *GoBumpApplier) Apply(ctx context.Context, p processor.Processor) error {
	gp, ok := p.(*GoBumpProcessor)
	if !ok {
		return fmt.Errorf("expected GoBumpProcessor, got %T", p)
	}

	// Apply the changes directly
	// but track whether actual changes were made
	originalYAML := make([]byte, len(gp.GetCurrentYAML()))
	copy(originalYAML, gp.GetCurrentYAML())

	err := g.applyGoBumpChanges(ctx, gp, gp.VulnerabilityAnalysis)
	if err != nil {
		return err
	}

	// Check if actual changes were made - THIS IS THE KEY FIX
	if !bytes.Equal(originalYAML, gp.GetCurrentYAML()) {
		gp.MarkActualChangesApplied()
		gp.AddMessage("go/bump changes applied")
	} else {
		gp.AddMessage("no go/bump changes needed")
	}

	return nil
}

// NewGoBumpPipeline creates the gobump pipeline with the critical fix
func NewGoBumpPipeline(analyzer *Analyzer) *processor.Pipeline {
	pipeline := processor.NewPipeline("gobump")

	// Add stages in order
	pipeline.AddStages(
		// Check phase
		NewVulnerabilityChecker(analyzer),

		// Apply phase
		NewGoBumpApplier(analyzer),

		// Epoch handling - ONLY bump if actual changes were applied
		// This is the critical fix that solves the issue described in the implementation plan
		stages.NewEpochStage(&stages.BumpOnSecurityFixStrategy{
			CheckFunc: func(p processor.Processor) bool {
				if gp, ok := p.(*GoBumpProcessor); ok {
					// Critical fix: Only bump epoch if actual changes were applied AND security fixes exist
					return gp.ActualChangesApplied && len(gp.SecurityFixes) > 0
				}
				return false
			},
		}),

		// File writing - only writes if there are actual file changes
		stages.NewFileWriterStage(false, ""),

		// Final validation
		stages.NewValidationStage(false, true),
	)

	return pipeline
}

// checkVulnerabilities performs real vulnerability analysis
func (v *VulnerabilityChecker) checkVulnerabilities(ctx context.Context, gp *GoBumpProcessor) (*VulnerabilityAnalysis, error) {
	slog.Debug("checking vulnerabilities",
		"file", gp.GetFilePath())

	// Check if this is a Go project by looking for go/build pipelines
	loader := newMelangeLoader()
	goBuildIndices, err := loader.FindPipelinesByUse(gp.GetCurrentYAML(), "go/build")
	if err != nil {
		return nil, fmt.Errorf("checking for go/build pipelines: %w", err)
	}

	if len(goBuildIndices) == 0 {
		slog.Debug("not a Go project",
			"file", gp.GetFilePath(),
			"reason", "no go/build pipelines found")
		gp.AddMessage("Not a Go project - skipping Go deps analysis")
		return &VulnerabilityAnalysis{}, nil
	}

	slog.Debug("Go project detected",
		"file", gp.GetFilePath(),
		"go_build_pipelines", len(goBuildIndices))

	// Get repository information
	repoURL, tag, err := extractRepositoryFromYAML(gp.GetCurrentYAML(), gp.Config, gp.GetCurrentVersion())
	if err != nil {
		slog.Debug("could not extract repository info",
			"file", gp.GetFilePath(),
			"error", err)
		gp.AddMessage(fmt.Sprintf("Could not extract repository info - skipping: %v", err))
		return &VulnerabilityAnalysis{}, nil
	}

	if repoURL == "" {
		slog.Debug("no repository URL found",
			"file", gp.GetFilePath())
		gp.AddMessage("No repository URL found - skipping Go deps analysis")
		return &VulnerabilityAnalysis{}, nil
	}

	// Check for modroot and modpath in go/build pipelines
	modPath := extractModPath(gp.GetCurrentYAML(), goBuildIndices, loader)

	slog.Debug("analyzing repository",
		"repository", repoURL,
		"tag", tag,
		"mod_path", modPath)

	gp.AddMessage(fmt.Sprintf("Analyzing Go dependencies from %s @ %s (path: %s)", repoURL, tag, modPath))

	// Perform the analysis
	analysis, err := v.performAnalysis(ctx, repoURL, tag, modPath, gp)
	if err != nil {
		return nil, fmt.Errorf("performing Go deps analysis: %w", err)
	}

	slog.Debug("vulnerability analysis complete",
		"vulnerabilities", analysis.VulnerabilitiesFound,
		"security_bumps", len(analysis.SecurityBumps),
		"actions", len(analysis.BumpActions))

	gp.AddMessage(fmt.Sprintf("Analysis complete: %d vulnerabilities, %d security bumps, %d actions",
		analysis.VulnerabilitiesFound, len(analysis.SecurityBumps), len(analysis.BumpActions)))

	return analysis, nil
}

// performAnalysis performs the actual Go dependency analysis
func (v *VulnerabilityChecker) performAnalysis(ctx context.Context, repoURL, tag, modPath string, gp *GoBumpProcessor) (*VulnerabilityAnalysis, error) {
	fetcher := v.Analyzer.GetFetcher()
	parser := v.Analyzer.GetParser()
	scanner := v.Analyzer.GetVulnerabilityScanner()

	// Fetch and parse go.mod
	slog.Debug("fetching go.mod",
		"repository", repoURL,
		"tag", tag,
		"path", modPath)

	goModContent, err := fetcher.FetchGoMod(ctx, repoURL, tag, modPath)
	if err != nil {
		return nil, fmt.Errorf("fetching go.mod: %w", err)
	}

	slog.Debug("fetched go.mod",
		"bytes", len(goModContent))

	// Fetch go.sum for complete dependency list (including indirect dependencies)
	goSumPath := strings.Replace(modPath, "go.mod", "go.sum", 1)
	goSumContent, err := fetcher.FetchGoSum(ctx, repoURL, tag, goSumPath)
	if err != nil {
		// go.sum might not exist for all projects, continue with warning
		slog.Debug("could not fetch go.sum",
			"path", goSumPath,
			"error", err,
			"warning", "will only scan direct dependencies")
		gp.AddMessage(fmt.Sprintf("Could not fetch go.sum (will only scan direct deps): %v", err))
		goSumContent = nil
	} else {
		slog.Debug("fetched go.sum",
			"bytes", len(goSumContent))
	}

	// Parse both go.mod and go.sum to get complete dependency information
	goModInfo, err := parser.ParseGoModWithSum(goModContent, goSumContent)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod/go.sum: %w", err)
	}

	slog.Debug("parsed go.mod and go.sum",
		"direct_deps", len(goModInfo.Requirements),
		"total_deps", len(goModInfo.AllRequirements))

	// Create vulnerability scanner input with all dependencies (direct + indirect)
	vulnScanInput := parser.CreateVulnScanInput(goModInfo)

	slog.Debug("created vulnerability scan input",
		"deps_count", len(goModInfo.AllRequirements))

	// Perform vulnerability scan with complete dependency list
	scanResult, err := scanner.ScanGoMod(ctx, []byte(vulnScanInput))
	if err != nil {
		return nil, fmt.Errorf("scanning dependencies for vulnerabilities: %w", err)
	}

	if scanResult.Error != "" {
		return nil, fmt.Errorf("security scan error: %s", scanResult.Error)
	}

	slog.Debug("OSV scan results",
		"total_vulns", len(scanResult.Vulnerabilities),
		"critical", scanResult.GetCriticalCount(),
		"high", scanResult.GetHighCount())

	if scanResult.HasSecurityBumps() {
		slog.Debug("raw security bumps from OSV",
			"count", len(scanResult.SecurityBumps),
			"bumps", scanResult.SecurityBumps)
	} else {
		slog.Debug("no security bumps from OSV")
	}

	gp.AddMessage(fmt.Sprintf("Scanned %d direct and %d total dependencies",
		len(goModInfo.Requirements), len(goModInfo.AllRequirements)))

	// Get vulnerability counts
	criticalCount := scanResult.GetCriticalCount()
	highCount := scanResult.GetHighCount()
	totalVulns := len(scanResult.Vulnerabilities)

	// Get security bumps
	securityBumps := make([]string, 0)
	if scanResult.HasSecurityBumps() {
		securityBumps = scanResult.SecurityBumps
	}

	// Determine go/bump actions needed
	actions := v.determineGoBumpActions(goModInfo, scanResult)

	return &VulnerabilityAnalysis{
		GoModInfo:            goModInfo,
		ScanResult:           scanResult,
		VulnerabilitiesFound: totalVulns,
		CriticalCount:        criticalCount,
		HighCount:            highCount,
		SecurityBumps:        securityBumps,
		BumpActions:          actions,
	}, nil
}

// determineGoBumpActions analyzes security bumps and determines what actions are needed
func (v *VulnerabilityChecker) determineGoBumpActions(goModInfo *GoModInfo, scanResult *scan.ScanResult) []BumpAction {
	var actions []BumpAction

	if !scanResult.HasSecurityBumps() {
		slog.Debug("no security bumps to analyze")
		return actions
	}

	slog.Debug("analyzing security bumps",
		"raw_bumps_count", len(scanResult.SecurityBumps))

	// Analyze and filter the security bumps against go.mod info
	analysis, filteredDeps := v.Analyzer.AnalyzeBumps(scanResult.SecurityBumps, goModInfo)

	slog.Debug("bump analysis complete",
		"total_analyzed", len(analysis),
		"filtered_deps", len(filteredDeps),
		"deps", filteredDeps)

	if len(filteredDeps) > 0 {
		actions = append(actions, BumpAction{
			Action:       "needs_gobump",
			Dependencies: filteredDeps,
			Reason:       fmt.Sprintf("go/bump needed with %d security fixes", len(filteredDeps)),
		})
		slog.Debug("created go/bump action",
			"action", "needs_gobump",
			"deps_count", len(filteredDeps))
	} else {
		slog.Debug("no go/bump actions needed",
			"reason", "all bumps filtered out")
	}

	return actions
}

// applyGoBumpChanges applies real go/bump pipeline changes
func (g *GoBumpApplier) applyGoBumpChanges(ctx context.Context, gp *GoBumpProcessor, analysis *VulnerabilityAnalysis) error {
	// Skip if no vulnerabilities found
	if analysis.VulnerabilitiesFound == 0 {
		slog.Debug("skipping apply - no vulnerabilities found")
		return nil
	}

	// Skip if no actions to apply
	if len(analysis.BumpActions) == 0 {
		slog.Debug("skipping apply - no actions to apply")
		return nil
	}

	slog.Debug("applying go/bump changes",
		"actions_count", len(analysis.BumpActions))

	loader := newMelangeLoader()

	// Apply each action in order
	for i, action := range analysis.BumpActions {
		slog.Debug("applying action",
			"index", i,
			"action", action.Action,
			"deps_count", len(action.Dependencies))

		if err := g.applyAction(gp, action, analysis, loader); err != nil {
			return fmt.Errorf("applying action %d (%s): %w", i, action.Action, err)
		}
	}

	gp.AddMessage(fmt.Sprintf("Applied %d go/bump actions", len(analysis.BumpActions)))
	return nil
}

// applyAction applies a single BumpAction
func (g *GoBumpApplier) applyAction(gp *GoBumpProcessor, action BumpAction, analysis *VulnerabilityAnalysis, loader *config.Loader) error {
	switch action.Action {
	case "needs_gobump":
		// Determine if we should insert or update
		return g.handleGoBumpNeeded(gp, action, analysis, loader)
	default:
		return fmt.Errorf("unknown action: %s", action.Action)
	}
}

// handleGoBumpNeeded determines whether to insert or update go/bump pipeline
func (g *GoBumpApplier) handleGoBumpNeeded(gp *GoBumpProcessor, action BumpAction, analysis *VulnerabilityAnalysis, loader *config.Loader) error {
	// Find existing go/bump pipelines
	goBumpIndices, err := loader.FindPipelinesByUse(gp.GetCurrentYAML(), "go/bump")
	if err != nil {
		return fmt.Errorf("finding go/bump pipelines: %w", err)
	}

	slog.Debug("checking for existing go/bump pipeline",
		"existing_count", len(goBumpIndices))

	if len(goBumpIndices) == 0 {
		// Need to insert a new go/bump pipeline
		slog.Debug("no existing go/bump pipeline - will insert")
		return g.insertGoBumpPipeline(gp, action, loader)
	} else {
		// Update existing pipeline
		slog.Debug("existing go/bump pipeline found - will update",
			"pipeline_index", goBumpIndices[0])
		return g.updateGoBumpPipeline(gp, action, goBumpIndices[0], analysis, loader)
	}
}

// insertGoBumpPipeline inserts a new go/bump pipeline
func (g *GoBumpApplier) insertGoBumpPipeline(gp *GoBumpProcessor, action BumpAction, loader *config.Loader) error {
	// Find position to insert (after git-checkout if present)
	gitCheckoutIndices, err := loader.FindPipelinesByUse(gp.GetCurrentYAML(), "git-checkout")
	if err != nil {
		return fmt.Errorf("finding git-checkout pipeline for insertion: %w", err)
	}

	insertPosition := 0
	if len(gitCheckoutIndices) > 0 {
		insertPosition = gitCheckoutIndices[0] + 1
	}

	slog.Debug("inserting go/bump pipeline",
		"position", insertPosition,
		"deps_count", len(action.Dependencies),
		"deps", action.Dependencies)

	// Insert the go/bump pipeline step with filtered deps
	updatedContent, err := loader.InsertGoBumpPipelineStep(gp.GetCurrentYAML(), insertPosition, action.Dependencies)
	if err != nil {
		return fmt.Errorf("inserting go/bump pipeline step: %w", err)
	}

	gp.SetCurrentYAML(updatedContent)

	// Mark that actual changes were applied
	gp.MarkActualChangesApplied()

	slog.Debug("go/bump pipeline inserted",
		"yaml_modified", true,
		"deps_added", len(action.Dependencies))

	// Record the change
	gp.AddMessage(fmt.Sprintf("Inserted go/bump pipeline at position %d with %d dependencies", insertPosition, len(action.Dependencies)))

	// Add security fixes for reporting (one per dependency)
	g.recordSecurityFixes(gp, action.Dependencies)

	return nil
}

// updateGoBumpPipeline updates an existing go/bump pipeline
func (g *GoBumpApplier) updateGoBumpPipeline(gp *GoBumpProcessor, action BumpAction, pipelineIdx int, analysis *VulnerabilityAnalysis, loader *config.Loader) error {
	// Get existing dependencies
	existingDeps, err := loader.GetGoBumpDeps(gp.GetCurrentYAML(), pipelineIdx)
	if err != nil {
		return fmt.Errorf("getting existing go/bump deps: %w", err)
	}

	slog.Debug("updating go/bump pipeline",
		"pipeline_index", pipelineIdx,
		"existing_deps_count", len(existingDeps),
		"existing_deps", existingDeps,
		"new_deps_count", len(action.Dependencies),
		"new_deps", action.Dependencies)

	// Merge existing deps with new security bumps
	allDeps := append(existingDeps, action.Dependencies...)

	slog.Debug("merging dependencies",
		"total_deps", len(allDeps))

	_, filteredDeps := g.Analyzer.AnalyzeBumps(allDeps, analysis.GoModInfo)

	slog.Debug("merged and filtered dependencies",
		"filtered_count", len(filteredDeps),
		"filtered_deps", filteredDeps)

	// Check if deps actually changed
	depsChanged := g.Analyzer.HaveDepsChanged(existingDeps, filteredDeps)

	slog.Debug("checking if dependencies changed",
		"changed", depsChanged)

	if !depsChanged {
		slog.Debug("no changes needed - pipeline already up-to-date")
		gp.AddMessage("go/bump pipeline already up-to-date")
		return nil
	}

	// Update the pipeline with merged deps
	updatedContent, err := loader.UpdateGoBumpDeps(gp.GetCurrentYAML(), pipelineIdx, filteredDeps)
	if err != nil {
		return fmt.Errorf("updating go/bump deps: %w", err)
	}

	gp.SetCurrentYAML(updatedContent)

	// Mark that actual changes were applied
	gp.MarkActualChangesApplied()

	slog.Debug("go/bump pipeline updated",
		"yaml_modified", true,
		"final_deps_count", len(filteredDeps))

	// Record the change
	gp.AddMessage(fmt.Sprintf("Updated go/bump pipeline[%d] with %d dependencies", pipelineIdx, len(filteredDeps)))

	// Add security fixes for reporting (one per dependency, using filteredDeps not action.Dependencies)
	g.recordSecurityFixes(gp, filteredDeps)

	return nil
}

// recordSecurityFixes records security fixes in the processor for reporting
// Creates one SecurityFix per dependency so len(SecurityFixes) accurately reflects the count
func (g *GoBumpApplier) recordSecurityFixes(gp *GoBumpProcessor, dependencies []string) {
	for _, dep := range dependencies {
		// Parse module@version from dependency
		parts := strings.Split(dep, "@")
		module := dep
		version := "unknown"
		if len(parts) == 2 {
			module = parts[0]
			version = parts[1]
		}

		fix := SecurityFix{
			Module:        module,
			Vulnerability: "security vulnerability",
			OldVersion:    "vulnerable",
			NewVersion:    version,
			Severity:      "varies",
		}
		gp.AddSecurityFix(fix)
	}
}

// Helper functions

// newMelangeLoader creates a new melange configuration loader
func newMelangeLoader() *config.Loader {
	return config.NewLoader()
}

// extractModPath extracts the go module path from go/build pipeline configuration
func extractModPath(currentYAML []byte, goBuildIndices []int, loader *config.Loader) string {
	modPath := "go.mod"
	if len(goBuildIndices) > 0 {
		withFields, err := loader.GetPipelineWithField(currentYAML, goBuildIndices[0])
		if err == nil {
			var basePath string

			// Check for modroot first (base directory for the module)
			if modroot, ok := withFields["modroot"]; ok && modroot != "" {
				basePath = modroot
			}

			// Check for modpath (subdirectory within modroot containing go.mod)
			if customModPath, ok := withFields["modpath"]; ok && customModPath != "" {
				if basePath != "" {
					// Combine modroot and modpath
					modPath = basePath + "/" + customModPath + "/go.mod"
				} else {
					// Just modpath
					modPath = customModPath + "/go.mod"
				}
			} else if basePath != "" {
				// Just modroot
				modPath = basePath + "/go.mod"
			}
		}
	}
	return modPath
}

// extractRepositoryFromYAML extracts repository URL and tag from melange YAML
func extractRepositoryFromYAML(yamlContent []byte, cfg *melange.Configuration, latestVersion string) (string, string, error) {
	loader := newMelangeLoader()

	// Find git-checkout pipelines
	gitCheckoutIndices, err := loader.FindPipelinesByUse(yamlContent, "git-checkout")
	if err != nil {
		return "", "", fmt.Errorf("finding git-checkout pipelines: %w", err)
	}

	if len(gitCheckoutIndices) == 0 {
		return "", "", fmt.Errorf("no git-checkout pipeline found")
	}

	// Get the first git-checkout pipeline fields
	withFields, err := loader.GetPipelineWithField(yamlContent, gitCheckoutIndices[0])
	if err != nil {
		return "", "", fmt.Errorf("getting git-checkout pipeline fields: %w", err)
	}

	repoURL, hasRepo := withFields["repository"]
	tag, hasTag := withFields["tag"]

	if !hasRepo || repoURL == "" {
		return "", "", fmt.Errorf("no repository URL found in git-checkout pipeline")
	}

	if !hasTag || tag == "" {
		// Use the latest version as tag if no tag specified
		tag = latestVersion
	}

	// Resolve template variables in repoURL and tag using the Renderer
	renderer, err := config.NewRenderer(cfg)
	if err != nil {
		return "", "", fmt.Errorf("creating template renderer: %w", err)
	}

	// Resolve repository URL template variables
	resolvedRepoURL, err := renderer.RenderString(repoURL)
	if err != nil {
		return "", "", fmt.Errorf("resolving repository URL template %q: %w", repoURL, err)
	}

	// Resolve tag template variables
	resolvedTag, err := renderer.RenderString(tag)
	if err != nil {
		return "", "", fmt.Errorf("resolving tag template %q: %w", tag, err)
	}

	return resolvedRepoURL, resolvedTag, nil
}
