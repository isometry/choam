package gobump

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	melange "chainguard.dev/melange/pkg/config"
	melangeConfig "github.com/isometry/choam/pkg/config"
	"github.com/isometry/choam/pkg/scan"
)

// Checker performs vulnerability analysis on Go dependencies
type Checker struct {
	analyzer *Analyzer
}

// NewChecker creates a new vulnerability checker
func NewChecker(analyzer *Analyzer) *Checker {
	return &Checker{
		analyzer: analyzer,
	}
}

// CheckVulnerabilities analyzes Go dependencies for security vulnerabilities
// and determines what go/bump pipeline changes are needed
func (c *Checker) CheckVulnerabilities(ctx context.Context, processor *Processor) (*VulnerabilityAnalysis, error) {
	logger := processor.Logger.With("stage", "gobump_check")

	// Check if this is a Go project by looking for go/build pipelines
	loader := newMelangeLoader()
	goBuildIndices, err := loader.FindPipelinesByUse(processor.CurrentYAML, "go/build")
	if err != nil {
		return nil, fmt.Errorf("checking for go/build pipelines: %w", err)
	}

	if len(goBuildIndices) == 0 {
		logger.Debug("Not a Go project - skipping Go deps analysis")
		return &VulnerabilityAnalysis{}, nil
	}

	// Get repository information
	repoURL, tag, err := c.extractRepositoryFromYAML(processor.CurrentYAML, processor.Config, processor.CurrentVersion)
	if err != nil {
		logger.Debug("Could not extract repository info - skipping Go deps analysis", "error", err)
		return &VulnerabilityAnalysis{}, nil
	}

	if repoURL == "" {
		logger.Debug("No repository URL found - skipping Go deps analysis")
		return &VulnerabilityAnalysis{}, nil
	}

	// Check for modroot and modpath in go/build pipelines
	modPath := c.extractModPath(processor.CurrentYAML, goBuildIndices, loader, logger)

	logger.Info("Starting Go dependency analysis", "repo_url", repoURL, "tag", tag, "modpath", modPath)

	// Perform the analysis
	analysis, err := c.performAnalysis(ctx, repoURL, tag, modPath, logger)
	if err != nil {
		return nil, fmt.Errorf("performing Go deps analysis: %w", err)
	}

	logger.Info("Go dependency analysis completed",
		"vulnerabilities_found", analysis.VulnerabilitiesFound,
		"security_bumps", len(analysis.SecurityBumps),
		"actions", len(analysis.BumpActions))

	return analysis, nil
}

// performAnalysis performs the actual Go dependency analysis
func (c *Checker) performAnalysis(ctx context.Context, repoURL, tag, modPath string, logger *slog.Logger) (*VulnerabilityAnalysis, error) {
	fetcher := c.analyzer.GetFetcher()
	parser := c.analyzer.GetParser()
	scanner := c.analyzer.GetVulnerabilityScanner()

	// Fetch and parse go.mod
	goModContent, err := fetcher.FetchGoMod(ctx, repoURL, tag, modPath)
	if err != nil {
		return nil, fmt.Errorf("fetching go.mod: %w", err)
	}

	// Fetch go.sum for complete dependency list (including indirect dependencies)
	goSumPath := strings.Replace(modPath, "go.mod", "go.sum", 1)
	goSumContent, err := fetcher.FetchGoSum(ctx, repoURL, tag, goSumPath)
	if err != nil {
		// go.sum might not exist for all projects, continue with warning
		logger.Warn("Could not fetch go.sum, will only scan direct dependencies", "error", err)
		goSumContent = nil
	}

	// Parse both go.mod and go.sum to get complete dependency information
	goModInfo, err := parser.ParseGoModWithSum(goModContent, goSumContent)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod/go.sum: %w", err)
	}

	// Create vulnerability scanner input with all dependencies (direct + indirect)
	vulnScanInput := parser.CreateVulnScanInput(goModInfo)

	// Perform vulnerability scan with complete dependency list
	scanResult, err := scanner.ScanGoMod(ctx, []byte(vulnScanInput))
	if err != nil {
		return nil, fmt.Errorf("scanning dependencies for vulnerabilities: %w", err)
	}

	if scanResult.Error != "" {
		return nil, fmt.Errorf("security scan error: %s", scanResult.Error)
	}

	logger.Info("Vulnerability scan completed",
		"direct_deps", len(goModInfo.Requirements),
		"total_deps", len(goModInfo.AllRequirements),
		"vulnerabilities_found", len(scanResult.Vulnerabilities))

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
	actions := c.determineGoBumpActions(goModInfo, scanResult, logger)

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

// determineGoBumpActions analyzes existing go/bump pipelines and determines what actions are needed
func (c *Checker) determineGoBumpActions(goModInfo *GoModInfo, scanResult *scan.ScanResult, logger *slog.Logger) []BumpAction {
	var actions []BumpAction

	if !scanResult.HasSecurityBumps() {
		logger.Debug("No security bumps needed")
		return actions
	}

	// For the new gobump command, we always work with security bumps
	// Analyze and filter the security bumps against go.mod info
	_, filteredDeps := c.analyzer.AnalyzeBumps(scanResult.SecurityBumps, goModInfo)

	if len(filteredDeps) > 0 {
		actions = append(actions, BumpAction{
			Action:       "needs_gobump",
			Dependencies: filteredDeps,
			Reason:       fmt.Sprintf("go/bump needed with %d security fixes", len(filteredDeps)),
		})
	}

	return actions
}

// extractModPath extracts the go module path from go/build pipeline configuration
func (c *Checker) extractModPath(currentYAML []byte, goBuildIndices []int, loader *melangeConfig.Loader, logger *slog.Logger) string {
	modPath := "go.mod"
	if len(goBuildIndices) > 0 {
		withFields, err := loader.GetPipelineWithField(currentYAML, goBuildIndices[0])
		if err == nil {
			var basePath string

			// Check for modroot first (base directory for the module)
			if modroot, ok := withFields["modroot"]; ok && modroot != "" {
				basePath = modroot
				logger.Debug("Using modroot from go/build pipeline", "modroot", modroot)
			}

			// Check for modpath (subdirectory within modroot containing go.mod)
			if customModPath, ok := withFields["modpath"]; ok && customModPath != "" {
				if basePath != "" {
					// Combine modroot and modpath
					modPath = basePath + "/" + customModPath + "/go.mod"
					logger.Debug("Using combined modroot and modpath", "modroot", basePath, "modpath", customModPath, "final_path", modPath)
				} else {
					// Just modpath
					modPath = customModPath + "/go.mod"
					logger.Debug("Using custom modpath", "modpath", customModPath)
				}
			} else if basePath != "" {
				// Just modroot
				modPath = basePath + "/go.mod"
				logger.Debug("Using modroot only", "modroot", basePath)
			}
		}
	}
	return modPath
}

// extractRepositoryFromYAML extracts repository URL and tag from melange YAML
func (c *Checker) extractRepositoryFromYAML(yamlContent []byte, config *melange.Configuration, latestVersion string) (string, string, error) {
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
	renderer, err := melangeConfig.NewRenderer(config)
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

// newMelangeLoader creates a new melange configuration loader
func newMelangeLoader() *melangeConfig.Loader {
	return melangeConfig.NewLoader()
}