package updater

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/isometry/choam/pkg/scan"
)

// GoDepsChecker implements CheckStage to analyze Go dependencies for security vulnerabilities
// and determine what go/bump pipeline changes are needed during the check phase
type GoDepsChecker struct{}

func (gdc *GoDepsChecker) Name() string {
	return "go_deps_check"
}

func (gdc *GoDepsChecker) Description() string {
	return "Check Go dependencies for security vulnerabilities and needed updates"
}

// Check analyzes Go dependencies and stores the results in the processor
func (gdc *GoDepsChecker) Check(ctx context.Context, processor *PackageProcessor) error {
	logger := processor.WithStage(gdc.Name())

	// Check if this is a Go project by looking for go/build pipelines
	loader := newMelangeLoader()
	goBuildIndices, err := loader.FindPipelinesByUse(processor.CurrentYAML, "go/build")
	if err != nil {
		return fmt.Errorf("checking for go/build pipelines: %w", err)
	}

	if len(goBuildIndices) == 0 {
		logger.Debug("Not a Go project - skipping Go deps analysis")
		processor.AddMessage("go deps check skipped - no go/build found")
		return nil
	}

	// Get repository information
	repoURL, tag, err := extractRepositoryFromYAML(processor.CurrentYAML, processor.Config, processor.LatestVersion)
	if err != nil {
		logger.Debug("Could not extract repository info - skipping Go deps analysis", "error", err)
		processor.AddMessage("go deps check skipped - no git-checkout found")
		return nil
	}

	if repoURL == "" {
		logger.Debug("No repository URL found - skipping Go deps analysis")
		processor.AddMessage("go deps check skipped - no git-checkout found")
		return nil
	}

	// Check for modroot and modpath in go/build pipelines
	modPath := "go.mod"
	if len(goBuildIndices) > 0 {
		withFields, err := loader.GetPipelineWithField(processor.CurrentYAML, goBuildIndices[0])
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

	logger.Info("Starting Go dependency analysis", "repo_url", repoURL, "tag", tag, "modpath", modPath)

	// Get service clients
	orchestrator := NewOrchestrator()
	_, _, _, httpClient := orchestrator.GetServiceClients()

	// Create go/bump updater for dependency analysis
	goBumpUpdater := NewGoBumpUpdater(httpClient)

	// Perform the analysis
	if err := gdc.performAnalysis(ctx, processor, repoURL, tag, modPath, goBumpUpdater, httpClient, logger); err != nil {
		return fmt.Errorf("performing Go deps analysis: %w", err)
	}

	logger.Info("Go dependency analysis completed",
		"vulnerabilities_found", processor.VulnerabilitiesFound,
		"security_bumps", len(processor.SecurityBumps),
		"actions", len(processor.GoBumpActions))

	return nil
}

// performAnalysis performs the actual Go dependency analysis
func (gdc *GoDepsChecker) performAnalysis(ctx context.Context, processor *PackageProcessor, repoURL, tag, modPath string, goBumpUpdater *GoBumpUpdater, httpClient *http.Client, logger *slog.Logger) error {
	// Fetch and parse go.mod
	goModContent, err := goBumpUpdater.fetchGoMod(ctx, repoURL, tag, modPath)
	if err != nil {
		return fmt.Errorf("fetching go.mod: %w", err)
	}

	goModInfo, err := goBumpUpdater.parseGoMod(goModContent)
	if err != nil {
		return fmt.Errorf("parsing go.mod: %w", err)
	}

	// Perform vulnerability scan using the scanner from GoBumpUpdater (which has cache)
	scanResult, err := goBumpUpdater.vulnerabilityScanner.ScanGoMod(ctx, goModContent)
	if err != nil {
		return fmt.Errorf("scanning go.mod for vulnerabilities: %w", err)
	}

	if scanResult.Error != "" {
		return fmt.Errorf("security scan error: %s", scanResult.Error)
	}

	// Set vulnerability information
	criticalCount := scanResult.GetCriticalCount()
	highCount := scanResult.GetHighCount()
	totalVulns := len(scanResult.Vulnerabilities)
	processor.SetVulnerabilityInfo(totalVulns, criticalCount, highCount)

	// Analyze existing go/bump pipelines and determine actions needed
	actions, err := gdc.determineGoBumpActions(processor, goModInfo, scanResult, goBumpUpdater, logger)
	if err != nil {
		return fmt.Errorf("determining go/bump actions: %w", err)
	}

	// Store analysis results in processor
	securityBumps := make([]string, 0)
	if scanResult.HasSecurityBumps() {
		securityBumps = scanResult.SecurityBumps
	}

	processor.SetGoDepsAnalysis(goModInfo.Requirements, securityBumps, actions)

	return nil
}

// determineGoBumpActions analyzes existing go/bump pipelines and determines what actions are needed
func (gdc *GoDepsChecker) determineGoBumpActions(processor *PackageProcessor, goModInfo *GoModInfo, scanResult *scan.ScanResult, goBumpUpdater *GoBumpUpdater, logger *slog.Logger) ([]BumpAction, error) {
	var actions []BumpAction

	if !scanResult.HasSecurityBumps() {
		logger.Debug("No security bumps needed")
		return actions, nil
	}

	loader := newMelangeLoader()

	// Find existing go/bump pipelines
	goBumpIndices, err := loader.FindPipelinesByUse(processor.CurrentYAML, "go/bump")
	if err != nil {
		return nil, fmt.Errorf("finding go/bump pipelines: %w", err)
	}

	if len(goBumpIndices) == 0 {
		// Need to insert a new go/bump pipeline
		_, filteredDeps := goBumpUpdater.analyzeBumps(scanResult.SecurityBumps, goModInfo)
		if len(filteredDeps) > 0 {
			actions = append(actions, BumpAction{
				Action:       "insert",
				Dependencies: filteredDeps,
				Reason:       fmt.Sprintf("insert go/bump with %d security fixes", len(filteredDeps)),
			})
		}
	} else {
		// Check existing pipeline and determine if we need to update it
		firstPipelineIdx := goBumpIndices[0]
		existingDeps, err := loader.GetGoBumpDeps(processor.CurrentYAML, firstPipelineIdx)
		if err != nil {
			return nil, fmt.Errorf("getting existing go/bump deps: %w", err)
		}

		// Combine existing deps with security bumps and filter against go.mod
		allDeps := append(existingDeps, scanResult.SecurityBumps...)
		_, filteredDeps := goBumpUpdater.analyzeBumps(allDeps, goModInfo)

		// Check if deps actually changed
		depsChanged := goBumpUpdater.haveDepsChanged(existingDeps, filteredDeps)
		if depsChanged {
			actions = append(actions, BumpAction{
				Action:       "update",
				PipelineIdx:  firstPipelineIdx,
				Dependencies: filteredDeps,
				Reason:       fmt.Sprintf("update go/bump pipeline with security fixes"),
			})
		}
	}

	return actions, nil
}
