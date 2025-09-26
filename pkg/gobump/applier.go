package gobump

import (
	"context"
	"fmt"
	"log/slog"

	melangeConfig "github.com/isometry/choam/pkg/config"
)

// Applier applies go/bump pipeline changes to melange YAML files
type Applier struct {
	analyzer *Analyzer
}

// NewApplier creates a new applier
func NewApplier(analyzer *Analyzer) *Applier {
	return &Applier{
		analyzer: analyzer,
	}
}

// ApplyGoBumpChanges applies go/bump pipeline changes based on vulnerability analysis
func (a *Applier) ApplyGoBumpChanges(ctx context.Context, processor *Processor, analysis *VulnerabilityAnalysis) error {
	logger := processor.Logger.With("stage", "gobump_apply")

	// Skip if no vulnerabilities found
	if analysis.VulnerabilitiesFound == 0 {
		logger.Debug("No vulnerabilities found - skipping apply")
		return nil
	}

	// Skip if no actions to apply
	if len(analysis.BumpActions) == 0 {
		logger.Debug("No go/bump actions to apply")
		return nil
	}

	// Skip if dry run
	if processor.Options.DryRun {
		logger.Info("Dry run - would apply go/bump changes", "actions", len(analysis.BumpActions))
		for _, action := range analysis.BumpActions {
			processor.AddMessage(fmt.Sprintf("would %s: %s", action.Action, action.Reason))
		}
		return nil
	}

	logger.Info("Applying go/bump changes", "actions", len(analysis.BumpActions))

	loader := newMelangeLoader()

	// Apply each action in order
	for i, action := range analysis.BumpActions {
		actionLogger := logger.With("action_index", i, "action", action.Action)

		if err := a.applyAction(processor, action, analysis, loader, actionLogger); err != nil {
			return fmt.Errorf("applying action %d (%s): %w", i, action.Action, err)
		}
	}

	// Mark that go/bump fixes were applied and epoch needs bumping
	processor.MarkSecurityFixesApplied(analysis.VulnerabilitiesFound, analysis.CriticalCount, analysis.HighCount)

	logger.Info("go/bump changes applied successfully")
	return nil
}

// applyAction applies a single BumpAction
func (a *Applier) applyAction(processor *Processor, action BumpAction, analysis *VulnerabilityAnalysis, loader *melangeConfig.Loader, logger *slog.Logger) error {
	switch action.Action {
	case "needs_gobump":
		// For the new gobump flow, we need to determine if we should insert or update
		return a.handleGoBumpNeeded(processor, action, analysis, loader, logger)
	default:
		return fmt.Errorf("unknown action: %s", action.Action)
	}
}

// handleGoBumpNeeded determines whether to insert or update go/bump pipeline
func (a *Applier) handleGoBumpNeeded(processor *Processor, action BumpAction, analysis *VulnerabilityAnalysis, loader *melangeConfig.Loader, logger *slog.Logger) error {
	// Find existing go/bump pipelines
	goBumpIndices, err := loader.FindPipelinesByUse(processor.CurrentYAML, "go/bump")
	if err != nil {
		return fmt.Errorf("finding go/bump pipelines: %w", err)
	}

	if len(goBumpIndices) == 0 {
		// Need to insert a new go/bump pipeline
		return a.insertGoBumpPipeline(processor, action, loader, logger)
	} else {
		// Update existing pipeline
		return a.updateGoBumpPipeline(processor, action, goBumpIndices[0], analysis, loader, logger)
	}
}

// insertGoBumpPipeline inserts a new go/bump pipeline
func (a *Applier) insertGoBumpPipeline(processor *Processor, action BumpAction, loader *melangeConfig.Loader, logger *slog.Logger) error {
	// Find position to insert (after git-checkout if present)
	gitCheckoutIndices, err := loader.FindPipelinesByUse(processor.CurrentYAML, "git-checkout")
	if err != nil {
		return fmt.Errorf("finding git-checkout pipeline for insertion: %w", err)
	}

	insertPosition := 0
	if len(gitCheckoutIndices) > 0 {
		insertPosition = gitCheckoutIndices[0] + 1
	}

	// Insert the go/bump pipeline step with filtered deps
	updatedContent, err := loader.InsertGoBumpPipelineStep(processor.CurrentYAML, insertPosition, action.Dependencies)
	if err != nil {
		return fmt.Errorf("inserting go/bump pipeline step: %w", err)
	}

	processor.CurrentYAML = updatedContent
	processor.FileWasWritten = true

	// Record the change
	processor.AddMessage(fmt.Sprintf("inserted go/bump pipeline at position %d with %d dependencies", insertPosition, len(action.Dependencies)))

	// Add security fixes for reporting
	a.recordSecurityFixes(processor, action, logger)

	logger.Info("go/bump pipeline inserted", "position", insertPosition, "deps_count", len(action.Dependencies))
	return nil
}

// updateGoBumpPipeline updates an existing go/bump pipeline
func (a *Applier) updateGoBumpPipeline(processor *Processor, action BumpAction, pipelineIdx int, analysis *VulnerabilityAnalysis, loader *melangeConfig.Loader, logger *slog.Logger) error {
	// Get existing dependencies
	existingDeps, err := loader.GetGoBumpDeps(processor.CurrentYAML, pipelineIdx)
	if err != nil {
		return fmt.Errorf("getting existing go/bump deps: %w", err)
	}

	// Merge existing deps with new security bumps
	allDeps := append(existingDeps, action.Dependencies...)
	_, filteredDeps := a.analyzer.AnalyzeBumps(allDeps, analysis.GoModInfo)

	// Check if deps actually changed
	depsChanged := a.analyzer.HaveDepsChanged(existingDeps, filteredDeps)
	if !depsChanged {
		logger.Debug("No changes needed to existing go/bump pipeline")
		processor.AddMessage("go/bump pipeline already up to date")
		return nil
	}

	// Update the pipeline with merged deps
	updatedContent, err := loader.UpdateGoBumpDeps(processor.CurrentYAML, pipelineIdx, filteredDeps)
	if err != nil {
		return fmt.Errorf("updating go/bump deps: %w", err)
	}

	processor.CurrentYAML = updatedContent
	processor.FileWasWritten = true

	// Record the change
	processor.AddMessage(fmt.Sprintf("updated go/bump pipeline[%d] with %d dependencies", pipelineIdx, len(filteredDeps)))

	// Add security fixes for reporting
	a.recordSecurityFixes(processor, action, logger)

	logger.Info("go/bump pipeline updated", "pipeline_index", pipelineIdx, "deps_count", len(filteredDeps))
	return nil
}

// recordSecurityFixes records security fixes in the processor for reporting
func (a *Applier) recordSecurityFixes(processor *Processor, action BumpAction, logger *slog.Logger) {
	if len(action.Dependencies) > 0 {
		// Create a consolidated security fix record
		fix := SecurityFix{
			Module:        "go.mod dependencies",
			Vulnerability: fmt.Sprintf("%d vulnerabilities", len(action.Dependencies)),
			OldVersion:    "various",
			NewVersion:    "updated",
			Severity:      "varies",
		}
		processor.AddSecurityFix(fix)

		logger.Info("Security fixes recorded",
			"action", action.Action,
			"dependencies", len(action.Dependencies))
	}
}