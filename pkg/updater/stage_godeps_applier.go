package updater

import (
	"context"
	"fmt"
	"log/slog"

	melangeConfig "github.com/isometry/choam/pkg/config"
)

// GoDepsApplier implements ApplyStage to apply Go dependency changes
// determined during the check phase (by GoDepsChecker)
type GoDepsApplier struct{}

func (gda *GoDepsApplier) Name() string {
	return "go_deps_apply"
}

func (gda *GoDepsApplier) Description() string {
	return "Apply Go dependency changes to go/bump pipelines"
}

// Apply executes the planned go/bump pipeline changes
func (gda *GoDepsApplier) Apply(ctx context.Context, processor *PackageProcessor) error {
	logger := processor.WithStage(gda.Name())

	// Skip if Go deps were not analyzed (not a Go project)
	if !processor.GoDepsAnalyzed {
		logger.Debug("Go deps not analyzed - skipping apply")
		return nil
	}

	// Skip if no actions to apply
	if !processor.HasGoDepsActions() {
		logger.Debug("No Go deps actions to apply")
		return nil
	}

	// Skip if dry run
	if processor.Options.DryRun {
		logger.Info("Dry run - would apply Go deps changes", "actions", len(processor.GoBumpActions))
		for _, action := range processor.GoBumpActions {
			processor.AddMessage(fmt.Sprintf("would %s: %s", action.Action, action.Reason))
		}
		return nil
	}

	logger.Info("Applying Go dependency changes", "actions", len(processor.GoBumpActions))

	loader := newMelangeLoader()

	// Apply each action in order
	for i, action := range processor.GoBumpActions {
		actionLogger := logger.With("action_index", i, "action", action.Action)

		if err := gda.applyAction(processor, action, loader, actionLogger); err != nil {
			return fmt.Errorf("applying action %d (%s): %w", i, action.Action, err)
		}
	}

	// If we applied any go/bump actions that actually changed dependencies, mark that epoch bump is required
	hasActualChanges := false
	for _, action := range processor.GoBumpActions {
		if action.Action == "insert" || action.Action == "update" {
			hasActualChanges = true
			break
		}
	}

	if hasActualChanges && len(processor.SecurityBumps) > 0 {
		processor.MarkSecurityFixesApplied()
		logger.Debug("Security fixes applied - epoch bump will be required")
	}

	logger.Info("Go dependency changes applied successfully")
	return nil
}

// applyAction applies a single BumpAction
func (gda *GoDepsApplier) applyAction(processor *PackageProcessor, action BumpAction, loader *melangeConfig.Loader, logger *slog.Logger) error {
	switch action.Action {
	case "insert":
		return gda.insertGoBumpPipeline(processor, action, loader, logger)
	case "update":
		return gda.updateGoBumpPipeline(processor, action, loader, logger)
	case "remove":
		return gda.removeGoBumpPipeline(processor, action, loader, logger)
	default:
		return fmt.Errorf("unknown action: %s", action.Action)
	}
}

// insertGoBumpPipeline inserts a new go/bump pipeline
func (gda *GoDepsApplier) insertGoBumpPipeline(processor *PackageProcessor, action BumpAction, loader *melangeConfig.Loader, logger *slog.Logger) error {
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

	// Record the change
	change := PipelineChange{
		Type:        "go/bump",
		Index:       insertPosition,
		Field:       "deps",
		OldValue:    "(none)",
		NewValue:    fmt.Sprintf("%d dependencies", len(action.Dependencies)),
		Description: fmt.Sprintf("inserted pipeline[%d] (go/bump with %d security fixes)", insertPosition, len(action.Dependencies)),
	}
	processor.AddPipelineChange(change)

	// Add security fixes for reporting
	gda.recordSecurityFixes(processor, action, logger)

	logger.Info("Go/bump pipeline inserted", "position", insertPosition, "deps_count", len(action.Dependencies))
	return nil
}

// updateGoBumpPipeline updates an existing go/bump pipeline
func (gda *GoDepsApplier) updateGoBumpPipeline(processor *PackageProcessor, action BumpAction, loader *melangeConfig.Loader, logger *slog.Logger) error {
	// Update the pipeline with merged deps
	updatedContent, err := loader.UpdateGoBumpDeps(processor.CurrentYAML, action.PipelineIdx, action.Dependencies)
	if err != nil {
		return fmt.Errorf("updating go/bump deps: %w", err)
	}

	processor.CurrentYAML = updatedContent

	// Record the change
	change := PipelineChange{
		Type:        "go/bump",
		Index:       action.PipelineIdx,
		Field:       "deps",
		OldValue:    "(existing deps)",
		NewValue:    fmt.Sprintf("%d dependencies", len(action.Dependencies)),
		Description: fmt.Sprintf("pipeline[%d].with.deps (updated with security fixes)", action.PipelineIdx),
	}
	processor.AddPipelineChange(change)

	// Add security fixes for reporting
	gda.recordSecurityFixes(processor, action, logger)

	logger.Info("Go/bump pipeline updated", "pipeline_index", action.PipelineIdx, "deps_count", len(action.Dependencies))
	return nil
}

// removeGoBumpPipeline removes a go/bump pipeline
func (gda *GoDepsApplier) removeGoBumpPipeline(processor *PackageProcessor, action BumpAction, loader *melangeConfig.Loader, logger *slog.Logger) error {
	// Remove the pipeline
	updatedContent, err := loader.RemovePipelineStep(processor.CurrentYAML, action.PipelineIdx)
	if err != nil {
		return fmt.Errorf("removing go/bump pipeline: %w", err)
	}

	processor.CurrentYAML = updatedContent

	// Record the change
	change := PipelineChange{
		Type:        "go/bump",
		Index:       action.PipelineIdx,
		Field:       "removed",
		OldValue:    "pipeline step",
		NewValue:    "(removed)",
		Description: fmt.Sprintf("removed pipeline[%d] (go/bump)", action.PipelineIdx),
	}
	processor.AddPipelineChange(change)

	logger.Info("Go/bump pipeline removed", "pipeline_index", action.PipelineIdx)
	return nil
}

// recordSecurityFixes records security fixes in the processor for reporting
func (gda *GoDepsApplier) recordSecurityFixes(processor *PackageProcessor, action BumpAction, logger *slog.Logger) {
	if len(processor.SecurityBumps) > 0 {
		// Count vulnerabilities actually fixed by this action
		// This should be the number of dependencies that had vulnerabilities and are being bumped
		vulnerabilitiesFixed := len(processor.SecurityBumps)
		criticalFixed := 0
		highFixed := 0

		// For now, assume proportional distribution of severity for fixed vulnerabilities
		// In a more sophisticated implementation, we'd track severity per dependency
		totalVulns := processor.VulnerabilitiesFound
		if totalVulns > 0 {
			criticalFixed = (processor.CriticalVulns * vulnerabilitiesFixed) / totalVulns
			highFixed = (processor.HighVulns * vulnerabilitiesFixed) / totalVulns
		}

		// Record the actual fixes being applied
		processor.SetVulnerabilityFixes(vulnerabilitiesFixed, criticalFixed, highFixed)

		// Create a consolidated security fix record
		fix := SecurityFix{
			Module:        "go.mod dependencies",
			Vulnerability: fmt.Sprintf("%d vulnerabilities", vulnerabilitiesFixed),
			OldVersion:    "various",
			NewVersion:    "updated",
			Severity:      gda.determineSeverity(criticalFixed, highFixed),
		}
		processor.AddSecurityFix(fix)

		logger.Info("Security fixes recorded",
			"action_index", action.PipelineIdx,
			"action", action.Action,
			"vulnerabilities", vulnerabilitiesFixed,
			"critical", criticalFixed,
			"high", highFixed)
	}
}

// determineSeverity determines overall severity based on vulnerability counts
func (gda *GoDepsApplier) determineSeverity(critical, high int) string {
	if critical > 0 {
		return "critical"
	}
	if high > 0 {
		return "high"
	}
	return "medium"
}
