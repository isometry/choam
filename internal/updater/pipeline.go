package updater

import (
	"github.com/isometry/choam/internal/processor"
	"github.com/isometry/choam/internal/processor/stages"
)

// NewPipeline creates the updater pipeline using the shared processor architecture
func NewPipeline(orchestrator *UpdateOrchestrator) *processor.Pipeline {
	pipeline := processor.NewPipeline("updater")

	// Add stages in order
	pipeline.AddStages(
		// Check phase
		NewVersionChecker(orchestrator),

		// Apply phase
		NewVersionApplier(),
		NewPipelineProcessor(orchestrator),

		// Epoch handling - use the common epoch stage with version-change strategy
		stages.NewEpochStage(&stages.ResetOnVersionChangeStrategy{}),

		// Validate the rewritten YAML before anything touches disk.
		stages.NewValidationStage(false, true),

		// File writing - only writes if there are actual file changes
		stages.NewFileWriterStage(false, ""),
	)

	return pipeline
}
