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

		// File writing - only writes if there are actual file changes
		stages.NewFileWriterStage(false, ""),

		// Final validation
		stages.NewValidationStage(false, true),
	)

	return pipeline
}