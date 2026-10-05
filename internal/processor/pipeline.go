package processor

import (
	"context"
	"fmt"

	"github.com/isometry/choam/internal/logging"
)

// Pipeline represents a sequence of stages that operate on a processor
type Pipeline struct {
	Name     string
	Stages   []Stage
	Options  PipelineOptions
	Registry *StageRegistry
}

// PipelineOptions configures pipeline behavior
type PipelineOptions struct {
	StopOnError       bool // Stop execution if a stage fails
	SkipValidation    bool // Skip validation stages
	ParallelExecution bool // Enable parallel execution of independent stages (future enhancement)
}

// NewPipeline creates a new pipeline
func NewPipeline(name string) *Pipeline {
	return &Pipeline{
		Name:     name,
		Stages:   make([]Stage, 0),
		Registry: NewStageRegistry(),
		Options: PipelineOptions{
			StopOnError:    true,
			SkipValidation: false,
		},
	}
}

// AddStage adds a stage to the pipeline
func (p *Pipeline) AddStage(stage Stage) {
	p.Stages = append(p.Stages, stage)
}

// AddStages adds multiple stages to the pipeline
func (p *Pipeline) AddStages(stages ...Stage) {
	p.Stages = append(p.Stages, stages...)
}

// Execute runs the pipeline on the given processor
func (p *Pipeline) Execute(ctx context.Context, processor Processor) error {
	logger := processor.GetLogger().With("pipeline", p.Name)
	logger.Info("Starting pipeline execution", "stages", len(p.Stages))

	// Seed ctx with the same attribution logger carries, so stages that
	// have no Processor handy (only ctx) can still reach it via
	// logging.From(ctx) - see internal/logging.
	ctx = logging.Into(ctx, logger)

	for i, stage := range p.Stages {
		if err := ctx.Err(); err != nil {
			return err
		}

		// Shadowed for this stage only - layers onto the pipeline-level
		// logger just seeded above.
		ctx := logging.With(ctx, "stage", stage.Name(), "stage_index", i)
		stageLogger := logger.With("stage", stage.Name(), "stage_index", i)

		// Check if stage should run
		shouldRun, err := stage.ShouldRun(ctx, processor)
		if err != nil {
			err = fmt.Errorf("checking if stage %s should run: %w", stage.Name(), err)
			processor.AddError(err)
			if p.Options.StopOnError {
				return err
			}
			continue
		}

		if !shouldRun {
			stageLogger.Debug("Skipping stage", "reason", "shouldRun returned false")
			continue
		}

		// Validate if stage supports validation and validation is enabled
		if !p.Options.SkipValidation {
			if validator, ok := stage.(ValidatingStage); ok {
				if err := validator.Validate(ctx, processor); err != nil {
					err = fmt.Errorf("validating stage %s: %w", stage.Name(), err)
					processor.AddError(err)
					if p.Options.StopOnError {
						return err
					}
					continue
				}
			}
		}

		// Execute the stage based on its interface
		stageLogger.Info("Executing stage")

		switch s := stage.(type) {
		case ExecutableStage:
			err = s.Execute(ctx, processor)
		case CheckStage:
			err = s.Check(ctx, processor)
		case ApplyStage:
			err = s.Apply(ctx, processor)
		default:
			err = fmt.Errorf("stage %s does not implement any execution interface", stage.Name())
		}

		if err != nil {
			err = fmt.Errorf("stage %s failed: %w", stage.Name(), err)
			processor.AddError(err)
			stageLogger.Error("Stage failed", "error", err)

			if p.Options.StopOnError {
				return err
			}
		} else {
			stageLogger.Info("Stage completed successfully")
		}
	}

	logger.Info("Pipeline execution completed",
		"total_stages", len(p.Stages),
		"has_changes", processor.HasChanges(),
		"has_errors", len(processor.GetErrors()) > 0)

	return nil
}

// SetOptions configures pipeline execution options
func (p *Pipeline) SetOptions(opts PipelineOptions) {
	p.Options = opts
}
