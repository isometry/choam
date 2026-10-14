package processor

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/isometry/choam/internal/logging"
)

// Pipeline represents a sequence of stages that operate on a processor
type Pipeline struct {
	Name    string
	Stages  []Stage
	Options PipelineOptions
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
		Name:   name,
		Stages: make([]Stage, 0),
		Options: PipelineOptions{
			StopOnError:    true,
			SkipValidation: false,
		},
	}
}

// AddStages adds multiple stages to the pipeline
func (p *Pipeline) AddStages(stages ...Stage) {
	p.Stages = append(p.Stages, stages...)
}

// Execute runs the pipeline on the given processor
func (p *Pipeline) Execute(ctx context.Context, processor Processor) error {
	logger := processor.GetLogger().With("pipeline", p.Name)
	logger.Debug("Starting pipeline execution", "stages", len(p.Stages))

	// Seed ctx with the same attribution logger carries, so stages that
	// have no Processor handy (only ctx) can still reach it via
	// logging.From(ctx) - see internal/logging.
	ctx = logging.Into(ctx, logger)

	for i, stage := range p.Stages {
		if err := ctx.Err(); err != nil {
			return err
		}
		from := len(processor.GetMessages())
		err := p.runStage(ctx, logger, i, stage, processor)
		if tagger, ok := processor.(MessageTagger); ok {
			tagger.TagMessages(stage.Name(), from)
		}
		if err != nil {
			return err
		}
	}

	logger.Debug("Pipeline execution completed",
		"total_stages", len(p.Stages),
		"has_changes", processor.HasChanges(),
		"has_errors", len(processor.GetErrors()) > 0)

	return nil
}

// MessageTagger is optionally implemented by a processor that attributes its
// messages to the stage that added them: after each stage (run or skipped)
// Execute passes the stage name and the message count before it.
type MessageTagger interface {
	TagMessages(stage string, from int)
}

// runStage runs one stage; a non-nil error stops the pipeline
// (Options.StopOnError).
func (p *Pipeline) runStage(ctx context.Context, logger *slog.Logger, i int, stage Stage, processor Processor) error {
	// Layers onto the pipeline-level logger Execute seeded.
	ctx = logging.With(ctx, "stage", stage.Name(), "stage_index", i)
	stageLogger := logger.With("stage", stage.Name(), "stage_index", i)

	// Check if stage should run
	shouldRun, err := stage.ShouldRun(ctx, processor)
	if err != nil {
		err = fmt.Errorf("checking if stage %s should run: %w", stage.Name(), err)
		processor.AddError(err)
		if p.Options.StopOnError {
			return err
		}
		return nil
	}

	if !shouldRun {
		stageLogger.Debug("Skipping stage", "reason", "shouldRun returned false")
		return nil
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
				return nil
			}
		}
	}

	// Execute the stage based on its interface
	stageLogger.Debug("Executing stage")

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
		return nil
	}
	stageLogger.Debug("Stage completed successfully")
	return nil
}
