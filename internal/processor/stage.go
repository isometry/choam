package processor

import (
	"context"
)

// Stage represents a single processing step
type Stage interface {
	Name() string
	Description() string

	// Conditional execution - stages can decide if they should run
	ShouldRun(ctx context.Context, p Processor) (bool, error)
}

// ExecutableStage is a stage that can be executed (generic execution)
type ExecutableStage interface {
	Stage
	Execute(ctx context.Context, p Processor) error
}

// CheckStage performs checks without modifications
type CheckStage interface {
	Stage
	Check(ctx context.Context, p Processor) error
}

// ApplyStage applies modifications
type ApplyStage interface {
	Stage
	Apply(ctx context.Context, p Processor) error
}

// ValidatingStage can validate its preconditions before execution
type ValidatingStage interface {
	Stage
	Validate(ctx context.Context, p Processor) error
}

// BaseStage provides common functionality for stages
type BaseStage struct {
	StageName        string
	StageDescription string
}

func (bs *BaseStage) Name() string        { return bs.StageName }
func (bs *BaseStage) Description() string { return bs.StageDescription }

// DefaultShouldRun implementation - always run unless overridden
func (bs *BaseStage) ShouldRun(ctx context.Context, p Processor) (bool, error) {
	return true, nil
}
