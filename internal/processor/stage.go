package processor

import (
	"context"
	"fmt"
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

// StageRegistry manages available stages and provides stage construction
type StageRegistry struct {
	stages map[string]func() Stage
}

// NewStageRegistry creates a new stage registry
func NewStageRegistry() *StageRegistry {
	return &StageRegistry{
		stages: make(map[string]func() Stage),
	}
}

// Register adds a stage constructor to the registry
func (r *StageRegistry) Register(name string, constructor func() Stage) {
	r.stages[name] = constructor
}

// Create instantiates a stage by name
func (r *StageRegistry) Create(name string) (Stage, error) {
	if constructor, ok := r.stages[name]; ok {
		return constructor(), nil
	}
	return nil, fmt.Errorf("unknown stage: %s", name)
}

// ListStages returns all registered stage names
func (r *StageRegistry) ListStages() []string {
	names := make([]string, 0, len(r.stages))
	for name := range r.stages {
		names = append(names, name)
	}
	return names
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
