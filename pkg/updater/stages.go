package updater

import "context"

// CheckStage defines the interface for stages that check for available updates
// without modifying any files. These stages populate the PackageProcessor with
// update availability information.
type CheckStage interface {
	Stage
	Check(ctx context.Context, processor *PackageProcessor) error
}

// ApplyStage defines the interface for stages that apply updates to packages
// These stages modify the package files and update the processor state.
type ApplyStage interface {
	Stage
	Apply(ctx context.Context, processor *PackageProcessor) error
}

// Stage represents a general processing stage that can be used in pipelines
type Stage interface {
	Name() string
	Description() string
}

// CheckStageInfo provides metadata about a check stage
type CheckStageInfo struct {
	StageName string
	StageDesc string
}

func (c CheckStageInfo) Name() string        { return c.StageName }
func (c CheckStageInfo) Description() string { return c.StageDesc }

// ApplyStageInfo provides metadata about an apply stage
type ApplyStageInfo struct {
	StageName string
	StageDesc string
}

func (a ApplyStageInfo) Name() string        { return a.StageName }
func (a ApplyStageInfo) Description() string { return a.StageDesc }

// StageRegistry manages available processing stages
type StageRegistry struct {
	checkStages []CheckStage
	applyStages []ApplyStage
}

// NewStageRegistry creates a new stage registry
func NewStageRegistry() *StageRegistry {
	return &StageRegistry{
		checkStages: make([]CheckStage, 0),
		applyStages: make([]ApplyStage, 0),
	}
}

// RegisterCheckStage adds a check stage to the registry
func (sr *StageRegistry) RegisterCheckStage(stage CheckStage) {
	sr.checkStages = append(sr.checkStages, stage)
}

// RegisterApplyStage adds an apply stage to the registry
func (sr *StageRegistry) RegisterApplyStage(stage ApplyStage) {
	sr.applyStages = append(sr.applyStages, stage)
}

// GetCheckStages returns all registered check stages
func (sr *StageRegistry) GetCheckStages() []CheckStage {
	return sr.checkStages
}

// GetApplyStages returns all registered apply stages
func (sr *StageRegistry) GetApplyStages() []ApplyStage {
	return sr.applyStages
}

// DefaultStageRegistry creates a registry with all default stages
func DefaultStageRegistry() *StageRegistry {
	registry := NewStageRegistry()

	// Register default check stages
	registry.RegisterCheckStage(&VersionChecker{})
	registry.RegisterCheckStage(&GoDepsChecker{})

	// Register default apply stages
	registry.RegisterApplyStage(&VersionApplier{})
	registry.RegisterApplyStage(&PipelineProcessor{})
	registry.RegisterApplyStage(&GoDepsApplier{})

	// FileWriter must be the final stage to ensure all modifications are complete
	registry.RegisterApplyStage(&FileWriter{})

	return registry
}
