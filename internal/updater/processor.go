package updater

import (
	"fmt"
	"log/slog"

	"github.com/isometry/choam/internal/processor"
)

// UpdaterProcessor extends BaseProcessor for updater-specific functionality
type UpdaterProcessor struct {
	processor.BaseProcessor

	// Update-specific state
	UpdateAvailable bool             `json:"update_available"`
	CurrentVersion  string           `json:"current_version"`
	LatestVersion   string           `json:"latest_version"`
	UpdateSource    string           `json:"update_source"`
	IsManual        bool             `json:"is_manual"`
	VersionChanged  bool             `json:"version_changed"`
	PipelineChanges []PipelineChange `json:"pipeline_changes"`
}

// NewUpdaterProcessor creates a new updater processor extending BaseProcessor
func NewUpdaterProcessor(filePath, packageName, currentVersion string, currentEpoch int64) *UpdaterProcessor {
	// Create the base processor
	baseProcessor := processor.NewBaseProcessor(filePath, packageName, currentVersion, currentEpoch)

	// Create the updater processor
	return &UpdaterProcessor{
		BaseProcessor:   *baseProcessor,
		CurrentVersion:  currentVersion,
		PipelineChanges: make([]PipelineChange, 0),
	}
}

// GetCurrentVersion returns the current version (override to use local field)
func (p *UpdaterProcessor) GetCurrentVersion() string {
	return p.CurrentVersion
}

// SetUpdateResult updates the processor with check results
func (p *UpdaterProcessor) SetUpdateResult(hasUpdate bool, latestVersion, source string, isManual bool) {
	p.UpdateAvailable = hasUpdate
	p.LatestVersion = latestVersion
	p.UpdateSource = source
	p.IsManual = isManual
}

// SetVersionUpdate marks that the version was updated (implements Processor interface)
func (p *UpdaterProcessor) SetVersionUpdate(old, new string) {
	p.VersionChanged = true
	p.LatestVersion = new
	p.AddMessage(fmt.Sprintf("version updated: %s -> %s", old, new))
	p.GetLogger().Info("Version updated", "old_version", old, "new_version", new)
}

// GetLatestVersion returns the latest version
func (p *UpdaterProcessor) GetLatestVersion() string {
	return p.LatestVersion
}

// IsVersionChanged returns true if version was changed
func (p *UpdaterProcessor) IsVersionChanged() bool {
	return p.VersionChanged
}

// GetNewEpoch returns the new epoch (delegate to base processor)
func (p *UpdaterProcessor) GetNewEpoch() int64 {
	return p.BaseProcessor.GetNewEpoch()
}

// GetOldEpoch returns the old epoch (for compatibility)
func (p *UpdaterProcessor) GetOldEpoch() int64 {
	return p.GetCurrentEpoch()
}

// AddPipelineChange records a pipeline modification
func (p *UpdaterProcessor) AddPipelineChange(change PipelineChange) {
	p.PipelineChanges = append(p.PipelineChanges, change)
	p.AddMessage(change.Description)

	p.GetLogger().Debug("Pipeline change recorded",
		"type", change.Type,
		"index", change.Index,
		"field", change.Field,
		"description", change.Description)
}

// HasChanges returns true if any changes were made to the package
func (p *UpdaterProcessor) HasChanges() bool {
	return p.VersionChanged || p.IsEpochChanged() || len(p.PipelineChanges) > 0
}

// WithStage creates a child logger for a specific processing stage
func (p *UpdaterProcessor) WithStage(stage string) *slog.Logger {
	return p.GetLogger().With("stage", stage)
}

// WithPipeline creates a child logger for a specific pipeline operation
func (p *UpdaterProcessor) WithPipeline(stage string, index int) *slog.Logger {
	return p.GetLogger().With("stage", stage, "pipeline_index", index)
}

// Summary returns a brief summary of the processing results
func (p *UpdaterProcessor) Summary() string {
	if len(p.GetErrors()) > 0 {
		return p.GetPackageName() + ": error"
	}

	if !p.UpdateAvailable {
		return p.GetPackageName() + ": up to date"
	}

	if p.IsManual {
		return p.GetPackageName() + ": manual update available (" +
			p.CurrentVersion + " -> " + p.LatestVersion + ")"
	}

	if p.HasChanges() {
		changeCount := len(p.GetMessages())
		return p.GetPackageName() + ": updated with " +
			fmt.Sprintf("%d", changeCount) + " changes"
	}

	return p.GetPackageName() + ": update available (" +
		p.CurrentVersion + " -> " + p.LatestVersion + ")"
}
