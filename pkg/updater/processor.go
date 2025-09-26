package updater

import (
	"fmt"
	"log/slog"

	melange "chainguard.dev/melange/pkg/config"
)

// PipelineChange represents a change made to a pipeline step
type PipelineChange struct {
	Type        string `json:"type"`        // "git-checkout", "fetch", "go/bump"
	Index       int    `json:"index"`       // pipeline index
	Field       string `json:"field"`       // field changed
	OldValue    string `json:"old_value"`   // previous value
	NewValue    string `json:"new_value"`   // new value
	Description string `json:"description"` // human-readable description
}


// ProcessorOptions contains configuration for package processing
type ProcessorOptions struct {
	DryRun        bool   `json:"dry_run"`
	Force         bool   `json:"force"`
	SharedUpdates bool   `json:"shared_updates"`
	BackupSuffix  string `json:"backup_suffix"`
	TempDir       string `json:"temp_dir"`
}

// PackageProcessor represents a single package throughout its entire update lifecycle
// This provides a unified state container with consistent logging that can be used
// across check and apply phases, supporting future concurrency and maintainability
type PackageProcessor struct {
	// Identity and file information
	FilePath    string `json:"file_path"`
	PackageName string `json:"package_name"`

	// Consistent logger with package context - created once, used everywhere
	Logger *slog.Logger `json:"-"`

	// Configuration state
	Config       *melange.Configuration `json:"-"`
	OriginalYAML []byte                 `json:"-"`
	CurrentYAML  []byte                 `json:"-"`

	// Check phase results
	UpdateAvailable bool   `json:"update_available"`
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateSource    string `json:"update_source"`
	IsManual        bool   `json:"is_manual"`

	// Apply phase state
	VersionChanged  bool             `json:"version_changed"`
	EpochChanged    bool             `json:"epoch_changed"`
	OldEpoch        int64            `json:"old_epoch"`
	NewEpoch        int64            `json:"new_epoch"`
	PipelineChanges []PipelineChange `json:"pipeline_changes"`

	// Accumulated state and messages
	Messages       []string `json:"messages"`
	Errors         []string `json:"errors,omitempty"`
	FileWasWritten bool     `json:"file_was_written"`

	// Processing options
	Options ProcessorOptions `json:"options"`
}

// NewPackageProcessor creates a new package processor with proper logger context
// The logger includes the package name for all subsequent operations
func NewPackageProcessor(filePath, packageName, currentVersion string, currentEpoch int64) *PackageProcessor {
	// Create a logger with minimal package context - other fields added when relevant
	logger := slog.Default().With(
		"package", packageName,
	)

	return &PackageProcessor{
		FilePath:        filePath,
		PackageName:     packageName,
		Logger:          logger,
		CurrentVersion:  currentVersion,
		OldEpoch:        currentEpoch,
		NewEpoch:        currentEpoch,
		Messages:        make([]string, 0),
		Errors:          make([]string, 0),
		PipelineChanges: make([]PipelineChange, 0),
	}
}

// WithStage creates a child logger for a specific processing stage
func (p *PackageProcessor) WithStage(stage string) *slog.Logger {
	return p.Logger.With("stage", stage)
}

// WithPipeline creates a child logger for a specific pipeline operation
func (p *PackageProcessor) WithPipeline(stage string, index int) *slog.Logger {
	return p.Logger.With("stage", stage, "pipeline_index", index)
}

// SetUpdateResult updates the processor with check results
func (p *PackageProcessor) SetUpdateResult(hasUpdate bool, latestVersion, source string, isManual bool) {
	p.UpdateAvailable = hasUpdate
	p.LatestVersion = latestVersion
	p.UpdateSource = source
	p.IsManual = isManual
}

// SetVersionUpdate marks that the version was updated (epoch handling moved to EpochApplier)
func (p *PackageProcessor) SetVersionUpdate(newVersion string) {
	p.VersionChanged = true
	p.LatestVersion = newVersion
	// Epoch handling is now centralized in EpochApplier

	p.AddMessage(fmt.Sprintf("version updated: %s -> %s", p.CurrentVersion, newVersion))
	p.Logger.Info("Version updated", "old_version", p.CurrentVersion, "new_version", newVersion)
}


// AddPipelineChange records a pipeline modification
func (p *PackageProcessor) AddPipelineChange(change PipelineChange) {
	p.PipelineChanges = append(p.PipelineChanges, change)
	p.AddMessage(change.Description)

	p.Logger.Debug("Pipeline change recorded",
		"type", change.Type,
		"index", change.Index,
		"field", change.Field,
		"description", change.Description)
}


// AddMessage adds a human-readable message about changes
func (p *PackageProcessor) AddMessage(message string) {
	p.Messages = append(p.Messages, message)
}

// AddError records an error that occurred during processing
func (p *PackageProcessor) AddError(err error) {
	errorStr := err.Error()
	p.Errors = append(p.Errors, errorStr)
	p.Logger.Error("Processing error", "error", err)
}

// HasChanges returns true if any changes were made to the package
func (p *PackageProcessor) HasChanges() bool {
	return p.VersionChanged || p.EpochChanged || len(p.PipelineChanges) > 0
}

// HasFileChanges returns true if actual file modifications were made
func (p *PackageProcessor) HasFileChanges() bool {
	return p.FileWasWritten
}


// HasErrors returns true if any errors were recorded
func (p *PackageProcessor) HasErrors() bool {
	return len(p.Errors) > 0
}

// Summary returns a brief summary of the processing results
func (p *PackageProcessor) Summary() string {
	if p.HasErrors() {
		return fmt.Sprintf("%s: error", p.PackageName)
	}

	if !p.UpdateAvailable {
		return fmt.Sprintf("%s: up to date", p.PackageName)
	}

	if p.IsManual {
		return fmt.Sprintf("%s: manual update available (%s -> %s)",
			p.PackageName, p.CurrentVersion, p.LatestVersion)
	}

	if p.HasChanges() {
		changeCount := len(p.Messages)
		return fmt.Sprintf("%s: updated with %d changes", p.PackageName, changeCount)
	}

	return fmt.Sprintf("%s: update available (%s -> %s)",
		p.PackageName, p.CurrentVersion, p.LatestVersion)
}
