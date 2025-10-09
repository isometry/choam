package processor

import (
	"bytes"
	"fmt"
	"log/slog"

	melange "chainguard.dev/melange/pkg/config"
)

// Processor defines the core interface for all package processors
type Processor interface {
	// Identity
	GetFilePath() string
	GetPackageName() string
	GetLogger() *slog.Logger

	// Configuration
	GetConfig() *melange.Configuration
	GetOriginalYAML() []byte
	GetCurrentYAML() []byte
	SetCurrentYAML([]byte)

	// Version tracking
	GetCurrentVersion() string
	GetLatestVersion() string
	SetVersionUpdate(old, new string)
	IsVersionChanged() bool

	// Epoch tracking
	GetCurrentEpoch() int64
	GetNewEpoch() int64
	SetEpochUpdate(old, new int64)
	IsEpochChanged() bool

	// Change tracking
	AddChange(Change)
	GetChanges() []Change
	HasChanges() bool
	HasFileChanges() bool

	// Messaging
	AddMessage(string)
	AddError(error)
	GetMessages() []string
	GetErrors() []error

	// Options
	GetOptions() ProcessorOptions
	SetOptions(ProcessorOptions)

	// Context for custom data
	GetContext(key string) any
	SetContext(key string, value any)
}

// Change represents a modification made to the package
type Change struct {
	Type        string `json:"type"`        // "version", "epoch", "pipeline", "security"
	Field       string `json:"field"`       // specific field changed
	OldValue    string `json:"old_value"`   // previous value
	NewValue    string `json:"new_value"`   // new value
	Description string `json:"description"` // human-readable description
	Reason      string `json:"reason"`      // why the change was made
}

// ProcessorOptions contains configuration for package processing
type ProcessorOptions struct {
	DryRun        bool   `json:"dry_run"`
	Force         bool   `json:"force"`
	SharedUpdates bool   `json:"shared_updates"`
	BackupSuffix  string `json:"backup_suffix"`
	TempDir       string `json:"temp_dir"`
}

// BaseProcessor provides a base implementation that can be embedded
type BaseProcessor struct {
	// Core fields
	FilePath    string
	PackageName string
	Logger      *slog.Logger

	// Configuration
	Config       *melange.Configuration
	OriginalYAML []byte
	CurrentYAML  []byte

	// Version state
	CurrentVersion string
	LatestVersion  string
	VersionChanged bool
	OldVersion     string
	NewVersion     string

	// Epoch state
	CurrentEpoch int64
	NewEpoch     int64
	EpochChanged bool
	OldEpoch     int64

	// Change tracking
	Changes  []Change
	Messages []string
	Errors   []error

	// Options
	Options ProcessorOptions

	// Extensibility
	Context map[string]any
}

// NewBaseProcessor creates a new base processor
func NewBaseProcessor(filePath, packageName, currentVersion string, currentEpoch int64) *BaseProcessor {
	logger := slog.Default().With(
		"package", packageName,
		"file", filePath,
	)

	return &BaseProcessor{
		FilePath:       filePath,
		PackageName:    packageName,
		Logger:         logger,
		CurrentVersion: currentVersion,
		CurrentEpoch:   currentEpoch,
		OldEpoch:       currentEpoch,
		NewEpoch:       currentEpoch,
		Changes:        make([]Change, 0),
		Messages:       make([]string, 0),
		Errors:         make([]error, 0),
		Context:        make(map[string]any),
	}
}

// Implementation of Processor interface
func (bp *BaseProcessor) GetFilePath() string               { return bp.FilePath }
func (bp *BaseProcessor) GetPackageName() string            { return bp.PackageName }
func (bp *BaseProcessor) GetLogger() *slog.Logger           { return bp.Logger }
func (bp *BaseProcessor) GetConfig() *melange.Configuration { return bp.Config }
func (bp *BaseProcessor) GetOriginalYAML() []byte           { return bp.OriginalYAML }
func (bp *BaseProcessor) GetCurrentYAML() []byte            { return bp.CurrentYAML }
func (bp *BaseProcessor) SetCurrentYAML(yaml []byte)        { bp.CurrentYAML = yaml }
func (bp *BaseProcessor) GetCurrentVersion() string         { return bp.CurrentVersion }
func (bp *BaseProcessor) GetLatestVersion() string          { return bp.LatestVersion }
func (bp *BaseProcessor) IsVersionChanged() bool            { return bp.VersionChanged }
func (bp *BaseProcessor) GetCurrentEpoch() int64            { return bp.CurrentEpoch }
func (bp *BaseProcessor) GetNewEpoch() int64                { return bp.NewEpoch }
func (bp *BaseProcessor) IsEpochChanged() bool              { return bp.EpochChanged }
func (bp *BaseProcessor) GetChanges() []Change              { return bp.Changes }
func (bp *BaseProcessor) GetMessages() []string             { return bp.Messages }
func (bp *BaseProcessor) GetErrors() []error                { return bp.Errors }
func (bp *BaseProcessor) GetOptions() ProcessorOptions      { return bp.Options }
func (bp *BaseProcessor) SetOptions(opts ProcessorOptions)  { bp.Options = opts }
func (bp *BaseProcessor) GetContext(key string) any         { return bp.Context[key] }
func (bp *BaseProcessor) SetContext(key string, value any)  { bp.Context[key] = value }

func (bp *BaseProcessor) SetVersionUpdate(old, new string) {
	bp.OldVersion = old
	bp.NewVersion = new
	bp.LatestVersion = new
	bp.VersionChanged = true
	bp.AddChange(Change{
		Type:        "version",
		Field:       "package.version",
		OldValue:    old,
		NewValue:    new,
		Description: fmt.Sprintf("version updated: %s -> %s", old, new),
		Reason:      "new version available",
	})
}

func (bp *BaseProcessor) SetEpochUpdate(old, new int64) {
	bp.OldEpoch = old
	bp.NewEpoch = new
	bp.EpochChanged = true
	bp.AddChange(Change{
		Type:        "epoch",
		Field:       "package.epoch",
		OldValue:    fmt.Sprintf("%d", old),
		NewValue:    fmt.Sprintf("%d", new),
		Description: fmt.Sprintf("epoch updated: %d -> %d", old, new),
	})
}

func (bp *BaseProcessor) AddChange(change Change) {
	bp.Changes = append(bp.Changes, change)
}

func (bp *BaseProcessor) HasChanges() bool {
	return len(bp.Changes) > 0
}

func (bp *BaseProcessor) HasFileChanges() bool {
	return !bytes.Equal(bp.OriginalYAML, bp.CurrentYAML)
}

func (bp *BaseProcessor) AddMessage(message string) {
	bp.Messages = append(bp.Messages, message)
}

func (bp *BaseProcessor) AddError(err error) {
	bp.Errors = append(bp.Errors, err)
}
