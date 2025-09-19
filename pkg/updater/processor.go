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

// SecurityFix represents a security vulnerability fix applied
type SecurityFix struct {
	Module        string `json:"module"`        // Go module affected
	Vulnerability string `json:"vulnerability"` // CVE or vulnerability ID
	OldVersion    string `json:"old_version"`   // version before fix
	NewVersion    string `json:"new_version"`   // version after fix
	Severity      string `json:"severity"`      // critical, high, medium, low
}

// BumpAction represents a planned action for go/bump pipelines
type BumpAction struct {
	Action       string   `json:"action"`       // "insert", "update", "remove"
	PipelineIdx  int      `json:"pipeline_idx"` // pipeline index for update/remove
	Dependencies []string `json:"dependencies"` // dependencies to insert/update with
	Reason       string   `json:"reason"`       // human-readable reason
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
	VersionChanged    bool             `json:"version_changed"`
	EpochChanged      bool             `json:"epoch_changed"`
	OldEpoch          int64            `json:"old_epoch"`
	NewEpoch          int64            `json:"new_epoch"`
	PipelineChanges   []PipelineChange `json:"pipeline_changes"`
	SecurityFixes     []SecurityFix    `json:"security_fixes"`
	RequiresEpochBump bool             `json:"requires_epoch_bump"`

	// Go dependency analysis results
	GoDepsAnalyzed    bool              `json:"go_deps_analyzed"`
	GoModRequirements map[string]string `json:"go_mod_requirements,omitempty"`
	SecurityBumps     []string          `json:"security_bumps,omitempty"`
	GoBumpActions     []BumpAction      `json:"go_bump_actions,omitempty"`

	// Accumulated state and messages
	Messages             []string `json:"messages"`
	Errors               []string `json:"errors,omitempty"`
	VulnerabilitiesFound int      `json:"vulnerabilities_found"`
	VulnerabilitiesFixed int      `json:"vulnerabilities_fixed"`
	FileWasWritten       bool     `json:"file_was_written"`

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
		FilePath:          filePath,
		PackageName:       packageName,
		Logger:            logger,
		CurrentVersion:    currentVersion,
		OldEpoch:          currentEpoch,
		NewEpoch:          currentEpoch,
		GoModRequirements: make(map[string]string),
		SecurityBumps:     make([]string, 0),
		GoBumpActions:     make([]BumpAction, 0),
		Messages:          make([]string, 0),
		Errors:            make([]string, 0),
		PipelineChanges:   make([]PipelineChange, 0),
		SecurityFixes:     make([]SecurityFix, 0),
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

// SetEpochBump marks that the epoch was bumped
func (p *PackageProcessor) SetEpochBump(reason string) {
	p.EpochChanged = true
	p.NewEpoch++

	p.AddMessage(fmt.Sprintf("epoch bumped: %d -> %d (%s)", p.OldEpoch, p.NewEpoch, reason))
	p.Logger.Info("Epoch bumped", "old_epoch", p.OldEpoch, "new_epoch", p.NewEpoch, "reason", reason)
}

// MarkSecurityFixesApplied marks that security fixes were applied
func (p *PackageProcessor) MarkSecurityFixesApplied() {
	p.RequiresEpochBump = true
	p.Logger.Debug("Security fixes applied - epoch bump will be required")
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

// AddSecurityFix records a security vulnerability fix
func (p *PackageProcessor) AddSecurityFix(fix SecurityFix) {
	p.SecurityFixes = append(p.SecurityFixes, fix)
	p.AddMessage(fmt.Sprintf("security fix: %s %s -> %s (%s)", fix.Module, fix.OldVersion, fix.NewVersion, fix.Vulnerability))

	p.Logger.Info("Security fix applied",
		"module", fix.Module,
		"vulnerability", fix.Vulnerability,
		"old_version", fix.OldVersion,
		"new_version", fix.NewVersion,
		"severity", fix.Severity)
}

// SetGoDepsAnalysis sets the Go dependency analysis results
func (p *PackageProcessor) SetGoDepsAnalysis(requirements map[string]string, securityBumps []string, actions []BumpAction) {
	p.GoDepsAnalyzed = true
	p.GoModRequirements = requirements
	p.SecurityBumps = securityBumps
	p.GoBumpActions = actions

	p.Logger.Debug("Go deps analysis set",
		"go_mod_deps", len(requirements),
		"security_bumps", len(securityBumps),
		"actions", len(actions))
}

// HasGoDepsActions returns true if there are go/bump actions to apply
func (p *PackageProcessor) HasGoDepsActions() bool {
	return len(p.GoBumpActions) > 0
}

// AddBumpAction adds a go/bump action to be applied
func (p *PackageProcessor) AddBumpAction(action BumpAction) {
	p.GoBumpActions = append(p.GoBumpActions, action)
	p.Logger.Debug("Go bump action added", "action", action.Action, "reason", action.Reason)
}

// SetVulnerabilityInfo updates vulnerability scan results (found, not necessarily fixed)
func (p *PackageProcessor) SetVulnerabilityInfo(vulnCount, criticalCount, highCount int) {
	p.VulnerabilitiesFound = vulnCount

	// Don't add messages here - only add messages when vulnerabilities are actually fixed
	p.Logger.Info("Vulnerability scan completed",
		"total_vulnerabilities", vulnCount,
		"critical", criticalCount,
		"high", highCount)
}

// SetVulnerabilityFixes updates vulnerability fix results (actually fixed)
func (p *PackageProcessor) SetVulnerabilityFixes(fixedCount, criticalFixed, highFixed int) {
	p.VulnerabilitiesFixed = fixedCount

	// Only add messages when vulnerabilities are actually fixed
	if fixedCount > 0 {
		if criticalFixed > 0 || highFixed > 0 {
			p.AddMessage(fmt.Sprintf("security fixes applied: %d vulnerabilities fixed (%d critical, %d high)",
				fixedCount, criticalFixed, highFixed))
		} else {
			p.AddMessage(fmt.Sprintf("security fixes applied: %d vulnerabilities fixed", fixedCount))
		}
	}

	p.Logger.Info("Vulnerability fixes applied",
		"vulnerabilities_fixed", fixedCount,
		"critical_fixed", criticalFixed,
		"high_fixed", highFixed)
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
	return p.VersionChanged || p.EpochChanged || len(p.PipelineChanges) > 0 || len(p.SecurityFixes) > 0
}

// HasFileChanges returns true if actual file modifications were made
func (p *PackageProcessor) HasFileChanges() bool {
	return p.FileWasWritten
}

// NeedsEpochBump returns true if epoch should be bumped (changes without version change)
func (p *PackageProcessor) NeedsEpochBump() bool {
	return p.RequiresEpochBump && !p.VersionChanged && !p.EpochChanged
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
