package gobump

import (
	"bytes"
	"fmt"

	"github.com/isometry/choam/internal/processor"
)

// GoBumpProcessor extends BaseProcessor with security-specific fields
type GoBumpProcessor struct {
	*processor.BaseProcessor

	// Security-specific fields
	VulnerabilityAnalysis *VulnerabilityAnalysis `json:"vulnerability_analysis,omitempty"`
	SecurityFixes         []SecurityFix          `json:"security_fixes"`
	ActualChangesApplied  bool                   `json:"actual_changes_applied"`
}

// NewGoBumpProcessor creates a new gobump processor
func NewGoBumpProcessor(filePath, packageName, currentVersion string, currentEpoch int64) *GoBumpProcessor {
	return &GoBumpProcessor{
		BaseProcessor:        processor.NewBaseProcessor(filePath, packageName, currentVersion, currentEpoch),
		SecurityFixes:        make([]SecurityFix, 0),
		ActualChangesApplied: false,
	}
}

// AddSecurityFix adds a security fix to the processor
func (p *GoBumpProcessor) AddSecurityFix(fix SecurityFix) {
	p.SecurityFixes = append(p.SecurityFixes, fix)

	// Add as a change for tracking
	p.AddChange(processor.Change{
		Type:        "security",
		Field:       fix.Module,
		OldValue:    fix.OldVersion,
		NewValue:    fix.NewVersion,
		Description: fmt.Sprintf("security fix: %s %s -> %s", fix.Module, fix.OldVersion, fix.NewVersion),
		Reason:      fmt.Sprintf("vulnerability: %s (%s)", fix.Vulnerability, fix.Severity),
	})
}

// MarkActualChangesApplied marks that actual changes were made to the YAML
// This is critical for the epoch bumping logic - epoch should only bump when file changes occur
func (p *GoBumpProcessor) MarkActualChangesApplied() {
	p.ActualChangesApplied = true
}

// HasActualChanges returns true if actual file modifications were made (not just vulnerabilities found)
func (p *GoBumpProcessor) HasActualChanges() bool {
	// Check if YAML content actually changed
	return !bytes.Equal(p.GetOriginalYAML(), p.GetCurrentYAML()) || p.ActualChangesApplied
}

// ToResult converts the processor state to a GoBumpResult
func (p *GoBumpProcessor) ToResult() *GoBumpResult {
	vulnerabilitiesFound := 0
	vulnerabilitiesFixed := 0

	// Only count fixes when actual changes were made to the file
	if p.HasActualChanges() {
		vulnerabilitiesFixed = len(p.SecurityFixes)
	}

	if p.VulnerabilityAnalysis != nil {
		vulnerabilitiesFound = p.VulnerabilityAnalysis.VulnerabilitiesFound
	}

	var errorStr string
	if len(p.GetErrors()) > 0 {
		errorStr = p.GetErrors()[0].Error()
	}

	actionsApplied := make([]BumpAction, 0)
	if p.VulnerabilityAnalysis != nil && p.HasActualChanges() {
		actionsApplied = p.VulnerabilityAnalysis.BumpActions
	}

	return &GoBumpResult{
		PackageName:          p.GetPackageName(),
		FilePath:             p.GetFilePath(),
		VulnerabilitiesFound: vulnerabilitiesFound,
		VulnerabilitiesFixed: vulnerabilitiesFixed,
		SecurityFixes:        p.SecurityFixes,
		ActionsApplied:       actionsApplied,
		OldEpoch:             p.OldEpoch,
		NewEpoch:             p.NewEpoch,
		EpochChanged:         p.IsEpochChanged(),
		FileWasWritten:       p.HasFileChanges(),
		Messages:             p.GetMessages(),
		Error:                errorStr,
	}
}
