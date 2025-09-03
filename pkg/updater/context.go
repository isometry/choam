package updater

import "fmt"

// UpdateContext tracks all changes through the update pipeline
// This provides a robust way to track what changes were made and whether
// they require epoch bumps or other actions.
type UpdateContext struct {
	// Version changes
	VersionChanged bool
	OldVersion     string
	NewVersion     string

	// Epoch changes
	EpochChanged      bool
	OldEpoch          int64
	NewEpoch          int64
	RequiresEpochBump bool // Set by any phase that makes changes requiring epoch bump

	// Pipeline changes tracking
	GitCheckoutUpdated bool
	FetchUpdated       bool
	GoBumpUpdated      bool
	SecurityFixesAdded int // Count of security fixes added

	// Content tracking
	OriginalContent []byte
	CurrentContent  []byte

	// Messages for display - human-readable messages about what was updated
	UpdateMessages []string

	// Vulnerability information
	VulnerabilitiesFound int
	CriticalVulns        int
	HighVulns           int
}

// NewUpdateContext creates a new UpdateContext with initial state
func NewUpdateContext(originalContent []byte, oldVersion string, oldEpoch int64) *UpdateContext {
	return &UpdateContext{
		OriginalContent:  originalContent,
		CurrentContent:   originalContent,
		OldVersion:      oldVersion,
		NewVersion:      oldVersion, // Initially same as old
		OldEpoch:        oldEpoch,
		NewEpoch:        oldEpoch, // Initially same as old
		UpdateMessages:  make([]string, 0),
	}
}

// SetVersionUpdate marks that the version was updated
func (uc *UpdateContext) SetVersionUpdate(newVersion string) {
	uc.VersionChanged = true
	uc.NewVersion = newVersion
	uc.NewEpoch = 0 // Reset epoch when version changes
	uc.UpdateMessages = append(uc.UpdateMessages, "package.version", "package.epoch")
}

// SetEpochBump marks that the epoch should be bumped (usually for security fixes without version change)
func (uc *UpdateContext) SetEpochBump(reason string) {
	if !uc.VersionChanged { // Only bump epoch if version didn't change
		uc.RequiresEpochBump = true
		uc.EpochChanged = true
		uc.NewEpoch = uc.OldEpoch + 1
		uc.UpdateMessages = append(uc.UpdateMessages, "package.epoch ("+reason+")")
	}
}

// SetSecurityFixes records vulnerability information found during security scan
func (uc *UpdateContext) SetSecurityFixes(count int, vulnCount, criticalCount, highCount int) {
	uc.SecurityFixesAdded += count
	uc.VulnerabilitiesFound = vulnCount
	uc.CriticalVulns = criticalCount
	uc.HighVulns = highCount

	// Add vulnerability summary message
	vulnSummary := "security scan found %d vulnerabilities"
	if criticalCount > 0 || highCount > 0 {
		vulnSummary += " (%d critical, %d high)"
		uc.UpdateMessages = append(uc.UpdateMessages, 
			fmt.Sprintf(vulnSummary, vulnCount, criticalCount, highCount))
	} else {
		uc.UpdateMessages = append(uc.UpdateMessages, 
			fmt.Sprintf(vulnSummary, vulnCount))
	}
}

// MarkSecurityFixesApplied marks that actual security fixes have been applied to the file
func (uc *UpdateContext) MarkSecurityFixesApplied() {
	// Security fixes require epoch bump if no version change
	uc.RequiresEpochBump = true
}

// AddGoBumpUpdate marks that go/bump pipeline was updated
func (uc *UpdateContext) AddGoBumpUpdate(message string) {
	uc.GoBumpUpdated = true
	uc.UpdateMessages = append(uc.UpdateMessages, message)
}

// AddGitCheckoutUpdate marks that git-checkout pipeline was updated
func (uc *UpdateContext) AddGitCheckoutUpdate(pipelineIndex int) {
	uc.GitCheckoutUpdated = true
	uc.UpdateMessages = append(uc.UpdateMessages, 
		fmt.Sprintf("pipeline[%d].with.expected-commit", pipelineIndex))
}

// AddFetchUpdate marks that fetch pipeline was updated
func (uc *UpdateContext) AddFetchUpdate(pipelineIndex int) {
	uc.FetchUpdated = true
	uc.UpdateMessages = append(uc.UpdateMessages, 
		fmt.Sprintf("pipeline[%d].with.expected-sha256", pipelineIndex))
}

// HasChanges returns true if any changes were made
func (uc *UpdateContext) HasChanges() bool {
	return uc.VersionChanged || uc.EpochChanged || uc.GitCheckoutUpdated || 
		   uc.FetchUpdated || uc.GoBumpUpdated || len(uc.UpdateMessages) > 0
}

// NeedsEpochBump returns true if epoch should be bumped
func (uc *UpdateContext) NeedsEpochBump() bool {
	return uc.RequiresEpochBump && !uc.VersionChanged && !uc.EpochChanged
}