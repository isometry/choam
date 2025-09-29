package gobump

import (
	"github.com/isometry/choam/internal/scan"
	"golang.org/x/mod/modfile"
)

// BumpAction represents a planned action for go/bump pipelines
type BumpAction struct {
	Action       string   `json:"action"`       // "insert", "update", "remove"
	PipelineIdx  int      `json:"pipeline_idx"` // pipeline index for update/remove
	Dependencies []string `json:"dependencies"` // dependencies to insert/update with
	Reason       string   `json:"reason"`       // human-readable reason
}

// SecurityFix represents a security vulnerability fix applied
type SecurityFix struct {
	Module        string `json:"module"`        // Go module affected
	Vulnerability string `json:"vulnerability"` // CVE or vulnerability ID
	OldVersion    string `json:"old_version"`   // version before fix
	NewVersion    string `json:"new_version"`   // version after fix
	Severity      string `json:"severity"`      // critical, high, medium, low
}

// BumpAnalysis represents the analysis result for a single bump
type BumpAnalysis struct {
	Module       string
	BumpVersion  string
	GoModVersion string
	Action       string // "keep", "remove-noop", "remove-downgrade", "remove-missing"
	Reason       string
}

// GoModInfo contains parsed go.mod information including requirements and replacements
type GoModInfo struct {
	Requirements    map[string]string           // module -> version (direct dependencies)
	AllRequirements map[string]string           // module -> version (all dependencies including indirect)
	Replacements    map[string]*modfile.Replace // module -> replacement
}

// GoBumpResult represents the result of a go bump operation
type GoBumpResult struct {
	PackageName          string        `json:"package_name"`
	FilePath             string        `json:"file_path"`
	VulnerabilitiesFound int           `json:"vulnerabilities_found"`
	VulnerabilitiesFixed int           `json:"vulnerabilities_fixed"`
	CriticalFixed        int           `json:"critical_fixed"`
	HighFixed            int           `json:"high_fixed"`
	SecurityFixes        []SecurityFix `json:"security_fixes"`
	ActionsApplied       []BumpAction  `json:"actions_applied"`
	OldEpoch             int64         `json:"old_epoch"`
	NewEpoch             int64         `json:"new_epoch"`
	EpochChanged         bool          `json:"epoch_changed"`
	FileWasWritten       bool          `json:"file_was_written"`
	Messages             []string      `json:"messages"`
	Error                string        `json:"error,omitempty"`
}

// VulnerabilityAnalysis contains the results of scanning go dependencies
type VulnerabilityAnalysis struct {
	GoModInfo            *GoModInfo       `json:"go_mod_info"`
	ScanResult           *scan.ScanResult `json:"scan_result"`
	VulnerabilitiesFound int              `json:"vulnerabilities_found"`
	CriticalCount        int              `json:"critical_count"`
	HighCount            int              `json:"high_count"`
	SecurityBumps        []string         `json:"security_bumps"`
	BumpActions          []BumpAction     `json:"bump_actions"`
	Analysis             []BumpAnalysis   `json:"analysis"`
}

// ProcessorOptions configures processor behavior
type ProcessorOptions struct {
	DryRun       bool   `json:"dry_run"`
	BackupSuffix string `json:"backup_suffix"`
	TempDir      string `json:"temp_dir"`
}
