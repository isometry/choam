package gobump

import (
	"bytes"
	"fmt"

	"github.com/isometry/choam/internal/processor"
	"github.com/isometry/choam/internal/simulate"
)

// GoBumpProcessor extends BaseProcessor with security-specific fields
type GoBumpProcessor struct {
	*processor.BaseProcessor

	// Security-specific fields
	VulnerabilityAnalysis *VulnerabilityAnalysis `json:"vulnerability_analysis,omitempty"`
	SecurityFixes         []SecurityFix          `json:"security_fixes"`
	ActualChangesApplied  bool                   `json:"actual_changes_applied"`

	// Validated is true when the written deps lists were proven by
	// simulation (see SimulationStage); Residuals aggregates the advisories
	// simulation could not eliminate, across all modroots.
	Validated bool                `json:"validated"`
	Residuals []simulate.Residual `json:"residuals,omitempty"`

	// UnreachableVulnIDs are advisory IDs found by the analysis scan whose
	// modules are not linked into any build artifact in ANY modroot (see
	// SimulationStage's reachability diff) - informational: no bump is
	// proposed for them and they count neither as fixed nor residual.
	UnreachableVulnIDs []string `json:"unreachable_vuln_ids,omitempty"`
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

// AddResiduals aggregates per-modroot simulation residuals, deduplicated by
// (module, reason) across modroots.
func (p *GoBumpProcessor) AddResiduals(residuals []simulate.Residual) {
	seen := make(map[string]struct{}, len(p.Residuals))
	for _, r := range p.Residuals {
		seen[r.Module+"|"+r.Reason] = struct{}{}
	}
	for _, r := range residuals {
		key := r.Module + "|" + r.Reason
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		p.Residuals = append(p.Residuals, r)
	}
}

// AddUnreachableVulnIDs records advisory IDs affecting only unlinked
// modules, deduplicated.
func (p *GoBumpProcessor) AddUnreachableVulnIDs(ids []string) {
	seen := make(map[string]struct{}, len(p.UnreachableVulnIDs))
	for _, id := range p.UnreachableVulnIDs {
		seen[id] = struct{}{}
	}
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		p.UnreachableVulnIDs = append(p.UnreachableVulnIDs, id)
	}
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

// ToResult converts the processor state to a GoBumpResult.
//
// Advisory accounting: VulnerabilitiesFound counts unique advisories across
// the package. When the bump was validated by simulation, the residual
// advisory count is exact (the final resolved graph was rescanned) and
// unreachable advisories (unlinked modules, informational only) are known,
// so VulnerabilitiesFixed = found - residual - unreachable. Without
// validation there is no proof of what the bump actually fixes, so Fixed
// falls back to the historical approximation (modules changed), which is
// also always reported separately as ModulesBumped.
func (p *GoBumpProcessor) ToResult() *GoBumpResult {
	vulnerabilitiesFound := 0
	if p.VulnerabilityAnalysis != nil {
		vulnerabilitiesFound = p.VulnerabilityAnalysis.VulnerabilitiesFound
	}

	modulesBumped := 0
	if p.HasActualChanges() {
		modulesBumped = len(p.SecurityFixes)
	}

	residualIDs := make(map[string]struct{})
	vulnerabilitiesResidual := 0
	for _, r := range p.Residuals {
		vulnerabilitiesResidual += len(r.VulnIDs)
		for _, id := range r.VulnIDs {
			residualIDs[id] = struct{}{}
		}
	}

	// Defensive: an ID that ended up residual anywhere is accounted there,
	// never double-counted as unreachable.
	unreachableIDs := make([]string, 0, len(p.UnreachableVulnIDs))
	for _, id := range p.UnreachableVulnIDs {
		if _, ok := residualIDs[id]; !ok {
			unreachableIDs = append(unreachableIDs, id)
		}
	}
	vulnerabilitiesUnreachable := len(unreachableIDs)

	vulnerabilitiesFixed := modulesBumped
	if p.Validated {
		vulnerabilitiesFixed = max(vulnerabilitiesFound-vulnerabilitiesResidual-vulnerabilitiesUnreachable, 0)
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
		PackageName:                p.GetPackageName(),
		FilePath:                   p.GetFilePath(),
		VulnerabilitiesFound:       vulnerabilitiesFound,
		VulnerabilitiesFixed:       vulnerabilitiesFixed,
		VulnerabilitiesResidual:    vulnerabilitiesResidual,
		VulnerabilitiesUnreachable: vulnerabilitiesUnreachable,
		UnreachableVulnIDs:         unreachableIDs,
		ModulesBumped:              modulesBumped,
		Validated:                  p.Validated,
		Residuals:                  p.Residuals,
		SecurityFixes:              p.SecurityFixes,
		ActionsApplied:             actionsApplied,
		OldEpoch:                   p.OldEpoch,
		NewEpoch:                   p.NewEpoch,
		EpochChanged:               p.IsEpochChanged(),
		FileWasWritten:             p.HasFileChanges(),
		Messages:                   p.GetMessages(),
		Error:                      errorStr,
	}
}
