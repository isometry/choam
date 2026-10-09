package gobump

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/isometry/choam/internal/logging"
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

	// HygieneBumps are the scanner-hygiene entries the applier wrote (see
	// GoBumpResult.HygieneBumps); like SecurityFixes they justify an epoch
	// bump only together with ActualChangesApplied.
	HygieneBumps []SecurityFix `json:"hygiene_bumps,omitempty"`

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

	// SkipReasons say why (part of) the package was not analyzed - e.g. its
	// source cannot be fetched (no git-checkout step, a non-GitHub
	// repository) or a detected language is unsupported. Non-empty means the
	// result is SKIPPED, never clean.
	SkipReasons []string `json:"skip_reasons,omitempty"`

	// StdlibBumps are the Go stdlib staleness findings (see StdlibStage) -
	// each justifies an epoch bump on its own, independent of dependency
	// changes. StdlibChecked is true when the staleness check ran to
	// completion (false when skipped or degraded).
	StdlibBumps   []StdlibBump `json:"stdlib_bumps,omitempty"`
	StdlibChecked bool         `json:"stdlib_checked"`

	// LinkedStdPackages is the union, across simulated Go modroots, of
	// standard-library import paths linked into the build artifacts
	// (GOOS=linux; see simulate.ModrootResult.StdPackages). Non-nil only
	// when EVERY simulated Go modroot contributed a validated set (see
	// SimulationStage.Apply's stdComplete tracking); a modroot that was
	// skipped or whose stdlib walk failed open discards the whole union
	// rather than publishing a partial one. nil = unknown (simulation
	// didn't run, a modroot was skipped, or any modroot's toolchain walk
	// failed open) - the stdlib staleness stage then fails open.
	LinkedStdPackages map[string]struct{} `json:"-"`

	// RaisedPinMinors records the effective outcome of this run's go-package
	// pin reconciliation (see reconcileGoPackagePins): original pin minor ->
	// post-run minor, identity when the pin was already sufficient. Only
	// versioned, non-templated pins record entries; nil when reconciliation
	// didn't run. The stdlib staleness check applies it so the rebuild-side
	// constraint reflects same-run pin raises.
	RaisedPinMinors map[string]string `json:"-"`
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

// AddHygieneBump records a scanner-hygiene entry the applier wrote.
func (p *GoBumpProcessor) AddHygieneBump(fix SecurityFix) {
	p.HygieneBumps = append(p.HygieneBumps, fix)
	p.AddChange(processor.Change{
		Type:        "hygiene",
		Field:       fix.Module,
		OldValue:    fix.OldVersion,
		NewValue:    fix.NewVersion,
		Description: fmt.Sprintf("scanner hygiene: %s %s -> %s", fix.Module, fix.OldVersion, fix.NewVersion),
		Reason:      fmt.Sprintf("advisories in unlinked packages: %s (not a security fix)", fix.Vulnerability),
	})
}

// Skip records why (part of) the package was not analyzed: logged now, and
// reported with the result (see SkipReasons).
func (p *GoBumpProcessor) Skip(ctx context.Context, reason string) {
	logging.From(ctx).Info("skipped", "reason", reason)
	p.SkipReasons = append(p.SkipReasons, reason)
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

// fixedVulnIDs is the one definition of the dependency advisories this
// package's deps list fixes (VulnerabilitiesFixed when validated,
// CriticalFixed/HighFixed, the epoch comment). Validated: every advisory the
// analysis found, minus those still residual and those in unlinked code.
// Unvalidated: the advisory IDs recorded on the applied SecurityFixes (no
// proof beyond "this module moved").
func (p *GoBumpProcessor) fixedVulnIDs() map[string]struct{} {
	ids := make(map[string]struct{})
	if p.Validated {
		for id := range analysisSeverities(p) {
			ids[id] = struct{}{}
		}
		for _, residual := range p.Residuals {
			for _, id := range residual.VulnIDs {
				delete(ids, id)
			}
		}
		for _, id := range p.UnreachableVulnIDs {
			delete(ids, id)
		}
		return ids
	}
	if !p.HasActualChanges() {
		return ids
	}
	return fixVulnIDs(p.SecurityFixes)
}

// fixVulnIDs collects the advisory IDs recorded on fixes (skipping the
// free-text placeholder used when no OSV ID was matched).
func fixVulnIDs(fixes []SecurityFix) map[string]struct{} {
	ids := make(map[string]struct{})
	for _, fix := range fixes {
		for id := range strings.SplitSeq(fix.Vulnerability, ",") {
			id = strings.TrimSpace(id)
			if id == "" || strings.ContainsRune(id, ' ') {
				continue // free-text placeholder, not an advisory ID
			}
			ids[id] = struct{}{}
		}
	}
	return ids
}

// noFixResiduals reports, for an unvalidated run, the analysis advisories
// with no released fix: they remain whatever the deps list says, and must not
// read as fixed or up to date. (A validated run's final rescan already
// reports them in Residuals.)
func (p *GoBumpProcessor) noFixResiduals() []simulate.Residual {
	if p.Validated || p.VulnerabilityAnalysis == nil {
		return nil
	}
	byModule := make(map[string]*simulate.Residual)
	var modules []string
	for _, lang := range p.VulnerabilityAnalysis.ByLanguage {
		for _, m := range lang.ByModroot {
			if m.ScanResult == nil {
				continue
			}
			for _, vuln := range m.ScanResult.Vulnerabilities {
				if vuln.FixedVersion != "" {
					continue
				}
				r, ok := byModule[vuln.Module]
				if !ok {
					r = &simulate.Residual{Module: vuln.Module, ResolvedVersion: vuln.CurrentVersion, Reason: "no released fix"}
					byModule[vuln.Module] = r
					modules = append(modules, vuln.Module)
				}
				if !slices.Contains(r.VulnIDs, vuln.ID) {
					r.VulnIDs = append(r.VulnIDs, vuln.ID)
				}
			}
		}
	}
	residuals := make([]simulate.Residual, 0, len(modules))
	for _, module := range modules {
		residuals = append(residuals, *byModule[module])
	}
	return residuals
}

// ToResult converts the processor state to a GoBumpResult.
//
// Advisory accounting: VulnerabilitiesFound counts unique advisories across
// the package (the baseline analysis scan). When the bump was validated by
// simulation, the residual advisory count is exact (the final resolved graph
// was rescanned) and unreachable advisories (unlinked modules, informational
// only) are known, so VulnerabilitiesFixed = found - baseline residuals -
// unreachable (the count of fixedVulnIDs). Residuals the bump itself INTRODUCED
// (advisories absent from the baseline scan - see
// simulate.Residual.Introduced) still count as residual but never subtract
// from found: they were never in it. Without validation there is no proof of
// what the bump actually fixes, so Fixed falls back to the historical
// approximation (modules changed), which is also always reported separately
// as ModulesBumped, and advisories with no released fix are residual (see
// noFixResiduals). CriticalFixed/HighFixed count fixedVulnIDs by the
// analysis scan's severity.
func (p *GoBumpProcessor) ToResult() *GoBumpResult {
	vulnerabilitiesFound := 0
	if p.VulnerabilityAnalysis != nil {
		vulnerabilitiesFound = p.VulnerabilityAnalysis.VulnerabilitiesFound
	}

	modulesBumped, hygieneBumped := 0, 0
	if p.HasActualChanges() {
		modulesBumped, hygieneBumped = len(p.SecurityFixes), len(p.HygieneBumps)
	}

	residuals := append(slices.Clone(p.Residuals), p.noFixResiduals()...)
	residualIDs := make(map[string]struct{})
	baselineResidualIDs := make(map[string]struct{})
	for _, r := range residuals {
		for _, id := range r.VulnIDs {
			residualIDs[id] = struct{}{}
			if !r.Introduced {
				baselineResidualIDs[id] = struct{}{}
			}
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

	vulnerabilitiesFixed := modulesBumped
	if p.Validated {
		vulnerabilitiesFixed = max(vulnerabilitiesFound-len(baselineResidualIDs)-len(unreachableIDs), 0)
	}
	fixedIDs := p.fixedVulnIDs()
	severities := analysisSeverities(p)
	criticalFixed, highFixed := 0, 0
	for id := range fixedIDs {
		switch severities[id] {
		case "CRITICAL":
			criticalFixed++
		case "HIGH":
			highFixed++
		}
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
		VulnerabilitiesResidual:    len(residualIDs),
		VulnerabilitiesUnreachable: len(unreachableIDs),
		UnreachableVulnIDs:         unreachableIDs,
		ModulesBumped:              modulesBumped,
		Validated:                  p.Validated,
		Residuals:                  residuals,
		CriticalFixed:              criticalFixed,
		HighFixed:                  highFixed,
		SkipReasons:                p.SkipReasons,
		StdlibBumps:                p.StdlibBumps,
		StdlibChecked:              p.StdlibChecked,
		SecurityFixes:              p.SecurityFixes,
		HygieneBumps:               p.HygieneBumps,
		HygieneModulesBumped:       hygieneBumped,
		ActionsApplied:             actionsApplied,
		OldEpoch:                   p.OldEpoch,
		NewEpoch:                   p.NewEpoch,
		EpochChanged:               p.IsEpochChanged(),
		FileWasWritten:             p.HasFileChanges(),
		Messages:                   p.GetMessages(),
		Error:                      errorStr,
	}
}
