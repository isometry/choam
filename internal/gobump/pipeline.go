package gobump

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/isometry/choam/internal/processor"
	"github.com/isometry/choam/internal/processor/stages"
	"github.com/isometry/choam/internal/scan"
)

// GoBumpApplier applies bump/go-bump pipeline changes
type GoBumpApplier struct {
	processor.BaseStage
	Analyzer *Analyzer
}

func NewGoBumpApplier(analyzer *Analyzer) *GoBumpApplier {
	return &GoBumpApplier{
		BaseStage: processor.BaseStage{
			StageName:        "gobump_apply",
			StageDescription: "Apply bump/go-bump pipeline changes",
		},
		Analyzer: analyzer,
	}
}

// bumpActionsPending is the apply phase's gate: vulnerabilities were found
// and there are bump actions to apply. The applier and the Go-only stages
// around it (GoVersionFallbackStage, GoPackagePinStage) share it.
func bumpActionsPending(gp *GoBumpProcessor) bool {
	return gp.VulnerabilityAnalysis != nil &&
		gp.VulnerabilityAnalysis.VulnerabilitiesFound > 0 &&
		len(gp.VulnerabilityAnalysis.BumpActions) > 0
}

func (g *GoBumpApplier) ShouldRun(ctx context.Context, p processor.Processor) (bool, error) {
	gp, err := asBump(p)
	if err != nil {
		return false, err
	}
	return bumpActionsPending(gp), nil
}

func (g *GoBumpApplier) Apply(ctx context.Context, p processor.Processor) error {
	gp, err := asBump(p)
	if err != nil {
		return err
	}

	if err := g.applyGoBumpChanges(ctx, gp, gp.VulnerabilityAnalysis); err != nil {
		return err
	}

	// A go-package pin raise is an applied change too: when the pin stage
	// follows, it reports the apply phase's outcome once it has run.
	if !goPackagePinsPending(gp) {
		reportApplyOutcome(gp)
	}

	return nil
}

// reportApplyOutcome emits the apply phase's one-line outcome, once every
// stage of the phase that can change the YAML has run (see
// GoBumpApplier.Apply and GoPackagePinStage.Apply).
func reportApplyOutcome(gp *GoBumpProcessor) {
	if gp.ActualChangesApplied {
		gp.AddMessage("bump changes applied")
	} else {
		gp.AddMessage("no bump changes needed")
	}
}

// NewGoBumpPipeline creates the gobump pipeline with the critical fix
func NewGoBumpPipeline(analyzer *Analyzer, opts ProcessorOptions) *processor.Pipeline {
	pipeline := processor.NewPipeline("bump")

	// Add stages in order
	pipeline.AddStages(
		// Check phase
		NewVulnerabilityChecker(analyzer),

		// Validation phase: prove the Go candidate sets resolve and cover
		// every fixable advisory before anything is written (see
		// SimulationStage; skipped and loudly reported when unavailable).
		NewSimulationStage(analyzer, opts),

		// Go only: best-effort required Go version for modroots the
		// simulation did not prove - before the applier, whose go-version
		// edits (fastPathGoVersion) read RequiredGoVersion.
		NewGoVersionFallbackStage(analyzer),

		// Apply phase
		NewGoBumpApplier(analyzer),

		// Go only: raise too-old go-package toolchain pins - after the
		// applier (it edits the rewritten YAML) and before the stdlib stage
		// (which reads RaisedPinMinors).
		NewGoPackagePinStage(analyzer),

		// Stdlib staleness: does rebuilding with a newer Go toolchain fix
		// stdlib vulnerabilities baked into the last build? Runs even when
		// no dependency changes exist (the pipeline runner evaluates each
		// stage's ShouldRun independently), because the fix IS the rebuild.
		NewStdlibStage(analyzer, opts),

		// Epoch handling - ONLY bump if actual changes were applied
		// This is the critical fix that solves the issue described in the implementation plan
		stages.NewEpochStage(&stages.BumpOnSecurityFixStrategy{
			CheckFunc: func(p processor.Processor) bool {
				if gp, ok := p.(*GoBumpProcessor); ok {
					// Dependency changes only count when actual changes were
					// applied AND they include security fixes (the critical
					// fix) or scanner-hygiene bumps (the rebuild is what
					// clears the scanner finding). A stdlib staleness finding
					// justifies a bump on its own - the epoch bump itself is
					// what triggers the fixing rebuild, with zero dependency
					// changes.
					return (gp.ActualChangesApplied && (len(gp.SecurityFixes) > 0 || len(gp.HygieneBumps) > 0)) ||
						len(gp.StdlibBumps) > 0
				}
				return false
			},
			CommentFunc: func(p processor.Processor) string {
				if gp, ok := p.(*GoBumpProcessor); ok {
					return epochComment(gp)
				}
				return ""
			},
		}),

		// Validate the rewritten YAML before anything touches disk.
		stages.NewValidationStage(false, true),

		// File writing - only writes if there are actual file changes
		// (atomically; backup of the original with --backup-suffix).
		stages.NewFileWriterStage(opts.BackupSuffix != "", opts.BackupSuffix),
	)

	return pipeline
}

// epochCommentMaxIDs caps the fixes list in the epoch intent comment: the
// most critical advisories lead, the rest collapse to "+N more" (the full
// list is always in choam's own output).
const epochCommentMaxIDs = 5

// epochComment composes the inline intent comment the epoch stage writes on
// the epoch line: which action(s) triggered the rebuild ("updated bumps",
// "updated bumps (scanner hygiene)" when only hygiene entries changed,
// "rebuild with go<V>"), the advisories it fixes and those its hygiene
// bumps clear for scanners, most critical first. The clause conditions
// mirror the epoch CheckFunc exactly, so the comment always states why the
// epoch actually bumped.
func epochComment(gp *GoBumpProcessor) string {
	security := gp.ActualChangesApplied && len(gp.SecurityFixes) > 0
	hygiene := gp.ActualChangesApplied && len(gp.HygieneBumps) > 0
	var clauses []string
	switch {
	case security:
		clauses = append(clauses, "updated bumps")
	case hygiene:
		clauses = append(clauses, "updated bumps (scanner hygiene)")
	}
	if versions := stdlibRebuildVersions(gp.StdlibBumps); len(versions) > 0 {
		clauses = append(clauses, "rebuild with "+strings.Join(versions, ", "))
	}
	if len(clauses) == 0 {
		return ""
	}

	comment := strings.Join(clauses, ", ")
	severities := analysisSeverities(gp)
	if list := renderFixList(epochFixedVulnIDs(gp), severities); list != "" {
		comment += "; fixes: " + list
	}
	if hygiene {
		if list := renderFixList(slices.Sorted(maps.Keys(fixVulnIDs(gp.HygieneBumps))), severities); list != "" {
			comment += "; hygiene: " + list
		}
	}
	return comment
}

// epochFixedVulnIDs derives the advisory IDs this epoch bump fixes. For
// validated dependency bumps that is the proven set: everything the analysis
// scan found, minus residuals, minus advisories in unlinked code (the same
// arithmetic ToResult counts with). Unvalidated bumps fall back to the IDs
// recorded on the SecurityFixes (skipping the "security vulnerability"
// placeholder used when no OSV ID was matched). Stdlib rebuild fixes are
// always included.
func epochFixedVulnIDs(gp *GoBumpProcessor) []string {
	ids := make(map[string]struct{})
	if gp.ActualChangesApplied && len(gp.SecurityFixes) > 0 {
		ids = gp.fixedVulnIDs()
	}
	for _, bump := range gp.StdlibBumps {
		for _, id := range bump.VulnIDs {
			ids[id] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(ids))
}

// analysisSeverities maps every advisory ID the analysis scan found to its
// most critical observed severity.
func analysisSeverities(gp *GoBumpProcessor) map[string]string {
	severities := make(map[string]string)
	if gp.VulnerabilityAnalysis == nil {
		return severities
	}
	for _, lang := range gp.VulnerabilityAnalysis.ByLanguage {
		for _, modroot := range lang.ByModroot {
			if modroot.ScanResult == nil {
				continue
			}
			for _, vuln := range modroot.ScanResult.Vulnerabilities {
				if existing, ok := severities[vuln.ID]; !ok || scan.SeverityRank(vuln.Severity) < scan.SeverityRank(existing) {
					severities[vuln.ID] = vuln.Severity
				}
			}
		}
	}
	return severities
}

// renderFixList renders advisory IDs most-critical-first (alphabetical
// within a severity tier; IDs without a known severity - including stdlib
// GO-* records, which carry none - rank last), truncated to
// epochCommentMaxIDs with a "+N more" tail.
func renderFixList(ids []string, severities map[string]string) string {
	if len(ids) == 0 {
		return ""
	}
	slices.SortFunc(ids, func(a, b string) int {
		return cmp.Or(cmp.Compare(scan.SeverityRank(severities[a]), scan.SeverityRank(severities[b])), strings.Compare(a, b))
	})
	if len(ids) > epochCommentMaxIDs {
		return fmt.Sprintf("%s, +%d more",
			strings.Join(ids[:epochCommentMaxIDs], ", "), len(ids)-epochCommentMaxIDs)
	}
	return strings.Join(ids, ", ")
}
