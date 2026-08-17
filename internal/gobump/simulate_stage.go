package gobump

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	omnibumpgolang "github.com/chainguard-dev/omnibump/pkg/languages/golang"
	ecogolang "github.com/isometry/choam/internal/ecosystem/golang"
	"github.com/isometry/choam/internal/goversion"
	"github.com/isometry/choam/internal/processor"
	"github.com/isometry/choam/internal/scan"
	"github.com/isometry/choam/internal/simulate"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// bumpSimulator is the seam between the pipeline stage and
// simulate.Simulator, injectable for tests.
type bumpSimulator interface {
	Simulate(ctx context.Context, repoURL, tag, expectedCommit string, reqs []simulate.ModrootRequest) (map[string]*simulate.ModrootResult, error)
}

// SimulationStage validates the Go bump candidate sets computed by the
// vulnerability check before the applier writes them: it clones the source
// the build will use, applies the candidates with the real go toolchain, and
// OSV-rescans the resolved graph to a fixpoint (see internal/simulate). The
// per-modroot DesiredDeps are replaced with the proven set; anything
// unreachable is reported as a residual. When simulation cannot run at all
// (no go binary, clone failure, --no-validate) the pre-simulation candidates
// pass through unchanged and the result is marked unvalidated.
type SimulationStage struct {
	processor.BaseStage
	Analyzer *Analyzer
	Options  ProcessorOptions

	// newSimulator constructs the simulator lazily so a missing go toolchain
	// degrades at Apply time (with a message) instead of failing pipeline
	// construction; tests override it.
	newSimulator func(ctx context.Context, opts ProcessorOptions, analyzer *Analyzer) (bumpSimulator, error)

	// detectCoUpdates reproduces melange gobump's build-time co-update
	// advisory (see declareCoUpdates); a func field so tests can inject a
	// fake without live proxy.golang.org access.
	detectCoUpdates func(ctx context.Context, packagesToUpdate map[string]string, modFile *modfile.File) map[string]omnibumpgolang.MissingDependency
}

func NewSimulationStage(analyzer *Analyzer, opts ProcessorOptions) *SimulationStage {
	return &SimulationStage{
		BaseStage: processor.BaseStage{
			StageName:        "bump_simulation",
			StageDescription: "Validate Go bump candidates against a source checkout",
		},
		Analyzer:        analyzer,
		Options:         opts,
		newSimulator:    defaultSimulator,
		detectCoUpdates: defaultDetectCoUpdates,
	}
}

// defaultDetectCoUpdates wraps omnibump's DetectCoUpdates - the exact
// function melange's bump pipeline runs at build time - discarding its
// API-compat alert map (a heuristic "verify manually" tier, not actionable
// here).
func defaultDetectCoUpdates(ctx context.Context, packagesToUpdate map[string]string, modFile *modfile.File) map[string]omnibumpgolang.MissingDependency {
	missing, _ := omnibumpgolang.DetectCoUpdates(ctx, packagesToUpdate, modFile)
	return missing
}

func defaultSimulator(ctx context.Context, opts ProcessorOptions, analyzer *Analyzer) (bumpSimulator, error) {
	simOpts := simulate.Options{Budget: opts.SimulationTimeout}.WithDefaults()
	toolchain, err := simulate.NewToolchain(ctx, simOpts.CommandTimeout)
	if err != nil {
		return nil, err
	}
	return simulate.NewSimulator(nil, toolchain, analyzer.vulnerabilityScanner, opts.TempDir, simOpts), nil
}

func (s *SimulationStage) ShouldRun(_ context.Context, p processor.Processor) (bool, error) {
	gp, ok := p.(*GoBumpProcessor)
	if !ok {
		return false, fmt.Errorf("expected GoBumpProcessor, got %T", p)
	}
	if !s.Options.Validate {
		return false, nil
	}
	analysis := gp.VulnerabilityAnalysis
	if analysis == nil || analysis.RepoURL == "" || analysis.Tag == "" {
		return false, nil
	}
	for _, action := range analysis.BumpActions {
		if action.Language == "go" {
			return true, nil
		}
	}
	return false, nil
}

func (s *SimulationStage) Apply(ctx context.Context, p processor.Processor) error {
	gp, ok := p.(*GoBumpProcessor)
	if !ok {
		return fmt.Errorf("expected GoBumpProcessor, got %T", p)
	}
	analysis := gp.VulnerabilityAnalysis

	sim, err := s.newSimulator(ctx, s.Options, s.Analyzer)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		s.degrade(gp, err)
		return nil
	}

	for i := range analysis.ByLanguage {
		lang := &analysis.ByLanguage[i]
		if lang.Language != "go" || len(lang.ByModroot) == 0 {
			continue
		}

		goEco := ecogolang.New()
		reqs := make([]simulate.ModrootRequest, 0, len(lang.ByModroot))
		for _, m := range lang.ByModroot {
			reqs = append(reqs, simulate.ModrootRequest{
				Modroot:         m.Modroot,
				Seeds:           seedCandidates(m),
				Baseline:        goEco.EffectiveVersions(m.Deps),
				Packages:        m.BuildPackages,
				VulnImports:     vulnImportPaths(m.ScanResult),
				BaselineVulnIDs: baselineVulnIDs(m.ScanResult),
			})
		}

		results, err := sim.Simulate(ctx, analysis.RepoURL, analysis.Tag, analysis.ExpectedCommit, reqs)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			s.degrade(gp, err)
			return nil
		}

		reach := newReachabilityDiff()
		// stdUnion accumulates the linked-stdlib packages across every
		// modroot in this language; stdComplete tracks whether every one of
		// them actually contributed a validated set. A skipped modroot or a
		// failed-open stdlib walk in ANY modroot must invalidate the whole
		// union - see below.
		stdUnion := map[string]struct{}{}
		stdComplete := true
		for mi := range lang.ByModroot {
			m := &lang.ByModroot[mi]
			result := results[m.Modroot]
			if result == nil {
				// Skipped/unsimulated modroot: everything it found counts as
				// reachable (fail open).
				reach.observe(*m, nil, nil, false, nil)
				stdComplete = false
				continue
			}
			m.DesiredDeps = result.FinalDeps
			m.DesiredReplaces = result.FinalReplaces
			m.SecurityBumpModules = result.CVEBackedModules
			m.Simulated = true
			m.SimulationConverged = result.Converged
			m.Residuals = result.Residuals
			m.Dropped = result.Dropped
			gp.AddResiduals(result.Residuals)
			unlinkedHere := reach.observe(*m, result.Linked, result.LinkedPackages, true, degradedUnlinkedSet(result))

			// Union the linked stdlib slice into a local set for the stdlib
			// staleness stage (Go only - this loop already is), so it can
			// filter stdlib advisories by artifact reachability without its
			// own checkout. nil = this modroot's walk failed open, which
			// taints the whole union (see below) rather than just
			// contributing nothing.
			if result.StdPackages != nil {
				for pkg := range result.StdPackages {
					stdUnion[pkg] = struct{}{}
				}
			} else {
				stdComplete = false
			}

			s.declareCoUpdates(ctx, gp, m, result)

			// The proven graph's Go language requirement, gated against the
			// module's own pristine baseline: only a genuine raise is recorded
			// (an existing step's go-version is additionally never lowered -
			// see the reconcilers' effectiveGoVersion handling).
			if result.MaxDepGoVersion != "" {
				baseline := pristineGoBaseline(m)
				if goversion.Compare(result.MaxDepGoVersion, baseline) > 0 {
					m.RequiredGoVersion = result.MaxDepGoVersion
					gp.AddMessage(fmt.Sprintf("modroot %s: validated dependencies require Go %s (module baseline %s)",
						m.Modroot, result.MaxDepGoVersion, baselineWord(baseline)))
				}
			}

			gp.AddMessage(fmt.Sprintf(
				"simulation: modroot %s %s in %d iteration(s): %d validated dep(s), %d replace(s), %d dropped, %d residual advisory(ies), %d advisory(ies) in unlinked modules",
				m.Modroot, convergedWord(result.Converged), result.Iterations,
				len(result.FinalDeps), len(result.FinalReplaces), len(result.Dropped), len(result.RemainingVulnIDs), unlinkedHere))
			for _, dropped := range result.Dropped {
				slog.Info("bump candidate dropped by simulation",
					"modroot", m.Modroot, "module", dropped.Module, "version", dropped.Version, "reason", dropped.Reason)
			}
			for _, residual := range result.Residuals {
				slog.Warn("residual vulnerability after simulation",
					"modroot", m.Modroot, "module", residual.Module,
					"resolved", residual.ResolvedVersion, "fix", residual.FixedVersion,
					"vulns", strings.Join(residual.VulnIDs, ","), "reason", residual.Reason)
			}
		}

		// Publish the union only when every modroot actually contributed a
		// validated stdlib set - a partial union must not masquerade as
		// complete (the stdlib stage treats non-nil as proof it can safely
		// demote unlinked-package advisories). Otherwise leave
		// gp.LinkedStdPackages nil: unknown, so the stdlib stage fails open.
		if stdComplete && len(stdUnion) > 0 {
			gp.LinkedStdPackages = stdUnion
		} else if !stdComplete {
			slog.Debug("discarding partial linked-stdlib union: not every go modroot contributed a validated stdlib package set",
				"language", lang.Language, "modroot_count", len(lang.ByModroot))
		}

		// Advisories whose modules were unlinked in EVERY modroot that saw
		// them: informational only - no bump proposed, neither fixed nor
		// residual (an ID linked - and therefore fixed or residual - in any
		// other modroot counts as reachable).
		unreachableIDs, unreachableModules := reach.finalize()
		gp.AddUnreachableVulnIDs(unreachableIDs)
		for _, module := range unreachableModules {
			var msg string
			switch {
			case module.moduleLinked:
				// Precise, package-only: the module IS in the artifact, the
				// vulnerable packages are not.
				msg = fmt.Sprintf("info: %s (%s) vulnerable but not linked into build artifacts (module is linked; the vulnerable packages are not) - no bump proposed",
					module.name, strings.Join(module.vulnIDs, ", "))
			case module.degraded:
				// Degraded module-level signal: precise reachability was
				// unavailable, but the tidied go.mod's require block proves
				// the module unlinkable.
				msg = fmt.Sprintf("info: %s (%s) vulnerable but not required by the tidied go.mod - cannot be linked into build artifacts - no bump proposed (module-level signal; package import graph unavailable)",
					module.name, strings.Join(module.vulnIDs, ", "))
			default:
				msg = fmt.Sprintf("info: %s (%s) vulnerable but not linked into build artifacts - no bump proposed",
					module.name, strings.Join(module.vulnIDs, ", "))
			}
			gp.AddMessage(msg)
			slog.Info("advisory in unlinked code - no bump proposed",
				"module", module.name, "module_linked", module.moduleLinked, "degraded", module.degraded, "vulns", strings.Join(module.vulnIDs, ","))
		}

		rebuildLanguageActions(analysis, lang)
	}

	gp.Validated = true
	return nil
}

// coUpdateBudget bounds each declareCoUpdates round - DetectCoUpdates
// prefetches dependency go.mod files from proxy.golang.org and can be slow
// on huge module graphs; failing open just means the build-time advisory
// reappears.
const coUpdateBudget = 2 * time.Minute

// declareCoUpdates makes the written deps list satisfy melange gobump's
// build-time co-update advisory. It runs omnibump's own DetectCoUpdates -
// the exact check the build will run - with the PROVEN final deps against
// the pristine go.mod, and appends the recommendations that are already
// true in the validated graph as explicit, coherence-only deps entries.
// Gates keep this a pure declaration step with zero resolution impact:
//   - sustained: the final tidied go.mod must require the module at >= the
//     recommended version (a pin above that is unproven and would fail
//     gobump's post-tidy verification);
//   - linked: an unlinked pin would be re-dropped by the NEXT run's
//     reachability pruning, churning the YAML forever - skip those (the
//     build-time advisory persists for them, rarely);
//   - absent: never duplicate a coordinate already in the list.
//
// Appending can itself trigger new group recommendations at build time
// (e.g. otel -> otel/trace -> otel/metric), so the check iterates to a
// small fixpoint. Recommendations the proven graph did NOT satisfy (a
// lagging family member MVS didn't raise, cross-major suggestions) are
// skipped by the sustained gate - bumping those for real would need
// another simulation round. Best-effort throughout: any failure leaves the
// deps list unchanged. Appended entries are absent from
// SecurityBumpModules, so accounting never credits them as security fixes.
// The build image may run a different omnibump version than the omnibump
// v0.23.1 CHOAM links (the parity target), so silence is parity-by-
// same-function, not a guarantee.
func (s *SimulationStage) declareCoUpdates(ctx context.Context, gp *GoBumpProcessor, m *ModrootAnalysis, result *simulate.ModrootResult) {
	if len(result.FinalDeps) == 0 || len(result.Requires) == 0 {
		return
	}
	modFile := ecogolang.ModFileOf(m.Deps)
	if modFile == nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, coUpdateBudget)
	defer cancel()

	const maxRounds = 3
	for range maxRounds {
		// Build-time omnibump's update list spans deps AND replaces, so the
		// parity check must too ("old=new@version" contributes new@version).
		packagesToUpdate := make(map[string]string, len(m.DesiredDeps)+len(m.DesiredReplaces))
		for _, dep := range m.DesiredDeps {
			if module, version, ok := splitCoordVersion(dep); ok {
				packagesToUpdate[module] = version
			}
		}
		for _, replace := range m.DesiredReplaces {
			coord, version, ok := splitCoordVersion(replace)
			if !ok {
				continue
			}
			if _, newPath, found := strings.Cut(coord, "="); found {
				packagesToUpdate[newPath] = version
			}
		}
		if len(packagesToUpdate) == 0 {
			return
		}

		missing := s.safeDetectCoUpdates(ctx, packagesToUpdate, modFile)

		appended := false
		for module, rec := range missing {
			if _, present := packagesToUpdate[module]; present {
				continue
			}
			sustainedVersion, required := result.Requires[module]
			if !required || semver.Compare(sustainedVersion, rec.RequiredVersion) < 0 {
				slog.Debug("co-update recommendation not satisfied by the validated graph - skipping",
					"modroot", m.Modroot, "module", module, "recommended", rec.RequiredVersion, "reason", rec.Reason)
				continue
			}
			if result.Linked != nil {
				if _, linked := result.Linked[module]; !linked {
					slog.Debug("co-update recommendation for unlinked module - skipping",
						"modroot", m.Modroot, "module", module, "recommended", rec.RequiredVersion)
					continue
				}
			}

			entry := module + "@" + sustainedVersion
			m.DesiredDeps = append(m.DesiredDeps, entry)
			appended = true
			gp.AddMessage(fmt.Sprintf("declared co-update: %s (required alongside the validated bumps; already satisfied by the proven graph)", entry))
			slog.Info("declared co-update", "modroot", m.Modroot, "module", module,
				"version", sustainedVersion, "reason", rec.Reason)
		}

		if !appended {
			return
		}
	}
}

// safeDetectCoUpdates guards the injected detector (omnibump internals or a
// test double) so a panic or late failure never breaks the run - worst case
// the build-time advisory reappears.
func (s *SimulationStage) safeDetectCoUpdates(ctx context.Context, packagesToUpdate map[string]string, modFile *modfile.File) (missing map[string]omnibumpgolang.MissingDependency) {
	defer func() {
		if r := recover(); r != nil {
			slog.Debug("co-update declaration panicked - skipping", "recover", r)
			missing = nil
		}
	}()
	return s.detectCoUpdates(ctx, packagesToUpdate, modFile)
}

// degrade falls back to the unvalidated pre-simulation candidate set,
// loudly: the written deps list has not been proven to resolve or to cover
// every advisory. Callers must check ctx.Err() before calling this - a
// cancelled run must propagate that cancellation, not degrade and write an
// unvalidated result as if simulation had merely failed.
func (s *SimulationStage) degrade(gp *GoBumpProcessor, err error) {
	gp.Validated = false
	slog.Warn("bump simulation unavailable - proceeding with UNVALIDATED deps", "error", err)
	gp.AddMessage(fmt.Sprintf("WARNING: deps list NOT validated - simulation unavailable: %v", err))
}

// seedCandidates converts a modroot's post-FilterBumps desired deps and its
// existing replace directives into simulation candidates, marking those
// backed by an OSV advisory (with their advisory IDs) so the loop knows
// which entries to defend. Replace seeds come first: the loop routes a deps
// seed for an already-replace-claimed module into the replace channel.
func seedCandidates(m ModrootAnalysis) []simulate.Candidate {
	bumpByModule := make(map[string]*simulateBumpInfo)
	if m.ScanResult != nil {
		for _, bump := range m.ScanResult.SecurityBumps {
			bumpByModule[bump.Name] = &simulateBumpInfo{vulnIDs: bump.VulnIDs}
		}
	}
	infoFor := func(module string) *simulateBumpInfo {
		if info := bumpByModule[module]; info != nil {
			return info
		}
		// OSV names v2+ modules without the /vN path suffix that
		// FilterBumps normalizes in.
		return bumpByModule[trimMajorSuffix(module)]
	}

	seeds := make([]simulate.Candidate, 0, len(m.DesiredDeps)+len(m.ExistingReplaces))

	for _, replace := range m.ExistingReplaces {
		coord, version, ok := splitCoordVersion(replace)
		if !ok {
			continue
		}
		oldPath, newPath, found := strings.Cut(coord, "=")
		if !found {
			continue // not gobump grammar; leave to the loop's residual reporting
		}
		candidate := simulate.Candidate{
			Module: newPath, Version: version,
			Replace: true, ReplaceOld: oldPath,
		}
		if info := infoFor(newPath); info != nil {
			candidate.FromCVE = true
			candidate.VulnIDs = info.vulnIDs
		}
		seeds = append(seeds, candidate)
	}

	for _, dep := range m.DesiredDeps {
		module, version, ok := splitCoordVersion(dep)
		if !ok {
			continue
		}
		candidate := simulate.Candidate{Module: module, Version: version}
		if info := infoFor(module); info != nil {
			candidate.FromCVE = true
			candidate.VulnIDs = info.vulnIDs
		}
		seeds = append(seeds, candidate)
	}
	return seeds
}

type simulateBumpInfo struct {
	vulnIDs []string
}

// rebuildLanguageActions recomputes one language's bump actions from its
// post-simulation desired deps, leaving other languages' actions untouched.
func rebuildLanguageActions(analysis *VulnerabilityAnalysis, lang *LanguageAnalysis) {
	kept := make([]BumpAction, 0, len(analysis.BumpActions))
	for _, action := range analysis.BumpActions {
		if action.Language != lang.Language {
			kept = append(kept, action)
		}
	}
	for _, m := range lang.ByModroot {
		// Replaces-only changes (a promotion with unchanged deps) must also
		// produce an action, or the applier never writes them.
		if haveDepsChanged(m.ExistingDeps, m.DesiredDeps) || haveDepsChanged(m.ExistingReplaces, m.DesiredReplaces) {
			kept = append(kept, BumpAction{
				Action:       "needs_bump",
				Language:     lang.Language,
				Modroots:     []string{m.Modroot},
				Dependencies: newlyAddedDeps(m.ExistingDeps, m.DesiredDeps),
				Replaces:     newlyAddedDeps(m.ExistingReplaces, m.DesiredReplaces),
				Reason:       fmt.Sprintf("validated dependency changes for modroot %s", m.Modroot),
			})
		}
	}
	analysis.BumpActions = kept
}

// degradedUnlinkedSet copies result.UnrequiredModules (the degraded
// module-level reachability signal - see simulate.ModrootResult) and adds,
// for each /vN major-suffixed entry, the trimmed OSV-named alias when
// unambiguous: absent from both Resolved and Requires, so it cannot collide
// with a distinct module of that trimmed name. nil in, nil out.
func degradedUnlinkedSet(result *simulate.ModrootResult) map[string]struct{} {
	if result.UnrequiredModules == nil {
		return nil
	}
	set := make(map[string]struct{}, len(result.UnrequiredModules))
	for module := range result.UnrequiredModules {
		set[module] = struct{}{}
		trimmed := trimMajorSuffix(module)
		if trimmed == module {
			continue
		}
		if _, inResolved := result.Resolved[trimmed]; inResolved {
			continue
		}
		if _, inRequires := result.Requires[trimmed]; inRequires {
			continue
		}
		set[trimmed] = struct{}{}
	}
	return set
}

// reachabilityDiff accumulates, across a language's modroots, which
// analysis-scan advisories affect only unlinked modules. The analysis scan
// already paid for the full-graph findings (ModrootAnalysis.ScanResult);
// diffing them once per modroot against the simulation's final linked set is
// what lets the loop itself scan linked-only without losing the
// "vulnerable but not linked" information.
type reachabilityDiff struct {
	reachableIDs   map[string]struct{}
	unreachableIDs map[string]struct{}
	moduleIDs      map[string]*unreachableModule // unlinked module -> its advisory IDs
}

func newReachabilityDiff() *reachabilityDiff {
	return &reachabilityDiff{
		reachableIDs:   make(map[string]struct{}),
		unreachableIDs: make(map[string]struct{}),
		moduleIDs:      make(map[string]*unreachableModule),
	}
}

// observe records one modroot's analysis findings against its linked module
// and package sets. simulated=false or a nil set means the corresponding
// granularity is unknown for this modroot (skipped, or the loop failed open)
// - findings then count as reachable at that granularity. A finding is
// unreachable when its module is unlinked, OR when the module IS linked but
// the advisory's vulnerable packages (OSV ecosystem_specific.imports) are
// all outside the artifact's import graph (e.g. x/sys/windows in a module
// linked via x/sys/unix). unrequired is the degraded module-level signal
// (see degradedUnlinkedSet): consulted only when linkedModules is nil (no
// precise signal) and non-nil (degraded signal available for this modroot).
// Returns how many advisory IDs were unlinked in THIS modroot.
func (r *reachabilityDiff) observe(m ModrootAnalysis, linkedModules, linkedPackages map[string]struct{}, simulated bool, unrequired map[string]struct{}) int {
	if !simulated {
		linkedModules, linkedPackages, unrequired = nil, nil, nil
	}
	degradedMode := linkedModules == nil && unrequired != nil

	moduleLinked := func(module string) bool {
		if linkedModules == nil {
			if unrequired == nil {
				return true // fail open: no precise or degraded signal
			}
			_, unreq := unrequired[module]
			return !unreq
		}
		if _, ok := linkedModules[module]; ok {
			return true
		}
		// The analysis map's coordinates are go.mod-normalized, but no-fix
		// vulnerability records carry OSV's own naming, which drops v2+
		// path suffixes - tolerate the mismatch in the linked direction.
		for candidate := range linkedModules {
			if trimMajorSuffix(candidate) == module {
				return true
			}
		}
		return false
	}

	// Per-advisory vulnerable import paths, from the analysis scan.
	importsByID := make(map[string][]scan.VulnerableImport)
	if m.ScanResult != nil {
		for _, vuln := range m.ScanResult.Vulnerabilities {
			importsByID[vuln.ID] = vuln.VulnerableImports
		}
	}
	packagesLinked := func(vulnID string) bool {
		imports := importsByID[vulnID]
		if linkedPackages == nil || len(imports) == 0 {
			return true // unknown either way - fail open
		}
		for _, imp := range imports {
			if imp.Path == "" {
				return true
			}
			if _, ok := linkedPackages[imp.Path]; ok {
				return true
			}
		}
		return false
	}

	record := func(module string, vulnIDs []string) {
		if len(vulnIDs) == 0 {
			return
		}
		modLinked := moduleLinked(module)
		for _, id := range vulnIDs {
			if modLinked && packagesLinked(id) {
				r.reachableIDs[id] = struct{}{}
				continue
			}
			entry, ok := r.moduleIDs[module]
			if !ok {
				entry = &unreachableModule{name: module, moduleLinked: modLinked, idSet: make(map[string]struct{})}
				r.moduleIDs[module] = entry
			}
			entry.moduleLinked = entry.moduleLinked || modLinked
			entry.degraded = entry.degraded || degradedMode
			entry.idSet[id] = struct{}{}
			r.unreachableIDs[id] = struct{}{}
		}
	}

	unlinkedBefore := len(r.unreachableIDs)

	// Fixable advisories, in rendered-coordinate space (go.mod-normalized);
	// fall back to OSV naming when the coordinate map is absent (the linked
	// check tolerates the missing /vN suffix either way).
	if len(m.SecurityBumpsByCoord) > 0 {
		for coord, bump := range m.SecurityBumpsByCoord {
			record(coord, bump.VulnIDs)
		}
	} else if m.ScanResult != nil {
		for _, bump := range m.ScanResult.SecurityBumps {
			record(bump.Name, bump.VulnIDs)
		}
	}
	// No-fix advisories only exist in the raw vulnerability list.
	if m.ScanResult != nil {
		for _, vuln := range m.ScanResult.Vulnerabilities {
			if vuln.FixedVersion == "" {
				record(vuln.Module, []string{vuln.ID})
			}
		}
	}

	return len(r.unreachableIDs) - unlinkedBefore
}

// unreachableModule is one unlinked module and its advisory IDs, for
// reporting. moduleLinked distinguishes the package-only case (the module IS
// in the artifact but the vulnerable packages are not). degraded marks a
// module whose unlinked verdict came from the degraded module-level signal
// (tidied go.mod require membership) rather than precise go list -deps
// reachability.
type unreachableModule struct {
	name         string
	vulnIDs      []string
	moduleLinked bool
	degraded     bool
	idSet        map[string]struct{}
}

// finalize returns the advisory IDs unlinked in every modroot that saw them,
// plus the per-module breakdown (IDs that proved reachable anywhere are
// subtracted from both).
func (r *reachabilityDiff) finalize() ([]string, []unreachableModule) {
	var ids []string
	for id := range r.unreachableIDs {
		if _, ok := r.reachableIDs[id]; !ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	var modules []unreachableModule
	for name, entry := range r.moduleIDs {
		module := unreachableModule{name: name, moduleLinked: entry.moduleLinked, degraded: entry.degraded}
		for id := range entry.idSet {
			if _, ok := r.reachableIDs[id]; !ok {
				module.vulnIDs = append(module.vulnIDs, id)
			}
		}
		if len(module.vulnIDs) == 0 {
			continue
		}
		sort.Strings(module.vulnIDs)
		modules = append(modules, module)
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].name < modules[j].name })

	return ids, modules
}

// vulnImportPaths projects a modroot's analysis findings onto advisory ID ->
// vulnerable import paths, for threading into the simulation (seed advisories
// were scanned before the checkout exists).
func vulnImportPaths(scanResult *scan.ScanResult) map[string][]string {
	if scanResult == nil {
		return nil
	}
	paths := make(map[string][]string)
	for _, vuln := range scanResult.Vulnerabilities {
		for _, imp := range vuln.VulnerableImports {
			if imp.Path != "" {
				paths[vuln.ID] = append(paths[vuln.ID], imp.Path)
			}
		}
	}
	if len(paths) == 0 {
		return nil
	}
	return paths
}

// baselineVulnIDs collects the advisory IDs the analysis scan found in the
// pristine graph - the simulation's baseline for classifying residual
// advisories as pre-existing vs introduced by the bump itself. Nil (fail
// open, classification disabled) when there is no scan result.
func baselineVulnIDs(scanResult *scan.ScanResult) map[string]struct{} {
	if scanResult == nil || len(scanResult.Vulnerabilities) == 0 {
		return nil
	}
	ids := make(map[string]struct{}, len(scanResult.Vulnerabilities))
	for _, vuln := range scanResult.Vulnerabilities {
		ids[vuln.ID] = struct{}{}
	}
	return ids
}

// trimMajorSuffix strips a trailing /vN major-version path element
// (e.g. github.com/foo/bar/v2 -> github.com/foo/bar).
func trimMajorSuffix(module string) string {
	idx := strings.LastIndex(module, "/")
	if idx < 0 {
		return module
	}
	last := module[idx+1:]
	if len(last) < 2 || last[0] != 'v' {
		return module
	}
	if _, err := strconv.Atoi(last[1:]); err != nil {
		return module
	}
	return module[:idx]
}

// pristineGoBaseline is the Go language version the modroot's own pristine
// go.mod already demands: the max of its go directive and toolchain directive
// (bare form). Empty when the parsed go.mod is unavailable (non-Go analyses,
// or fixtures without a manifest) - callers gating on "required > baseline"
// then fail open toward emitting the requirement, which is always safe (it
// only ever selects at least the toolchain the module would need anyway).
func pristineGoBaseline(m *ModrootAnalysis) string {
	modFile := ecogolang.ModFileOf(m.Deps)
	if modFile == nil {
		return ""
	}
	var goDirective, toolchainDirective string
	if modFile.Go != nil {
		goDirective = modFile.Go.Version
	}
	if modFile.Toolchain != nil {
		toolchainDirective = strings.TrimPrefix(modFile.Toolchain.Name, "go")
	}
	return goversion.Max(goDirective, toolchainDirective)
}

// baselineWord renders a possibly-unknown baseline for messages.
func baselineWord(baseline string) string {
	if baseline == "" {
		return "unknown"
	}
	return baseline
}

func convergedWord(converged bool) string {
	if converged {
		return "converged"
	}
	return "did NOT converge"
}
