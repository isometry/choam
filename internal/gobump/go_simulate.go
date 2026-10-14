package gobump

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	ecogolang "github.com/isometry/choam/internal/ecosystem/golang"
	"github.com/isometry/choam/internal/goversion"
	"github.com/isometry/choam/internal/logging"
	"github.com/isometry/choam/internal/processor"
	"github.com/isometry/choam/internal/scan"
	"github.com/isometry/choam/internal/simulate"
	"golang.org/x/mod/semver"
)

// bumpSimulator is the seam between the pipeline stage and
// simulate.Simulator, injectable for tests.
type bumpSimulator interface {
	Simulate(ctx context.Context, repoURL, tag, expectedCommit string, reqs []simulate.ModrootRequest) (map[string]*simulate.ModrootResult, error)
}

// compileCgoNote reports the compile gate's cgo limitation for modroot m:
// the spec sets CGO_ENABLED=1, but the host cannot compile linux cgo for
// some target arch, so the gate type-checks it with CGO_ENABLED=0
// (reachability still uses 1: see simulate.BuildEnv). "" when not limited.
func compileCgoNote(m ModrootAnalysis, compile bool) string {
	if !compile || m.BuildEnv.CGO != "1" {
		return ""
	}
	var limited []string
	for _, arch := range simulate.TargetArches(m.BuildArches) {
		if simulate.CompileCgoLimited(arch, m.BuildEnv) {
			limited = append(limited, arch)
		}
	}
	if len(limited) == 0 {
		return ""
	}
	return fmt.Sprintf("modroot %s: compile gate ran with CGO_ENABLED=0 for GOARCH=%s (the spec sets CGO_ENABLED=1, but this host cannot compile linux cgo) - cgo files count as linked but are not compile-checked",
		m.Modroot, strings.Join(limited, ","))
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
	Options  Options

	// newSimulator constructs the simulator lazily so a missing go toolchain
	// degrades at Apply time (with a message) instead of failing pipeline
	// construction; tests override it.
	newSimulator func(ctx context.Context, opts Options, analyzer *Analyzer) (bumpSimulator, error)
}

func NewSimulationStage(analyzer *Analyzer, opts Options) *SimulationStage {
	return &SimulationStage{
		BaseStage: processor.BaseStage{
			StageName:        "bump_simulation",
			StageDescription: "Validate Go bump candidates against a source checkout",
		},
		Analyzer:     analyzer,
		Options:      opts,
		newSimulator: defaultSimulator,
	}
}

func defaultSimulator(ctx context.Context, opts Options, analyzer *Analyzer) (bumpSimulator, error) {
	simOpts := simulate.Options{
		Budget:    opts.SimulationTimeout,
		NoCompile: !opts.Compile,
	}.WithDefaults()
	toolchain, err := simulate.NewToolchain(ctx, simOpts.CommandTimeout)
	if err != nil {
		return nil, err
	}
	return simulate.NewSimulator(nil, toolchain, analyzer.vulnerabilityScanner, opts.TempDir, simOpts), nil
}

func (s *SimulationStage) ShouldRun(_ context.Context, p processor.Processor) (bool, error) {
	gp, err := asBump(p)
	if err != nil {
		return false, err
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
	gp, err := asBump(p)
	if err != nil {
		return err
	}
	analysis := gp.VulnerabilityAnalysis

	sim, err := s.newSimulator(ctx, s.Options, s.Analyzer)
	if err != nil {
		return cancelledOr(ctx, func() { s.degrade(ctx, gp, err) })
	}

	for i := range analysis.ByLanguage {
		lang := &analysis.ByLanguage[i]
		if lang.Language != "go" || len(lang.ByModroot) == 0 {
			continue
		}
		// Shadowed for the rest of this iteration: every log emitted while
		// simulating this language carries it.
		ctx := logging.With(ctx, "language", lang.Language)

		reqs := s.buildRequests(ctx, gp, lang)
		results, err := sim.Simulate(ctx, analysis.RepoURL, analysis.Tag, analysis.ExpectedCommit, reqs)
		if err != nil {
			if ctx.Err() == nil && s.failClosed(err) {
				// The simulation could not prove the candidate set (compile
				// gate, or a go tool infrastructure failure): writing it (or
				// the raw pre-simulation set) could break the build, so fail
				// the file and leave its deps untouched.
				return fmt.Errorf("bump simulation could not validate the deps (file left unchanged): %w", err)
			}
			return cancelledOr(ctx, func() { s.degrade(ctx, gp, err) })
		}

		adoptResults(ctx, gp, lang, results)
		rebuildLanguageActions(analysis, lang)
	}

	gp.Validated = true
	return nil
}

// buildRequests turns one language's modroot analyses into simulation
// requests, emitting the per-modroot compile-gate cgo notes and (once) the
// omnibump engine note as it goes.
func (s *SimulationStage) buildRequests(ctx context.Context, gp *Processor, lang *LanguageAnalysis) []simulate.ModrootRequest {
	goEco := ecogolang.New()
	reqs := make([]simulate.ModrootRequest, 0, len(lang.ByModroot))
	omnibumpRoots := 0
	for _, m := range lang.ByModroot {
		if m.BumpEngine == simulate.EngineOmnibump {
			omnibumpRoots++
		}
		if note := compileCgoNote(m, s.Options.Compile); note != "" {
			gp.AddMessage(note)
		}
		reqs = append(reqs, simulate.ModrootRequest{
			Modroot:         m.Modroot,
			Seeds:           seedCandidates(m),
			Baseline:        goEco.EffectiveVersions(ctx, m.Deps),
			Packages:        m.BuildPackages,
			Tags:            m.BuildTags,
			Arches:          m.BuildArches,
			Env:             m.BuildEnv,
			VulnImports:     vulnImports(m.ScanResult),
			BaselineVulnIDs: baselineVulnIDs(m.ScanResult),
			Engine:          m.BumpEngine,
			NoTidy:          m.BumpNoTidy,
			ProbeTidy:       m.BumpMigrating && m.BumpNoTidy,
			GoVersion:       s.buildGoVersion(ctx, m.GoPackageMinor),
		})
	}
	if omnibumpRoots > 0 {
		version := simulate.OmnibumpVersion()
		logging.From(ctx).Debug("simulating uses: bump steps with omnibump", "omnibump", version, "modroots", omnibumpRoots)
		gp.AddMessage(fmt.Sprintf("simulation: uses: bump applied with omnibump %s", version))
	}
	return reqs
}

// adoptResults folds one language's simulation results back into its
// modroot analyses, reports each modroot's outcome, publishes the linked
// stdlib union and reports the advisories unreachable in every modroot.
func adoptResults(ctx context.Context, gp *Processor, lang *LanguageAnalysis, results map[string]*simulate.ModrootResult) {
	reach := newReachabilityDiff()
	// Scanner-hygiene bumps proposed in any modroot, by module (OSV
	// naming included), for the unreachable-advisory messages below.
	hygieneProposed := make(map[string]bool)
	// A versioned go/install builds another module version, whose
	// stdlib slice no checkout shows.
	std := newStdUnion(len(scanBuildSteps(ctx, gp.Config).versionedInstalls) == 0)
	for mi := range lang.ByModroot {
		m := &lang.ByModroot[mi]
		// Shadowed for the rest of this iteration - see the
		// language-level shadow in Apply.
		ctx := logging.With(ctx, "modroot", m.Modroot)

		result := results[m.Modroot]
		if result == nil {
			// Skipped/unsimulated modroot: everything it found counts as
			// reachable (fail open).
			reach.observe(*m, nil, nil, false, nil)
			std.taint()
			continue
		}
		unlinkedHere := adoptResult(gp, m, result, reach, std)
		reportModrootResult(ctx, gp, m, result, unlinkedHere, hygieneProposed)
	}

	std.publish(ctx, gp, len(lang.ByModroot))
	reportUnreachable(ctx, gp, reach, hygieneProposed)
}

// adoptResult replaces modroot m's desired state with the simulation's
// proven result, records its reachability and linked-stdlib slice, and
// records a genuine Go language requirement raise. Returns how many
// advisory IDs were unlinked in this modroot.
func adoptResult(gp *Processor, m *ModrootAnalysis, result *simulate.ModrootResult, reach *reachabilityDiff, std *stdUnion) int {
	m.DesiredDeps = result.FinalDeps
	m.DesiredReplaces = result.FinalReplaces
	m.SecurityBumpModules = result.CVEBackedModules
	m.Simulated = true
	m.SimulationConverged = result.Converged
	m.Residuals = result.Residuals
	m.Dropped = result.Dropped
	m.BaselineTidies = result.BaselineTidies
	m.HygieneModules = result.HygieneModules
	gp.AddResiduals(result.Residuals)
	unlinkedHere := reach.observe(*m, result.Linked, result.LinkedPackages, true, degradedUnlinkedSet(result))

	// Union the linked stdlib slice into a local set for the stdlib
	// staleness stage (Go only), so it can filter stdlib advisories by
	// artifact reachability without its own checkout. nil = this modroot's
	// walk failed open, which taints the whole union (see stdUnion) rather
	// than just contributing nothing.
	std.add(result.StdPackages)

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
	return unlinkedHere
}

// reportBlindSpots surfaces what the simulation could not see in one
// modroot: unavailable artifact linkage as a default-verbosity note (every
// reachability verdict was skipped - fail open), and at -v the tolerated
// unmatched //go:embed patterns and the packages the compile gate cannot
// check because they already fail to build at baseline.
func reportBlindSpots(gp *Processor, modroot string, result *simulate.ModrootResult) {
	if result.LinkageError != "" {
		prefix := ""
		if modroot != "." {
			prefix = "modroot " + modroot + ": "
		}
		cause, _, _ := strings.Cut(result.LinkageError, "\n")
		gp.AddNote(fmt.Sprintf("%sartifact linkage unavailable (%s) - unlinked/hygiene classification and stdlib filtering skipped",
			prefix, cause))
	}
	if len(result.UnmatchedEmbeds) > 0 {
		var byPackage []string
		var patterns []string
		for i, e := range result.UnmatchedEmbeds {
			patterns = append(patterns, e.Pattern)
			if i+1 == len(result.UnmatchedEmbeds) || result.UnmatchedEmbeds[i+1].Package != e.Package {
				byPackage = append(byPackage, fmt.Sprintf("%s (%s)", e.Package, strings.Join(patterns, ", ")))
				patterns = nil
			}
		}
		gp.AddMessage(fmt.Sprintf("modroot %s: tolerated unmatched go:embed pattern(s) in %s (generated at build time): linkage computed from imports",
			modroot, strings.Join(byPackage, ", ")))
	}
	if result.GateUnchecked > 0 {
		gp.AddMessage(fmt.Sprintf("modroot %s: compile gate cannot check %d package(s) that fail to build at baseline (first: %s)",
			modroot, result.GateUnchecked, result.GateUncheckedFirst))
	}
}

// reportModrootResult reports one simulated modroot's outcome: the summary
// line, redundant and hygiene drops, proposed hygiene bumps (recorded into
// hygieneProposed for reportUnreachable) and residual advisories.
func reportModrootResult(ctx context.Context, gp *Processor, m *ModrootAnalysis, result *simulate.ModrootResult, unlinkedHere int, hygieneProposed map[string]bool) {
	gp.AddMessage(fmt.Sprintf(
		"simulation: modroot %s %s in %d iteration(s): %d validated dep(s), %d replace(s), %d dropped, %d residual advisory(ies), %d advisory(ies) in unlinked modules",
		m.Modroot, convergedWord(result.Converged), result.Iterations,
		len(result.FinalDeps), len(result.FinalReplaces), len(result.Dropped), len(result.RemainingVulnIDs), unlinkedHere))
	for _, dropped := range result.Dropped {
		if dropped.Redundant {
			gp.AddMessage(fmt.Sprintf("modroot %s: removed redundant %s@%s (%s)",
				m.Modroot, dropped.Module, dropped.Version, strings.TrimPrefix(dropped.Reason, "redundant: ")))
		}
		switch {
		case dropped.Hygiene && strings.HasPrefix(dropped.Reason, "shed: "):
			gp.AddMessage(fmt.Sprintf("modroot %s: hygiene: %s - no bump proposed",
				m.Modroot, strings.TrimPrefix(dropped.Reason, "shed: ")))
		case dropped.Hygiene:
			gp.AddMessage(fmt.Sprintf("modroot %s: hygiene: %s@%s %s - no bump proposed",
				m.Modroot, dropped.Module, dropped.Version, strings.TrimPrefix(dropped.Reason, "scanner hygiene: ")))
		}
		logging.From(ctx).Debug("bump candidate dropped by simulation",
			"module", dropped.Module, "version", dropped.Version, "reason", dropped.Reason)
	}
	for _, h := range result.HygieneModules {
		hygieneProposed[h.Module], hygieneProposed[ecogolang.TrimMajorSuffix(h.Module)] = true, true
		gp.AddMessage(fmt.Sprintf("modroot %s: hygiene: %s@%s proposed for scanners (%s; vulnerable package not linked, not a security fix)",
			m.Modroot, h.Module, h.Version, strings.Join(h.VulnIDs, ", ")))
	}
	if result.HygieneSkipped != "" {
		gp.AddMessage(fmt.Sprintf("modroot %s: hygiene: scanner-hygiene bumps not evaluated: %s", m.Modroot, result.HygieneSkipped))
	}
	reportBlindSpots(gp, m.Modroot, result)
	for _, residual := range result.Residuals {
		logging.From(ctx).Debug("residual vulnerability after simulation",
			"module", residual.Module,
			"resolved", residual.ResolvedVersion, "fix", residual.FixedVersion,
			"vulns", strings.Join(residual.VulnIDs, ","), "reason", residual.Reason)
	}
}

// stdUnion accumulates the linked-stdlib packages across every modroot of
// a language; complete tracks whether every one of them actually
// contributed a validated set. A skipped modroot or a failed-open stdlib
// walk in ANY modroot invalidates the whole union.
type stdUnion struct {
	pkgs     map[string]struct{}
	complete bool
}

func newStdUnion(complete bool) *stdUnion {
	return &stdUnion{pkgs: map[string]struct{}{}, complete: complete}
}

// taint marks the union incomplete.
func (u *stdUnion) taint() { u.complete = false }

// add unions one modroot's linked stdlib packages; nil (the walk failed
// open) taints the union.
func (u *stdUnion) add(pkgs map[string]struct{}) {
	if pkgs == nil {
		u.taint()
		return
	}
	for pkg := range pkgs {
		u.pkgs[pkg] = struct{}{}
	}
}

// publish sets gp.LinkedStdPackages only when every modroot actually
// contributed a validated stdlib set - a partial union must not masquerade
// as complete (the stdlib stage treats non-nil as proof it can safely
// demote unlinked-package advisories). Otherwise gp.LinkedStdPackages stays
// nil: unknown, so the stdlib stage fails open.
func (u *stdUnion) publish(ctx context.Context, gp *Processor, modroots int) {
	if u.complete && len(u.pkgs) > 0 {
		gp.LinkedStdPackages = u.pkgs
	} else if !u.complete {
		logging.From(ctx).Debug("discarding partial linked-stdlib union: not every go modroot contributed a validated stdlib package set",
			"modroot_count", modroots)
	}
}

// reportUnreachable reports the advisories whose modules were unlinked in
// EVERY modroot that saw them: informational only - no bump proposed,
// neither fixed nor residual (an ID linked - and therefore fixed or
// residual - in any other modroot counts as reachable).
func reportUnreachable(ctx context.Context, gp *Processor, reach *reachabilityDiff, hygieneProposed map[string]bool) {
	unreachableIDs, unreachableModules := reach.finalize()
	gp.AddUnreachableVulnIDs(unreachableIDs)
	for _, module := range unreachableModules {
		var msg string
		switch {
		case module.moduleLinked && hygieneProposed[module.name]:
			msg = fmt.Sprintf("info: %s (%s) vulnerable but not linked into build artifacts (module is linked; the vulnerable packages are not) - scanner hygiene bump proposed, not a security fix",
				module.name, strings.Join(module.vulnIDs, ", "))
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
		logging.From(ctx).Debug("advisory in unlinked code - no bump proposed",
			"module", module.name, "module_linked", module.moduleLinked, "degraded", module.degraded, "vulns", strings.Join(module.vulnIDs, ","))
	}
}

// buildGoVersion is the Go version the build's bump step runs with, for the
// omnibump engine's go-directive lowering: the latest release of the minor
// the modroot's go/build steps pin via go-package. "" (the host go) when
// nothing is pinned or the release index cannot answer.
func (s *SimulationStage) buildGoVersion(ctx context.Context, minor string) string {
	if minor == "" || s.Analyzer == nil || s.Analyzer.goReleases == nil {
		return ""
	}
	version, err := s.Analyzer.goReleases.LatestAvailable(ctx, minor)
	if err != nil {
		logging.From(ctx).Debug("could not resolve the pinned Go minor's latest release - simulating with the host go",
			"go_minor", minor, "error", err)
		return ""
	}
	return version
}

// failClosed reports whether a simulation error must fail the file instead
// of degrading to the unvalidated candidate set: a compile-gate failure, an
// infrastructure failure of the go tool (network, proxy, per-command
// timeout - no verdict could be reached), or a timeout while the gate is
// enabled (the set was never proven to compile).
func (s *SimulationStage) failClosed(err error) bool {
	return errors.Is(err, simulate.ErrCompileGate) || errors.Is(err, simulate.ErrInfrastructure) ||
		(s.Options.Compile && errors.Is(err, context.DeadlineExceeded))
}

// degrade falls back to the unvalidated pre-simulation candidate set,
// loudly: the written deps list has not been proven to resolve or to cover
// every advisory. Callers must check ctx.Err() before calling this (see
// cancelledOr) - a cancelled run must propagate that cancellation, not
// degrade and write an unvalidated result as if simulation had merely failed.
func (s *SimulationStage) degrade(ctx context.Context, gp *Processor, err error) {
	gp.Validated = false
	gp.SimulationError = err.Error()
	logging.From(ctx).Info("bump simulation unavailable - proceeding with UNVALIDATED deps", "error", err)
}

// seedCandidates converts a modroot's post-FilterBumps desired deps and its
// existing replace directives into simulation candidates, marking those
// backed by an OSV advisory (with their advisory IDs) so the loop knows
// which entries to defend. Replace seeds come first: the loop routes a deps
// seed for an already-replace-claimed module into the replace channel.
func seedCandidates(m ModrootAnalysis) []simulate.Candidate {
	bumpByModule := make(map[string]scan.SecurityBump)
	var vulns []scan.Vulnerability
	if m.ScanResult != nil {
		vulns = m.ScanResult.Vulnerabilities
		for _, bump := range m.ScanResult.SecurityBumps {
			bumpByModule[bump.Name] = bump
		}
	}
	existingVersions := make(map[string][]string)
	for _, dep := range m.ExistingDeps {
		if module, version, ok := splitCoordVersion(dep); ok {
			existingVersions[module] = append(existingVersions[module], version)
		}
	}
	seeds := make([]simulate.Candidate, 0, len(m.DesiredDeps)+len(m.ExistingReplaces))

	for _, replace := range m.ExistingReplaces {
		oldPath, newPath, version, ok := ecogolang.ParseReplace(replace)
		if !ok {
			continue // not gobump grammar; leave to the loop's residual reporting
		}
		candidate := simulate.Candidate{
			Module: newPath, Version: version,
			Replace: true, ReplaceOld: oldPath,
		}
		if info, ok := lookupModule(bumpByModule, newPath); ok {
			candidate.FromCVE = true
			candidate.VulnIDs = info.VulnIDs
			candidate.Severity = info.Severity
		}
		seeds = append(seeds, candidate)
	}

	for _, dep := range m.DesiredDeps {
		module, version, ok := splitCoordVersion(dep)
		if !ok {
			continue
		}
		candidate := simulate.Candidate{Module: module, Version: version}
		if info, ok := lookupModule(bumpByModule, module); ok {
			candidate.FromCVE = true
			candidate.VulnIDs = info.VulnIDs
			candidate.Severity = info.Severity
			// The fix ladder keeps every advisory's own fix version and the
			// existing YAML pin, which FilterBumps merged into one (the
			// highest) version: the compile gate relaxes down these rungs.
			// A single rung is implied by the candidate itself.
			also := []string{version}
			for _, existing := range existingVersions[module] {
				if semver.Compare(existing, info.CurrentVersion) > 0 {
					also = append(also, existing) // a pin at/below the vulnerable baseline is no rung
				}
			}
			if rungs := simulate.FixRungs(vulns, info.Name, info.VulnIDs, also...); len(rungs) > 1 {
				candidate.Rungs = rungs
			}
		}
		seeds = append(seeds, candidate)
	}
	return seeds
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
		// Replaces-only changes (a raised or retired user replace with
		// unchanged deps) must also produce an action, or the applier never
		// writes them.
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
		trimmed := ecogolang.TrimMajorSuffix(module)
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

	// Per-advisory vulnerable import paths, from the analysis scan.
	var importsByID map[string][]scan.VulnerableImport
	if m.ScanResult != nil {
		importsByID = importsByAdvisory(m.ScanResult.Vulnerabilities)
	}

	record := func(module string, vulnIDs []string) {
		if len(vulnIDs) == 0 {
			return
		}
		modLinked := moduleLinkedIn(module, linkedModules, unrequired)
		for _, id := range vulnIDs {
			if modLinked && scan.ImportsLinked(importsByID[id], linkedPackages) {
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

// moduleLinkedIn reports whether module is linked per the precise linked
// module set, else (linkedModules nil) per the degraded unrequired signal,
// else true (fail open: no precise or degraded signal).
func moduleLinkedIn(module string, linkedModules, unrequired map[string]struct{}) bool {
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
		if ecogolang.TrimMajorSuffix(candidate) == module {
			return true
		}
	}
	return false
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
	slices.SortFunc(modules, func(a, b unreachableModule) int { return strings.Compare(a.name, b.name) })

	return ids, modules
}

// vulnImports projects a modroot's analysis findings onto advisory ID ->
// vulnerable imports, for threading into the simulation (seed advisories
// were scanned before the checkout exists; see
// simulate.ModrootRequest.VulnImports). Advisories without import metadata
// are omitted. Nil when nothing is known.
func vulnImports(scanResult *scan.ScanResult) map[string][]scan.VulnerableImport {
	if scanResult == nil {
		return nil
	}
	imports := importsByAdvisory(scanResult.Vulnerabilities)
	maps.DeleteFunc(imports, func(_ string, v []scan.VulnerableImport) bool { return len(v) == 0 })
	if len(imports) == 0 {
		return nil
	}
	return imports
}

// importsByAdvisory maps advisory ID -> vulnerable imports. One ID can name
// findings in several modules (IDs are CVE-first, so two modules' GO- records
// can share one): their imports union, but a finding without import metadata
// makes the ID's imports unknown (empty - every consumer fails open).
func importsByAdvisory(vulns []scan.Vulnerability) map[string][]scan.VulnerableImport {
	imports := make(map[string][]scan.VulnerableImport, len(vulns))
	for _, vuln := range vulns {
		prev, seen := imports[vuln.ID]
		if seen && (len(prev) == 0 || len(vuln.VulnerableImports) == 0) {
			imports[vuln.ID] = nil
			continue
		}
		imports[vuln.ID] = append(prev, vuln.VulnerableImports...)
	}
	return imports
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
