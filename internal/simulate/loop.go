package simulate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/isometry/choam/internal/goversion"
	"github.com/isometry/choam/internal/logging"
	"github.com/isometry/choam/internal/scan"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// candState is a Candidate plus its lifecycle within the loop. A replace
// candidate (Candidate.Replace) is always a user-authored YAML replace: the
// loop never creates replace directives of its own.
type candState struct {
	Candidate
	seed    bool // seeded by the caller (vs raised by a rescan)
	remedy  bool // added to repair an ambiguous import (applied first)
	dropped bool

	// ceiling is the lowest version whose fetch failed (see stepDown): the
	// candidate never raises to it or above again, so the residual recorded
	// for it stands.
	ceiling string
	// residualized marks a dropped candidate whose advisories were accounted
	// for at drop time - either recorded as a residual or deliberately
	// residual-free (unreachable, redundant). The rescan backfill only
	// synthesizes residuals for dropped CVE candidates NOT marked here.
	residualized bool
	// dropReason mirrors the DroppedCandidate reason, for backfill wording.
	dropReason string

	// repair marks a coherence-only pin the compile gate added to keep a
	// module compatible with a raised dependency (see repairsFor).
	repair bool
}

// drop marks the candidate dropped and records it with the given reason.
func (l *loop) drop(c *candState, reason string) {
	c.dropped = true
	c.dropReason = reason
	l.dropped = append(l.dropped, DroppedCandidate{
		Module:  c.Module,
		Version: c.Version,
		Reason:  reason,
	})
}

type loop struct {
	tc   Toolchain
	sc   Scanner
	dir  string
	req  ModrootRequest
	opts Options

	engine engine // the bump step's apply semantics (see Engine)

	cands    []*candState
	byModule map[string]*candState

	pristine map[string][]byte // go.mod/go.sum contents at clone time

	dropped             []DroppedCandidate
	persistentResiduals []Residual // apply-time failures: survive rescans
	scanResiduals       []Residual // recomputed from each rescan
	lastRaised          []*candState
	remedied            map[string]remedyState // monoliths advanced to repair an ambiguous import
	requirements        map[string]string      // go.mod requires after the last clean apply

	replaces         map[string]ReplaceTarget // go.mod replace directives after the last clean apply
	pristineReplaces map[string]ReplaceTarget // upstream go.mod replace directives at clone time

	// infraErr is the first infrastructure failure a best-effort lookup
	// swallowed (see recordInfra): once set, no further verdict is trusted
	// and the simulation fails with it.
	infraErr error

	// Artifact reachability: buildPatterns are the go/build package patterns
	// (default ./...) whose non-test import graph decides what actually
	// ships; linked/linkedPackages are the module and package sets from the
	// last Toolchain.Linked query, nil when unknown (query failed) -
	// reachability then fails OPEN and no filtering happens.
	buildPatterns  []string
	linked         map[string]struct{}
	linkedPackages map[string]struct{}
	linkedWarned   bool

	// Degraded module-level reachability (see degradedUnlinked): tidiedModern
	// tracks whether the current on-disk go.mod's go directive is >= 1.17 -
	// the threshold at which the require block covers the main module's
	// whole import closure. linkedStdWarned/degradedNoted are warn/info-once
	// guards, mirroring linkedWarned.
	tidiedModern    bool
	linkedStdWarned bool
	degradedNoted   bool

	// Compile gate (see compileGate): compiler is nil when the gate is off
	// (toolchain without Compiler support, or Options.NoCompile).
	// baselineFailed are the packages already failing to compile in the
	// pristine checkout (excluded from every verdict); baselineResolved is
	// the pristine tidied module graph.
	compiler         Compiler
	baselineFailed   map[string]struct{}
	baselineResolved map[string]string
}

// raise is a rescan finding that requires moving a module further forward;
// rungs are its per-advisory fix versions (see FixRungs).
type raise struct {
	module   string
	version  string
	vulnIDs  []string
	severity string
	rungs    []Rung
}

// RunLoop applies the seed candidates to the module at dir with the real go
// toolchain, rescans the resolved graph, raises versions for any residual
// advisories, and iterates to a fixpoint (see package doc). It returns a
// ModrootResult even on non-convergence (Converged=false); an error return
// means the simulation itself could not run (unreadable module, toolchain or
// scanner failure) and the caller should fall back to unvalidated behavior.
func RunLoop(ctx context.Context, tc Toolchain, sc Scanner, dir string, req ModrootRequest, opts Options) (*ModrootResult, error) {
	opts = opts.WithDefaults()

	var pristineReplaces map[string]ReplaceTarget
	l := &loop{
		tc:            tc,
		sc:            sc,
		dir:           dir,
		req:           req,
		opts:          opts,
		byModule:      make(map[string]*candState),
		remedied:      make(map[string]remedyState),
		buildPatterns: req.Packages,
	}
	if len(l.buildPatterns) == 0 {
		l.buildPatterns = []string{"./..."}
	}
	if compiler, ok := tc.(Compiler); ok && !opts.NoCompile {
		l.compiler = compiler
	}
	if err := l.savePristine(ctx); err != nil {
		return nil, err
	}
	eng, err := l.newEngine(ctx)
	if err != nil {
		return nil, err
	}
	l.engine = eng
	baselineTidies := false
	if prober, ok := eng.(*omnibumpEngine); ok && req.ProbeTidy && req.NoTidy {
		if baselineTidies, err = prober.probeTidy(ctx); err != nil {
			return nil, err
		}
	}
	pristineReplaces, err = tc.Replaces(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("reading upstream replace directives: %w", err)
	}
	l.pristineReplaces = pristineReplaces

	for _, seed := range req.Seeds {
		l.seedCandidate(seed)
	}

	// Pristine reachability: shed unreachable seeds BEFORE the first apply.
	// A doomed candidate must never get to perturb the module graph - an
	// unlinked-but-unappliable fix would otherwise destabilize a fragile
	// graph and surface as a bogus "fix breaks module graph" residual.
	l.refreshLinked(ctx)
	l.dropUnreachable()

	if l.compiler != nil {
		if err := l.compileBaseline(ctx); err != nil {
			return nil, err
		}
	}

	result := &ModrootResult{Modroot: req.Modroot, BaselineTidies: baselineTidies}

	var resolved map[string]string
	for iter := 1; iter <= opts.MaxIterations; iter++ {
		result.Iterations = iter

		if err := l.apply(ctx); err != nil {
			return nil, err
		}

		// Re-apply until every surviving pin is sustained by the tidied
		// go.mod (melange's gobump rejects entries the tidy pruned or
		// downgraded) AND linked into a build artifact; each pass sheds at
		// least one candidate, so this is bounded. Shedding inside this loop
		// (rather than a separate phase) matters: a dropped candidate's MVS
		// ripple is unwound by the re-apply, so the validated final state
		// matches what melange's gobump will produce from FinalDeps alone.
		for {
			var err error
			resolved, err = l.tc.ListModules(ctx, l.dir)
			if err != nil {
				return nil, err
			}
			l.requirements, err = l.tc.Requirements(ctx, l.dir)
			if err != nil {
				return nil, err
			}
			// The tidied go.mod's go directive cannot change between applies
			// by the same engine (gobump tidies with the same `-go=` flag,
			// omnibump lowers to the same build Go), so this needs no
			// recompute in adoptTrial.
			l.tidiedModern = l.tidiedGoModern()
			if l.tidiedModern && l.linked == nil && !l.degradedNoted {
				l.degradedNoted = true
				logging.From(ctx).Info("artifact reachability degraded: using tidied go.mod require membership as module-level reachability",
					"modroot", l.req.Modroot)
			}
			l.replaces, err = l.tc.Replaces(ctx, l.dir)
			if err != nil {
				return nil, err
			}
			l.refreshLinked(ctx)
			if !l.dropUnsustained() && !l.dropUnreachable() {
				break
			}
			if err := l.apply(ctx); err != nil {
				return nil, err
			}
		}

		scanResult, err := l.sc.ScanPackages(ctx, l.scanTargets(resolved, l.requirements, l.replaces))
		if err != nil {
			return nil, err
		}

		raises := l.processScan(ctx, scanResult, resolved)
		if len(raises) == 0 {
			result.Converged = true
			break
		}
	}

	// Dependency-graph capabilities (max go directive, linked stdlib set) are
	// computed HERE: right after the fixpoint loop exits (converged or
	// iteration-cap exhausted) and BEFORE the refinement phases
	// (confirmMinimalSet, the compile gate, minimise) run. At this exact point the
	// checkout on disk is guaranteed to be the state that produced
	// `resolved` - the loop body's last apply() is always immediately
	// followed by ListModules/Requirements/Replaces/refreshLinked with no
	// intervening disk mutation, and the inner sustain-loop only exits once
	// dropUnsustained/dropUnreachable report no further change, so nothing
	// after that last apply() touches go.mod/go.sum before here. The
	// refinement phases, by contrast, call trialApply, which restores the
	// pristine snapshot and reapplies only a candidate subset; on ANY
	// failure partway through, the phase returns the original `resolved`
	// value unchanged but leaves the checkout in whatever partial state the
	// failed trial produced, never resyncing disk back to the full
	// converged state it's about to report. Querying the toolchain after
	// that point could read a go.mod that doesn't correspond to `resolved`
	// at all. Hooking in before the refinement phases sidesteps that gap.
	//
	// These values describe the converged FULL candidate set - a superset of
	// whatever the refinement phases may go on to adopt. For MaxDepGoVersion
	// that's always a safe over-approximation: dropping redundant candidates
	// can only lower or hold the max go directive, never raise it.
	// StdPackages does NOT share that property - a smaller set can pin
	// different (typically older) module versions than the full set, and an
	// older version's import graph is not guaranteed to be a subset of the
	// newer one's; it can reference stdlib packages the full set's versions
	// never touched. So when a refinement phase adopts a trial, adoptTrial
	// recomputes both fields immediately (same fail-open helpers, same
	// "disk == the graph just adopted" guarantee) and overwrites the
	// superset values set here; a recompute failure there fails open by
	// KEEPING these superset values.
	result.MaxDepGoVersion = l.maxDepGoVersion(ctx)
	result.StdPackages = l.linkedStdPackages(ctx)

	if !result.Converged {
		// The final rescan still wanted to move modules forward; surface
		// those targets as residuals rather than looping further.
		for _, c := range l.lastRaised {
			l.persistentResiduals = append(l.persistentResiduals, Residual{
				Module:          c.Module,
				ResolvedVersion: resolved[c.Module],
				FixedVersion:    c.Version,
				VulnIDs:         c.VulnIDs,
				Reason:          "iteration cap reached before fix could be validated",
			})
		}
	} else {
		// Post-convergence refinement (one trial): shed pins no advisory
		// needs.
		if resolved, err = l.confirmMinimalSet(ctx, resolved, result); err != nil {
			return nil, err
		}
	}

	// The compile gate runs last, against the final candidate set: the
	// fixpoint only proves the graph resolves and tidies - MVS has no upper
	// bounds, so a raised dependency can still remove API a lagging sibling
	// compiles against (see compileGate).
	if l.compiler != nil {
		gated, err := l.compileGate(ctx, resolved, result)
		if err != nil {
			return nil, err
		}
		resolved = gated
	}

	// Last, on the final set: remove every redundant entry. The final
	// tidied go.mod is unchanged by construction, so resolved and the
	// capability fields still describe it.
	if err := l.minimise(ctx); err != nil {
		return nil, err
	}

	if l.infraErr != nil {
		// A best-effort lookup hit an infrastructure failure: some verdict
		// above may rest on it, so nothing here is trusted.
		return nil, l.infraErr
	}

	result.Resolved = resolved
	result.Linked = l.linked
	result.LinkedPackages = l.linkedPackages
	result.Requires = l.requirements
	result.UnrequiredModules = l.unrequiredModules(resolved)
	result.FinalDeps, result.FinalReplaces, result.CVEBackedModules = l.finalOutputs(resolved)
	result.Dropped = l.dropped
	result.Residuals = append(append([]Residual{}, l.persistentResiduals...), l.scanResiduals...)
	for i := range result.Residuals {
		// Apply-time residuals are recorded before any clean resolve exists;
		// backfill the module's final graph version for honest reporting.
		if result.Residuals[i].ResolvedVersion == "" {
			result.Residuals[i].ResolvedVersion = resolved[result.Residuals[i].Module]
		}
	}
	l.classifyIntroduced(ctx, result.Residuals)
	sort.Slice(result.Residuals, func(i, j int) bool { return result.Residuals[i].Module < result.Residuals[j].Module })
	result.RemainingVulnIDs = remainingVulnIDs(result.Residuals)

	return result, nil
}

// seedCandidate routes one caller-provided seed into the right channel.
// Replace seeds (user-authored YAML replaces) enter as-is, and a deps seed
// for a module a replace seed already claims merges into that replace (a
// `go get` cannot out-vote a replace directive). A deps seed for a module the
// upstream go.mod replace-pins is held back: the build's bump step cannot
// move it and the loop never adds replace directives of its own, so it is
// dropped here and the rescan reports any advisory it would have fixed as a
// hold-back residual (see scanFindings).
func (l *loop) seedCandidate(c Candidate) {
	if c.Replace {
		l.addCandidate(c, true)
		return
	}

	if existing, ok := l.byModule[c.Module]; ok && !existing.dropped && existing.Replace {
		// Merge advisory backing, but the entry stays in the replace channel.
		l.addCandidate(Candidate{
			Module: c.Module, Version: c.Version, FromCVE: c.FromCVE, VulnIDs: c.VulnIDs,
			Replace: true, ReplaceOld: existing.ReplaceOld,
		}, true)
		l.dropped = append(l.dropped, DroppedCandidate{
			Module:  c.Module,
			Version: c.Version,
			Reason:  "superseded by replaces entry for the same module",
		})
		return
	}

	if oldPath, target, pinned := l.pristinePinFor(c.Module); pinned {
		if target.Version == "" {
			l.dropLocalReplacePinned(c, oldPath)
			return
		}
		l.dropped = append(l.dropped, DroppedCandidate{
			Module:  c.Module,
			Version: c.Version,
			Reason:  holdBackReason(oldPath),
		})
		return
	}

	l.addCandidate(c, true)
}

// holdBackReason is the residual/drop reason for a fix the upstream go.mod's
// replace directive for module holds back.
func holdBackReason(module string) string {
	return fmt.Sprintf("upstream go.mod replace-pins %s (hold-back)", module)
}

// pristinePinFor reports whether module is subject to an upstream go.mod
// replace directive, matching either side of the directive.
func (l *loop) pristinePinFor(module string) (oldPath string, target ReplaceTarget, ok bool) {
	if target, found := l.pristineReplaces[module]; found {
		return module, target, true
	}
	for old, target := range l.pristineReplaces {
		if target.Path == module && target.Version != "" {
			return old, target, true
		}
	}
	return "", ReplaceTarget{}, false
}

// dropLocalReplacePinned records a candidate that cannot be moved because
// the upstream go.mod replace-pins its module to a local filesystem path.
func (l *loop) dropLocalReplacePinned(c Candidate, oldPath string) {
	l.dropped = append(l.dropped, DroppedCandidate{
		Module:  c.Module,
		Version: c.Version,
		Reason:  fmt.Sprintf("module is replace-pinned to a local path in upstream go.mod (%s)", oldPath),
	})
	if c.FromCVE {
		l.persistentResiduals = append(l.persistentResiduals, Residual{
			Module:       c.Module,
			FixedVersion: c.Version,
			VulnIDs:      c.VulnIDs,
			Reason:       "module is replace-pinned to a local path in upstream go.mod",
		})
	}
}

func (l *loop) addCandidate(c Candidate, seed bool) *candState {
	if existing, ok := l.byModule[c.Module]; ok && !existing.dropped {
		existing.Rungs = mergeRungs(existing.fixRungs(), c.fixRungs())
		if semver.Compare(c.Version, existing.Version) > 0 {
			existing.Version = c.Version
		}
		existing.FromCVE = existing.FromCVE || c.FromCVE
		existing.VulnIDs = mergeIDs(existing.VulnIDs, c.VulnIDs)
		existing.Severity = mergeSeverity(existing.Severity, c.Severity)
		return existing
	}
	state := &candState{Candidate: c, seed: seed}
	l.cands = append(l.cands, state)
	l.byModule[c.Module] = state
	return state
}

// mergeSeverity keeps the more severe of two advisory levels.
func mergeSeverity(a, b string) string {
	if a == "" || (b != "" && scan.SeverityRank(b) < scan.SeverityRank(a)) {
		return b
	}
	return a
}

func (l *loop) activeCandidates() []*candState {
	active := make([]*candState, 0, len(l.cands))
	for _, c := range l.cands {
		if !c.dropped {
			active = append(active, c)
		}
	}
	return active
}

// savePristine snapshots go.mod/go.sum so each apply attempt starts from the
// tagged state - only these two files change under -mod=mod. ctx is accepted
// for consistency with the rest of the loop's methods; the reads themselves
// are local disk I/O and not currently cancellable.
func (l *loop) savePristine(_ context.Context) error {
	l.pristine = make(map[string][]byte, 2)
	for _, name := range []string{"go.mod", "go.sum"} {
		content, err := os.ReadFile(filepath.Join(l.dir, name))
		if err != nil {
			if os.IsNotExist(err) && name == "go.sum" {
				continue // pre-go.sum era projects
			}
			return fmt.Errorf("reading %s: %w", name, err)
		}
		l.pristine[name] = content
	}
	if _, ok := l.pristine["go.mod"]; !ok {
		return fmt.Errorf("no go.mod at %s", l.dir)
	}
	return nil
}

// restore reverts go.mod/go.sum to the pristine snapshot savePristine took.
// ctx is accepted for consistency with the rest of the loop's methods (and
// is checked at the top of every call site that runs this on each apply
// attempt); the writes themselves are local disk I/O and not currently
// cancellable.
func (l *loop) restore(_ context.Context) error {
	for _, name := range []string{"go.mod", "go.sum"} {
		path := filepath.Join(l.dir, name)
		content, ok := l.pristine[name]
		if !ok {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("removing %s: %w", name, err)
			}
			continue
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			return fmt.Errorf("restoring %s: %w", name, err)
		}
	}
	return nil
}

// apply establishes a clean toolchain state with every active candidate
// applied by the step's engine (see Engine), in apply order. Any failure
// repairs, steps down or removes exactly one candidate and restarts the
// attempt, so the loop is bounded by the candidates and their fix rungs (a
// repair happens at most once per module). An infrastructure failure (see
// ErrInfrastructure) is never a verdict on a candidate: it fails the apply.
func (l *loop) apply(ctx context.Context) error {
	attempts := 3*len(l.cands) + 8 + maxRemedySteps
	for _, c := range l.cands {
		attempts += len(c.Rungs)
	}
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			// Without this, a cancellation mid-loop can still burn several
			// more attempts, and exhausting the attempt budget afterward
			// would report a misleading "module graph did not stabilize"
			// instead of the real cancellation.
			return err
		}
		fail := l.engine.apply(ctx, l.inApplyOrder(l.activeCandidates()))
		if fail != nil {
			if ierr := l.recordInfra(fail.err); ierr != nil {
				return ierr
			}
		}
		switch {
		case fail == nil, fail.step == stepVerify:
			// A verification failure leaves the tidied result on disk: the
			// sustain checks (dropUnsustained) shed the rejected entry
			// exactly as they do for gobump's identical verification.
			return nil
		case fail.step == stepSetup:
			return fail.err
		case fail.step == stepGet && fail.cand != nil:
			l.handleGetFailure(ctx, fail.cand, fail.err)
		default: // the closing tidy, or a get failure no candidate is named in
			if !l.handleTidyFailure(ctx, fail.err) {
				return fmt.Errorf("final go mod tidy: %w", fail.err)
			}
		}
	}
	return fmt.Errorf("module graph did not stabilize after %d apply attempts", attempts)
}

// handleTidyFailure repairs or sheds exactly one candidate after a
// failed attempt-closing tidy, in escalating order of sacrifice:
//  1. Repair a monolith-vs-split-module "ambiguous import" by advancing the
//     monolith module past the split point (once per module).
//  2. Drop the most recently raised (non-seed) candidate - the likeliest
//     culprit for a graph that resolves per-module but won't tidy.
//  3. Drop the last coherence-only seed.
//  4. Drop the last CVE-backed candidate, recording its advisories as
//     residuals ("bump as high as viable, report the rest").
//  5. Only then drop remedies - they are load-bearing repairs, not
//     candidates, and must outlive the candidates that depend on them.
//
// Returns false only when nothing is left to shed.
func (l *loop) handleTidyFailure(ctx context.Context, err error) bool {
	if l.addAmbiguityRemedies(ctx, err) {
		return true
	}
	if l.dropLatestRaise(err) {
		return true
	}
	if l.dropLastCandidate(err, false) {
		return true
	}
	if l.dropLastCandidate(err, true) {
		return true
	}
	return l.dropLastRemedy(err)
}

// versionLister is the module-version lookup the ambiguous-import remedy
// walks with (*GoToolchain implements it; without it no remedy is found).
type versionLister interface {
	ModuleVersions(ctx context.Context, dir, module string) ([]string, error)
	ModuleRequires(ctx context.Context, dir, module, version string) (map[string]string, error)
	ResolveQuery(ctx context.Context, dir, module, query string) (string, error)
}

// maxRemedySteps bounds how often one monolith is advanced to repair a
// recurring ambiguous import.
const maxRemedySteps = 8

// remedyState tracks one monolith's ambiguous-import repair: the version it
// was last advanced to and how many times.
type remedyState struct {
	version string
	steps   int
}

// addAmbiguityRemedies parses "ambiguous import: found package ... in
// multiple modules" failures and advances the monolith module of each
// ambiguous pair to the minimal version that resolves it (see
// ambiguityRemedy; the canonical google.golang.org/genproto case). If the
// same ambiguity recurs at the remedied version, the monolith advances again
// from there (bounded by maxRemedySteps); if it recurs below it, the remedy
// never took effect where the failure happens (omnibump edits required
// modules in place only after every `go get`), so nothing further is tried.
// A replace-pinned monolith is left alone: a version pin cannot move it, so
// the sacrifice ladder proceeds instead. Returns true when it changed at
// least one candidate.
func (l *loop) addAmbiguityRemedies(ctx context.Context, err error) bool {
	changed := false
	for _, amb := range ambiguousImports(err.Error()) {
		module := amb.monolith
		state, seen := l.remedied[module]
		if seen && (state.steps >= maxRemedySteps || semver.Compare(amb.from, state.version) < 0) {
			continue
		}
		existing, ok := l.byModule[module]
		active := ok && !existing.dropped
		if active && existing.Replace {
			continue
		}
		if _, _, upstream := l.pristinePinFor(module); upstream {
			continue
		}
		version := l.ambiguityRemedy(ctx, amb)
		if version == "" {
			logging.From(ctx).Info("ambiguous import: no monolith version resolves the split",
				"modroot", l.req.Modroot, "module", module, "from", amb.from, "split", amb.split+"@"+amb.splitVersion)
			continue
		}
		l.remedied[module] = remedyState{version: version, steps: state.steps + 1}
		logging.From(ctx).Debug("ambiguous import remedy", "modroot", l.req.Modroot,
			"module", module, "from", amb.from, "to", version, "split", amb.split+"@"+amb.splitVersion)
		if active {
			if semver.Compare(version, existing.Version) > 0 {
				existing.Version = version
			}
			existing.remedy = true
			changed = true
			continue
		}
		delete(l.byModule, module)
		l.addCandidate(Candidate{Module: module, Version: version}, false).remedy = true
		changed = true
	}
	return changed
}

// ambiguityRemedy returns the minimal version of amb's monolith above its
// current one that should no longer provide the split module's packages, ""
// when none is found (or the toolchain cannot look versions up). When the
// split module's version is a pseudo-version its commit decides: both
// modules live in one repository (genproto's case: the monolith has no
// releases at all), and the monolith at that very commit cannot contain a
// directory the nested module owns. Otherwise the monolith's releases are
// walked upward (same major, no pre-releases unless already on one,
// bounded): the first whose go.mod requires the split module (the carve-out's
// signature), else the next release - a recurrence advances again (see
// addAmbiguityRemedies). Lookup failures find nothing, except an
// infrastructure failure, which is recorded (see recordInfra).
func (l *loop) ambiguityRemedy(ctx context.Context, amb ambiguity) string {
	lister, ok := l.tc.(versionLister)
	if !ok || !semver.IsValid(amb.from) {
		return ""
	}
	if rev, err := module.PseudoVersionRev(amb.splitVersion); err == nil {
		version, err := lister.ResolveQuery(ctx, l.dir, amb.monolith, rev)
		if err != nil {
			if l.recordInfra(err) != nil {
				return ""
			}
		} else if semver.Compare(version, amb.from) > 0 {
			return version
		}
	}
	versions, err := lister.ModuleVersions(ctx, l.dir, amb.monolith)
	if err != nil {
		_ = l.recordInfra(err) // recorded: fails the run (see RunLoop)
		return ""
	}
	next, inspected := "", 0
	for _, version := range versions {
		if semver.Compare(version, amb.from) <= 0 {
			continue
		}
		if semver.Major(version) != semver.Major(amb.from) {
			break
		}
		if semver.Prerelease(version) != "" && semver.Prerelease(amb.from) == "" {
			continue
		}
		if next == "" {
			next = version
		}
		if inspected++; inspected > maxCoherenceWalk {
			break
		}
		requires, err := lister.ModuleRequires(ctx, l.dir, amb.monolith, version)
		if err != nil {
			if l.recordInfra(err) != nil {
				return ""
			}
			continue
		}
		if _, ok := requires[amb.split]; ok {
			return version
		}
	}
	return next
}

// recordInfra classifies err (see asInfra) and, when it is an
// infrastructure failure, records the first one on the loop and returns it;
// nil otherwise. Best-effort lookups call it so a network or proxy outage
// they would otherwise swallow still fails the simulation (see RunLoop).
func (l *loop) recordInfra(err error) error {
	ierr := asInfra(err)
	if ierr != nil && l.infraErr == nil {
		l.infraErr = ierr
	}
	return ierr
}

// dropLastCandidate sheds an active non-remedy candidate of the given CVE
// class; CVE-backed drops are recorded as residuals.
func (l *loop) dropLastCandidate(err error, fromCVE bool) bool {
	return l.shedCandidate(err, func(c *candState) bool { return !c.remedy && c.FromCVE == fromCVE })
}

// dropLastRemedy is the last resort: shedding a repair only makes sense once
// every candidate that might have depended on it is gone.
func (l *loop) dropLastRemedy(err error) bool {
	return l.shedCandidate(err, func(c *candState) bool { return c.remedy })
}

// shedCandidate drops exactly one eligible active candidate: preferably one
// whose module path is actually named in the failure (blame the culprit, not
// the last arrival), falling back to the most recently added. CVE-backed
// drops are recorded as residuals.
func (l *loop) shedCandidate(err error, eligible func(*candState) bool) bool {
	errText := err.Error()
	var victim *candState
	for i := len(l.cands) - 1; i >= 0; i-- {
		c := l.cands[i]
		if c.dropped || !eligible(c) {
			continue
		}
		if victim == nil {
			victim = c
		}
		if strings.Contains(errText, c.Module) {
			victim = c
			break
		}
	}
	if victim == nil {
		return false
	}

	l.drop(victim, fmt.Sprintf("removed to restore resolvability: %v", err))
	if victim.FromCVE {
		victim.residualized = true
		l.persistentResiduals = append(l.persistentResiduals, Residual{
			Module:       victim.Module,
			FixedVersion: victim.Version,
			VulnIDs:      victim.VulnIDs,
			Reason:       fmt.Sprintf("fix breaks module graph: %v", err),
		})
	}
	return true
}

// getSatisfied reports whether the current go.mod already requires the
// candidate's module STRICTLY above the requested version, in which case the
// `go get` must be skipped (exact melange-gobump parity: such entries are
// warn-skipped at build time too). Equal versions still get - that keeps
// no-op seeds on their existing baseline-drop path. Fails open (get anyway)
// when go.mod cannot be read.
func (l *loop) getSatisfied(ctx context.Context, c *candState) bool {
	requirements, err := l.tc.Requirements(ctx, l.dir)
	if err != nil {
		logging.From(ctx).Debug("go.mod requirements unavailable during apply - not skipping",
			"modroot", l.req.Modroot, "module", c.Module, "error", err)
		return false
	}
	required, ok := requirements[c.Module]
	return ok && semver.Compare(required, c.Version) > 0
}

// handleGetFailure implements the repair-then-sacrifice policy for a failed
// fetch of one candidate: an ambiguous-import failure is repaired without
// penalizing the candidate; otherwise a coherence-only candidate is dropped
// outright and a CVE-backed one steps down one fix rung (see stepDown).
func (l *loop) handleGetFailure(ctx context.Context, c *candState, err error) {
	if l.addAmbiguityRemedies(ctx, err) {
		return
	}
	if !c.FromCVE {
		l.drop(c, fmt.Sprintf("unresolvable: %v", err))
		return
	}
	l.stepDown(ctx, c, fmt.Sprintf("fix unresolvable: %v", err))
}

// stepDown moves CVE candidate c, whose current version cannot be fetched,
// to its next lower fix rung still above the baseline, giving up the
// advisories only the rejected rungs fix (recorded as residuals with
// reason); with no rung left it is dropped and every advisory it addressed
// becomes a residual. c never raises to the rejected version again.
func (l *loop) stepDown(ctx context.Context, c *candState, reason string) {
	rejected := c.Version
	if c.ceiling == "" || semver.Compare(rejected, c.ceiling) < 0 {
		c.ceiling = rejected
	}
	var below []Rung
	for _, r := range c.fixRungs() {
		if semver.Compare(r.Version, rejected) < 0 && semver.Compare(r.Version, l.req.Baseline[c.Module]) > 0 {
			below = append(below, r)
		}
	}
	if len(below) == 0 {
		l.drop(c, reason)
		c.residualized = true
		l.persistentResiduals = append(l.persistentResiduals, Residual{
			Module:       c.Module,
			FixedVersion: rejected,
			VulnIDs:      c.VulnIDs,
			Reason:       reason,
		})
		return
	}
	var kept []string
	severity := ""
	for _, r := range below {
		kept = mergeIDs(kept, r.VulnIDs)
		severity = mergeSeverity(severity, r.Severity)
	}
	lost := slices.DeleteFunc(slices.Clone(c.VulnIDs), func(id string) bool { return slices.Contains(kept, id) })
	if len(lost) > 0 {
		l.persistentResiduals = append(l.persistentResiduals, Residual{
			Module:       c.Module,
			FixedVersion: rejected,
			VulnIDs:      lost,
			Reason:       reason,
		})
	}
	c.Version, c.Rungs, c.VulnIDs, c.Severity = below[0].Version, below, kept, severity
	c.FromCVE = len(kept) > 0
	logging.From(ctx).Info("fix unresolvable: stepped down one fix rung", "modroot", l.req.Modroot,
		"module", c.Module, "from", rejected, "to", c.Version, "reason", reason)
}

// dropLatestRaise handles a final-tidy failure by removing a raised
// (non-seed, non-remedy) candidate - the likeliest culprit for a graph that
// resolves per-module but won't tidy. Returns false when no raise is left to
// sacrifice.
func (l *loop) dropLatestRaise(err error) bool {
	return l.shedCandidate(err, func(c *candState) bool { return !c.seed && !c.remedy })
}

// refreshLinked recomputes the artifact-linked module and package sets for
// the current go.mod state. Recomputed every sustain pass rather than once:
// membership can drift as versions move (a raised module can import new
// modules - the genproto-split family is exactly this shape). Failure fails
// OPEN: both sets become nil and no reachability filtering happens (warned
// once per loop).
func (l *loop) refreshLinked(ctx context.Context) {
	linked, linkedPackages, err := l.tc.Linked(ctx, l.dir, l.buildPatterns, l.req.Tags)
	if err != nil {
		if !l.linkedWarned {
			logging.From(ctx).Warn("artifact reachability unavailable - not filtering",
				"modroot", l.req.Modroot, "packages", strings.Join(l.buildPatterns, " "), "error", err)
			l.linkedWarned = true
		}
		l.linked, l.linkedPackages = nil, nil
		return
	}
	l.linked, l.linkedPackages = linked, linkedPackages
}

// maxDepGoVersion computes the highest go directive across the current
// resolved build list's non-main modules. Fail-open: a toolchain error is
// logged and an empty string returned - never fails the simulation.
func (l *loop) maxDepGoVersion(ctx context.Context) string {
	versions, err := l.tc.DepGoVersions(ctx, l.dir)
	if err != nil {
		logging.From(ctx).Warn("dependency go directive lookup unavailable", "modroot", l.req.Modroot, "error", err)
		return ""
	}
	vs := make([]string, 0, len(versions))
	for _, v := range versions {
		vs = append(vs, v)
	}
	return goversion.Max(vs...)
}

// linkedStdPackages computes the stdlib slice of the current artifact import
// graph. Fail-open: a toolchain error is logged and nil returned.
func (l *loop) linkedStdPackages(ctx context.Context) map[string]struct{} {
	std, err := l.tc.LinkedStd(ctx, l.dir, l.buildPatterns, l.req.Tags)
	if err != nil {
		if !l.linkedStdWarned {
			logging.From(ctx).Warn("linked stdlib package lookup unavailable",
				"modroot", l.req.Modroot, "packages", strings.Join(l.buildPatterns, " "), "error", err)
			l.linkedStdWarned = true
		}
		return nil
	}
	return std
}

// isLinked reports whether module is linked into a build artifact; unknown
// reachability (linked == nil) counts every module as linked (fail open).
func (l *loop) isLinked(module string) bool {
	if l.linked == nil {
		return true
	}
	_, ok := l.linked[module]
	return ok
}

// tidiedGoModern reports whether the current on-disk go.mod's go directive is
// >= 1.17 - the module graph pruning threshold at which `go mod tidy` records
// every module providing a package in the main module's import closure
// (tests included) in the require block. Mirrors GoToolchain.Requirements'
// read/parse. Any read or parse error fails open (false, disabling the
// degraded signal) - a pre-tidy or malformed go.mod must never be trusted as
// the tidied contract.
func (l *loop) tidiedGoModern() bool {
	path := filepath.Join(l.dir, "go.mod")
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	modFile, err := modfile.ParseLax(path, content, nil)
	if err != nil {
		return false
	}
	return modFile.Go != nil && goversion.Compare(modFile.Go.Version, "1.17") >= 0
}

// degradedUnlinked reports whether module is PROVABLY absent from build
// artifacts under the degraded module-level signal: precise reachability is
// unknown (l.linked == nil), the tidied go.mod's go directive is >= 1.17
// (its require block covers every module providing a package in the main
// module's import closure, tests included), and the module has no require
// entry under any replace identity. linked => imported => required, so this
// can never shed a real fix. Module-granular only - no package-level detail.
func (l *loop) degradedUnlinked(module string, requirements map[string]string, replaces map[string]ReplaceTarget) bool {
	if l.linked != nil || !l.tidiedModern || len(requirements) == 0 {
		return false
	}
	if _, ok := requirements[module]; ok {
		return false
	}
	// Replace-resolved identities: resolved/scan coordinates are the
	// replacement path, the require block names the replaced path. Any
	// replace involvement fails open (conservative).
	if _, ok := replaces[module]; ok {
		return false
	}
	for old, target := range replaces {
		if target.Path == module {
			if _, ok := requirements[old]; ok {
				return false
			}
		}
	}
	return true
}

// unrequiredModules computes the degraded module-level reachability signal
// (see degradedUnlinked) for the given resolved graph: nil unless precise
// reachability is unavailable AND the tidied go.mod qualifies, else the set
// of resolved modules degradedUnlinked proves absent from build artifacts.
func (l *loop) unrequiredModules(resolved map[string]string) map[string]struct{} {
	if l.linked != nil || !l.tidiedModern {
		return nil
	}
	unrequired := make(map[string]struct{})
	for module := range resolved {
		if l.degradedUnlinked(module, l.requirements, l.replaces) {
			unrequired[module] = struct{}{}
		}
	}
	return unrequired
}

// scanTargets renders the resolved graph as OSV queries, restricted to
// modules linked into a build artifact - findings in unlinked modules can't
// affect anything that ships, and pre-filtering here (rather than
// partitioning findings afterwards) keeps scanFindings two-way and cuts both
// querybatch volume and per-finding detail fetches on every iteration. When
// precise reachability is unavailable, the degraded module-level signal
// (degradedUnlinked) still excludes modules PROVABLY absent from the require
// block - requirements/replaces are passed explicitly so a trial scan
// (trialApply) filters against the trial's own state, not the loop's.
func (l *loop) scanTargets(resolved map[string]string, requirements map[string]string, replaces map[string]ReplaceTarget) []scan.Package {
	filtered := make(map[string]string, len(resolved))
	for module, version := range resolved {
		if l.isLinked(module) && !l.degradedUnlinked(module, requirements, replaces) {
			filtered[module] = version
		}
	}
	return packagesFor(filtered)
}

// dropUnreachable sheds every active candidate - seeds included, which is
// what prunes already-declared YAML deps - whose module is not linked into
// any build artifact, or (for CVE-backed candidates with known advisory
// import metadata) whose advisories' vulnerable packages are all outside
// the artifact's import graph even though the module is linked (e.g.
// x/sys/windows in a module linked via x/sys/unix). An unlinked module's
// replace directive is equally inert in the artifact, so replace seeds are
// shed too (the one exception to "seed replaces are user intent, never
// shed"). Unlike every other CVE-backed drop, NO residual is recorded: the
// advisory affects nothing that ships, so the fix is neither applied nor
// outstanding (the orchestrator reports such advisories separately, as
// info). Returns true when anything was shed.
func (l *loop) dropUnreachable() bool {
	if l.linked == nil {
		return false
	}
	changed := false
	for _, c := range l.activeCandidates() {
		var reason string
		switch {
		case !l.isLinked(c.Module):
			reason = fmt.Sprintf("module not linked into build artifacts (packages: %s)", strings.Join(l.buildPatterns, " "))
		case c.FromCVE && !l.seedVulnPackagesLinked(c.VulnIDs):
			reason = "vulnerable package(s) not linked into build artifacts"
		default:
			continue
		}
		// Deliberately residual-free: the advisory affects nothing that
		// ships (the orchestrator reports it separately, as info). Marked
		// residualized so the rescan backfill never resurrects it.
		l.drop(c, reason)
		c.residualized = true
		changed = true
	}
	return changed
}

// seedVulnPackagesLinked reports whether any of the given seed advisories'
// vulnerable packages (threaded in via ModrootRequest.VulnImports) is in the
// artifact's import graph. Fail open everywhere data is missing: unknown
// package graph, no IDs, an ID without import metadata, or a pathless entry
// all count as linked.
func (l *loop) seedVulnPackagesLinked(vulnIDs []string) bool {
	if l.linkedPackages == nil || len(vulnIDs) == 0 {
		return true
	}
	for _, id := range vulnIDs {
		paths, known := l.req.VulnImports[id]
		if !known || len(paths) == 0 {
			return true
		}
		for _, path := range paths {
			if path == "" {
				return true
			}
			if _, linked := l.linkedPackages[path]; linked {
				return true
			}
		}
	}
	return false
}

// vulnApplies reports whether a rescan finding's vulnerable packages (from
// its own OSV metadata) intersect the artifact's import graph. Fail open
// when either side is unknown.
func (l *loop) vulnApplies(v scan.Vulnerability) bool {
	if l.linkedPackages == nil || len(v.VulnerableImports) == 0 {
		return true
	}
	for _, imp := range v.VulnerableImports {
		if imp.Path == "" {
			return true
		}
		if _, linked := l.linkedPackages[imp.Path]; linked {
			return true
		}
	}
	return false
}

// dropUnsustained sheds candidates the tidied go.mod does not sustain:
// melange's gobump errors when a requested package is missing from the
// post-tidy go.mod ("was not found on the go.mod file") or is required at a
// version below the requested one ("is less than the desired version").
// Returns true when anything changed (the apply must then be redone).
func (l *loop) dropUnsustained() bool {
	changed := false
	for _, c := range l.activeCandidates() {
		if c.Replace {
			if l.checkReplaceCandidate(c) {
				changed = true
			}
			continue
		}

		requiredVersion, required := l.requirements[c.Module]
		switch {
		case !required:
			// Pruned outright: nothing in the tidied build graph needs the
			// module. NOT residualized: the module can still be in the
			// resolved graph at a vulnerable version (another candidate
			// dragged it back down) - the rescan backfill in processScan
			// decides whether the advisory actually persists.
			l.drop(c, "pruned by go mod tidy: not required by the tidied go.mod")
			changed = true
		case semver.Compare(requiredVersion, c.Version) < 0:
			l.drop(c, fmt.Sprintf("go mod tidy reverts the pin to %s", requiredVersion))
			if c.FromCVE {
				c.residualized = true
				l.persistentResiduals = append(l.persistentResiduals, Residual{
					Module:          c.Module,
					ResolvedVersion: requiredVersion,
					FixedVersion:    c.Version,
					VulnIDs:         c.VulnIDs,
					Reason:          fmt.Sprintf("fix not sustained: go mod tidy reverts the pin to %s", requiredVersion),
				})
			}
			changed = true
		}
	}
	return changed
}

// checkReplaceCandidate verifies a (user-authored) replace candidate against
// the tidied go.mod: the directive must be present at >= the requested
// version (always true after a clean apply - defensively shed otherwise).
// Returns true when the candidate was shed.
func (l *loop) checkReplaceCandidate(c *candState) bool {
	target, present := l.replaces[c.OldPath()]
	if present && target.Path == c.Module && semver.Compare(target.Version, c.Version) >= 0 {
		return false
	}
	l.drop(c, "replace directive not sustained by the tidied go.mod")
	if c.FromCVE {
		c.residualized = true
		l.persistentResiduals = append(l.persistentResiduals, Residual{
			Module:       c.Module,
			FixedVersion: c.Version,
			VulnIDs:      c.VulnIDs,
			Reason:       "fix not sustained: replace directive lost during tidy",
		})
	}
	return true
}

// processScan converts a rescan of the resolved graph into raised candidates
// and recomputed scan residuals. It returns the raises applied this round.
func (l *loop) processScan(ctx context.Context, scanResult *scan.ScanResult, resolved map[string]string) []raise {
	raises, residuals := l.scanFindings(scanResult, resolved)
	l.scanResiduals = residuals

	l.lastRaised = l.lastRaised[:0]
	applied := make([]raise, 0, len(raises))
	for _, r := range raises {
		if existing, ok := l.byModule[r.module]; ok && existing.dropped {
			if existing.FromCVE {
				if !existing.residualized {
					if l.degradedUnlinked(r.module, l.requirements, l.replaces) {
						// Mirror dropUnreachable's deliberately residual-free
						// policy: the module cannot be linked, so the
						// advisory affects nothing that ships (the
						// orchestrator reports it separately, as info).
						logging.From(ctx).Info("advisory persists only in a module not required by the tidied go.mod - cannot be linked; not residual",
							"modroot", l.req.Modroot, "module", r.module, "vulns", strings.Join(r.vulnIDs, ","))
						continue
					}
					// The drop assumed no code shipped, but the advisory is
					// still present in the resolved graph (e.g. another
					// candidate dragged the module back down). Surface it
					// rather than letting it vanish; recomputed each rescan,
					// so it clears if a later graph genuinely fixes it.
					l.scanResiduals = append(l.scanResiduals, Residual{
						Module:          r.module,
						ResolvedVersion: resolved[r.module],
						FixedVersion:    r.version,
						VulnIDs:         r.vulnIDs,
						Reason: fmt.Sprintf("fix abandoned (%s) but advisory persists at %s",
							existing.dropReason, resolved[r.module]),
					})
					continue
				}
				// Already proven unresolvable - the residual stands.
				continue
			}
			// Dropped as a coherence hint; a CVE now demands it, so try
			// again as a defended candidate.
			delete(l.byModule, r.module)
		}
		if existing, ok := l.byModule[r.module]; ok && (semver.Compare(r.version, existing.Version) <= 0 ||
			(existing.ceiling != "" && semver.Compare(r.version, existing.ceiling) >= 0)) {
			// Already at or above the requested fix (a rescan should not
			// produce this - it scans the resolved graph - but guard against
			// loops), or at/above a version that could not be fetched (its
			// residual stands; see stepDown).
			continue
		}
		candidate := Candidate{
			Module:   r.module,
			Version:  r.version,
			FromCVE:  true,
			VulnIDs:  r.vulnIDs,
			Severity: r.severity,
			Rungs:    r.rungs,
		}
		// A raise for a module a user-authored replace pins must update that
		// replace - a plain `go get` cannot out-vote the directive. The scan
		// reports the replacement path, so identity already matches the
		// replace candidate's target. (Upstream-pinned modules never get
		// here: scanFindings holds them back.)
		if existing, ok := l.byModule[r.module]; ok && !existing.dropped && existing.Replace {
			candidate.Replace, candidate.ReplaceOld = true, existing.ReplaceOld
		}
		state := l.addCandidate(candidate, false)
		l.lastRaised = append(l.lastRaised, state)
		applied = append(applied, r)
	}
	return applied
}

// upstreamHoldBack returns the replaced path when the upstream go.mod
// replace-pins module (either side of the directive) to a module version and
// no user-authored replace candidate takes it over, "" otherwise.
func (l *loop) upstreamHoldBack(module string) string {
	if c, ok := l.byModule[module]; ok && !c.dropped && c.Replace {
		return ""
	}
	if oldPath, target, pinned := l.pristinePinFor(module); pinned && target.Version != "" {
		return oldPath
	}
	return ""
}

// scanFindings classifies a scan of the resolved graph without mutating loop
// state: advisories whose fix can be applied become raises; the rest become
// residuals (no released fix, a fix across a major version that a deps entry
// cannot express, or a module the upstream go.mod replace-pins).
func (l *loop) scanFindings(scanResult *scan.ScanResult, resolved map[string]string) ([]raise, []Residual) {
	// Package-level applicability: a finding whose vulnerable packages are
	// all outside the artifact's import graph is neither raised nor a
	// residual (the orchestrator reports it as info from the analysis scan).
	applies := make(map[string]bool, len(scanResult.Vulnerabilities))
	for _, vuln := range scanResult.Vulnerabilities {
		applies[vuln.ID] = l.vulnApplies(vuln)
	}
	anyApplies := func(vulnIDs []string) bool {
		if len(vulnIDs) == 0 {
			return true // no per-vuln data - fail open
		}
		for _, id := range vulnIDs {
			if applicable, known := applies[id]; !known || applicable {
				return true
			}
		}
		return false
	}

	noFixByModule := make(map[string]*Residual)
	for _, vuln := range scanResult.Vulnerabilities {
		if vuln.FixedVersion != "" || !applies[vuln.ID] {
			continue
		}
		if existing, ok := noFixByModule[vuln.Module]; ok {
			existing.VulnIDs = mergeIDs(existing.VulnIDs, []string{vuln.ID})
			continue
		}
		noFixByModule[vuln.Module] = &Residual{
			Module:          vuln.Module,
			ResolvedVersion: resolved[vuln.Module],
			VulnIDs:         []string{vuln.ID},
			Reason:          "no released fix",
		}
	}

	var raises []raise
	var residuals []Residual
	for _, r := range noFixByModule {
		residuals = append(residuals, *r)
	}

	for _, bump := range scanResult.SecurityBumps {
		if !anyApplies(bump.VulnIDs) {
			continue
		}
		resolvedVersion := resolved[bump.Name]
		if resolvedVersion != "" && semver.Compare(bump.FixedVersion, resolvedVersion) <= 0 {
			continue
		}
		reason := ""
		if majorChange(bump.Name, bump.FixedVersion, resolvedVersion) {
			reason = fmt.Sprintf("fix requires a major version change (%s -> %s)", resolvedVersion, bump.FixedVersion)
		} else if oldPath := l.upstreamHoldBack(bump.Name); oldPath != "" {
			reason = holdBackReason(oldPath)
		}
		if reason != "" {
			residuals = append(residuals, Residual{
				Module:          bump.Name,
				ResolvedVersion: resolvedVersion,
				FixedVersion:    bump.FixedVersion,
				VulnIDs:         bump.VulnIDs,
				Reason:          reason,
			})
			continue
		}
		raises = append(raises, raise{module: bump.Name, version: bump.FixedVersion, vulnIDs: bump.VulnIDs, severity: bump.Severity,
			rungs: FixRungs(scanResult.Vulnerabilities, bump.Name, bump.VulnIDs)})
	}

	sort.Slice(raises, func(i, j int) bool { return raises[i].module < raises[j].module })
	return raises, residuals
}

// trialResult is the outcome of one restore -> apply(keep) -> rescan round.
type trialResult struct {
	resolved     map[string]string
	requirements map[string]string
	replaces     map[string]ReplaceTarget
	raises       []raise
	residuals    []Residual
}

// trialApply re-applies exactly the keep set from the pristine snapshot with
// the step's engine (see applyExact), refreshes reachability for the trial
// graph, rescans it, and classifies the findings. Single-shot: any failure rejects the trial (non-nil error) with
// no repair ladder. Reachability must be recomputed for the trial graph and
// its rescan filtered identically to the main loop's - otherwise
// introducesNewVulns would compare linked-filtered accepted residuals
// against an unfiltered candidate scan, see "new" unlinked advisories, and
// spuriously reject the trial. Callers snapshot l.linked/l.linkedPackages
// beforehand and restore them when rejecting.
func (l *loop) trialApply(ctx context.Context, purpose string, keep []*candState) (*trialResult, error) {
	if err := l.applyExact(ctx, keep); err != nil {
		if ierr := l.recordInfra(err); ierr != nil {
			return nil, ierr
		}
		l.logTrial(ctx, trialLog{purpose: purpose, pins: keep, reject: err.Error()})
		return nil, err
	}

	tr := &trialResult{}
	var err error
	if tr.resolved, err = l.tc.ListModules(ctx, l.dir); err != nil {
		return nil, err
	}
	if tr.requirements, err = l.tc.Requirements(ctx, l.dir); err != nil {
		return nil, err
	}
	if tr.replaces, err = l.tc.Replaces(ctx, l.dir); err != nil {
		return nil, err
	}
	l.refreshLinked(ctx)

	scanResult, err := l.sc.ScanPackages(ctx, l.scanTargets(tr.resolved, tr.requirements, tr.replaces))
	if err != nil {
		return nil, err
	}
	tr.raises, tr.residuals = l.scanFindings(scanResult, tr.resolved)
	l.logTrial(ctx, trialLog{purpose: purpose, pins: keep, resolved: tr.resolved, raises: tr.raises, residuals: len(tr.residuals)})
	return tr, nil
}

// applyExact re-applies exactly the keep set from the pristine snapshot with
// the step's engine, in keep's order. Single-shot: any failure (including
// omnibump's post-tidy verification) is returned with no repair ladder.
func (l *loop) applyExact(ctx context.Context, keep []*candState) error {
	if fail := l.engine.apply(ctx, keep); fail != nil {
		return fail.err
	}
	return nil
}

// sustained verifies every keep candidate against the trial's tidied state:
// a replace directive must be present at >= its version, a deps pin must be
// required at >= its version - the contract melange's gobump verifies.
func (l *loop) sustained(tr *trialResult, keep []*candState) bool {
	for _, c := range keep {
		if c.Replace {
			target, present := tr.replaces[c.OldPath()]
			if !present || target.Path != c.Module || semver.Compare(target.Version, c.Version) < 0 {
				return false
			}
			continue
		}
		requiredVersion, required := tr.requirements[c.Module]
		if !required || semver.Compare(requiredVersion, c.Version) < 0 {
			return false
		}
	}
	return true
}

// adoptTrial commits a trial as the loop's accepted state. Disk ==
// tr.resolved at this instant (nothing here mutates go.mod/go.sum), so this
// is the same "checkout matches the graph being reported" guarantee the
// caller relied on for the full-set computation. Both capability fields are
// refreshed against the adopted graph: MaxDepGoVersion could only have gone
// down, but StdPackages may have picked up stdlib packages an older pinned
// version touches that the newer full-set version never did (see the doc
// comment in RunLoop). A fail-open zero value here (toolchain error) means
// "unknown", not "empty" - keep the existing superset value in that case
// rather than clobbering a correct wider set with nothing; an
// over-approximation beats an unvalidated miss on a stdlib-CVE check.
func (l *loop) adoptTrial(ctx context.Context, tr *trialResult, result *ModrootResult) {
	l.scanResiduals = tr.residuals
	l.requirements = tr.requirements
	l.replaces = tr.replaces
	if maxGo := l.maxDepGoVersion(ctx); maxGo != "" {
		result.MaxDepGoVersion = maxGo
	}
	if std := l.linkedStdPackages(ctx); std != nil {
		result.StdPackages = std
	}
}

// confirmMinimalSet checks whether the CVE-backed candidates alone reach a
// clean state: pins no advisory backs (existing YAML hints, raises) are
// shed when nothing needs them - this may change the graph, unlike the
// effect-based redundancy check (see minimise); the compile gate re-adds any
// a build turns out to need. Adopts the smaller set when the
// confirmation apply succeeds and its rescan demands no further raises and
// no new residual advisories; otherwise keeps the converged full set.
// result's MaxDepGoVersion/StdPackages - set by the caller from the
// converged full set - are refreshed in place on adoption (see adoptTrial).
// Only an infrastructure failure or a cancellation is returned as an error.
func (l *loop) confirmMinimalSet(ctx context.Context, resolved map[string]string, result *ModrootResult) (map[string]string, error) {
	// Essential candidates: CVE-backed fixes, remedies (they keep the graph
	// resolvable at all), and user-authored replaces (load-bearing fork
	// redirects - never dropped as redundant).
	active := l.activeCandidates()
	essential := make([]*candState, 0, len(active))
	isEssential := func(c *candState) bool { return c.FromCVE || c.remedy || c.Replace }
	for _, c := range active {
		if isEssential(c) {
			essential = append(essential, c)
		}
	}
	if len(essential) == len(active) {
		return resolved, nil
	}

	convergedLinked, convergedPackages := l.linked, l.linkedPackages
	tr, err := l.trialApply(ctx, "refine: minimal set", essential)
	if err != nil && (errors.Is(err, ErrInfrastructure) || ctx.Err() != nil) {
		return nil, err
	}
	if err != nil || len(tr.raises) > 0 ||
		introducesNewVulns(tr.residuals, l.scanResiduals) || !l.sustained(tr, essential) {
		l.linked, l.linkedPackages = convergedLinked, convergedPackages
		return resolved, nil
	}

	for _, c := range active {
		if isEssential(c) {
			continue
		}
		l.drop(c, "not needed: no advisory depends on it and the advisory-backed set resolves cleanly without it")
	}
	l.adoptTrial(ctx, tr, result)
	return tr.resolved, nil
}

// goModState is the effect of a pin set: the go.mod the step's engine leaves
// behind - require (path -> version, `// indirect` ignored) and replace
// directives, plus the go/toolchain lines - and, for go < 1.17 modules
// (whose require block does not pin the whole build list), the resolved
// build list.
type goModState struct {
	requires map[string]string
	replaces map[string]ReplaceTarget
	goLines  string
	graph    map[string]string
}

func (s *goModState) equal(o *goModState) bool {
	return maps.Equal(s.requires, o.requires) && maps.Equal(s.replaces, o.replaces) &&
		s.goLines == o.goLines && maps.Equal(s.graph, o.graph)
}

// finalState applies pins with the step's engine (its own tidy mode: no tidy
// at all for `tidy: false`) and reads the resulting go.mod. go.mod is read
// before any go list runs, so nothing but the engine has touched it. ok is
// false when the apply fails - the set is then not equivalent to anything.
func (l *loop) finalState(ctx context.Context, pins []*candState) (st *goModState, ok bool, err error) {
	if fail := l.engine.apply(ctx, l.inApplyOrder(pins)); fail != nil {
		if ierr := l.recordInfra(fail.err); ierr != nil {
			return nil, false, ierr
		}
		return nil, false, ctx.Err()
	}
	st = &goModState{}
	if st.requires, err = l.tc.Requirements(ctx, l.dir); err != nil {
		return nil, false, err
	}
	if st.replaces, err = l.tc.Replaces(ctx, l.dir); err != nil {
		return nil, false, err
	}
	if content, rerr := os.ReadFile(filepath.Join(l.dir, "go.mod")); rerr == nil {
		if f, perr := modfile.ParseLax("go.mod", content, nil); perr == nil {
			if f.Go != nil {
				st.goLines = f.Go.Version
			}
			if f.Toolchain != nil {
				st.goLines += " " + f.Toolchain.Name
			}
		}
	}
	if !l.tidiedGoModern() {
		if st.graph, err = l.tc.ListModules(ctx, l.dir); err != nil {
			return nil, false, err
		}
	}
	return st, true, nil
}

// minimise removes every redundant entry from the final set (design
// principle 2): first those that match or regress the upstream go.mod (no
// trial needed), then, one at a time, every entry whose removal leaves the
// final go.mod unchanged - re-checked after each removal, so of two entries
// that imply each other exactly one survives. Derived entries (no advisory)
// go first, then advisory-backed ones from the least severe; ties by module
// path, so the outcome is deterministic and a second run removes nothing.
// User-authored replaces are kept, except a self-replace (old == new) at or
// below the module's baseline-resolved version: it pins nothing upstream
// does not already select. When the simulation budget runs low the remaining
// entries are kept (correct, merely not minimal); only a cancellation or an
// infrastructure failure is returned as an error. The checkout is left
// holding the final set.
func (l *loop) minimise(ctx context.Context) error {
	var set, order []*candState
	for _, c := range l.activeCandidates() {
		switch {
		case c.Replace:
			if base := l.baselineVersion(c.Module); c.OldPath() == c.Module && semver.IsValid(base) &&
				semver.Compare(c.Version, base) <= 0 {
				l.dropRedundant(ctx, c, "self-replace at or below the baseline-resolved "+base)
				continue
			}
		default:
			if why := l.engine.upstreamSkip(c); why != "" {
				l.dropRedundant(ctx, c, "matches or regresses upstream go.mod ("+why+")")
				continue
			}
			order = append(order, c)
		}
		set = append(set, c)
	}
	if len(order) == 0 {
		return nil
	}
	slices.SortFunc(order, func(a, b *candState) int {
		if a.FromCVE != b.FromCVE {
			if a.FromCVE {
				return 1
			}
			return -1
		}
		if ra, rb := scan.SeverityRank(a.Severity), scan.SeverityRank(b.Severity); a.FromCVE && ra != rb {
			return rb - ra
		}
		return strings.Compare(a.Module, b.Module)
	})

	// settle leaves the checkout holding the final set, as the build's bump
	// step will: a later modroot of the same clone may depend on this one
	// (e.g. through a local replace), so a trial's state must not linger.
	settle := func() error {
		if fail := l.engine.apply(ctx, l.inApplyOrder(set)); fail != nil && errors.Is(ctx.Err(), context.Canceled) {
			return ctx.Err()
		}
		return nil
	}
	stop := func(err error, why string) error {
		if errors.Is(ctx.Err(), context.Canceled) {
			return ctx.Err()
		}
		if errors.Is(err, ErrInfrastructure) {
			return err
		}
		logging.From(ctx).Info("redundancy check stopped; keeping the remaining entries",
			"modroot", l.req.Modroot, "reason", why, "error", err)
		return settle()
	}
	start := time.Now()
	ref, ok, err := l.finalState(ctx, set)
	if err != nil || !ok {
		return stop(err, "the final set no longer applies")
	}
	cost := time.Since(start)
	// Necessary condition, from the final graph's requirement edges: an
	// entry for a module upstream already requires can only be implied when
	// some other selected module requires it at >= its version (tidy never
	// re-resolves an existing requirement; a module new to go.mod, by
	// contrast, may be re-added at @latest for a main-module import).
	// Unknown edges (no lister, or it failed) trial everything.
	var requiredBy map[string]map[string]string
	if g, ok := l.tc.(interface {
		RequiredBy(ctx context.Context, dir string) (map[string]map[string]string, error)
	}); ok {
		if requiredBy, err = g.RequiredBy(ctx, l.dir); err != nil {
			requiredBy = nil
		}
	}
	for _, c := range order {
		requirers := l.requirers(requiredBy, c, set)
		if _, upstream := l.req.Baseline[c.Module]; upstream && requiredBy != nil &&
			semver.IsValid(c.Version) && len(requirers) == 0 {
			continue
		}
		if dl, has := ctx.Deadline(); has && time.Until(dl) < 2*cost {
			return stop(nil, "simulation budget nearly exhausted")
		}
		without := slices.DeleteFunc(slices.Clone(set), func(p *candState) bool { return p == c })
		start := time.Now()
		st, ok, err := l.finalState(ctx, without)
		cost = max(cost, time.Since(start))
		if err != nil || ctx.Err() != nil {
			return stop(err, "trial interrupted")
		}
		if !ok || !st.equal(ref) {
			continue
		}
		set = without
		implied := "the remaining pins"
		if len(requirers) > 0 {
			implied = strings.Join(requirers, ", ")
		}
		l.dropRedundant(ctx, c, "implied by "+implied+" (final go.mod unchanged without it)")
	}
	return settle()
}

// baselineVersion is module's version in the pristine graph: the compile
// gate's tidied baseline when known, else the caller's go.mod view.
func (l *loop) baselineVersion(module string) string {
	if v, ok := l.baselineResolved[module]; ok {
		return v
	}
	return l.req.Baseline[module]
}

// requirers names the selected modules requiring c's module at >= c's
// version: the pins among them ("module@version"), else the others.
func (l *loop) requirers(requiredBy map[string]map[string]string, c *candState, set []*candState) []string {
	var pins, others []string
	for _, from := range sortedKeys(requiredBy[c.Module]) {
		if from == c.Module || semver.Compare(requiredBy[c.Module][from], c.Version) < 0 {
			continue
		}
		if p := slices.IndexFunc(set, func(p *candState) bool { return p.Module == from && p != c }); p >= 0 {
			pins = append(pins, from+"@"+set[p].Version)
		} else {
			others = append(others, from)
		}
	}
	if len(pins) > 0 {
		return pins
	}
	return others
}

// dropRedundant drops c as redundant: it did no work, so its advisories (if
// any) are exactly as fixed without it - no residual.
func (l *loop) dropRedundant(ctx context.Context, c *candState, why string) {
	l.drop(c, "redundant: "+why)
	l.dropped[len(l.dropped)-1].Redundant = true
	c.residualized = true
	logging.From(ctx).Debug("redundant entry removed", "modroot", l.req.Modroot,
		"module", c.Module, "version", c.Version, "reason", why)
}

// finalOutputs renders the surviving candidates: deps entries
// (module@version), replace entries (old=new@version, gobump grammar), and
// the modules among them that address at least one advisory. Redundant
// entries are already gone (see minimise); a deps entry the final tidy pruned is dropped
// here because gobump rejects it at build time.
//
// Entries are rendered in apply order (see inApplyOrder), not insertion
// order: the build's bump step applies the written list in order, so an
// ambiguous-import remedy must precede the split-module entry it unblocks,
// exactly as the simulation applied it.
func (l *loop) finalOutputs(resolved map[string]string) ([]string, []string, []string) {
	var deps []string
	var replaces []string
	var cveModules []string
	for _, c := range l.inApplyOrder(l.activeCandidates()) {
		if c.Replace {
			replaces = append(replaces, fmt.Sprintf("%s=%s@%s", c.OldPath(), c.Module, c.Version))
			if c.FromCVE {
				cveModules = append(cveModules, c.Module)
			}
			continue
		}

		if _, required := l.requirements[c.Module]; !required {
			// The final go mod tidy pruned this module from go.mod - and
			// melange's gobump go-gets an absent deps entry, then warns and
			// skips it once the final tidy prunes it back out (with Tidy on;
			// off, it hard-errors with ErrPackageNotFound instead). Writing
			// it is at best a churn-prone no-op, so drop it here too.
			l.drop(c, "pruned by go mod tidy: not required by the tidied go.mod")
			if c.FromCVE && resolved[c.Module] != "" && semver.Compare(resolved[c.Module], c.Version) < 0 {
				// Defensive: this runs after the last rescan, so the
				// processScan backfill can no longer catch it. A CVE entry
				// pruned here while its module still resolves below the fix
				// must not vanish silently.
				c.residualized = true
				l.persistentResiduals = append(l.persistentResiduals, Residual{
					Module:          c.Module,
					ResolvedVersion: resolved[c.Module],
					FixedVersion:    c.Version,
					VulnIDs:         c.VulnIDs,
					Reason: fmt.Sprintf("fix entry pruned after final validation; module still resolves at %s",
						resolved[c.Module]),
				})
			}
			continue
		}
		deps = append(deps, c.Module+"@"+c.Version)
		if c.FromCVE {
			cveModules = append(cveModules, c.Module)
		}
	}
	return deps, replaces, cveModules
}

// Compile-gate bounds: repair rounds per pin set (each repairs every newly
// failing module at most once more) and versions inspected per module walk.
const (
	maxRepairRounds  = 3
	maxCoherenceWalk = 40
)

// ErrCompileGate marks a simulation the compile gate could not finish
// (baseline unavailable, tool failure, budget exhausted, or a build that
// fails with every bump relaxed). Callers must fail closed: the candidate
// set was never proven to compile, so it must not be written.
var ErrCompileGate = errors.New("compile gate failed")

// gateErr wraps a compile-gate failure in ErrCompileGate, except that a
// cancellation propagates as itself (it is not a gate verdict).
func gateErr(ctx context.Context, err error) error {
	if cerr := ctx.Err(); errors.Is(cerr, context.Canceled) {
		return cerr
	}
	return fmt.Errorf("%w: %w", ErrCompileGate, err)
}

// trialOutcome is the outcome of one compile trial: a non-empty reject means
// the pins did not resolve/tidy; otherwise failures are the packages failing
// now but not at baseline.
type trialOutcome struct {
	reject   string
	report   *CompileReport
	resolved map[string]string
	failures map[string][]string
}

func (o *trialOutcome) passed() bool { return o.reject == "" && len(o.failures) == 0 }

// why renders the outcome's failure as a drop/residual reason.
func (o *trialOutcome) why() string {
	if o.reject != "" {
		return "breaks module graph: " + o.reject
	}
	return "breaks compile: " + firstCompileError(o.failures)
}

// compileBaseline compiles the pristine checkout once, after the initial
// tidy: packages that already fail there (missing C libraries, generated
// code, host-only noise) are excluded from every later verdict, so only
// failures a bump introduces count.
func (l *loop) compileBaseline(ctx context.Context) error {
	if err := l.engine.tidyBaseline(ctx); err != nil {
		return gateErr(ctx, fmt.Errorf("baseline go mod tidy: %w", err))
	}
	resolved, err := l.tc.ListModules(ctx, l.dir)
	if err != nil {
		return gateErr(ctx, err)
	}
	report, err := l.compiler.Compile(ctx, l.dir, l.buildPatterns, l.req.Tags)
	if err != nil {
		return gateErr(ctx, fmt.Errorf("baseline: %w", err))
	}
	l.baselineResolved = resolved
	l.baselineFailed = make(map[string]struct{}, len(report.Failed))
	for pkg := range report.Failed {
		l.baselineFailed[pkg] = struct{}{}
	}
	if len(report.Failed) > 0 {
		logging.From(ctx).Debug("compile gate baseline: packages already failing are excluded",
			"modroot", l.req.Modroot, "count", len(report.Failed), "first", firstCompileError(report.Failed))
	}
	return nil
}

// gateRun is the compile gate's search state: each candidate's fix ladder
// (see ladder) and the index of its active rung. Candidates themselves are
// never mutated until the accepted set is adopted.
type gateRun struct {
	ladders map[*candState][]Rung
	at      map[*candState]int
}

func (g *gateRun) rung(c *candState) Rung { return g.ladders[c][g.at[c]] }

// compileGate proves the final candidate set compiles, as a repair fixpoint
// with relaxation: trial every candidate at its active rung; on failure,
// add co-update repairs derived from that trial's failures and re-trial
// (see repairFixpoint); if it still fails, step the implicated candidate
// down one fix rung (see relaxTarget) - dropping it below its lowest rung -
// and start over with repairs recomputed from scratch. Each relaxation
// strictly lowers the pin set, so this terminates. The accepted set (pins
// plus the repairs of the passing trial) is adopted and rescanned; any
// advisory left unfixed by a relaxation becomes a residual carrying the
// rejected rung's failure. Errors are ErrCompileGate (or a cancellation):
// the caller must not trust the candidate set.
func (l *loop) compileGate(ctx context.Context, resolved map[string]string, result *ModrootResult) (map[string]string, error) {
	active := l.inApplyOrder(l.activeCandidates())
	if len(active) == 0 {
		return resolved, nil
	}
	g := &gateRun{ladders: make(map[*candState][]Rung, len(active)), at: make(map[*candState]int, len(active))}
	for _, c := range active {
		g.ladders[c] = l.ladder(c)
	}
	rejected := make(map[string]string) // module -> why its higher rung was rejected

	purpose, subject := "gate: converged set", ""
	for {
		live := slices.DeleteFunc(slices.Clone(active), func(c *candState) bool { return c.dropped })
		out, repairs, err := l.repairFixpoint(ctx, g, purpose, subject, live)
		if err != nil {
			return nil, err
		}
		if out.passed() {
			if len(rejected) == 0 && len(repairs) == 0 {
				logging.From(ctx).Debug("compile gate passed", "modroot", l.req.Modroot, "candidates", len(live))
				return resolved, nil
			}
			return l.gateAdopt(ctx, g, live, repairs, rejected, result)
		}
		if purpose == "gate: converged set" {
			logging.From(ctx).Info("compile gate: converged bump set breaks the build",
				"modroot", l.req.Modroot, "first", firstLine(out.why()))
		}

		victim := l.relaxTarget(ctx, g, out, live)
		if victim == nil {
			return nil, gateErr(ctx, fmt.Errorf("the build fails with every bump relaxed: %s", out.why()))
		}
		reason := out.why()
		rejected[victim.Module] = reason
		from := g.rung(victim).Version
		if g.at[victim]+1 < len(g.ladders[victim]) {
			g.at[victim]++
			logging.From(ctx).Info("compile gate: relaxed bump one fix rung", "modroot", l.req.Modroot,
				"module", victim.Module, "from", from, "to", g.rung(victim).Version, "reason", reason)
		} else {
			victim.Version = from
			l.drop(victim, reason)
			logging.From(ctx).Warn("compile gate rejected bump", "modroot", l.req.Modroot,
				"module", victim.Module, "version", from, "reason", reason)
		}
		purpose, subject = "gate: relaxed", victim.Module
	}
}

// ladder returns candidate c's target versions, highest first: its current
// version, then every lower fix rung still above the baseline-resolved
// version. Each rung carries the advisories first fixed there - what
// relaxing below it gives up. Ambiguity remedies have a single rung.
func (l *loop) ladder(c *candState) []Rung {
	top := Rung{Version: c.Version}
	if c.remedy {
		return []Rung{top}
	}
	var lower []Rung
	for _, r := range c.fixRungs() {
		switch cmp := semver.Compare(r.Version, c.Version); {
		case cmp == 0:
			top = r
		case cmp < 0 && semver.Compare(r.Version, l.baselineResolved[c.Module]) > 0:
			lower = append(lower, r)
		}
	}
	return append([]Rung{top}, lower...)
}

// repairFixpoint trials live at their active rungs and, while the trial
// fails to compile, adds the co-update repairs that trial's failures call
// for (see repairsFor) and re-trials, bounded by maxRepairRounds. Repairs
// are inputs of this pin set only: they are derived from its own failing
// trials and never carried over to another. Returns the last outcome that
// resolved and the repairs it was built with.
func (l *loop) repairFixpoint(ctx context.Context, g *gateRun, purpose, subject string, live []*candState) (*trialOutcome, map[string]string, error) {
	pins := l.trialPins(g, live, nil)
	out, err := l.trial(ctx, purpose, subject, pins)
	if err != nil {
		return nil, nil, err
	}
	var repairs map[string]string
	for range maxRepairRounds {
		if out.reject != "" || len(out.failures) == 0 {
			break
		}
		next, added, err := l.repairsFor(ctx, out, pins, repairs)
		if err != nil {
			return nil, nil, err
		}
		if !added {
			break
		}
		nextPins := l.trialPins(g, live, next)
		nextOut, err := l.trial(ctx, "gate: repair round", subject, nextPins)
		if err != nil {
			return nil, nil, err
		}
		if nextOut.reject != "" {
			break
		}
		out, repairs, pins = nextOut, next, nextPins
	}
	return out, repairs, nil
}

// trialPins materializes one trial's pin set as candidate snapshots: every
// live candidate at its active rung (raised in place when a repair targets
// its module), then the repairs for modules without a candidate. Snapshots
// keep trials stateless - nothing a trial does touches a live candidate.
func (l *loop) trialPins(g *gateRun, live []*candState, repairs map[string]string) []*candState {
	pins := make([]*candState, 0, len(live)+len(repairs))
	pinned := make(map[string]struct{}, len(live))
	for _, c := range live {
		pin := *c
		pin.Version = g.rung(c).Version
		if v, ok := repairs[c.Module]; ok && semver.Compare(v, pin.Version) > 0 {
			pin.Version = v
		}
		pins = append(pins, &pin)
		pinned[c.Module] = struct{}{}
	}
	for _, module := range sortedKeys(repairs) {
		if _, ok := pinned[module]; !ok {
			pins = append(pins, &candState{Candidate: Candidate{Module: module, Version: repairs[module]}, repair: true})
		}
	}
	return pins
}

// trial applies exactly pins from the pristine snapshot (see applyExact),
// lists the resolved graph and compiles it. It is stateless: the outcome is
// returned, nothing on the loop or the candidates changes. A resolve/tidy
// failure is a verdict (outcome.reject); an error means the gate cannot
// continue. purpose/subject only label the trial's debug record.
func (l *loop) trial(ctx context.Context, purpose, subject string, pins []*candState) (*trialOutcome, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if l.infraErr != nil {
		return nil, gateErr(ctx, l.infraErr)
	}
	if err := l.applyExact(ctx, pins); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, gateErr(ctx, cerr)
		}
		if ierr := l.recordInfra(err); ierr != nil {
			return nil, gateErr(ctx, ierr)
		}
		out := &trialOutcome{reject: firstLine(err.Error())}
		l.logTrial(ctx, trialLog{purpose: purpose, subject: subject, pins: pins, reject: out.reject})
		return out, nil
	}
	resolved, err := l.tc.ListModules(ctx, l.dir)
	if err != nil {
		return nil, gateErr(ctx, err)
	}
	report, err := l.compiler.Compile(ctx, l.dir, l.buildPatterns, l.req.Tags)
	if err != nil {
		return nil, gateErr(ctx, err)
	}
	out := &trialOutcome{report: report, resolved: resolved, failures: make(map[string][]string)}
	for pkg, lines := range report.Failed {
		if _, known := l.baselineFailed[pkg]; !known {
			out.failures[pkg] = lines
		}
	}
	l.logTrial(ctx, trialLog{purpose: purpose, subject: subject, pins: pins, resolved: resolved, compiled: out})
	return out, nil
}

// inApplyOrder orders a candidate subset for an engine apply: ambiguity
// remedies first (an ambiguous import blocks the get of the module that
// trips it, so the repair must land before that module is fetched), then
// candidates in the order they were added. Engines apply replace candidates
// before any get.
func (l *loop) inApplyOrder(keep []*candState) []*candState {
	include := make(map[*candState]struct{}, len(keep))
	for _, c := range keep {
		include[c] = struct{}{}
	}
	ordered := make([]*candState, 0, len(keep))
	for _, remedyPass := range []bool{true, false} {
		for _, c := range l.cands {
			if _, ok := include[c]; ok && c.remedy == remedyPass {
				ordered = append(ordered, c)
			}
		}
	}
	return ordered
}

// repairsFor derives co-update repairs from one failing trial: each failing
// package's module F that raised dependencies have outgrown (see
// outgrownDeps) is raised to the minimal same-major version built against
// them (see minCoherentVersion). A pinned F is raised in place - candidates
// and existing entries are floors, never skipped as "blamed" - except a
// replace or ambiguity-remedy pin, which is not a plain version pin.
// Returns prev merged with the new repairs, and whether anything was added.
func (l *loop) repairsFor(ctx context.Context, out *trialOutcome, pins []*candState, prev map[string]string) (map[string]string, bool, error) {
	repairs := maps.Clone(prev)
	if repairs == nil {
		repairs = make(map[string]string)
	}
	pinned := make(map[string]*candState, len(pins))
	for _, p := range pins {
		pinned[p.Module] = p
	}
	added := false
	for _, pkg := range sortedKeys(out.failures) {
		owner, outgrown := l.outgrownDeps(ctx, out, pkg)
		if len(outgrown) == 0 {
			continue
		}
		from := out.resolved[owner]
		if p, ok := pinned[owner]; ok && (p.Replace || p.remedy) {
			l.logRepair(ctx, repairLog{module: owner, from: from, outgrown: outgrown, skip: "owner is a replace or ambiguity-remedy pin"})
			continue
		}
		version, err := l.minCoherentVersion(ctx, owner, from, outgrown)
		if err != nil {
			return nil, false, gateErr(ctx, err)
		}
		if version == "" {
			l.logRepair(ctx, repairLog{module: owner, from: from, outgrown: outgrown, skip: "no coherent version"})
			continue
		}
		if semver.Compare(version, repairs[owner]) <= 0 {
			continue // another failing package of the same module already asked for it
		}
		repairs[owner] = version
		added = true
		l.logRepair(ctx, repairLog{module: owner, from: from, to: version, source: "version walk", outgrown: outgrown})
	}
	return repairs, added, nil
}

// relaxTarget picks the live candidate to step down one rung after a failed
// repair fixpoint. Implicated candidates come first: those whose module the
// failure points at (an outgrown dependency, else a moved failing module or
// moved import; for a resolve failure, a module the error names), or whose
// own go.mod requires such a module above baseline (the raise traces back
// to them). Among them - or among every relaxable candidate when nothing is
// implicated - the least severe active rung goes first, then the one moved
// furthest from baseline, then the latest added. Ambiguity remedies and
// user-authored replaces are never relaxed. nil when nothing is relaxable.
func (l *loop) relaxTarget(ctx context.Context, g *gateRun, out *trialOutcome, live []*candState) *candState {
	suspects := l.implicatedModules(ctx, out, live)
	var relaxable, implicated []*candState
	for _, c := range live {
		if c.remedy || c.Replace {
			continue
		}
		relaxable = append(relaxable, c)
		version := g.rung(c).Version
		if _, ok := suspects[c.Module]; ok {
			implicated = append(implicated, c)
			continue
		}
		for _, dep := range sortedKeys(suspects) {
			if l.candidateRaises(ctx, c.Module, version, dep) {
				implicated = append(implicated, c)
				break
			}
		}
	}
	pool := implicated
	if len(pool) == 0 {
		pool = relaxable
	}
	var best *candState
	for _, c := range pool { // pool is in apply order: later wins ties
		if best == nil || l.relaxBefore(g, c, best) >= 0 {
			best = c
		}
	}
	return best
}

// relaxBefore orders relaxation candidates: positive when a should be
// relaxed before b (less severe active rung, then further moved from
// baseline), 0 on a tie.
func (l *loop) relaxBefore(g *gateRun, a, b *candState) int {
	if ra, rb := scan.SeverityRank(g.rung(a).Severity), scan.SeverityRank(g.rung(b).Severity); ra != rb {
		return ra - rb
	}
	da := versionDistance(l.baselineResolved[a.Module], g.rung(a).Version)
	db := versionDistance(l.baselineResolved[b.Module], g.rung(b).Version)
	return slices.Compare(da[:], db[:])
}

// implicatedModules returns the modules a failing trial points at (see
// relaxTarget).
func (l *loop) implicatedModules(ctx context.Context, out *trialOutcome, live []*candState) map[string]struct{} {
	suspects := make(map[string]struct{})
	if out.reject != "" {
		for _, c := range live {
			if strings.Contains(out.reject, c.Module) {
				suspects[c.Module] = struct{}{}
			}
		}
		return suspects
	}
	for _, pkg := range sortedKeys(out.failures) {
		owner, outgrown := l.outgrownDeps(ctx, out, pkg)
		if len(outgrown) > 0 {
			for dep := range outgrown {
				suspects[dep] = struct{}{}
			}
			continue
		}
		if l.moved(out, owner) {
			suspects[owner] = struct{}{}
		}
		for _, imp := range out.report.Imports[pkg] {
			if dep := out.report.Modules[imp]; dep != owner && l.moved(out, dep) {
				suspects[dep] = struct{}{}
			}
		}
	}
	return suspects
}

// versionDistance is how far `to` moves a module from `from`, as
// (major, minor, patch) deltas.
func versionDistance(from, to string) [3]int {
	parse := func(v string) (out [3]int) {
		core, _, _ := strings.Cut(strings.TrimPrefix(semver.Canonical(v), "v"), "-")
		for i, part := range strings.SplitN(core, ".", 3) {
			out[i], _ = strconv.Atoi(part)
		}
		return out
	}
	f, t := parse(from), parse(to)
	return [3]int{t[0] - f[0], t[1] - f[1], t[2] - f[2]}
}

// moved reports whether module resolves differently than at baseline.
func (l *loop) moved(out *trialOutcome, module string) bool {
	return module != "" && out.resolved[module] != "" && out.resolved[module] != l.baselineResolved[module]
}

// outgrownDeps returns failing package pkg's module F and the dependencies
// F has been outgrown by: modules of packages pkg imports that were raised
// above baseline AND above the version F's own go.mod (at its resolved
// version) requires - the lockstep-family break MVS cannot see (no upper
// bounds). Empty for main-module packages or when F's go.mod is unknown.
func (l *loop) outgrownDeps(ctx context.Context, out *trialOutcome, pkg string) (string, map[string]string) {
	owner := out.report.Modules[pkg]
	ownerVersion := out.resolved[owner]
	if owner == "" || ownerVersion == "" {
		return owner, nil
	}
	requires, err := l.compiler.ModuleRequires(ctx, l.dir, owner, ownerVersion)
	if err != nil {
		_ = l.recordInfra(err) // recorded: fails the run (see RunLoop)
		return owner, nil
	}
	outgrown := make(map[string]string)
	for _, imp := range out.report.Imports[pkg] {
		dep, known := out.report.Modules[imp]
		if !known || dep == "" || dep == owner {
			continue
		}
		base, current := l.baselineResolved[dep], out.resolved[dep]
		if base == "" || semver.Compare(current, base) <= 0 {
			continue
		}
		if required, ok := requires[dep]; ok && semver.Compare(required, current) < 0 {
			outgrown[dep] = current
		}
	}
	return owner, outgrown
}

// candidateRaises reports whether module@version's own go.mod requires dep
// above its baseline version (best-effort: lookup failures attribute
// nothing).
func (l *loop) candidateRaises(ctx context.Context, module, version, dep string) bool {
	requires, err := l.compiler.ModuleRequires(ctx, l.dir, module, version)
	if err != nil {
		_ = l.recordInfra(err) // recorded: fails the run (see RunLoop)
		return false
	}
	required, ok := requires[dep]
	return ok && semver.Compare(required, l.baselineResolved[dep]) > 0
}

// minCoherentVersion walks module's released versions upward from `from`
// (same major, no pre-releases unless already on one, bounded) and returns
// the first whose go.mod requires every relevant raised dependency at or
// above its raised version - relevant meaning required by module@from below
// the raise. "" when there is nothing to repair or no such version exists;
// an error only for cancellation.
func (l *loop) minCoherentVersion(ctx context.Context, module, from string, raised map[string]string) (string, error) {
	current, err := l.compiler.ModuleRequires(ctx, l.dir, module, from)
	if err != nil {
		if ierr := l.recordInfra(err); ierr != nil {
			return "", ierr
		}
		return "", ctx.Err()
	}
	relevant := make(map[string]string)
	for dep, version := range raised {
		if required, ok := current[dep]; ok && semver.Compare(required, version) < 0 {
			relevant[dep] = version
		}
	}
	if len(relevant) == 0 {
		return "", nil
	}
	versions, err := l.compiler.ModuleVersions(ctx, l.dir, module)
	if err != nil {
		if ierr := l.recordInfra(err); ierr != nil {
			return "", ierr
		}
		return "", ctx.Err()
	}
	inspected := 0
	for _, version := range versions {
		if semver.Compare(version, from) <= 0 {
			continue
		}
		if semver.Major(version) != semver.Major(from) {
			break // cross-major: not expressible as a deps entry
		}
		if semver.Prerelease(version) != "" && semver.Prerelease(from) == "" {
			continue
		}
		inspected++
		if inspected > maxCoherenceWalk {
			break
		}
		requires, err := l.compiler.ModuleRequires(ctx, l.dir, module, version)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return "", cerr
			}
			if ierr := l.recordInfra(err); ierr != nil {
				return "", ierr
			}
			continue
		}
		coherent := true
		for dep, need := range relevant {
			if required, ok := requires[dep]; !ok || semver.Compare(required, need) < 0 {
				coherent = false
				break
			}
		}
		if coherent {
			return version, nil
		}
	}
	return "", nil
}

// gateAdopt commits the accepted pin set to the candidates - each at its
// active rung, raised in place by a repair of its module, plus a
// coherence-only candidate per repair of an unpinned module - then
// re-applies and rescans it (see gateFinish).
func (l *loop) gateAdopt(ctx context.Context, g *gateRun, live []*candState, repairs, rejected map[string]string, result *ModrootResult) (map[string]string, error) {
	for _, c := range live {
		c.Version = g.rung(c).Version
	}
	for _, module := range sortedKeys(repairs) {
		if c, ok := l.byModule[module]; ok && !c.dropped {
			if semver.Compare(repairs[module], c.Version) > 0 {
				c.Version = repairs[module]
			}
			continue
		}
		l.addCandidate(Candidate{Module: module, Version: repairs[module]}, false).repair = true
	}
	return l.gateFinish(ctx, l.inApplyOrder(l.activeCandidates()), rejected, result)
}

// gateFinish adopts the compile gate's accepted set: re-applies it,
// rescans, and refreshes the loop's accepted state. An advisory the rescan
// still finds for a module whose higher rung was rejected is a residual
// carrying that rejection; any other fix the rescan wants is surfaced as a
// residual rather than raised (it was never compile-validated).
func (l *loop) gateFinish(ctx context.Context, keep []*candState, rejected map[string]string, result *ModrootResult) (map[string]string, error) {
	tr, err := l.trialApply(ctx, "gate: adopt accepted set", keep)
	if err != nil {
		return nil, gateErr(ctx, fmt.Errorf("re-applying the accepted set: %w", err))
	}
	if !l.sustained(tr, keep) {
		logging.From(ctx).Warn("compile gate: accepted set not fully sustained by the tidied go.mod",
			"modroot", l.req.Modroot)
	}
	l.adoptTrial(ctx, tr, result)
	for _, r := range tr.raises {
		reason, wasRejected := rejected[r.module]
		if !wasRejected {
			reason = "advisory surfaced after compile-gate adjustments; fix not validated"
		}
		l.persistentResiduals = append(l.persistentResiduals, Residual{
			Module:          r.module,
			ResolvedVersion: tr.resolved[r.module],
			FixedVersion:    r.version,
			VulnIDs:         r.vulnIDs,
			Reason:          reason,
		})
	}
	return tr.resolved, nil
}

// Trial tracing (Debug level only; see logTrial/logRepair). The message
// strings are stable: tests capture these records to assert what each trial
// applied, so later stages that restructure the trials must keep emitting
// them.
const (
	trialLogMsg  = "simulate: trial"
	repairLogMsg = "simulate: repair decision"

	maxTrialLogDiff   = 25 // changed modules listed per trial record
	maxTrialLogErrors = 3  // compile error lines listed per trial record
)

// trialLog describes one trial for logTrial: the pins it applied (in apply
// order), and whichever outcome applies - a resolve/tidy rejection, a
// compile report (gate trials), or a rescan (refinement trials).
type trialLog struct {
	purpose   string
	subject   string // module the trial is about, when it has one (the relaxed bump)
	pins      []*candState
	reject    string
	resolved  map[string]string
	compiled  *trialOutcome
	raises    []raise
	residuals int
}

// pinRole names the provenance a pin carries in the loop, for tracing:
// remedy (ambiguous-import repair), coherence (compile-gate co-update
// repair), cve (advisory-backed), seed (caller-provided, no advisory), raise.
func pinRole(c *candState) string {
	switch {
	case c.remedy:
		return "remedy"
	case c.repair:
		return "coherence"
	case c.FromCVE:
		return "cve"
	case c.seed:
		return "seed"
	default:
		return "raise"
	}
}

// trialPin renders a pin as "module@version(role)", replaces as
// "old=module@version(role)".
func trialPin(c *candState) string {
	coord := c.Module + "@" + c.Version
	if c.Replace {
		coord = c.OldPath() + "=" + coord
	}
	return coord + "(" + pinRole(c) + ")"
}

// logTrial emits one structured Debug record per trial: the pins applied
// with their roles, the resolved graph's changes against the pristine
// baseline (capped), and the outcome. It returns immediately when Debug is
// disabled, so the formatting costs nothing on normal runs.
func (l *loop) logTrial(ctx context.Context, tl trialLog) {
	logger := logging.From(ctx)
	if !logger.Enabled(ctx, slog.LevelDebug) {
		return
	}
	pins := make([]string, 0, len(tl.pins))
	for _, c := range tl.pins {
		pins = append(pins, trialPin(c))
	}
	attrs := []any{"modroot", l.req.Modroot, "purpose", tl.purpose, "pins", pins}
	if tl.subject != "" {
		attrs = append(attrs, "subject", tl.subject)
	}
	if tl.reject != "" {
		attrs = append(attrs, "outcome", "rejected", "reject", firstLine(tl.reject))
		logger.Debug(trialLogMsg, attrs...)
		return
	}
	if tl.resolved != nil {
		attrs = append(attrs, "resolved_diff", l.resolvedDiff(tl.resolved))
	}
	if st := tl.compiled; st != nil {
		outcome := "compiles"
		if len(st.failures) > 0 {
			outcome = "breaks compile"
		}
		attrs = append(attrs, "outcome", outcome, "failing", len(st.failures))
		if len(st.failures) > 0 {
			attrs = append(attrs, "failing_owners", failingOwners(st), "errors", firstCompileErrors(st.failures, maxTrialLogErrors))
		}
	} else {
		raises := make([]string, 0, len(tl.raises))
		for _, r := range tl.raises {
			raises = append(raises, r.module+"@"+r.version)
		}
		attrs = append(attrs, "outcome", "resolved", "raises", raises, "residuals", tl.residuals)
	}
	logger.Debug(trialLogMsg, attrs...)
}

// resolvedDiff lists the modules whose resolved version differs from the
// pristine baseline graph ("module old->new"; "-" for absent), capped at
// maxTrialLogDiff with a trailing "+N more". The baseline is the compile
// gate's pristine tidied graph when known, else the caller's go.mod view.
func (l *loop) resolvedDiff(resolved map[string]string) []string {
	baseline := l.baselineResolved
	if baseline == nil {
		baseline = l.req.Baseline
	}
	orDash := func(v string) string {
		if v == "" {
			return "-"
		}
		return v
	}
	var changed []string
	for _, module := range sortedKeys(resolved) {
		if resolved[module] != baseline[module] {
			changed = append(changed, module+" "+orDash(baseline[module])+"->"+resolved[module])
		}
	}
	for _, module := range sortedKeys(baseline) {
		if _, ok := resolved[module]; !ok {
			changed = append(changed, module+" "+baseline[module]+"->-")
		}
	}
	if len(changed) > maxTrialLogDiff {
		more := len(changed) - maxTrialLogDiff
		changed = append(changed[:maxTrialLogDiff], fmt.Sprintf("+%d more", more))
	}
	return changed
}

// failingOwners lists the distinct modules owning a trial's newly failing
// packages ("(main)" for the main module), sorted.
func failingOwners(st *trialOutcome) []string {
	owners := make(map[string]struct{})
	for pkg := range st.failures {
		owner := st.report.Modules[pkg]
		if owner == "" {
			owner = "(main)"
		}
		owners[owner] = struct{}{}
	}
	return sortedKeys(owners)
}

// firstCompileErrors renders up to n compile failures, one line each, in
// package order (see firstCompileError for the line shape).
func firstCompileErrors(failures map[string][]string, n int) []string {
	var lines []string
	for _, pkg := range sortedKeys(failures) {
		if len(lines) == n {
			break
		}
		lines = append(lines, firstCompileError(map[string][]string{pkg: failures[pkg]}))
	}
	return lines
}

// repairLog describes one compile-gate repair decision for logRepair: the
// failing module, its version, the raised dependencies that outgrew it,
// and either the chosen raise (to/source) or the skip reason.
type repairLog struct {
	module, from, to, source string
	outgrown                 map[string]string
	skip                     string
}

// logRepair emits one structured Debug record per repair decision (free
// when Debug is disabled).
func (l *loop) logRepair(ctx context.Context, rl repairLog) {
	logger := logging.From(ctx)
	if !logger.Enabled(ctx, slog.LevelDebug) {
		return
	}
	outgrown := make([]string, 0, len(rl.outgrown))
	for _, dep := range sortedKeys(rl.outgrown) {
		outgrown = append(outgrown, dep+"@"+rl.outgrown[dep])
	}
	attrs := []any{"modroot", l.req.Modroot, "module", rl.module, "from", rl.from, "outgrown", outgrown}
	if rl.skip != "" {
		attrs = append(attrs, "decision", "skip", "reason", rl.skip)
	} else {
		attrs = append(attrs, "decision", "raise", "to", rl.to, "source", rl.source)
	}
	logger.Debug(repairLogMsg, attrs...)
}

// firstCompileError renders the first (by package path) compile failure as
// "pkg: file.go:line:col: message", trimming the file's directory.
func firstCompileError(failures map[string][]string) string {
	pkgs := sortedKeys(failures)
	if len(pkgs) == 0 || len(failures[pkgs[0]]) == 0 {
		return "unknown compile error"
	}
	line := failures[pkgs[0]][0]
	if idx := strings.Index(line, ".go:"); idx >= 0 {
		file := line[:idx+len(".go")]
		line = filepath.Base(file) + line[idx+len(".go"):]
	}
	return pkgs[0] + ": " + line
}

func firstLine(text string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(text), "\n")
	return line
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// packagesFor renders a resolved module graph as OSV scan queries, in stable order.
func packagesFor(resolved map[string]string) []scan.Package {
	pkgs := make([]scan.Package, 0, len(resolved))
	for module, version := range resolved {
		pkgs = append(pkgs, scan.Package{Name: module, Version: version, Ecosystem: "Go"})
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
	return pkgs
}

// majorChange reports whether moving module from the resolved version to
// the fixed version crosses a major version boundary - v0 -> v1 included:
// v0 promises no compatibility, and a v1 release is the API break that
// declares the stable one - unless module's path already encodes the fixed
// version's major (/vN, gopkg.in .vN). Such a fix is not a compatible raise
// a deps entry can express.
func majorChange(modulePath, fixedVersion, resolvedVersion string) bool {
	if resolvedVersion == "" {
		return false
	}
	fixedMajor := semver.Major(fixedVersion)
	if fixedMajor == semver.Major(resolvedVersion) {
		return false
	}
	_, pathMajor, ok := module.SplitPathVersion(modulePath)
	return !ok || strings.TrimLeft(pathMajor, "/.") != fixedMajor
}

// introducesNewVulns reports whether candidate residuals reference advisories
// absent from the accepted residual set - i.e. the minimal candidate set
// regressed some module into a vulnerability the full set had avoided.
func introducesNewVulns(candidate, accepted []Residual) bool {
	known := make(map[string]struct{})
	for _, r := range accepted {
		for _, id := range r.VulnIDs {
			known[id] = struct{}{}
		}
	}
	for _, r := range candidate {
		for _, id := range r.VulnIDs {
			if _, ok := known[id]; !ok {
				return true
			}
		}
	}
	return false
}

// ambiguity is one "ambiguous import" pair to repair: the monolith module
// (at version from) that must move past the version where the split module
// (at splitVersion) took the package over.
type ambiguity struct {
	monolith, from      string
	split, splitVersion string
}

// ambiguousImports extracts, from a go tool "ambiguous import: found package
// X in multiple modules" failure, the pair to repair for each ambiguous
// package: when one module path is a prefix of another (the
// monolith-vs-split case, e.g. google.golang.org/genproto vs
// google.golang.org/genproto/googleapis/rpc), the monolith must advance past
// the version where the split module took the packages over. Falls back to
// the first-listed module (against the second) when neither path nests in
// the other.
func ambiguousImports(errText string) []ambiguity {
	var pairs []ambiguity
	seen := make(map[string]struct{})

	lines := strings.Split(errText, "\n")
	for i := range lines {
		if !strings.Contains(lines[i], "ambiguous import: found package") {
			continue
		}
		var modules, versions []string
		for j := i + 1; j < len(lines); j++ {
			fields := strings.Fields(lines[j])
			if len(fields) < 2 || !strings.HasPrefix(fields[1], "v") || strings.HasSuffix(fields[0], ":") {
				break
			}
			modules = append(modules, fields[0])
			versions = append(versions, fields[1])
		}
		if len(modules) < 2 {
			continue
		}

		pair := ambiguity{monolith: modules[0], from: versions[0], split: modules[1], splitVersion: versions[1]}
		for ci, candidate := range modules {
			for oi, other := range modules {
				if candidate != other && strings.HasPrefix(other, candidate+"/") {
					pair = ambiguity{monolith: candidate, from: versions[ci], split: other, splitVersion: versions[oi]}
				}
			}
		}
		if _, ok := seen[pair.monolith]; !ok {
			seen[pair.monolith] = struct{}{}
			pairs = append(pairs, pair)
		}
	}
	return pairs
}

// classifyIntroduced marks residual advisories absent from the baseline
// analysis scan: they apply only to a version the bump itself moved to, not
// to the original graph. Reporting/accounting only (no toolchain calls) -
// fixable introduced advisories were already raised and fixed by the
// fixpoint loop; what reaches here is genuinely unavoidable, but must be
// reported distinctly and must not deflate the baseline fixed count. No-op
// when the caller provided no baseline (fail open).
func (l *loop) classifyIntroduced(ctx context.Context, residuals []Residual) {
	if l.req.BaselineVulnIDs == nil {
		return
	}
	for i := range residuals {
		r := &residuals[i]
		if len(r.VulnIDs) == 0 {
			continue
		}
		introduced := true
		for _, id := range r.VulnIDs {
			if _, ok := l.req.BaselineVulnIDs[id]; ok {
				introduced = false
				break
			}
		}
		if !introduced {
			continue
		}
		r.Introduced = true
		r.Reason = fmt.Sprintf("introduced by bump to %s; not present at baseline; %s",
			r.ResolvedVersion, r.Reason)
		logging.From(ctx).Warn("bump introduces new advisory",
			"modroot", l.req.Modroot, "module", r.Module, "resolved", r.ResolvedVersion,
			"vulns", strings.Join(r.VulnIDs, ","))
	}
}

func remainingVulnIDs(residuals []Residual) []string {
	seen := make(map[string]struct{})
	var ids []string
	for _, r := range residuals {
		for _, id := range r.VulnIDs {
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	return ids
}

func mergeIDs(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	merged := make([]string, 0, len(a)+len(b))
	for _, id := range append(append([]string{}, a...), b...) {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			merged = append(merged, id)
		}
	}
	sort.Strings(merged)
	return merged
}
