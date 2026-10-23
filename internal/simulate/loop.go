package simulate

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/isometry/choam/internal/logging"
	"github.com/isometry/choam/internal/scan"
	"golang.org/x/mod/semver"
)

// candState is a Candidate plus its lifecycle within the loop. A replace
// candidate (Candidate.Replace) is always a user-authored YAML replace: the
// loop never creates replace directives of its own.
type candState struct {
	Candidate
	seed   bool // seeded by the caller (vs raised by a rescan)
	remedy bool // added to repair an ambiguous import (applied first)

	// ceiling is the lowest version whose fetch failed (see stepDown): the
	// candidate never raises to it or above again, so the residual recorded
	// for it stands.
	ceiling string
	// residualized marks a dropped candidate whose advisories were accounted
	// for at drop time - either recorded as a residual or deliberately
	// residual-free (unreachable, redundant). The rescan backfill only
	// synthesizes residuals for dropped CVE candidates NOT marked here.
	residualized bool
	// dropReason mirrors the DroppedCandidate reason, for backfill wording;
	// non-empty exactly when the candidate is dropped (see isDropped).
	dropReason string
	// shedUnlinked marks a drop by dropUnreachable: judged against the graph
	// current at the time, which a later adjustment can replace.
	shedUnlinked bool

	// repair marks a coherence-only pin the type-check gate added to keep a
	// module compatible with a raised dependency (see repairsFor).
	repair bool

	// hygieneSeed is the version a seed carried above its linked fixes - its
	// whole version when shed because no advisory it addresses is linked
	// (see dropUnreachable), or the part trimmed off a partly linked one
	// (see trimUnlinkedRungs). The scanner-hygiene pass tries it first, so
	// an existing pin is kept exactly when it is free (see hygienePass).
	hygieneSeed string
	// hygieneIDs are the unlinked advisories a scanner-hygiene bump clears
	// (see hygienePass); non-empty marks the entry as hygiene.
	hygieneIDs []string
}

// isDropped reports whether the candidate was dropped (see loop.drop).
func (c *candState) isDropped() bool { return c.dropReason != "" }

// drop marks the candidate dropped and records it with the given reason
// (never empty).
func (l *loop) drop(c *candState, reason string) {
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

	// Artifact reachability: target is what the build compiles (go/build
	// package patterns, default ./..., tags, arches - normalized, the first
	// is the type-check gate's - and environment) whose non-test import graph
	// decides what actually ships; linked/linkedPackages are the module and
	// package sets from the last Toolchain.Linked query, nil when unknown
	// (query failed) - reachability then fails OPEN and no filtering happens.
	target         BuildTarget
	linked         map[string]struct{}
	linkedPackages map[string]struct{}
	linkedWarned   bool
	// linkedErr is the last Linked query's error, embeds its tolerated
	// embed gaps (see Linkage.Embeds).
	linkedErr error
	embeds    []UnmatchedEmbed

	// Degraded module-level reachability (see degradedUnlinked): tidiedModern
	// tracks whether the current on-disk go.mod's go directive is >= 1.17 -
	// the threshold at which the require block covers the main module's
	// whole import closure. linkedStdWarned/degradedNoted are warn/info-once
	// guards, mirroring linkedWarned.
	tidiedModern    bool
	linkedStdWarned bool
	degradedNoted   bool

	// Type-check gate (see typecheckGate): checker is nil when the gate is off
	// (toolchain without Checker support, or Options.NoTypecheck).
	// baselineFailed maps each target arch to the packages already failing
	// to type-check there in the pristine checkout (excluded from every
	// verdict on that arch); baselineResolved is the pristine tidied module
	// graph.
	checker          Checker
	baselineFailed   map[string]map[string]struct{}
	baselineResolved map[string]string
	// gateUnchecked counts the distinct baselineFailed packages across
	// arches; baselineFirst is the first one's first error line ("pkg:
	// line"; see ModrootResult.GateUnchecked).
	gateUnchecked int
	baselineFirst string
	// gateRejected maps a module to why the gate rejected its higher rung,
	// across gate rounds; revived marks candidates shed as unlinked that a
	// gate round brought back because the gated graph links them again
	// (each at most once, so the rounds are bounded).
	gateRejected map[string]string
	revived      map[string]bool
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
	l, baselineTidies, err := newLoop(ctx, tc, sc, dir, req, opts)
	if err != nil {
		return nil, err
	}

	for _, seed := range req.Seeds {
		l.seedCandidate(seed)
	}

	// Pristine reachability: shed unreachable seeds BEFORE the first apply.
	// A doomed candidate must never get to perturb the module graph - an
	// unlinked-but-unappliable fix would otherwise destabilize a fragile
	// graph and surface as a bogus "fix breaks module graph" residual.
	l.refreshLinked(ctx)
	l.dropUnreachable()

	if l.checker != nil {
		if err := l.typecheckBaseline(ctx); err != nil {
			return nil, err
		}
	}

	result := &ModrootResult{Modroot: req.Modroot, BaselineTidies: baselineTidies}

	resolved, err := l.converge(ctx, result)
	if err != nil {
		return nil, err
	}

	// Dependency-graph capabilities (max go directive, linked stdlib set) are
	// computed HERE: right after the fixpoint loop exits (converged or
	// iteration-cap exhausted) and BEFORE the refinement phases
	// (confirmMinimalSet, the type-check gate, minimise) run. At this exact point the
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

	if resolved, err = l.refine(ctx, resolved, result); err != nil {
		return nil, err
	}

	if l.infraErr != nil {
		// A best-effort lookup hit an infrastructure failure: some verdict
		// above may rest on it, so nothing here is trusted.
		return nil, l.infraErr
	}

	l.buildResult(ctx, resolved, result)
	return result, nil
}

// newLoop builds the loop for the module at dir: the build target, the
// type-check gate (when the toolchain supports it), the pristine go.mod/go.sum
// snapshot, the step's engine and the upstream replace directives. It also
// reports whether the pristine module already tidies (see
// ModrootResult.BaselineTidies; probed only for `tidy: false`).
func newLoop(ctx context.Context, tc Toolchain, sc Scanner, dir string, req ModrootRequest, opts Options) (*loop, bool, error) {
	opts = opts.WithDefaults()

	l := &loop{
		tc:       tc,
		sc:       sc,
		dir:      dir,
		req:      req,
		opts:     opts,
		byModule: make(map[string]*candState),
		remedied: make(map[string]remedyState),
		target: BuildTarget{
			Patterns: req.Packages,
			Tags:     req.Tags,
			Arches:   TargetArches(req.Arches),
			Env:      req.Env,
		},
	}
	if len(l.target.Patterns) == 0 {
		l.target.Patterns = []string{"./..."}
	}
	if checker, ok := tc.(Checker); ok && !opts.NoTypecheck {
		l.checker = checker
	}
	if err := l.savePristine(ctx); err != nil {
		return nil, false, err
	}
	eng, err := l.newEngine(ctx)
	if err != nil {
		return nil, false, err
	}
	l.engine = eng
	baselineTidies := false
	if prober, ok := eng.(*omnibumpEngine); ok && req.ProbeTidy && req.NoTidy {
		if baselineTidies, err = prober.probeTidy(ctx); err != nil {
			return nil, false, err
		}
	}
	pristineReplaces, err := tc.Replaces(ctx, dir)
	if err != nil {
		return nil, false, fmt.Errorf("reading upstream replace directives: %w", err)
	}
	l.pristineReplaces = pristineReplaces
	return l, baselineTidies, nil
}

// converge runs the fixpoint: apply the candidates, resync to the resolved
// graph, rescan it and raise, until a rescan demands no further raise
// (result.Converged) or opts.MaxIterations is reached. It records the
// iteration count in result and returns the last resolved graph (nil when no
// iteration ran).
func (l *loop) converge(ctx context.Context, result *ModrootResult) (map[string]string, error) {
	var resolved map[string]string
	for iter := 1; iter <= l.opts.MaxIterations; iter++ {
		result.Iterations = iter

		if err := l.apply(ctx); err != nil {
			return nil, err
		}

		var err error
		if resolved, err = l.resync(ctx); err != nil {
			return nil, err
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
	return resolved, nil
}

// resync reads the applied checkout back (resolved graph, requirements,
// replaces, reachability) and returns the resolved graph.
//
// It re-applies until every surviving pin is sustained by the tidied
// go.mod (melange's gobump rejects entries the tidy pruned or
// downgraded) AND linked into a build artifact; each pass sheds at
// least one candidate, so this is bounded. Shedding inside this loop
// (rather than a separate phase) matters: a dropped candidate's MVS
// ripple is unwound by the re-apply, so the validated final state
// matches what melange's gobump will produce from FinalDeps alone.
func (l *loop) resync(ctx context.Context) (map[string]string, error) {
	for {
		resolved, err := l.tc.ListModules(ctx, l.dir)
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
		if !l.dropUnsustained(ctx) && !l.dropUnreachable() {
			return resolved, nil
		}
		if err := l.apply(ctx); err != nil {
			return nil, err
		}
	}
}

// refine runs the post-fixpoint phases on the converged set, in order:
// shed pins no advisory needs (confirmMinimalSet; on non-convergence the
// last raises become residuals instead), the type-check gate, the redundancy
// check (minimise) and scanner-hygiene bumps. Returns the final resolved
// graph.
func (l *loop) refine(ctx context.Context, resolved map[string]string, result *ModrootResult) (map[string]string, error) {
	var err error
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

	// The type-check gate runs last, against the final candidate set: the
	// fixpoint only proves the graph resolves and tidies - MVS has no upper
	// bounds, so a raised dependency can still remove API a lagging sibling
	// type-checks against (see typecheckGate).
	if l.checker != nil {
		for {
			gated, again, err := l.typecheckGate(ctx, resolved, result)
			if err != nil {
				return nil, err
			}
			resolved = gated
			if !again {
				break
			}
		}
	}

	// Then, on the final set: remove every redundant entry. The final
	// tidied go.mod is unchanged by construction, so resolved and the
	// capability fields still describe it.
	ref, err := l.minimise(ctx)
	if err != nil {
		return nil, err
	}

	// Last: scanner-hygiene bumps, only where they are free against that
	// final go.mod (see hygienePass).
	return l.hygienePass(ctx, ref, resolved, result)
}

// buildResult fills result from the final loop state and resolved graph:
// the outputs, drops and residuals (backfilled, classified and sorted).
func (l *loop) buildResult(ctx context.Context, resolved map[string]string, result *ModrootResult) {
	result.Resolved = resolved
	result.Linked = l.linked
	result.LinkedPackages = l.linkedPackages
	if l.linkedErr != nil {
		result.LinkageError = l.linkedErr.Error()
	}
	result.UnmatchedEmbeds = l.embeds
	result.GateUnchecked, result.GateUncheckedFirst = l.gateUnchecked, l.baselineFirst
	result.Requires = l.requirements
	result.UnrequiredModules = l.unrequiredModules(resolved)
	result.FinalDeps, result.FinalReplaces, result.CVEBackedModules = l.finalOutputs(resolved)
	result.HygieneModules = l.hygieneModules()
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
	slices.SortStableFunc(result.Residuals, compareResiduals)
	result.RemainingVulnIDs = remainingVulnIDs(result.Residuals)
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

	if existing, ok := l.byModule[c.Module]; ok && !existing.isDropped() && existing.Replace {
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
	for _, old := range sortedKeys(l.pristineReplaces) {
		if target := l.pristineReplaces[old]; target.Path == module && target.Version != "" {
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

// addCandidate adds c, or merges it into the live candidate for the same
// module: the higher version wins, and of two spellings of the same version
// the one scan.PreferVersion picks.
func (l *loop) addCandidate(c Candidate, seed bool) *candState {
	if existing, ok := l.byModule[c.Module]; ok && !existing.isDropped() {
		existing.Rungs = mergeRungs(existing.fixRungs(), c.fixRungs())
		switch rel := semver.Compare(c.Version, existing.Version); {
		case rel > 0:
			existing.Version = c.Version
		case rel == 0:
			existing.Version = scan.PreferVersion(existing.Version, c.Version)
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
		if !c.isDropped() {
			active = append(active, c)
		}
	}
	return active
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
