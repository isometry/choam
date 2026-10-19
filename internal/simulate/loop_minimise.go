package simulate

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/isometry/choam/internal/logging"
	"github.com/isometry/choam/internal/scan"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

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
	tr.raises, tr.residuals, _ = l.scanFindings(scanResult, tr.resolved)
	l.logTrial(ctx, trialLog{purpose: purpose, pins: keep, resolved: tr.resolved, raises: tr.raises, residuals: len(tr.residuals)})
	return tr, nil
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
// effect-based redundancy check (see minimise); the type-check gate re-adds any
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

// finalState applies pins (in the given order) with the step's engine (its
// own tidy mode: no tidy at all for `tidy: false`) and reads the resulting
// go.mod (see readGoModState). ok is false when the apply fails - the set is
// then not equivalent to anything.
func (l *loop) finalState(ctx context.Context, pins []*candState) (st *goModState, ok bool, err error) {
	if fail := l.engine.apply(ctx, pins); fail != nil {
		if ierr := l.recordInfra(fail.err); ierr != nil {
			return nil, false, ierr
		}
		return nil, false, ctx.Err()
	}
	if st, err = l.readGoModState(ctx); err != nil {
		return nil, false, err
	}
	return st, true, nil
}

// readGoModState reads the checkout's go.mod effect (see goModState). Called
// right after an engine apply: go.mod is read before any go list runs, so
// nothing but the engine has touched it.
func (l *loop) readGoModState(ctx context.Context) (st *goModState, err error) {
	st = &goModState{}
	if st.requires, err = l.tc.Requirements(ctx, l.dir); err != nil {
		return nil, err
	}
	if st.replaces, err = l.tc.Replaces(ctx, l.dir); err != nil {
		return nil, err
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
			return nil, err
		}
	}
	return st, nil
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
// holding the final set; the returned state is its go.mod (nil when it was
// never computed: nothing to trial, or the final set no longer applies).
func (l *loop) minimise(ctx context.Context) (*goModState, error) {
	set, order := l.minimiseCandidates(ctx)
	if len(order) == 0 {
		return nil, nil
	}

	start := time.Now()
	ref, ok, err := l.finalState(ctx, l.inApplyOrder(set))
	if err != nil || !ok {
		return nil, l.stopMinimise(ctx, set, err, "the final set no longer applies")
	}
	return l.leaveOneOut(ctx, ref, set, order, time.Since(start))
}

// minimiseCandidates drops the active entries that are redundant without a
// trial (see classifyRedundant) and returns the rest: set is the final set,
// order the entries to trial for redundancy (every one but the user-authored
// replaces), in trial order (see compareMinimiseOrder).
func (l *loop) minimiseCandidates(ctx context.Context) (set, order []*candState) {
	for _, c := range l.activeCandidates() {
		if why, redundant := l.classifyRedundant(c); redundant {
			l.dropRedundant(ctx, c, why)
			continue
		}
		if !c.Replace {
			order = append(order, c)
		}
		set = append(set, c)
	}
	slices.SortFunc(order, compareMinimiseOrder)
	return set, order
}

// classifyRedundant reports why c is redundant without a trial: a
// self-replace at or below the baseline-resolved version, or a deps entry
// that matches or regresses the upstream go.mod. Other user-authored
// replaces are never redundant this way.
func (l *loop) classifyRedundant(c *candState) (why string, ok bool) {
	if c.Replace {
		if base := l.baselineVersion(c.Module); c.OldPath() == c.Module && semver.IsValid(base) &&
			semver.Compare(c.Version, base) <= 0 {
			return "self-replace at or below the baseline-resolved " + base, true
		}
		return "", false
	}
	if why := l.engine.upstreamSkip(c); why != "" {
		return "matches or regresses upstream go.mod (" + why + ")", true
	}
	return "", false
}

// compareMinimiseOrder is the redundancy trial order: derived entries (no
// advisory) first, then advisory-backed ones from the least severe; ties by
// module path.
func compareMinimiseOrder(a, b *candState) int {
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
}

// settleMinimise leaves the checkout holding the final set, as the build's
// bump step will: a later modroot of the same clone may depend on this one
// (e.g. through a local replace), so a trial's state must not linger.
func (l *loop) settleMinimise(ctx context.Context, set []*candState) error {
	if fail := l.engine.apply(ctx, l.inApplyOrder(set)); fail != nil && errors.Is(ctx.Err(), context.Canceled) {
		return ctx.Err()
	}
	return nil
}

// stopMinimise ends the redundancy check early, keeping the remaining
// entries of set: a cancellation or an infrastructure failure is returned,
// anything else is logged and the checkout settled (see settleMinimise).
func (l *loop) stopMinimise(ctx context.Context, set []*candState, err error, why string) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return ctx.Err()
	}
	if errors.Is(err, ErrInfrastructure) {
		return err
	}
	logging.From(ctx).Info("redundancy check stopped; keeping the remaining entries",
		"modroot", l.req.Modroot, "reason", why, "error", err)
	return l.settleMinimise(ctx, set)
}

// leaveOneOut trials, in order, the final set without each entry and drops
// the entry when the final go.mod (ref) is unchanged without it; cost is the
// slowest apply so far, for the budget guard. Returns ref after settling the
// checkout on the surviving set.
func (l *loop) leaveOneOut(ctx context.Context, ref *goModState, set, order []*candState, cost time.Duration) (*goModState, error) {
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
		var err error
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
			return ref, l.stopMinimise(ctx, set, nil, "simulation budget nearly exhausted")
		}
		without := slices.DeleteFunc(slices.Clone(set), func(p *candState) bool { return p == c })
		start := time.Now()
		st, ok, err := l.finalState(ctx, l.inApplyOrder(without))
		cost = max(cost, time.Since(start))
		if err != nil || ctx.Err() != nil {
			return ref, l.stopMinimise(ctx, set, err, "trial interrupted")
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
	return ref, l.settleMinimise(ctx, set)
}

// baselineVersion is module's version in the pristine graph: the type-check
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
