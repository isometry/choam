package simulate

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/isometry/choam/internal/goversion"
	"github.com/isometry/choam/internal/logging"
	"github.com/isometry/choam/internal/scan"
	"golang.org/x/mod/semver"
)

// Scanner hygiene ("bump when free"): a module linked into the artifact
// whose advisories' vulnerable packages are not linked is not a security
// finding (see scanFindings), but module-level scanners (grype) still flag
// its version. hygienePass raises such a module anyway when doing so is
// free, reported apart from security fixes (ModrootResult.HygieneModules).

// maxHygieneDiff caps the changed modules a "not free" reason lists.
const maxHygieneDiff = 3

// hygienePin is one scanner-hygiene pin: the module, the version tried and
// the unlinked advisories it clears.
type hygienePin struct {
	module, version string
	ids             []string
}

// hygieneTarget is one module the hygiene pass may raise: the finding (see
// scanFindings) and the versions to try, highest first - the pin a seed
// carried in (see candState.hygieneSeed) when above the fix, then the fix.
type hygieneTarget struct {
	raise
	versions []string
	seed     string
}

// hygieneOutcome is one hygiene trial: why it is not free ("" when free)
// and, when free, the state it leaves.
type hygieneOutcome struct {
	why            string
	st             *goModState
	resolved       map[string]string
	linked         map[string]struct{}
	linkedPackages map[string]struct{}
	residuals      []Residual
}

// errHygieneBudget stops the hygiene search when the simulation budget runs
// low: the targets not yet decided are reported as not evaluated.
var errHygieneBudget = errors.New("simulation budget nearly exhausted")

// hygienePass proposes scanner-hygiene bumps on the final set (ref is its
// go.mod, nil when minimise did not compute it). A target is accepted only
// when free: the final go.mod changes by exactly that module's version (no
// other module moves, none is added or removed, replaces and the
// go/toolchain lines are unchanged; for go < 1.17 nor does the build list),
// the dependency graph needs no newer Go than the validated set (so neither
// RequiredGoVersion nor a go-package pin can move), nothing new fails to
// compile, and the rescan asks for no raise and finds no advisory the final
// set did not have. One batch trial of every target first; if it is not
// free, each target alone in a fixed order (most severe first, then by
// module) on top of those already accepted, a carried-in pin before the
// minimal fix. Accepted bumps are written but never defended, relaxed or
// counted as security fixes; rejected ones are recorded as dropped with the
// reason. Skipped (HygieneSkipped) without the compile gate or on a
// non-converged result. Returns the final resolved graph, leaving the
// checkout holding the final set; only a cancellation, an infrastructure or
// a scanner failure is an error.
func (l *loop) hygienePass(ctx context.Context, ref *goModState, resolved map[string]string, result *ModrootResult) (map[string]string, error) {
	scanResult, err := l.sc.ScanPackages(ctx, l.scanTargets(resolved, l.requirements, l.replaces))
	if err != nil {
		return nil, err
	}
	_, baseResiduals, found := l.scanFindings(scanResult, resolved)
	targets := l.hygieneTargets(found, resolved)
	if len(targets) == 0 {
		return resolved, nil
	}
	skip := ""
	switch {
	case !result.Converged:
		skip = "the simulation did not converge"
	case l.compiler == nil:
		skip = "compile gate disabled"
	}
	if skip != "" {
		coords := make([]string, 0, len(targets))
		for _, t := range targets {
			coords = append(coords, t.module+"@"+t.version)
		}
		result.HygieneSkipped = skip + " (" + strings.Join(coords, ", ") + ")"
		logging.From(ctx).Info("scanner hygiene bumps not evaluated", "modroot", l.req.Modroot, "reason", result.HygieneSkipped)
		return resolved, nil
	}

	set := l.inApplyOrder(l.activeCandidates())
	if ref == nil {
		st, ok, err := l.finalState(ctx, set)
		if err != nil {
			return nil, err
		}
		if !ok {
			result.HygieneSkipped = "the final set no longer applies"
			return resolved, nil
		}
		ref = st
	}

	start := time.Now()
	savedLinked, savedPackages := l.linked, l.linkedPackages
	var cost time.Duration
	trials := 0
	try := func(purpose string, pins []hygienePin) (*hygieneOutcome, error) {
		if dl, has := ctx.Deadline(); has && time.Until(dl) < 2*cost {
			return nil, errHygieneBudget
		}
		began := time.Now()
		out, err := l.hygieneTrial(ctx, purpose, set, pins, ref, result.MaxDepGoVersion, baseResiduals)
		cost = max(cost, time.Since(began))
		trials++
		if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errHygieneBudget
		}
		return out, err
	}

	var accepted []hygienePin
	var acceptedOut *hygieneOutcome
	lastAccepted := false
	whys := make(map[string]string, len(targets))
	stopped := ""
	if len(targets) > 1 {
		pins := make([]hygienePin, 0, len(targets))
		for _, t := range targets {
			pins = append(pins, hygienePin{module: t.module, version: t.versions[0], ids: t.vulnIDs})
		}
		out, err := try("hygiene: batch", pins)
		switch {
		case errors.Is(err, errHygieneBudget):
			stopped = err.Error()
		case err != nil:
			return nil, err
		case out.why == "":
			accepted, acceptedOut, lastAccepted = pins, out, true
		}
	}
	if accepted == nil && stopped == "" {
	search:
		for _, t := range targets {
			for _, version := range t.versions {
				pins := append(slices.Clone(accepted), hygienePin{module: t.module, version: version, ids: t.vulnIDs})
				out, err := try("hygiene: "+t.module, pins)
				if errors.Is(err, errHygieneBudget) {
					stopped = err.Error()
					break search
				}
				if err != nil {
					return nil, err
				}
				lastAccepted = out.why == ""
				if lastAccepted {
					accepted, acceptedOut = pins, out
					delete(whys, t.module)
					break
				}
				whys[t.module] = out.why
			}
		}
	}
	l.linked, l.linkedPackages = savedLinked, savedPackages

	final := set
	if len(accepted) > 0 {
		final = withHygiene(set, accepted)
	}
	settled := lastAccepted || trials == 0
	if !settled {
		// Leave the checkout holding the final set, as the build will (a
		// later modroot of the same clone may depend on it).
		if fail := l.engine.apply(ctx, final); fail != nil {
			if cerr := ctx.Err(); errors.Is(cerr, context.Canceled) {
				return nil, cerr
			}
			if ierr := l.recordInfra(fail.err); ierr != nil {
				return nil, ierr
			}
		} else {
			settled = true
		}
	}
	l.rejectHygiene(ctx, targets, accepted, whys, stopped)
	logging.From(ctx).Info("scanner hygiene pass", "modroot", l.req.Modroot, "targets", len(targets),
		"accepted", len(accepted), "trials", trials, "duration", time.Since(start).Round(time.Millisecond))
	if len(accepted) == 0 {
		return resolved, nil
	}

	l.adoptHygiene(accepted)
	l.requirements, l.replaces = acceptedOut.st.requires, acceptedOut.st.replaces
	l.linked, l.linkedPackages = acceptedOut.linked, acceptedOut.linkedPackages
	l.scanResiduals = acceptedOut.residuals
	if !settled {
		return acceptedOut.resolved, nil // disk state unknown: keep the superset stdlib slice
	}
	if std := l.linkedStdPackages(ctx); std != nil {
		result.StdPackages = std
	}
	return acceptedOut.resolved, nil
}

// hygieneTargets turns scanFindings' hygiene findings into targets, most
// severe first, then by module. A module held by a user-authored replace or
// an ambiguity remedy is left alone, as is a fix at or above a version that
// could not be fetched (see stepDown).
func (l *loop) hygieneTargets(found []raise, resolved map[string]string) []hygieneTarget {
	var targets []hygieneTarget
	for _, r := range found {
		if c := l.byModule[r.module]; c != nil && ((!c.dropped && (c.Replace || c.remedy)) ||
			(c.ceiling != "" && semver.Compare(r.version, c.ceiling) >= 0)) {
			continue
		}
		t := hygieneTarget{raise: r, versions: []string{r.version}}
		for _, c := range l.cands {
			if c.Module == r.module && semver.Compare(c.hygieneSeed, t.seed) > 0 {
				t.seed = c.hygieneSeed
			}
		}
		switch rel := semver.Compare(t.seed, r.version); {
		case t.seed == "":
		case rel > 0 && !majorChange(r.module, t.seed, resolved[r.module]):
			t.versions = []string{t.seed, r.version}
		case rel == 0:
			t.versions = []string{scan.PreferVersion(r.version, t.seed)}
		}
		targets = append(targets, t)
	}
	slices.SortFunc(targets, func(a, b hygieneTarget) int {
		return cmp.Or(cmp.Compare(scan.SeverityRank(a.severity), scan.SeverityRank(b.severity)), strings.Compare(a.module, b.module))
	})
	return targets
}

// hygieneTrial applies set with pins on top (see withHygiene) and judges
// whether the result is free against ref (see hygienePass). A verdict is an
// outcome; an error means the search cannot continue (cancellation,
// infrastructure, toolchain or scanner failure).
func (l *loop) hygieneTrial(ctx context.Context, purpose string, set []*candState, pins []hygienePin, ref *goModState, maxGo string, baseResiduals []Residual) (*hygieneOutcome, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	trialPins := withHygiene(set, pins)
	notFree := func(why string) (*hygieneOutcome, error) {
		l.logTrial(ctx, trialLog{purpose: purpose, pins: trialPins, reject: "not free: " + why})
		return &hygieneOutcome{why: why}, nil
	}
	if fail := l.engine.apply(ctx, trialPins); fail != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if ierr := l.recordInfra(fail.err); ierr != nil {
			return nil, ierr
		}
		return notFree("does not apply: " + firstLine(fail.err.Error()))
	}
	st, err := l.readGoModState(ctx)
	if err != nil {
		return nil, err
	}
	if why := hygieneDiff(ref, st, pins); why != "" {
		return notFree(why)
	}
	switch depGo := l.maxDepGoVersion(ctx); {
	case depGo == "" || maxGo == "":
		return notFree("dependency Go version unknown")
	case goversion.Compare(depGo, maxGo) > 0:
		return notFree(fmt.Sprintf("raises dependency Go %s->%s", maxGo, depGo))
	}
	report, err := l.compiler.Compile(ctx, l.dir, l.buildPatterns, l.req.Tags)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		if ierr := l.recordInfra(err); ierr != nil {
			return nil, ierr
		}
		return notFree("compile check failed: " + firstLine(err.Error()))
	}
	failures := make(map[string][]string)
	for pkg, lines := range report.Failed {
		if _, known := l.baselineFailed[pkg]; !known {
			failures[pkg] = lines
		}
	}
	if len(failures) > 0 {
		return notFree("breaks compile: " + firstCompileError(failures))
	}
	resolved, err := l.tc.ListModules(ctx, l.dir)
	if err != nil {
		return nil, err
	}
	l.refreshLinked(ctx)
	scanResult, err := l.sc.ScanPackages(ctx, l.scanTargets(resolved, st.requires, st.replaces))
	if err != nil {
		return nil, err
	}
	raises, residuals, _ := l.scanFindings(scanResult, resolved)
	if len(raises) > 0 {
		coords := make([]string, 0, len(raises))
		for _, r := range raises {
			coords = append(coords, r.module+"@"+r.version)
		}
		return notFree("needs further raises: " + strings.Join(coords, ", "))
	}
	if ids := newVulnIDs(residuals, baseResiduals); len(ids) > 0 {
		return notFree("introduces " + strings.Join(ids, ", "))
	}
	l.logTrial(ctx, trialLog{purpose: purpose, pins: trialPins, resolved: resolved, residuals: len(residuals)})
	return &hygieneOutcome{st: st, resolved: resolved, linked: l.linked, linkedPackages: l.linkedPackages, residuals: residuals}, nil
}

// hygieneDiff reports how st differs from ref beyond the pins' own modules
// moving to exactly the pins' versions ("" when it does not).
func hygieneDiff(ref, st *goModState, pins []hygienePin) string {
	if st.goLines != ref.goLines {
		return fmt.Sprintf("changes the go/toolchain lines (%q -> %q)", ref.goLines, st.goLines)
	}
	if !maps.Equal(st.replaces, ref.replaces) {
		return "changes replace directives"
	}
	want := make(map[string]string, len(pins))
	for _, p := range pins {
		want[p.module] = p.version
		if _, ok := ref.requires[p.module]; !ok {
			return "adds " + p.module + " to go.mod"
		}
		if got := st.requires[p.module]; got != p.version {
			return fmt.Sprintf("go.mod keeps %s at %s, not %s", p.module, orNone(got), p.version)
		}
	}
	if changes := mapChanges(ref.requires, st.requires, want); len(changes) > 0 {
		return capList(changes)
	}
	if ref.graph != nil {
		if changes := mapChanges(ref.graph, st.graph, want); len(changes) > 0 {
			return "build list " + capList(changes)
		}
	}
	return ""
}

// mapChanges lists the modules whose version differs between before and
// after, skipping those at exactly their pinned version, in module order.
func mapChanges(before, after, pinned map[string]string) []string {
	modules := slices.Sorted(maps.Keys(before))
	for module := range after {
		if _, ok := before[module]; !ok {
			modules = append(modules, module)
		}
	}
	slices.Sort(modules)
	var changes []string
	for _, module := range slices.Compact(modules) {
		from, had := before[module]
		to, has := after[module]
		switch {
		case has && pinned[module] == to:
		case !had:
			changes = append(changes, "adds "+module+"@"+to)
		case !has:
			changes = append(changes, "removes "+module)
		case from != to:
			changes = append(changes, "changes "+module+" "+from+"->"+to)
		}
	}
	return changes
}

// capList joins up to maxHygieneDiff entries, with a "+N more" tail.
func capList(entries []string) string {
	if len(entries) > maxHygieneDiff {
		return strings.Join(entries[:maxHygieneDiff], ", ") + fmt.Sprintf(", +%d more", len(entries)-maxHygieneDiff)
	}
	return strings.Join(entries, ", ")
}

func orNone(v string) string {
	if v == "" {
		return "none"
	}
	return v
}

// withHygiene is set with pins applied on top, in the order the build's
// step will see them: a pin for a module set already carries raises that
// entry in place, the others follow set in pin order.
func withHygiene(set []*candState, pins []hygienePin) []*candState {
	at := make(map[string]int, len(pins))
	for i, p := range pins {
		at[p.module] = i
	}
	out := make([]*candState, 0, len(set)+len(pins))
	placed := make(map[string]bool, len(pins))
	for _, c := range set {
		if i, ok := at[c.Module]; ok && !c.Replace {
			pin := *c
			pin.Version, pin.hygieneIDs = pins[i].version, pins[i].ids
			out = append(out, &pin)
			placed[c.Module] = true
			continue
		}
		out = append(out, c)
	}
	for _, p := range pins {
		if !placed[p.module] {
			out = append(out, &candState{Candidate: Candidate{Module: p.module, Version: p.version}, hygieneIDs: p.ids})
		}
	}
	return out
}

// adoptHygiene commits accepted pins to the candidates exactly as
// withHygiene laid them out: an active entry is raised in place, any other
// module gets a new entry (after every existing one). A seed shed for its
// unlinked advisories is kept after all, so its drop record is withdrawn.
func (l *loop) adoptHygiene(accepted []hygienePin) {
	for _, p := range accepted {
		if c := l.byModule[p.module]; c != nil && !c.dropped {
			c.Version, c.hygieneIDs = p.version, p.ids
			continue
		}
		for _, c := range l.cands {
			if c.Module == p.module && c.dropped && c.shedUnlinked && c.hygieneSeed != "" {
				l.dropped = slices.DeleteFunc(l.dropped, func(d DroppedCandidate) bool {
					return d.Module == c.Module && d.Reason == c.dropReason
				})
			}
		}
		l.addCandidate(Candidate{Module: p.module, Version: p.version}, false).hygieneIDs = p.ids
	}
}

// rejectHygiene records every target not accepted as a dropped hygiene
// bump with the reason it is not free (or why it was not evaluated). A pin
// a seed carried in is reported as shed: its shed record (see
// dropUnreachable) is reworded, or added for a trimmed active entry.
func (l *loop) rejectHygiene(ctx context.Context, targets []hygieneTarget, accepted []hygienePin, whys map[string]string, stopped string) {
	for _, t := range targets {
		if slices.ContainsFunc(accepted, func(p hygienePin) bool { return p.module == t.module }) {
			continue
		}
		why, ok := whys[t.module]
		if !ok {
			why = "not evaluated: " + stopped
		}
		logging.From(ctx).Info("scanner hygiene bump not free - not proposed", "modroot", l.req.Modroot,
			"module", t.module, "version", t.version, "vulns", strings.Join(t.vulnIDs, ","), "reason", why)
		if t.seed == "" {
			l.dropped = append(l.dropped, DroppedCandidate{Module: t.module, Version: t.version,
				Reason: "scanner hygiene: not free (" + why + ")", Hygiene: true})
			continue
		}
		reason := fmt.Sprintf("shed: scanner hygiene pin %s@%s not free (%s)", t.module, t.seed, why)
		reworded := false
		for _, c := range l.cands {
			if c.Module != t.module || c.hygieneSeed != t.seed || !c.dropped || !c.shedUnlinked {
				continue
			}
			for i := range l.dropped {
				if d := &l.dropped[i]; d.Module == c.Module && d.Reason == c.dropReason {
					d.Version, d.Reason, d.Hygiene = t.seed, reason, true
					reworded = true
				}
			}
			c.dropReason = reason
		}
		if !reworded {
			l.dropped = append(l.dropped, DroppedCandidate{Module: t.module, Version: t.seed, Reason: reason, Hygiene: true})
		}
	}
}

// hygieneModules lists the final scanner-hygiene entries, by module.
func (l *loop) hygieneModules() []HygieneModule {
	var modules []HygieneModule
	for _, c := range l.activeCandidates() {
		if len(c.hygieneIDs) > 0 {
			modules = append(modules, HygieneModule{Module: c.Module, Version: c.Version, VulnIDs: c.hygieneIDs})
		}
	}
	slices.SortFunc(modules, func(a, b HygieneModule) int { return strings.Compare(a.Module, b.Module) })
	return modules
}
