package simulate

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/isometry/choam/internal/logging"
	"github.com/isometry/choam/internal/scan"
	"golang.org/x/mod/semver"
)

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

// compileBaseline compiles the pristine checkout once per target arch,
// after the initial tidy: packages that already fail there (missing C
// libraries, generated code, host-only noise) are excluded from every later
// verdict, so only failures a bump introduces count. The arches compile
// concurrently; the primary arch's failures are baselineFailed, the others'
// archBaselineFailed (for crossArchCompile).
func (l *loop) compileBaseline(ctx context.Context) error {
	if err := l.engine.tidyBaseline(ctx); err != nil {
		return gateErr(ctx, fmt.Errorf("baseline go mod tidy: %w", err))
	}
	resolved, err := l.tc.ListModules(ctx, l.dir)
	if err != nil {
		return gateErr(ctx, err)
	}
	reports, err := l.compileArches(ctx, l.target.Arches)
	if err != nil {
		return gateErr(ctx, fmt.Errorf("baseline: %w", err))
	}
	l.baselineResolved = resolved
	l.archBaselineFailed = make(map[string]map[string]struct{}, len(reports)-1)
	for i, report := range reports {
		failed := make(map[string]struct{}, len(report.Failed))
		for pkg := range report.Failed {
			failed[pkg] = struct{}{}
		}
		arch := l.target.Arches[i]
		if i == 0 {
			l.baselineFailed = failed
			if len(failed) > 0 {
				l.baselineFirst = firstCompileError(report.Failed)
			}
		} else {
			l.archBaselineFailed[arch] = failed
		}
		if len(report.Failed) > 0 {
			logging.From(ctx).Debug("compile gate baseline: packages already failing are excluded",
				"modroot", l.req.Modroot, "arch", arch, "count", len(report.Failed), "first", firstCompileError(report.Failed))
		}
	}
	return nil
}

// compileArches compiles the checkout for each of arches concurrently,
// returning the reports in arch order; the error is the first failing
// arch's in arch order (every compile runs to completion).
func (l *loop) compileArches(ctx context.Context, arches []string) ([]*CompileReport, error) {
	reports := make([]*CompileReport, len(arches))
	errs := make([]error, len(arches))
	var wg sync.WaitGroup
	for i, arch := range arches {
		wg.Go(func() { reports[i], errs[i] = l.compiler.Compile(ctx, l.dir, l.target, arch) })
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("GOARCH=%s: %w", arches[i], err)
		}
	}
	return reports, nil
}

// crossArchCompile compiles the final set once on each target arch besides
// the primary one (the gate's and the hygiene trials' arch, which bounds
// their cost): a failure that arch's baseline did not have fails the
// simulation closed (ErrCompileGate) - the set was never proven to build
// there. The checkout is re-applied to the final set first (a trial may
// have left another state). Nothing to do without the compile gate, with a
// single arch, or with no entry to write.
func (l *loop) crossArchCompile(ctx context.Context) error {
	final := l.inApplyOrder(l.activeCandidates())
	if l.compiler == nil || len(l.target.Arches) < 2 || len(final) == 0 {
		return nil
	}
	start := time.Now()
	if fail := l.engine.apply(ctx, final); fail != nil {
		return gateErr(ctx, fmt.Errorf("re-applying the final set for the cross-arch compile: %w", fail.err))
	}
	arches := l.target.Arches[1:]
	reports, err := l.compileArches(ctx, arches)
	if err != nil {
		return gateErr(ctx, err)
	}
	for i, report := range reports {
		failures := make(map[string][]string)
		for pkg, lines := range report.Failed {
			if _, known := l.archBaselineFailed[arches[i]][pkg]; !known {
				failures[pkg] = lines
			}
		}
		if len(failures) > 0 {
			return gateErr(ctx, fmt.Errorf("the final bump set breaks the GOARCH=%s build: %s", arches[i], firstCompileError(failures)))
		}
	}
	logging.From(ctx).Info("cross-arch compile passed", "modroot", l.req.Modroot, "arches", strings.Join(arches, ","),
		"duration", time.Since(start).Round(time.Millisecond))
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
func (l *loop) compileGate(ctx context.Context, resolved map[string]string, result *ModrootResult) (map[string]string, bool, error) {
	active := l.inApplyOrder(l.activeCandidates())
	if len(active) == 0 {
		return resolved, false, nil
	}
	g := &gateRun{ladders: make(map[*candState][]Rung, len(active)), at: make(map[*candState]int, len(active))}
	for _, c := range active {
		g.ladders[c] = l.ladder(c)
	}
	if l.gateRejected == nil {
		l.gateRejected = make(map[string]string)
	}
	rejected := l.gateRejected // module -> why its higher rung was rejected

	purpose, subject := "gate: converged set", ""
	for {
		live := slices.DeleteFunc(slices.Clone(active), func(c *candState) bool { return c.isDropped() })
		out, repairs, err := l.repairFixpoint(ctx, g, purpose, subject, live)
		if err != nil {
			return nil, false, err
		}
		if out.passed() {
			if len(rejected) == 0 && len(repairs) == 0 && len(l.revived) == 0 {
				logging.From(ctx).Debug("compile gate passed", "modroot", l.req.Modroot, "candidates", len(live))
				return resolved, false, nil
			}
			return l.gateAdopt(ctx, g, live, repairs, rejected, result)
		}
		if purpose == "gate: converged set" {
			logging.From(ctx).Info("compile gate: converged bump set breaks the build",
				"modroot", l.req.Modroot, "first", firstLine(out.why()))
		}

		victim := l.relaxTarget(ctx, g, out, live)
		if victim == nil {
			return nil, false, gateErr(ctx, fmt.Errorf("the build fails with every bump relaxed: %s", out.why()))
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
		switch rel := semver.Compare(r.Version, c.Version); {
		case rel == 0:
			top = Rung{Version: scan.PreferVersion(top.Version, r.Version), VulnIDs: r.VulnIDs, Severity: r.Severity}
		case rel < 0 && semver.Compare(r.Version, l.baselineResolved[c.Module]) > 0:
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
	report, err := l.compiler.Compile(ctx, l.dir, l.target, l.target.Arches[0])
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
func (l *loop) gateAdopt(ctx context.Context, g *gateRun, live []*candState, repairs, rejected map[string]string, result *ModrootResult) (map[string]string, bool, error) {
	for _, c := range live {
		c.Version = g.rung(c).Version
	}
	for _, module := range sortedKeys(repairs) {
		if c, ok := l.byModule[module]; ok && !c.isDropped() {
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
// rescans, and refreshes the loop's accepted state. The rescan is the
// authoritative reachability judgement - it is made on the graph that ships
// - so a fix shed as unlinked under the (since rejected) full set whose
// vulnerable code the gated graph links again is revived, and the caller
// runs the gate once more with it (again=true): the result must not depend
// on which higher pins the input happened to carry. An advisory the rescan
// still finds for a module whose higher rung was rejected is a residual
// carrying that rejection; any other fix the rescan wants is surfaced as a
// residual rather than raised (it was never compile-validated).
func (l *loop) gateFinish(ctx context.Context, keep []*candState, rejected map[string]string, result *ModrootResult) (map[string]string, bool, error) {
	tr, err := l.trialApply(ctx, "gate: adopt accepted set", keep)
	if err != nil {
		return nil, false, gateErr(ctx, fmt.Errorf("re-applying the accepted set: %w", err))
	}
	if !l.sustained(tr, keep) {
		logging.From(ctx).Warn("compile gate: accepted set not fully sustained by the tidied go.mod",
			"modroot", l.req.Modroot)
	}
	l.adoptTrial(ctx, tr, result)
	if l.reviveRelinked(ctx, tr.raises) {
		return tr.resolved, true, nil
	}
	for _, r := range tr.raises {
		reason, wasRejected := rejected[r.module]
		switch c := l.byModule[r.module]; {
		case wasRejected:
		case c != nil && c.isDropped() && c.shedUnlinked:
			reason = "vulnerable code linked again after compile-gate adjustments (fix was shed as unlinked under the full bump set); fix not validated"
		default:
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
	return tr.resolved, false, nil
}

// reviveRelinked brings back every candidate dropUnreachable shed (and not
// yet revived) that a gated rescan wants raised again, withdrawing its drop
// record. Reports whether anything was revived.
func (l *loop) reviveRelinked(ctx context.Context, raises []raise) bool {
	if l.revived == nil {
		l.revived = make(map[string]bool)
	}
	revivedAny := false
	for _, r := range raises {
		c := l.byModule[r.module]
		if c == nil || !c.isDropped() || !c.shedUnlinked || l.revived[r.module] {
			continue
		}
		l.dropped = slices.DeleteFunc(l.dropped, func(d DroppedCandidate) bool {
			return d.Module == c.Module && d.Reason == c.dropReason
		})
		c.residualized, c.shedUnlinked, c.dropReason, c.hygieneSeed = false, false, "", ""
		l.revived[r.module] = true
		revivedAny = true
		logging.From(ctx).Info("compile gate: vulnerable code linked again - fix revived for another gate round",
			"modroot", l.req.Modroot, "module", c.Module, "version", c.Version)
	}
	return revivedAny
}
