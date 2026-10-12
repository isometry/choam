package simulate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/isometry/choam/internal/logging"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

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
		active := ok && !existing.isDropped()
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
		if c.isDropped() || !eligible(c) {
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

// stepDown moves CVE candidate c, whose current version cannot be fetched
// or is not sustained by the tidy, to its next lower fix rung still above the baseline, giving up the
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
	for _, r := range below {
		kept = mergeIDs(kept, r.VulnIDs)
	}
	severity := rungSeverity(below)
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
	logging.From(ctx).Info("bump stepped down one fix rung", "modroot", l.req.Modroot,
		"module", c.Module, "from", rejected, "to", c.Version, "reason", reason)
}

// dropLatestRaise handles a final-tidy failure by removing a raised
// (non-seed, non-remedy) candidate - the likeliest culprit for a graph that
// resolves per-module but won't tidy. Returns false when no raise is left to
// sacrifice.
func (l *loop) dropLatestRaise(err error) bool {
	return l.shedCandidate(err, func(c *candState) bool { return !c.seed && !c.remedy })
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
