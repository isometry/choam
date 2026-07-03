package simulate

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/isometry/choam/internal/scan"
	"golang.org/x/mod/semver"
)

// latestQuery is the go tool's "highest release" version query, used as the
// fallback when a CVE-backed candidate's exact fix version fails to resolve.
const latestQuery = "latest"

// candState is a Candidate plus its lifecycle within the loop.
type candState struct {
	Candidate
	seed        bool // seeded by the caller (vs raised by a rescan)
	remedy      bool // added to repair an ambiguous import (applied first)
	dropped     bool
	origVersion string // pre-@latest-fallback version, for reporting
}

type loop struct {
	tc   Toolchain
	sc   Scanner
	dir  string
	req  ModrootRequest
	opts Options

	cands    []*candState
	byModule map[string]*candState

	pristine map[string][]byte // go.mod/go.sum contents at clone time

	dropped             []DroppedCandidate
	persistentResiduals []Residual // apply-time failures: survive rescans
	scanResiduals       []Residual // recomputed from each rescan
	lastRaised          []*candState
	remedied            map[string]struct{} // modules already advanced to repair an ambiguous import
	requirements        map[string]string   // go.mod requires after the last clean apply

	replaces         map[string]ReplaceTarget // go.mod replace directives after the last clean apply
	pristineReplaces map[string]ReplaceTarget // upstream go.mod replace directives at clone time
	promoted         map[string]struct{}      // modules promoted deps->replace (once each)

	// Artifact reachability: buildPatterns are the go/build package patterns
	// (default ./...) whose non-test import graph decides what actually
	// ships; linked is the module set from the last LinkedModules query, nil
	// when unknown (query failed) - reachability then fails OPEN and no
	// filtering happens.
	buildPatterns []string
	linked        map[string]struct{}
	linkedWarned  bool
}

// raise is a rescan finding that requires moving a module further forward.
type raise struct {
	module  string
	version string
	vulnIDs []string
}

// RunLoop applies the seed candidates to the module at dir with the real go
// toolchain, rescans the resolved graph, raises versions for any residual
// advisories, and iterates to a fixpoint (see package doc). It returns a
// ModrootResult even on non-convergence (Converged=false); an error return
// means the simulation itself could not run (unreadable module, toolchain or
// scanner failure) and the caller should fall back to unvalidated behavior.
func RunLoop(ctx context.Context, tc Toolchain, sc Scanner, dir string, req ModrootRequest, opts Options) (*ModrootResult, error) {
	opts = opts.WithDefaults()

	l := &loop{
		tc:            tc,
		sc:            sc,
		dir:           dir,
		req:           req,
		opts:          opts,
		byModule:      make(map[string]*candState),
		remedied:      make(map[string]struct{}),
		promoted:      make(map[string]struct{}),
		buildPatterns: req.Packages,
	}
	if len(l.buildPatterns) == 0 {
		l.buildPatterns = []string{"./..."}
	}
	if err := l.savePristine(); err != nil {
		return nil, err
	}
	pristineReplaces, err := tc.Replaces(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("reading upstream replace directives: %w", err)
	}
	l.pristineReplaces = pristineReplaces

	for _, seed := range req.Seeds {
		l.seedCandidate(seed)
	}

	result := &ModrootResult{Modroot: req.Modroot}

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

		scanResult, err := l.sc.ScanPackages(ctx, l.scanTargets(resolved))
		if err != nil {
			return nil, err
		}

		raises := l.processScan(scanResult, resolved)
		if len(raises) == 0 {
			result.Converged = true
			break
		}
	}

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
		resolved = l.confirmMinimalSet(ctx, resolved)
	}

	result.Resolved = resolved
	result.Linked = l.linked
	result.Requires = l.requirements
	result.FinalDeps, result.FinalReplaces, result.CVEBackedModules = l.finalOutputs(resolved)
	result.Dropped = l.dropped
	result.Residuals = append(append([]Residual{}, l.persistentResiduals...), l.scanResiduals...)
	sort.Slice(result.Residuals, func(i, j int) bool { return result.Residuals[i].Module < result.Residuals[j].Module })
	result.RemainingVulnIDs = remainingVulnIDs(result.Residuals)

	return result, nil
}

// seedCandidate routes one caller-provided seed into the right channel.
// Replace seeds (user-authored YAML replaces) enter as-is; a deps seed for a
// module that is already replace-pinned - by an earlier replace seed or by
// the upstream go.mod - is either superseded (candidate exists) or converted
// to the replace channel (a `go get` cannot out-vote a replace directive).
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
		l.addCandidate(Candidate{
			Module: target.Path, Version: c.Version, FromCVE: c.FromCVE, VulnIDs: c.VulnIDs,
			Replace: true, ReplaceOld: oldPath,
		}, true)
		return
	}

	l.addCandidate(c, true)
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
		if semver.Compare(c.Version, existing.Version) > 0 {
			existing.Version = c.Version
		}
		existing.FromCVE = existing.FromCVE || c.FromCVE
		existing.VulnIDs = mergeIDs(existing.VulnIDs, c.VulnIDs)
		return existing
	}
	state := &candState{Candidate: c, seed: seed}
	l.cands = append(l.cands, state)
	l.byModule[c.Module] = state
	return state
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
// tagged state - only these two files change under -mod=mod.
func (l *loop) savePristine() error {
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

func (l *loop) restore() error {
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
// applied, in gobump-parity order: tidy first (what melange's go/bump does),
// then one `go get` per candidate, then a final tidy. Any failure repairs or
// removes exactly one candidate and restarts the attempt, so the loop is
// bounded by the candidate count (a repair happens at most once per module).
func (l *loop) apply(ctx context.Context) error {
	for attempt := 0; attempt < 3*len(l.cands)+8; attempt++ {
		if err := l.restore(); err != nil {
			return err
		}
		if err := l.tc.ModTidy(ctx, l.dir); err != nil {
			return fmt.Errorf("initial go mod tidy: %w", err)
		}

		// Replace directives first (gobump parity), then the gets. A
		// replace edit is syntactic - failure is fatal, not a graph problem.
		for _, c := range l.activeCandidates() {
			if !c.Replace {
				continue
			}
			if c.Version == latestQuery {
				return fmt.Errorf("internal error: replace candidate %s has unresolved @latest version", c.Module)
			}
			if err := l.tc.Replace(ctx, l.dir, c.OldPath(), c.Module, c.Version); err != nil {
				return fmt.Errorf("applying replace %s=%s@%s: %w", c.OldPath(), c.Module, c.Version, err)
			}
		}

		failed := false
		for _, c := range l.applyOrder() {
			if err := l.tc.Get(ctx, l.dir, c.Module+"@"+c.Version); err != nil {
				l.handleGetFailure(c, err)
				failed = true
				break
			}
		}
		if failed {
			continue
		}

		if err := l.tc.ModTidy(ctx, l.dir); err != nil {
			if l.handleTidyFailure(err) {
				continue
			}
			return fmt.Errorf("final go mod tidy: %w", err)
		}
		return nil
	}
	return fmt.Errorf("module graph did not stabilize after %d apply attempts", 3*len(l.cands)+8)
}

// handleTidyFailure repairs or sheds exactly one candidate after a
// failed attempt-closing tidy, in escalating order of sacrifice:
//  1. Repair a monolith-vs-split-module "ambiguous import" by advancing the
//     monolith module past the split point (once per module).
//  2. Promote the CVE-backed deps candidate the failure names to a replace
//     directive (once per module) - replace-pinned modules resolve without
//     graph negotiation, so this often repairs what a require pin breaks.
//  3. Drop the most recently raised (non-seed) candidate - the likeliest
//     culprit for a graph that resolves per-module but won't tidy.
//  4. Drop the last coherence-only seed.
//  5. Drop the last CVE-backed candidate, recording its advisories as
//     residuals ("bump as high as viable, report the rest").
//  6. Only then drop remedies - they are load-bearing repairs, not
//     candidates, and must outlive the candidates that depend on them.
//
// Returns false only when nothing is left to shed.
func (l *loop) handleTidyFailure(err error) bool {
	if l.addAmbiguityRemedies(err) {
		return true
	}
	if l.promoteBlamedCandidate(err) {
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

// promoteBlamedCandidate promotes the most recently added CVE-backed deps
// candidate whose module path is named in the failure text. Blame-gated:
// promoting an uninvolved candidate would just churn apply attempts.
func (l *loop) promoteBlamedCandidate(err error) bool {
	errText := err.Error()
	for i := len(l.cands) - 1; i >= 0; i-- {
		c := l.cands[i]
		if c.dropped || c.Replace || !c.FromCVE || c.Version == latestQuery {
			continue
		}
		if _, done := l.promoted[c.Module]; done {
			continue
		}
		if !strings.Contains(errText, c.Module) {
			continue
		}
		return l.promoteCandidate(c)
	}
	return false
}

// addAmbiguityRemedies parses "ambiguous import: found package ... in
// multiple modules" tidy failures and advances the monolith module of each
// ambiguous pair to @latest, past the point where the split module took the
// packages over (the canonical google.golang.org/genproto case). Returns
// true when it changed at least one candidate.
func (l *loop) addAmbiguityRemedies(err error) bool {
	changed := false
	for _, module := range ambiguousImportModules(err.Error()) {
		if _, done := l.remedied[module]; done {
			continue
		}
		l.remedied[module] = struct{}{}

		if existing, ok := l.byModule[module]; ok && !existing.dropped {
			if existing.Replace {
				// A remedy is a `go get @latest`, which cannot move a
				// replace-pinned module. Shed a promotion so the ordinary
				// remedy can take over; a seed replace is user intent and
				// stays - let the sacrifice ladder proceed instead.
				if _, wasPromoted := l.promoted[module]; !wasPromoted {
					continue
				}
				existing.dropped = true
				l.dropped = append(l.dropped, DroppedCandidate{
					Module:  module,
					Version: existing.Version,
					Reason:  "promotion conflicts with ambiguous-import repair",
				})
				if existing.FromCVE {
					l.persistentResiduals = append(l.persistentResiduals, Residual{
						Module:       module,
						FixedVersion: existing.Version,
						VulnIDs:      existing.VulnIDs,
						Reason:       "fix conflicts with ambiguous-import repair",
					})
				}
				delete(l.byModule, module)
				state := l.addCandidate(Candidate{Module: module, Version: latestQuery}, false)
				state.remedy = true
				changed = true
				continue
			}
			if existing.Version == latestQuery {
				continue
			}
			existing.origVersion = existing.Version
			existing.Version = latestQuery
			existing.remedy = true
			changed = true
			continue
		}
		if _, target, pinned := l.pristinePinFor(module); pinned && target.Version == "" {
			continue // local-path pinned: nothing can move it
		}
		state := l.addCandidate(Candidate{Module: module, Version: latestQuery}, false)
		state.remedy = true
		changed = true
	}
	return changed
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

	victim.dropped = true
	l.dropped = append(l.dropped, DroppedCandidate{
		Module:  victim.Module,
		Version: victim.Version,
		Reason:  fmt.Sprintf("removed to restore resolvability: %v", err),
	})
	if victim.FromCVE {
		l.persistentResiduals = append(l.persistentResiduals, Residual{
			Module:       victim.Module,
			FixedVersion: victim.Version,
			VulnIDs:      victim.VulnIDs,
			Reason:       fmt.Sprintf("fix breaks module graph: %v", err),
		})
	}
	return true
}

// applyOrder returns the active candidates to `go get`, with ambiguity
// remedies first: an ambiguous import blocks the `go get` of the module that
// trips it, so the repair must land before that module is fetched.
// Replace-channel candidates are excluded - they are applied as go.mod
// edits before any get (see apply).
func (l *loop) applyOrder() []*candState {
	active := l.activeCandidates()
	ordered := make([]*candState, 0, len(active))
	for _, c := range active {
		if c.remedy && !c.Replace {
			ordered = append(ordered, c)
		}
	}
	for _, c := range active {
		if !c.remedy && !c.Replace {
			ordered = append(ordered, c)
		}
	}
	return ordered
}

// handleGetFailure implements the repair-then-sacrifice policy: an
// ambiguous-import failure is repaired without penalizing the candidate;
// otherwise coherence-only candidates are dropped outright, and CVE-backed
// candidates get one retry at @latest, then one promotion to a replace
// directive (a `go mod edit -replace` needs no get-time resolution and
// survives tidy) before being dropped and reported as an unresolvable-fix
// residual.
func (l *loop) handleGetFailure(c *candState, err error) {
	if l.addAmbiguityRemedies(err) {
		return
	}
	if !c.FromCVE {
		c.dropped = true
		l.dropped = append(l.dropped, DroppedCandidate{
			Module:  c.Module,
			Version: c.Version,
			Reason:  fmt.Sprintf("unresolvable: %v", err),
		})
		return
	}
	if c.Version != latestQuery {
		c.origVersion = c.Version
		c.Version = latestQuery
		return
	}
	if l.promoteCandidate(c) {
		c.Version = c.origVersion // replaces carry the concrete fix version
		return
	}
	c.dropped = true
	l.dropped = append(l.dropped, DroppedCandidate{
		Module:  c.Module,
		Version: c.origVersion,
		Reason:  fmt.Sprintf("fix unresolvable even at @latest: %v", err),
	})
	l.persistentResiduals = append(l.persistentResiduals, Residual{
		Module:       c.Module,
		FixedVersion: c.origVersion,
		VulnIDs:      c.VulnIDs,
		Reason:       fmt.Sprintf("fix unresolvable: %v", err),
	})
}

// promoteCandidate moves a deps-channel candidate into the replace channel
// (self-replace at its current target), once per module. Returns false when
// the promotion was already spent or the candidate is already a replace.
func (l *loop) promoteCandidate(c *candState) bool {
	if c.Replace {
		return false
	}
	if _, done := l.promoted[c.Module]; done {
		return false
	}
	l.promoted[c.Module] = struct{}{}
	c.Replace = true
	c.ReplaceOld = c.Module
	return true
}

// dropLatestRaise handles a final-tidy failure by removing a raised
// (non-seed, non-remedy) candidate - the likeliest culprit for a graph that
// resolves per-module but won't tidy. Returns false when no raise is left to
// sacrifice.
func (l *loop) dropLatestRaise(err error) bool {
	return l.shedCandidate(err, func(c *candState) bool { return !c.seed && !c.remedy })
}

// dropUnsustained repairs or sheds candidates the tidied go.mod does not
// sustain: melange's gobump errors when a requested package is missing from
// the post-tidy go.mod ("was not found on the go.mod file") or is required
// at a version below the requested one ("is less than the desired version").
// A CVE-backed pin that tidy reverts is PROMOTED to a replace directive
// (once per module) - replaces survive tidy unconditionally and gobump
// verifies them against the Replace entries, not Require. Returns true when
// anything changed (the apply must then be redone).
// refreshLinked recomputes the artifact-linked module set for the current
// go.mod state. Recomputed every sustain pass rather than once: membership
// can drift as versions move (a raised module can import new modules - the
// genproto-split family is exactly this shape). Failure fails OPEN: linked
// becomes nil and no reachability filtering happens (warned once per loop).
func (l *loop) refreshLinked(ctx context.Context) {
	linked, err := l.tc.LinkedModules(ctx, l.dir, l.buildPatterns)
	if err != nil {
		if !l.linkedWarned {
			slog.Warn("artifact reachability unavailable - not filtering",
				"modroot", l.req.Modroot, "packages", strings.Join(l.buildPatterns, " "), "error", err)
			l.linkedWarned = true
		}
		l.linked = nil
		return
	}
	l.linked = linked
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

// scanTargets renders the resolved graph as OSV queries, restricted to
// modules linked into a build artifact - findings in unlinked modules can't
// affect anything that ships, and pre-filtering here (rather than
// partitioning findings afterwards) keeps scanFindings two-way and cuts both
// querybatch volume and per-finding detail fetches on every iteration.
func (l *loop) scanTargets(resolved map[string]string) []scan.Package {
	if l.linked == nil {
		return packagesFor(resolved)
	}
	filtered := make(map[string]string, len(resolved))
	for module, version := range resolved {
		if l.isLinked(module) {
			filtered[module] = version
		}
	}
	return packagesFor(filtered)
}

// dropUnreachable sheds every active candidate - seeds included, which is
// what prunes already-declared YAML deps - whose module is not linked into
// any build artifact. An unlinked module's replace directive is equally
// inert in the artifact, so replace seeds are shed too (the one exception to
// "seed replaces are user intent, never shed"). Unlike every other CVE-backed
// drop, NO residual is recorded: the advisory affects nothing that ships, so
// the fix is neither applied nor outstanding (the orchestrator reports such
// advisories separately, as info). Returns true when anything was shed.
func (l *loop) dropUnreachable() bool {
	if l.linked == nil {
		return false
	}
	changed := false
	for _, c := range l.activeCandidates() {
		if l.isLinked(c.Module) {
			continue
		}
		c.dropped = true
		l.dropped = append(l.dropped, DroppedCandidate{
			Module:  c.Module,
			Version: c.Version,
			Reason:  fmt.Sprintf("module not linked into build artifacts (packages: %s)", strings.Join(l.buildPatterns, " ")),
		})
		changed = true
	}
	return changed
}

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
			// module, so there is no fix to sustain (and no code shipped).
			c.dropped = true
			l.dropped = append(l.dropped, DroppedCandidate{
				Module:  c.Module,
				Version: c.Version,
				Reason:  "pruned by go mod tidy: not required by the tidied go.mod",
			})
			changed = true
		case c.Version != latestQuery && semver.Compare(requiredVersion, c.Version) < 0:
			if c.FromCVE {
				if _, done := l.promoted[c.Module]; !done {
					// Promote: apply the validated fix version as a replace
					// directive instead of shedding it.
					l.promoted[c.Module] = struct{}{}
					c.Replace = true
					c.ReplaceOld = c.Module
					changed = true
					continue
				}
			}
			c.dropped = true
			l.dropped = append(l.dropped, DroppedCandidate{
				Module:  c.Module,
				Version: c.Version,
				Reason:  fmt.Sprintf("go mod tidy reverts the pin to %s", requiredVersion),
			})
			if c.FromCVE {
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

// checkReplaceCandidate verifies a replace-channel candidate against the
// tidied go.mod: the directive must be present at >= the requested version
// (always true after a clean apply - defensively shed otherwise), and a
// PROMOTED replace whose module the build graph no longer requires is inert
// and dropped (a seed replace is user intent and preserved). Returns true
// when the candidate was shed.
func (l *loop) checkReplaceCandidate(c *candState) bool {
	target, present := l.replaces[c.OldPath()]
	if !present || target.Path != c.Module ||
		(c.Version != latestQuery && semver.Compare(target.Version, c.Version) < 0) {
		c.dropped = true
		l.dropped = append(l.dropped, DroppedCandidate{
			Module:  c.Module,
			Version: c.Version,
			Reason:  "replace directive not sustained by the tidied go.mod",
		})
		if c.FromCVE {
			l.persistentResiduals = append(l.persistentResiduals, Residual{
				Module:       c.Module,
				FixedVersion: c.Version,
				VulnIDs:      c.VulnIDs,
				Reason:       "fix not sustained: replace directive lost during tidy",
			})
		}
		return true
	}

	if _, wasPromoted := l.promoted[c.Module]; wasPromoted {
		_, oldRequired := l.requirements[c.OldPath()]
		_, newRequired := l.requirements[c.Module]
		if !oldRequired && !newRequired {
			c.dropped = true
			l.dropped = append(l.dropped, DroppedCandidate{
				Module:  c.Module,
				Version: c.Version,
				Reason:  "pruned by go mod tidy: replaced module no longer required",
			})
			return true
		}
	}
	return false
}

// processScan converts a rescan of the resolved graph into raised candidates
// and recomputed scan residuals. It returns the raises applied this round.
func (l *loop) processScan(scanResult *scan.ScanResult, resolved map[string]string) []raise {
	raises, residuals := l.scanFindings(scanResult, resolved)
	l.scanResiduals = residuals

	l.lastRaised = l.lastRaised[:0]
	applied := make([]raise, 0, len(raises))
	for _, r := range raises {
		if existing, ok := l.byModule[r.module]; ok && existing.dropped {
			if existing.FromCVE {
				// Already proven unresolvable - the residual stands.
				continue
			}
			// Dropped as a coherence hint; a CVE now demands it, so try
			// again as a defended candidate.
			delete(l.byModule, r.module)
		}
		if existing, ok := l.byModule[r.module]; ok &&
			existing.Version != latestQuery &&
			semver.Compare(r.version, existing.Version) <= 0 {
			// Already at or above the requested fix; nothing to raise. (A
			// rescan should not produce this - it scans the resolved graph -
			// but guard against loops.)
			continue
		}
		candidate := Candidate{
			Module:  r.module,
			Version: r.version,
			FromCVE: true,
			VulnIDs: r.vulnIDs,
		}
		// A raise for a replace-pinned module must update the replace - a
		// plain `go get` cannot out-vote the directive. (Local-path pins
		// never surface here: ListModules skips them, so they're never
		// scanned.) The scan reports the replacement path, so identity
		// already matches the replace candidate/directive target.
		if existing, ok := l.byModule[r.module]; ok && !existing.dropped && existing.Replace {
			candidate.Replace, candidate.ReplaceOld = true, existing.ReplaceOld
		} else if oldPath, target, pinned := l.pristinePinFor(r.module); pinned && target.Version != "" {
			candidate.Replace, candidate.ReplaceOld = true, oldPath
		}
		state := l.addCandidate(candidate, false)
		l.lastRaised = append(l.lastRaised, state)
		applied = append(applied, r)
	}
	return applied
}

// scanFindings classifies a scan of the resolved graph without mutating loop
// state: advisories whose fix can be applied become raises; the rest become
// residuals (no released fix, or the fix requires a major-version import
// path change that go/bump cannot express).
func (l *loop) scanFindings(scanResult *scan.ScanResult, resolved map[string]string) ([]raise, []Residual) {
	noFixByModule := make(map[string]*Residual)
	for _, vuln := range scanResult.Vulnerabilities {
		if vuln.FixedVersion != "" {
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
		resolvedVersion := resolved[bump.Name]
		if resolvedVersion != "" && semver.Compare(bump.FixedVersion, resolvedVersion) <= 0 {
			continue
		}
		if majorPathChange(bump.FixedVersion, resolvedVersion) {
			residuals = append(residuals, Residual{
				Module:          bump.Name,
				ResolvedVersion: resolvedVersion,
				FixedVersion:    bump.FixedVersion,
				VulnIDs:         bump.VulnIDs,
				Reason:          "fix requires major version import path change",
			})
			continue
		}
		raises = append(raises, raise{module: bump.Name, version: bump.FixedVersion, vulnIDs: bump.VulnIDs})
	}

	sort.Slice(raises, func(i, j int) bool { return raises[i].module < raises[j].module })
	return raises, residuals
}

// confirmMinimalSet checks whether the CVE-backed candidates alone reach the
// same clean state - MVS pulls required co-updates in by itself, so
// coherence-only entries are usually redundant (and are exactly where
// unvalidated vulnerable floors come from). Adopts the smaller set when the
// confirmation apply succeeds and its rescan demands no further raises and
// no new residual advisories; otherwise keeps the converged full set.
func (l *loop) confirmMinimalSet(ctx context.Context, resolved map[string]string) map[string]string {
	// Essential candidates: CVE-backed fixes, remedies (they keep the graph
	// resolvable at all), and user-authored replace seeds (load-bearing fork
	// redirects - never dropped as redundant). Promoted replaces are
	// CVE-backed by construction.
	active := l.activeCandidates()
	essential := make([]*candState, 0, len(active))
	isEssential := func(c *candState) bool { return c.FromCVE || c.remedy || (c.Replace && c.seed) }
	for _, c := range active {
		if isEssential(c) {
			essential = append(essential, c)
		}
	}
	if len(essential) == len(active) {
		return resolved
	}

	if err := l.restore(); err != nil {
		return resolved
	}
	if err := l.tc.ModTidy(ctx, l.dir); err != nil {
		return resolved
	}
	// gobump parity: replace directives before any get.
	for _, c := range essential {
		if !c.Replace {
			continue
		}
		if err := l.tc.Replace(ctx, l.dir, c.OldPath(), c.Module, c.Version); err != nil {
			return resolved
		}
	}
	for _, c := range essential {
		if c.Replace {
			continue
		}
		if err := l.tc.Get(ctx, l.dir, c.Module+"@"+c.Version); err != nil {
			return resolved
		}
	}
	if err := l.tc.ModTidy(ctx, l.dir); err != nil {
		return resolved
	}

	minimalResolved, err := l.tc.ListModules(ctx, l.dir)
	if err != nil {
		return resolved
	}
	minimalRequirements, err := l.tc.Requirements(ctx, l.dir)
	if err != nil {
		return resolved
	}
	minimalReplaces, err := l.tc.Replaces(ctx, l.dir)
	if err != nil {
		return resolved
	}
	// Reachability must be recomputed for the minimal graph and its rescan
	// filtered identically to the main loop's - otherwise introducesNewVulns
	// would compare linked-filtered accepted residuals against an unfiltered
	// candidate scan, see "new" unlinked advisories, and spuriously reject
	// the minimal set. Restore the converged set's view on any rejection.
	convergedLinked := l.linked
	adopted := false
	defer func() {
		if !adopted {
			l.linked = convergedLinked
		}
	}()
	l.refreshLinked(ctx)

	scanResult, err := l.sc.ScanPackages(ctx, l.scanTargets(minimalResolved))
	if err != nil {
		return resolved
	}

	raises, residuals := l.scanFindings(scanResult, minimalResolved)
	if len(raises) > 0 || introducesNewVulns(residuals, l.scanResiduals) {
		return resolved
	}
	for _, c := range essential {
		if c.Replace {
			target, present := minimalReplaces[c.OldPath()]
			if !present || target.Path != c.Module || semver.Compare(target.Version, c.Version) < 0 {
				return resolved
			}
			continue
		}
		requiredVersion, required := minimalRequirements[c.Module]
		if !required || (c.Version != latestQuery && semver.Compare(requiredVersion, c.Version) < 0) {
			return resolved
		}
	}

	for _, c := range active {
		if isEssential(c) {
			continue
		}
		c.dropped = true
		l.dropped = append(l.dropped, DroppedCandidate{
			Module:  c.Module,
			Version: c.Version,
			Reason:  "redundant: module graph resolves identically without it",
		})
	}
	l.scanResiduals = residuals
	l.requirements = minimalRequirements
	l.replaces = minimalReplaces
	adopted = true
	return minimalResolved
}

// finalOutputs renders the surviving candidates: deps entries
// (module@version), replace entries (old=new@version, gobump grammar), and
// the modules among them that address at least one advisory. @latest
// fallbacks are substituted with the resolved version; entries the baseline
// manifest already satisfies are dropped as no-ops (for promoted replaces
// the baseline resolves upstream replace directives, so an upstream replace
// already at >= target naturally no-ops - mirroring gobump's warn+skip).
func (l *loop) finalOutputs(resolved map[string]string) ([]string, []string, []string) {
	var deps []string
	var replaces []string
	var cveModules []string
	for _, c := range l.activeCandidates() {
		if c.Replace {
			_, wasPromoted := l.promoted[c.Module]
			if wasPromoted {
				if baseline, ok := l.req.Baseline[c.Module]; ok && semver.Compare(c.Version, baseline) <= 0 {
					l.dropped = append(l.dropped, DroppedCandidate{
						Module:  c.Module,
						Version: c.Version,
						Reason:  fmt.Sprintf("no-op: baseline already at %s", baseline),
					})
					continue
				}
			}
			replaces = append(replaces, fmt.Sprintf("%s=%s@%s", c.OldPath(), c.Module, c.Version))
			if c.FromCVE {
				cveModules = append(cveModules, c.Module)
			}
			continue
		}

		if _, required := l.requirements[c.Module]; !required {
			// The final go mod tidy pruned this module from go.mod - and
			// melange's gobump errors on any deps entry absent from the
			// tidied go.mod, so writing it would break the build.
			l.dropped = append(l.dropped, DroppedCandidate{
				Module:  c.Module,
				Version: c.Version,
				Reason:  "pruned by go mod tidy: not required by the tidied go.mod",
			})
			continue
		}
		version := c.Version
		if version == latestQuery {
			version = resolved[c.Module]
			if version == "" {
				version = l.requirements[c.Module]
			}
		}
		if baseline, ok := l.req.Baseline[c.Module]; ok && semver.Compare(version, baseline) <= 0 {
			l.dropped = append(l.dropped, DroppedCandidate{
				Module:  c.Module,
				Version: version,
				Reason:  fmt.Sprintf("no-op: baseline already at %s", baseline),
			})
			continue
		}
		deps = append(deps, c.Module+"@"+version)
		if c.FromCVE {
			cveModules = append(cveModules, c.Module)
		}
	}
	return deps, replaces, cveModules
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

// majorPathChange reports whether moving from the resolved version to the
// fixed version crosses a v2+ major boundary, which changes the module's
// import path - not expressible as a go/bump dependency entry.
func majorPathChange(fixedVersion, resolvedVersion string) bool {
	if resolvedVersion == "" {
		return false
	}
	fixedMajor, resolvedMajor := semver.Major(fixedVersion), semver.Major(resolvedVersion)
	if fixedMajor == resolvedMajor {
		return false
	}
	isLow := func(major string) bool { return major == "v0" || major == "v1" }
	return !isLow(fixedMajor) || !isLow(resolvedMajor)
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

// ambiguousImportModules extracts, from a go tool "ambiguous import: found
// package X in multiple modules" failure, the module of each ambiguous pair
// that must move forward: when one module path is a prefix of another (the
// monolith-vs-split case, e.g. google.golang.org/genproto vs
// google.golang.org/genproto/googleapis/rpc), the monolith must advance past
// the version where the split module took the packages over. Falls back to
// the first-listed module when neither path nests in the other.
func ambiguousImportModules(errText string) []string {
	var remedies []string
	seen := make(map[string]struct{})

	lines := strings.Split(errText, "\n")
	for i := 0; i < len(lines); i++ {
		if !strings.Contains(lines[i], "ambiguous import: found package") {
			continue
		}
		var modules []string
		for j := i + 1; j < len(lines); j++ {
			fields := strings.Fields(lines[j])
			if len(fields) < 2 || !strings.HasPrefix(fields[1], "v") || strings.HasSuffix(fields[0], ":") {
				break
			}
			modules = append(modules, fields[0])
		}
		if len(modules) < 2 {
			continue
		}

		remedy := modules[0]
		for _, candidate := range modules {
			for _, other := range modules {
				if candidate != other && strings.HasPrefix(other, candidate+"/") {
					remedy = candidate
				}
			}
		}
		if _, ok := seen[remedy]; !ok {
			seen[remedy] = struct{}{}
			remedies = append(remedies, remedy)
		}
	}
	return remedies
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
