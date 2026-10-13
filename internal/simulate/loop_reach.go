package simulate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/isometry/choam/internal/goversion"
	"github.com/isometry/choam/internal/logging"
	"github.com/isometry/choam/internal/scan"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// refreshLinked recomputes the artifact-linked module and package sets for
// the current go.mod state. Recomputed every sustain pass rather than once:
// membership can drift as versions move (a raised module can import new
// modules - the genproto-split family is exactly this shape). Failure fails
// OPEN: both sets become nil and no reachability filtering happens (warned
// once per loop; the last error is kept for ModrootResult.LinkageError).
func (l *loop) refreshLinked(ctx context.Context) {
	linkage, err := l.tc.Linked(ctx, l.dir, l.target)
	l.linkedErr = err
	if err != nil {
		if !l.linkedWarned {
			logging.From(ctx).Warn("artifact reachability unavailable - not filtering",
				"modroot", l.req.Modroot, "packages", strings.Join(l.target.Patterns, " "), "error", err)
			l.linkedWarned = true
		}
		l.linked, l.linkedPackages, l.embeds = nil, nil, nil
		return
	}
	l.linked, l.linkedPackages, l.embeds = linkage.Modules, linkage.Packages, linkage.Embeds
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
	std, err := l.tc.LinkedStd(ctx, l.dir, l.target)
	if err != nil {
		if !l.linkedStdWarned {
			logging.From(ctx).Warn("linked stdlib package lookup unavailable",
				"modroot", l.req.Modroot, "packages", strings.Join(l.target.Patterns, " "), "error", err)
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
			reason = fmt.Sprintf("module not linked into build artifacts (packages: %s)", strings.Join(l.target.Patterns, " "))
		case c.FromCVE && !l.seedVulnPackagesLinked(c.VulnIDs):
			reason = "vulnerable package(s) not linked into build artifacts"
			// The module ships: scanners still flag its version, so the
			// hygiene pass may keep this pin if it is free.
			c.hygieneSeed = c.Version
		default:
			if c.FromCVE && l.trimUnlinkedRungs(c) {
				changed = true
			}
			continue
		}
		// Deliberately residual-free: the advisory affects nothing that
		// ships (the orchestrator reports it separately, as info). Marked
		// residualized so the rescan backfill never resurrects it.
		l.drop(c, reason)
		c.residualized = true
		c.shedUnlinked = true
		changed = true
	}
	return changed
}

// trimUnlinkedRungs narrows a CVE candidate whose advisories are only partly
// linked to the linked ones: its target becomes the highest rung fixing a
// linked advisory, and whatever it carried above that (an unlinked
// advisory's fix, an existing pin) is left to the scanner-hygiene pass,
// which keeps it only when free (see hygienePass). The unlinked advisories
// leave its ladder too, so relaxing it never reports them as residual.
// Reports whether the candidate's version changed.
func (l *loop) trimUnlinkedRungs(c *candState) bool {
	if l.linkedPackages == nil || c.remedy || c.Replace {
		return false
	}
	var linked, unlinked []string
	for _, id := range c.VulnIDs {
		if l.seedVulnPackagesLinked([]string{id}) {
			linked = append(linked, id)
		} else {
			unlinked = append(unlinked, id)
		}
	}
	if len(linked) == 0 || len(unlinked) == 0 {
		return false
	}
	rungs := c.fixRungs()
	top := slices.IndexFunc(rungs, func(r Rung) bool {
		return slices.ContainsFunc(r.VulnIDs, func(id string) bool { return slices.Contains(linked, id) })
	})
	if top < 0 {
		return false // no rung names a linked advisory: fail open, keep it whole
	}
	kept := make([]Rung, 0, len(rungs)-top)
	for _, r := range rungs[top:] {
		r.VulnIDs = slices.DeleteFunc(slices.Clone(r.VulnIDs), func(id string) bool { return slices.Contains(unlinked, id) })
		if len(r.VulnIDs) == 0 {
			r.Severity = ""
		}
		kept = append(kept, r)
	}
	if top > 0 {
		c.hygieneSeed = c.Version
	}
	c.Version, c.Rungs, c.VulnIDs, c.Severity = kept[0].Version, kept, linked, rungSeverity(kept)
	return top > 0
}

// seedVulnPackagesLinked reports whether any of the given seed advisories'
// vulnerable packages (threaded in via ModrootRequest.VulnImports) is in the
// artifact's import graph (see scan.ImportsLinked). Fail open everywhere
// data is missing: unknown package graph, no IDs, or an ID without import
// metadata all count as linked.
func (l *loop) seedVulnPackagesLinked(vulnIDs []string) bool {
	if l.linkedPackages == nil || len(vulnIDs) == 0 {
		return true
	}
	for _, id := range vulnIDs {
		if scan.ImportsLinked(l.req.VulnImports[id], l.linkedPackages) {
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
func (l *loop) dropUnsustained(ctx context.Context) bool {
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
			if !c.FromCVE {
				l.drop(c, fmt.Sprintf("go mod tidy reverts the pin to %s", requiredVersion))
			} else {
				// Same policy as an unfetchable fix: fall back to the next
				// lower fix rung rather than abandon every advisory. A
				// higher rung is often just an existing YAML pin; dropping
				// the candidate outright would make the result depend on
				// whether such a pin was present (non-idempotent).
				l.stepDown(ctx, c, fmt.Sprintf("fix not sustained: go mod tidy reverts the pin to %s", requiredVersion))
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
