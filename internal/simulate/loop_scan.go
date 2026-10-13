package simulate

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/isometry/choam/internal/logging"
	"github.com/isometry/choam/internal/scan"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

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

// processScan converts a rescan of the resolved graph into raised candidates
// and recomputed scan residuals. It returns the raises applied this round.
func (l *loop) processScan(ctx context.Context, scanResult *scan.ScanResult, resolved map[string]string) []raise {
	raises, residuals, _ := l.scanFindings(scanResult, resolved)
	l.scanResiduals = residuals

	l.lastRaised = l.lastRaised[:0]
	applied := make([]raise, 0, len(raises))
	for _, r := range raises {
		if existing, ok := l.byModule[r.module]; ok && existing.isDropped() {
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
		if existing, ok := l.byModule[r.module]; ok && !existing.isDropped() && existing.Replace {
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
	if c, ok := l.byModule[module]; ok && !c.isDropped() && c.Replace {
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
// cannot express, or a module the upstream go.mod replace-pins). Advisories
// whose vulnerable packages are all outside the artifact's import graph are
// neither: the orchestrator reports them as info from the analysis scan,
// and those with a compatible fix above the module's security target are
// returned as hygiene targets (see hygienePass) - so a module's security
// target is the highest fix among its LINKED advisories only.
func (l *loop) scanFindings(scanResult *scan.ScanResult, resolved map[string]string) ([]raise, []Residual, []raise) {
	applies := make(map[string]bool, len(scanResult.Vulnerabilities))
	for _, vuln := range scanResult.Vulnerabilities {
		applies[vuln.ID] = scan.ImportsLinked(vuln.VulnerableImports, l.linkedPackages)
	}

	var raises, hygiene []raise
	residuals := noFixResiduals(scanResult, applies, resolved)
	for _, bump := range scanResult.SecurityBumps {
		linked, unlinked := splitLinked(bump.VulnIDs, applies)
		resolvedVersion := resolved[bump.Name]
		target, blocked := "", false
		if len(linked) > 0 || len(bump.VulnIDs) == 0 {
			fix := securityFix(scanResult, bump, linked, unlinked)
			target = fix.version
			if resolvedVersion == "" || semver.Compare(fix.version, resolvedVersion) > 0 {
				if reason := l.raiseBlocked(bump.Name, fix.version, resolvedVersion); reason != "" {
					blocked = true
					residuals = append(residuals, Residual{
						Module:          bump.Name,
						ResolvedVersion: resolvedVersion,
						FixedVersion:    fix.version,
						VulnIDs:         fix.vulnIDs,
						Reason:          reason,
					})
				} else {
					raises = append(raises, fix)
				}
			}
		}
		if len(unlinked) == 0 || blocked {
			continue
		}
		if h, ok := l.hygieneFinding(scanResult, bump.Name, unlinked, target, resolvedVersion); ok {
			hygiene = append(hygiene, h)
		}
	}

	byModule := func(a, b raise) int {
		return cmp.Or(strings.Compare(a.module, b.module), strings.Compare(a.version, b.version))
	}
	slices.SortFunc(raises, byModule)
	slices.SortFunc(hygiene, byModule)
	return raises, residuals, hygiene
}

// noFixResiduals groups the linked advisories without a released fix into
// one residual per module.
func noFixResiduals(scanResult *scan.ScanResult, applies map[string]bool, resolved map[string]string) []Residual {
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
	var residuals []Residual
	for _, r := range noFixByModule {
		residuals = append(residuals, *r)
	}
	return residuals
}

// splitLinked partitions advisory ids by whether their vulnerable packages
// are linked (see scanFindings); an id missing from applies counts as
// linked (fails open).
func splitLinked(ids []string, applies map[string]bool) (linked, unlinked []string) {
	for _, id := range ids {
		if applicable, known := applies[id]; known && !applicable {
			unlinked = append(unlinked, id)
		} else {
			linked = append(linked, id) // unknown fails open
		}
	}
	return linked, unlinked
}

// securityFix is bump's security raise: the scanner's fix for all its
// advisories, or, when some are unlinked, the highest fix among the linked
// ones only.
func securityFix(scanResult *scan.ScanResult, bump scan.SecurityBump, linked, unlinked []string) raise {
	fix := raise{module: bump.Name, version: bump.FixedVersion, vulnIDs: bump.VulnIDs, severity: bump.Severity,
		rungs: FixRungs(scanResult.Vulnerabilities, bump.Name, bump.VulnIDs)}
	if len(unlinked) > 0 {
		if rungs := FixRungs(scanResult.Vulnerabilities, bump.Name, linked); len(rungs) > 0 {
			fix = raise{module: bump.Name, version: rungs[0].Version, vulnIDs: linked, severity: rungSeverity(rungs), rungs: rungs}
		}
	}
	return fix
}

// raiseBlocked is why module cannot be raised from resolvedVersion to fix
// with a deps entry ("" when it can): a major version change, or an upstream
// replace pin.
func (l *loop) raiseBlocked(module, fix, resolvedVersion string) string {
	if majorChange(module, fix, resolvedVersion) {
		return fmt.Sprintf("fix requires a major version change (%s -> %s)", resolvedVersion, fix)
	}
	if oldPath := l.upstreamHoldBack(module); oldPath != "" {
		return holdBackReason(oldPath)
	}
	return ""
}

// hygieneFinding is module's scanner-hygiene target: its unlinked
// advisories fixed only above the security target (all of them when target
// is ""), when that fix is above resolvedVersion and reachable without a
// major change or an upstream replace pin.
func (l *loop) hygieneFinding(scanResult *scan.ScanResult, module string, unlinked []string, target, resolvedVersion string) (raise, bool) {
	var above []Rung
	for _, r := range FixRungs(scanResult.Vulnerabilities, module, unlinked) {
		if target == "" || semver.Compare(r.Version, target) > 0 {
			above = append(above, r)
		}
	}
	if len(above) == 0 || semver.Compare(above[0].Version, resolvedVersion) <= 0 ||
		majorChange(module, above[0].Version, resolvedVersion) || l.upstreamHoldBack(module) != "" {
		return raise{}, false
	}
	var ids []string
	for _, r := range above {
		ids = mergeIDs(ids, r.VulnIDs)
	}
	return raise{module: module, version: above[0].Version, vulnIDs: ids, severity: rungSeverity(above), rungs: above}, true
}

// rungSeverity is the most severe level across rungs.
func rungSeverity(rungs []Rung) string {
	severity := ""
	for _, r := range rungs {
		severity = mergeSeverity(severity, r.Severity)
	}
	return severity
}

// packagesFor renders a resolved module graph as OSV scan queries, in stable order.
func packagesFor(resolved map[string]string) []scan.Package {
	pkgs := make([]scan.Package, 0, len(resolved))
	for module, version := range resolved {
		pkgs = append(pkgs, scan.Package{Name: module, Version: version, Ecosystem: "Go"})
	}
	slices.SortFunc(pkgs, func(a, b scan.Package) int { return strings.Compare(a.Name, b.Name) })
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
	return len(newVulnIDs(candidate, accepted)) > 0
}

// newVulnIDs lists, sorted, the candidate residuals' advisories absent from
// the accepted residual set.
func newVulnIDs(candidate, accepted []Residual) []string {
	known := make(map[string]struct{})
	for _, r := range accepted {
		for _, id := range r.VulnIDs {
			known[id] = struct{}{}
		}
	}
	var ids []string
	for _, r := range candidate {
		for _, id := range r.VulnIDs {
			if _, ok := known[id]; !ok {
				ids = mergeIDs(ids, []string{id})
			}
		}
	}
	return ids
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

// compareResiduals is the total order residuals are reported in.
func compareResiduals(a, b Residual) int {
	return cmp.Or(
		strings.Compare(a.Module, b.Module),
		semver.Compare(a.FixedVersion, b.FixedVersion),
		strings.Compare(a.FixedVersion, b.FixedVersion),
		strings.Compare(a.Reason, b.Reason),
		slices.Compare(a.VulnIDs, b.VulnIDs),
		strings.Compare(a.ResolvedVersion, b.ResolvedVersion),
	)
}
