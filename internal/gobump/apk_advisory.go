package gobump

import (
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// ApkAdvisory.Status values.
const (
	apkProven     = "proven"      // every component its upstream records affect is provably fixed here
	apkUnproven   = "unproven"    // some component is still open, or cannot be verified
	apkFirstParty = "first-party" // an upstream record affects this package's own module
	// apkNotApplicable: every affected package is outside the analysed
	// dependency graph, so the shipped artifact cannot contain it - a scanner
	// hit on our APK is a false positive the matching epoch clears.
	apkNotApplicable = "not-applicable"
)

// apkEcosystems are the OSV ecosystems Chainguard publishes APK advisories
// under (every CGA- record lists both).
var apkEcosystems = []string{"Wolfi", "Chainguard"}

// apkFixedEpoch reads rec's fix for the APK name at version: ok when some
// Wolfi/Chainguard fixed event is exactly "<version>-r<N>" with N > epoch,
// returning the smallest such N (the advisory is epoch-addressable).
func apkFixedEpoch(rec *osvschema.Vulnerability, name, version string, epoch int64) (n int64, ok bool) {
	for _, affected := range rec.GetAffected() {
		if pkg := affected.GetPackage(); pkg.GetName() != name || !slices.Contains(apkEcosystems, pkg.GetEcosystem()) {
			continue
		}
		for _, r := range affected.GetRanges() {
			for _, event := range r.GetEvents() {
				rest, found := strings.CutPrefix(event.GetFixed(), version+"-r")
				if !found {
					continue
				}
				if m, err := strconv.ParseInt(rest, 10, 64); err == nil && m > epoch && (!ok || m < n) {
					n, ok = m, true
				}
			}
		}
	}
	return n, ok
}

// analysisAliases maps every advisory ID the analysis scan found to its
// aliases (see scan.Vulnerability.Aliases) - the analysisSeverities walk.
func analysisAliases(gp *Processor) map[string][]string {
	aliases := make(map[string][]string)
	if gp.VulnerabilityAnalysis == nil {
		return aliases
	}
	for _, lang := range gp.VulnerabilityAnalysis.ByLanguage {
		for _, modroot := range lang.ByModroot {
			if modroot.ScanResult == nil {
				continue
			}
			for _, vuln := range modroot.ScanResult.Vulnerabilities {
				aliases[vuln.ID] = append(aliases[vuln.ID], vuln.Aliases...)
			}
		}
	}
	return aliases
}

// aliasExpand is the set of ids plus every alias aliasesOf knows for them.
func aliasExpand(ids []string, aliasesOf map[string][]string) map[string]struct{} {
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
		for _, alias := range aliasesOf[id] {
			set[alias] = struct{}{}
		}
	}
	return set
}

// apkCauseNoRebuildToolchain is the cause of a stdlib component left
// unproven because the stdlib stage resolved no rebuild Go version (disabled
// by --no-stdlib, a deferred release, or a release-index failure).
const apkCauseNoRebuildToolchain = "stdlib: the rebuild Go toolchain could not be resolved"

// apkComponent kinds: what one affected entry of an upstream record names.
const (
	apkRoot     = "root"     // an analysed main module (the package's own code)
	apkStdlib   = "stdlib"   // the Go stdlib/toolchain
	apkModule   = "module"   // a package the pristine dependency scan queried
	apkOutside  = "outside"  // a package outside the analysed dependency graph
	apkNoRecord = "norecord" // no upstream record could be fetched
)

// apkComponent is one thing an advisory's upstream records say is affected:
// its kind, the IDs that identify the issue (upstream IDs plus the record's
// own aliases) and the affected package.
type apkComponent struct {
	kind   string
	ids    []string
	module string
}

// apkEvidence is what classifyApk weighs components against.
type apkEvidence struct {
	// open are the dependency advisories this build leaves open: unfixed
	// (residual, no-fix, unlinked and not hygiene-bumped) plus every pristine
	// advisory not proven fixed, alias-expanded.
	open    map[string]struct{}
	scanned map[string]struct{} // "ecosystem|name" of every package the pristine scan queried
	mains   []string            // analysed Go main module paths
	// stdlibRemaining are the stdlib advisories (IDs and aliases) still
	// affecting Go at a recorded rebuild version; nil = no stdlib proof.
	stdlibRemaining map[string]struct{}
}

// classifyApk gives an advisory its status and, unless proven, the cause:
// first-party when any component is the package's own module; unproven when
// any component is open or unverifiable (a stdlib one still affecting Go at
// the recorded rebuild versions or without one, a scanned module open, no
// record); otherwise proven when some component is proven (a stdlib one
// clear at the rebuild versions, a scanned module fixed here or never
// affected at the version shipped), ignoring components outside the graph;
// not-applicable when every component is outside the graph.
func classifyApk(components []apkComponent, ev apkEvidence) (status, cause string) {
	if len(components) == 0 {
		return apkUnproven, "no upstream advisory record"
	}
	for _, c := range components {
		if c.kind == apkRoot {
			return apkFirstParty, "affects " + c.module + ", this package's own module"
		}
	}
	var outside []string
	for _, c := range components {
		switch c.kind {
		case apkStdlib:
			if ev.stdlibRemaining == nil {
				return apkUnproven, apkCauseNoRebuildToolchain
			}
			if anyIn(c.ids, ev.stdlibRemaining) {
				return apkUnproven, "stdlib: still affected at the rebuild Go version"
			}
		case apkModule:
			if anyIn(c.ids, ev.open) {
				return apkUnproven, "module " + c.module + " residual, unlinked or not proven fixed"
			}
		case apkOutside:
			if !slices.Contains(outside, c.module) {
				outside = append(outside, c.module)
			}
		default:
			return apkUnproven, "no upstream advisory record"
		}
	}
	if !slices.ContainsFunc(components, func(c apkComponent) bool { return c.kind != apkOutside }) {
		return apkNotApplicable, pluralize(len(outside), "module ", "modules ") + strings.Join(outside, ", ") + " not in the dependency graph"
	}
	return apkProven, ""
}

// anyIn reports whether any of ids is in set.
func anyIn(ids []string, set map[string]struct{}) bool {
	return slices.ContainsFunc(ids, func(id string) bool {
		_, ok := set[id]
		return ok
	})
}

// apkEpochTarget is the highest -rN such that every addressable advisory at
// or below it is proven or not applicable: the epoch stops below the lowest
// other (unproven or first-party) one. 0 when nothing clearable sits below
// every blocker.
func apkEpochTarget(advs []ApkAdvisory) int64 {
	blocker := int64(math.MaxInt64)
	for _, adv := range advs {
		if !apkClearable(adv.Status) {
			blocker = min(blocker, adv.FixedEpoch)
		}
	}
	var target int64
	for _, adv := range advs {
		if apkClearable(adv.Status) && adv.FixedEpoch < blocker {
			target = max(target, adv.FixedEpoch)
		}
	}
	return target
}

// apkClearable reports whether an advisory with status may be cleared by the
// epoch: proven fixed here, or not applicable to what ships.
func apkClearable(status string) bool {
	return status == apkProven || status == apkNotApplicable
}
