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
// first-party when any component is the package's own module, otherwise
// proven only when it has components and every one is proven - a stdlib one
// not affecting Go at the recorded rebuild versions, a scanned module not
// open (fixed here, or never affected at the version shipped).
func classifyApk(components []apkComponent, ev apkEvidence) (status, cause string) {
	if len(components) == 0 {
		return apkUnproven, "no upstream advisory record"
	}
	for _, c := range components {
		if c.kind == apkRoot {
			return apkFirstParty, "affects " + c.module + ", this package's own module"
		}
	}
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
			return apkUnproven, "module " + c.module + " not in the analysed graph"
		default:
			return apkUnproven, "no upstream advisory record"
		}
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
// or below it is proven: the epoch stops below the lowest non-proven one.
// 0 when no proven advisory sits below every non-proven one.
func apkEpochTarget(advs []ApkAdvisory) int64 {
	blocker := int64(math.MaxInt64)
	for _, adv := range advs {
		if adv.Status != apkProven {
			blocker = min(blocker, adv.FixedEpoch)
		}
	}
	var target int64
	for _, adv := range advs {
		if adv.Status == apkProven && adv.FixedEpoch < blocker {
			target = max(target, adv.FixedEpoch)
		}
	}
	return target
}
