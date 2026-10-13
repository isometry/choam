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
	apkProven     = "proven"      // its upstream issue is provably fixed in this build
	apkUnproven   = "unproven"    // possibly still present (residual, unlinked, stdlib, or no fix recorded)
	apkFirstParty = "first-party" // matches no dependency or stdlib advisory we know of
)

// apkEcosystems are the OSV ecosystems Chainguard publishes APK advisories
// under (every CGA- record lists both).
var apkEcosystems = []string{"Wolfi", "Chainguard"}

// apkFixedEpoch reads rec's fix for the APK name at version: ok when some
// Wolfi/Chainguard fixed event is exactly "<version>-r<N>" with N > epoch,
// returning the smallest such N (the advisory is epoch-addressable). fixed is
// that event, or else the first fixed event seen ("" = no fix).
func apkFixedEpoch(rec *osvschema.Vulnerability, name, version string, epoch int64) (n int64, ok bool, fixed string) {
	for _, affected := range rec.GetAffected() {
		if pkg := affected.GetPackage(); pkg.GetName() != name || !slices.Contains(apkEcosystems, pkg.GetEcosystem()) {
			continue
		}
		for _, r := range affected.GetRanges() {
			for _, event := range r.GetEvents() {
				f := event.GetFixed()
				if f == "" {
					continue
				}
				if fixed == "" {
					fixed = f
				}
				rest, found := strings.CutPrefix(f, version+"-r")
				if !found {
					continue
				}
				if m, err := strconv.ParseInt(rest, 10, 64); err == nil && m > epoch && (!ok || m < n) {
					n, ok, fixed = m, true, f
				}
			}
		}
	}
	return n, ok, fixed
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

// apkEvidence is what classifyApk weighs an advisory's upstream IDs against,
// every set alias-expanded.
type apkEvidence struct {
	pristine map[string]struct{} // every advisory the pristine dependency scans found
	fixed    map[string]struct{} // proven fixed by this build's deps (and hygiene bumps)
	unfixed  map[string]struct{} // residual, no-fix residual, or unlinked and not hygiene-bumped
	stdlib   map[string]struct{} // upstream GO- IDs whose record affects the Go stdlib/toolchain
	modules  map[string]struct{} // upstream GO- IDs whose record affects a (non-stdlib) module
	// stdlibRemaining are the stdlib advisories (IDs and aliases) still
	// affecting Go at a recorded rebuild version; nil = no stdlib proof.
	stdlibRemaining map[string]struct{}
}

// classifyApk gives an advisory with the given upstream IDs its status.
// First-party: no stdlib component and no pristine dependency advisory.
// Otherwise every component must be proven: the dependency side (any
// non-stdlib advisory, or a stdlib+module record whose CVE is in our graph)
// needs an upstream ID fixed and none unfixed; the stdlib side needs no
// upstream ID still affecting Go at a recorded rebuild version.
func classifyApk(upstream []string, ev apkEvidence) string {
	stdlib, pristine := anyIn(upstream, ev.stdlib), anyIn(upstream, ev.pristine)
	if !stdlib && !pristine {
		return apkFirstParty
	}
	if !stdlib || (pristine && anyIn(upstream, ev.modules)) {
		if anyIn(upstream, ev.unfixed) || !anyIn(upstream, ev.fixed) {
			return apkUnproven
		}
	}
	if stdlib && (ev.stdlibRemaining == nil || anyIn(upstream, ev.stdlibRemaining)) {
		return apkUnproven
	}
	return apkProven
}

// anyIn reports whether any of ids is in set.
func anyIn(ids []string, set map[string]struct{}) bool {
	return slices.ContainsFunc(ids, func(id string) bool {
		_, ok := set[id]
		return ok
	})
}

// apkEpochTarget is the lowest epoch clearing every epoch-addressable proven
// advisory (the floor), held below the lowest first-party one (the cap): the
// package-name match is often a first-party issue's only downstream signal.
// 0 when nothing proven is addressable.
func apkEpochTarget(advs []ApkAdvisory) int64 {
	floor, ceiling := int64(0), int64(math.MaxInt64)
	for _, adv := range advs {
		if adv.FixedEpoch == 0 {
			continue
		}
		switch adv.Status {
		case apkProven:
			floor = max(floor, adv.FixedEpoch)
		case apkFirstParty:
			ceiling = min(ceiling, adv.FixedEpoch-1)
		}
	}
	return min(floor, ceiling)
}
