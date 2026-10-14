package gobump

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"

	ecogolang "github.com/isometry/choam/internal/ecosystem/golang"
	"github.com/isometry/choam/internal/logging"
	"github.com/isometry/choam/internal/processor"
	"github.com/isometry/choam/internal/scan"
	"github.com/isometry/choam/internal/simulate"
)

// apkAdvisorySource is the raw-OSV-record seam of ApkAdvisoryStage
// (scan.VulnerabilityScanner), injectable for tests.
type apkAdvisorySource interface {
	Advisories(ctx context.Context, pkgs []scan.Package) ([]*osvschema.Vulnerability, error)
	Advisory(ctx context.Context, id string) (*osvschema.Vulnerability, error)
}

// ApkAdvisoryStage aligns package.epoch with the Chainguard/Wolfi advisories
// published for the package's own APK name: scanners match those by name and
// "-r<epoch>", so an advisory whose upstream issue this build provably fixes
// (see classifyApk) still reads as open until our epoch reaches Chainguard's.
// It records ApkEpochTarget for the epoch stage (see apkNewEpoch) - never past
// an advisory not proven fixed - and alerts on advisories affecting the
// package's own module (first-party, which a dependency bump cannot fix).
//
// Best-effort like StdlibStage: an OSV failure skips with a message and never
// raises the epoch. Idempotent: at "<version>-r<target>" OSV no longer returns
// the advisories the target cleared.
type ApkAdvisoryStage struct {
	processor.BaseStage
	Options Options

	// Test seams (see StdlibStage), defaulting to the analyzer's scanner.
	advisories apkAdvisorySource
	scanner    simulate.Scanner
}

func NewApkAdvisoryStage(analyzer *Analyzer, opts Options) *ApkAdvisoryStage {
	stage := &ApkAdvisoryStage{
		BaseStage: processor.BaseStage{
			StageName:        "apk_advisories",
			StageDescription: "Align the epoch with Chainguard/Wolfi APK advisories",
		},
		Options: opts,
	}
	if analyzer != nil {
		stage.advisories = analyzer.vulnerabilityScanner
		stage.scanner = analyzer.vulnerabilityScanner
	}
	return stage
}

func (s *ApkAdvisoryStage) ShouldRun(ctx context.Context, p processor.Processor) (bool, error) {
	gp, err := asBump(p)
	if err != nil {
		return false, err
	}
	return s.Options.ApkAdvisoryCheck && gp.Config != nil, nil
}

// Apply classifies the advisories and reports them. Every failure degrades
// to a skip-with-message (no raise); only a cancellation propagates.
func (s *ApkAdvisoryStage) Apply(ctx context.Context, p processor.Processor) error {
	gp, err := asBump(p)
	if err != nil {
		return err
	}
	if s.advisories == nil || s.scanner == nil {
		s.skipWarn(ctx, gp, "apk: advisory source unavailable - skipping apk advisory check")
		return nil
	}

	// Without a complete dependency analysis there is no evidence to prove
	// (or place) anything against: no verdict.
	if !dependencyAnalysisComplete(gp) {
		gp.AddMessage("apk: no complete dependency analysis was performed - skipping apk advisory check")
		return nil
	}

	advs, err := s.classify(ctx, gp)
	if err != nil {
		return cancelledOr(ctx, func() { s.skipWarn(ctx, gp, fmt.Sprintf("apk: advisory check unavailable (%v) - skipping", err)) })
	}
	gp.ApkAdvisories = advs
	gp.ApkEpochTarget = apkEpochTarget(advs)
	reportApk(gp, advs)
	logging.From(ctx).Debug("apk advisories classified", "advisories", len(advs), "target_epoch", gp.ApkEpochTarget)
	return nil
}

// dependencyAnalysisComplete reports whether the analysis scanned at least
// one modroot and skipped no part of the package (see Processor.SkipReasons).
// A scanned project with zero vulnerabilities is complete.
func dependencyAnalysisComplete(gp *Processor) bool {
	if gp.VulnerabilityAnalysis == nil || len(gp.SkipReasons) > 0 {
		return false
	}
	for _, lang := range gp.VulnerabilityAnalysis.ByLanguage {
		for _, modroot := range lang.ByModroot {
			if modroot.ScanResult != nil {
				return true
			}
		}
	}
	return false
}

// classify queries OSV for "<version>-r<epoch>" (the pristine epoch) and
// classifies each epoch-addressable advisory by what its upstream records
// affect. Advisories no epoch can clear (no fix, another upstream version)
// and those without an upstream ID to correlate are dropped.
func (s *ApkAdvisoryStage) classify(ctx context.Context, gp *Processor) ([]ApkAdvisory, error) {
	name, version, epoch := gp.GetPackageName(), gp.GetCurrentVersion(), gp.GetCurrentEpoch()
	pkgs := make([]scan.Package, 0, len(apkEcosystems))
	for _, ecosystem := range apkEcosystems {
		pkgs = append(pkgs, scan.Package{Name: name, Ecosystem: ecosystem, Version: fmt.Sprintf("%s-r%d", version, epoch)})
	}
	records, err := s.advisories.Advisories(ctx, pkgs)
	if err != nil || len(records) == 0 {
		return nil, err
	}

	ev := apkDependencyEvidence(gp)
	fetched := make(map[string]*osvschema.Vulnerability) // upstream ID -> record (nil = 404)
	var advs []ApkAdvisory
	var components [][]apkComponent
	var notAddressable, uncorrelated int
	for _, rec := range records {
		n, ok := apkFixedEpoch(rec, name, version, epoch)
		switch {
		case !ok:
			notAddressable++
			continue
		case len(rec.GetUpstream()) == 0:
			uncorrelated++
			continue
		}
		adv := ApkAdvisory{ID: rec.GetId(), Upstream: slices.Sorted(slices.Values(rec.GetUpstream())), FixedVersion: fmt.Sprintf("%s-r%d", version, n), FixedEpoch: n}
		comps, err := s.components(ctx, adv.Upstream, fetched, ev)
		if err != nil {
			return nil, err
		}
		for _, c := range comps {
			if c.module != "" {
				adv.Modules = append(adv.Modules, c.module)
			}
		}
		adv.Modules = slices.Compact(slices.Sorted(slices.Values(adv.Modules)))
		advs = append(advs, adv)
		components = append(components, comps)
	}
	if notAddressable > 0 {
		gp.AddMessage(fmt.Sprintf("apk: %d %s with no fix at %s-r<N> (no fix, or fixed in another version) - ignored", notAddressable, pluralize(notAddressable, "advisory", "advisories"), version))
	}
	if uncorrelated > 0 {
		gp.AddMessage(fmt.Sprintf("apk: %d %s without an upstream CVE/GHSA/GO ID, cannot correlate - ignored", uncorrelated, pluralize(uncorrelated, "advisory", "advisories")))
	}

	// Stdlib proof: what still affects Go at every recorded rebuild version.
	stdlib := slices.ContainsFunc(components, func(cs []apkComponent) bool {
		return slices.ContainsFunc(cs, func(c apkComponent) bool { return c.kind == apkStdlib })
	})
	if stdlib && len(gp.StdlibRebuildGoVersions) > 0 {
		ev.stdlibRemaining = make(map[string]struct{})
		for _, v := range gp.StdlibRebuildGoVersions {
			vulns, err := scanStdlib(ctx, s.scanner, v)
			if err != nil {
				return nil, err
			}
			for _, vuln := range vulns {
				ev.stdlibRemaining[vuln.ID] = struct{}{}
				for _, alias := range vuln.Aliases {
					ev.stdlibRemaining[alias] = struct{}{}
				}
			}
		}
	}

	for i := range advs {
		advs[i].Status, advs[i].Reason = classifyApk(components[i], ev)
	}
	return advs, nil
}

// components fetches an advisory's upstream records - every GO- one, the
// GHSA- ones only when no GO- record exists (CVE records carry no package
// data) - memoized in fetched, and returns one component per affected
// package. None when no record could be fetched.
func (s *ApkAdvisoryStage) components(ctx context.Context, upstream []string, fetched map[string]*osvschema.Vulnerability, ev apkEvidence) ([]apkComponent, error) {
	var comps []apkComponent
	for _, prefix := range []string{"GO-", "GHSA-"} {
		for _, id := range upstream {
			if !strings.HasPrefix(id, prefix) {
				continue
			}
			rec, ok := fetched[id]
			if !ok {
				var err error
				if rec, err = s.advisories.Advisory(ctx, id); err != nil {
					return nil, err
				}
				fetched[id] = rec
			}
			ids := append(slices.Clone(upstream), rec.GetAliases()...)
			for _, affected := range rec.GetAffected() {
				pkg := affected.GetPackage()
				if pkg.GetName() == "" {
					continue
				}
				c := apkComponent{kind: apkOutside, ids: ids, module: pkg.GetName()}
				switch {
				case slices.Contains(ev.mains, pkg.GetName()):
					c.kind = apkRoot
				case pkg.GetEcosystem() == "Go" && (pkg.GetName() == "stdlib" || pkg.GetName() == "toolchain"):
					c.kind = apkStdlib
				default:
					if _, scanned := ev.scanned[pkg.GetEcosystem()+"|"+pkg.GetName()]; scanned {
						c.kind = apkModule
					}
				}
				comps = append(comps, c)
			}
		}
		if len(comps) > 0 {
			break
		}
	}
	return comps, nil
}

// apkDependencyEvidence gathers the dependency-side evidence. OPEN is what
// this build leaves unfixed plus every pristine advisory not proven fixed
// (under --no-validate that includes fixes made by earlier runs - the safe
// direction). Hygiene-bumped advisories stay unreachable (never security
// fixes) but are fixed for scanners, so they are not open.
//
// ponytail: an introduced residual (absent from the baseline scan) has no
// aliases in aliasesOf, so only its reported ID can match an upstream ID;
// carry the rescan's aliases on simulate.Residual if that ever misclassifies.
func apkDependencyEvidence(gp *Processor) apkEvidence {
	aliasesOf := analysisAliases(gp)
	hygiene := make(map[string]struct{})
	if gp.ActualChangesApplied {
		hygiene = fixVulnIDs(gp.HygieneBumps)
	}
	fixed := gp.fixedVulnIDs()
	maps.Copy(fixed, hygiene)
	var open []string
	for _, r := range append(slices.Clone(gp.Residuals), gp.noFixResiduals()...) {
		open = append(open, r.VulnIDs...)
	}
	for _, id := range gp.UnreachableVulnIDs {
		if _, ok := hygiene[id]; !ok {
			open = append(open, id)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(aliasesOf)) {
		if _, ok := fixed[id]; !ok {
			open = append(open, id)
		}
	}
	return apkEvidence{
		open:    aliasExpand(open, aliasesOf),
		scanned: analysisScanned(gp),
		mains:   analysisMainModules(gp),
	}
}

// analysisScanned is the set of "ecosystem|name" packages the analysis scan
// queried, across modroots.
func analysisScanned(gp *Processor) map[string]struct{} {
	scanned := make(map[string]struct{})
	for _, lang := range gp.VulnerabilityAnalysis.ByLanguage {
		for _, modroot := range lang.ByModroot {
			for _, pkg := range modroot.ScannedPackages {
				scanned[pkg.Ecosystem+"|"+pkg.Name] = struct{}{}
			}
		}
	}
	return scanned
}

// analysisMainModules are the Go main module paths of the analysed modroots.
func analysisMainModules(gp *Processor) []string {
	var mains []string
	for _, lang := range gp.VulnerabilityAnalysis.ByLanguage {
		for _, modroot := range lang.ByModroot {
			if modroot.Deps == nil {
				continue
			}
			if info, ok := modroot.Deps.Raw.(*ecogolang.GoModInfo); ok && info.ModFile != nil && info.ModFile.Module != nil {
				mains = append(mains, info.ModFile.Module.Mod.Path)
			}
		}
	}
	return mains
}

// reportApk renders the classification. First-party advisories are ALERT
// notes; non-proven advisories holding the epoch down (at or below the
// highest proven -rN), or that the epoch reaches anyway, are notes naming
// the cause; the rest are messages. One line per display ID and fix
// (Chainguard publishes a record per ecosystem for the same issue).
func reportApk(gp *Processor, advs []ApkAdvisory) {
	newEpoch := apkNewEpoch(gp)
	var highestProven int64
	for _, adv := range advs {
		if adv.Status == apkProven {
			highestProven = max(highestProven, adv.FixedEpoch)
		}
	}
	seen := make(map[string]bool)
	for _, adv := range advs {
		id := apkDisplayID(adv)
		key := id + "|" + adv.FixedVersion
		if seen[key] {
			continue
		}
		seen[key] = true
		blocking := adv.FixedEpoch <= highestProven
		switch adv.Status {
		case apkFirstParty:
			gp.FirstPartyVulnIDs = append(gp.FirstPartyVulnIDs, id)
			note := fmt.Sprintf("ALERT apk: %s (%s, fixed in %s) %s - possible first-party vulnerability; needs a patch, not a dependency bump",
				id, adv.ID, adv.FixedVersion, adv.Reason)
			switch {
			case newEpoch >= adv.FixedEpoch:
				note += fmt.Sprintf("; epoch %d reaches -r%d, so scanners will now treat it as fixed", newEpoch, adv.FixedEpoch)
			case blocking:
				note += fmt.Sprintf("; holds the epoch below -r%d", adv.FixedEpoch)
			}
			gp.AddNote(note)
		case apkUnproven:
			switch {
			case newEpoch >= adv.FixedEpoch:
				gp.AddNote(fmt.Sprintf("apk: %s (%s, fixed in %s) not proven fixed here (%s) - epoch %d reaches -r%d anyway, hiding it from distro-aware scanners",
					id, adv.ID, adv.FixedVersion, adv.Reason, newEpoch, adv.FixedEpoch))
			case blocking:
				gp.AddNote(fmt.Sprintf("apk: %s (%s, fixed in %s) not proven fixed here (%s) - holds the epoch below -r%d",
					id, adv.ID, adv.FixedVersion, adv.Reason, adv.FixedEpoch))
			default:
				gp.AddMessage(fmt.Sprintf("apk: %s (%s, fixed in %s) not proven fixed here (%s)", id, adv.ID, adv.FixedVersion, adv.Reason))
			}
		default:
			gp.AddMessage(fmt.Sprintf("apk: %s (%s, fixed in %s) proven fixed here", id, adv.ID, adv.FixedVersion))
		}
	}
}

// apkDisplayID reports an advisory by its upstream issue, CVE first (see
// scan.PreferredID); the CGA- ID only when it lists no upstream ID.
func apkDisplayID(adv ApkAdvisory) string {
	if len(adv.Upstream) == 0 {
		return adv.ID
	}
	return scan.PreferredID(&osvschema.Vulnerability{Id: adv.Upstream[0], Aliases: adv.Upstream[1:]})
}

// skipWarn records a degrade-to-skip as a default-verbosity note; the log
// line is Debug so the fact appears once.
func (s *ApkAdvisoryStage) skipWarn(ctx context.Context, gp *Processor, msg string) {
	logging.From(ctx).Debug(msg)
	gp.AddNote(msg)
}
