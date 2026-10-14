package gobump

import (
	"cmp"
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
	reportApk(gp, advs, s.rebuildUnresolved(gp))
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
	gp.ApkAlignment = &ApkAlignment{Version: fmt.Sprintf("%s-r%d", version, epoch), Ignored: notAddressable + uncorrelated, Uncorrelated: uncorrelated}
	return advs, nil
}

// rebuildUnresolved says why no rebuild Go toolchain is known for the
// stdlib proof (see Processor.stdlibUnresolved).
func (s *ApkAdvisoryStage) rebuildUnresolved(gp *Processor) string {
	switch {
	case gp.stdlibUnresolved != "":
		return gp.stdlibUnresolved
	case !s.Options.StdlibCheck:
		return "stdlib check disabled by --no-stdlib"
	default:
		return "stdlib check did not run"
	}
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

// reportApk renders the classification: first-party advisories are patch
// actions; non-proven advisories holding the epoch down (at or below the
// highest proven -rN, or the lowest non-proven one, where the epoch stops)
// are review actions grouped per fix epoch and cause, except those held only
// for want of a rebuild toolchain, which collapse into one rerun action
// naming why (unresolved); non-proven advisories the epoch reaches anyway
// are review actions grouped the same way; the rest are only in ApkAdvisories (the -v detail). One entry per display ID and fix
// (Chainguard publishes a record per ecosystem for the same issue), which is
// also what ApkAlignment counts.
func reportApk(gp *Processor, advs []ApkAdvisory, unresolved string) {
	newEpoch := apkNewEpoch(gp)
	if gp.ApkAlignment == nil { // no advisory at all
		gp.ApkAlignment = &ApkAlignment{Version: fmt.Sprintf("%s-r%d", gp.GetCurrentVersion(), gp.GetCurrentEpoch())}
	}
	align := gp.ApkAlignment
	align.TargetEpoch = gp.ApkEpochTarget
	var highestProven int64
	for _, adv := range advs {
		align.HighestFixedEpoch = max(align.HighestFixedEpoch, adv.FixedEpoch)
		if adv.Status == apkProven {
			highestProven = max(highestProven, adv.FixedEpoch)
		} else if align.BlockedAt == 0 || adv.FixedEpoch < align.BlockedAt {
			align.BlockedAt = adv.FixedEpoch
		}
	}
	var noToolchain int
	var noToolchainBelow int64
	blockers := make(map[apkBlockerKey][]string) // display IDs per (fix epoch, cause, reached)
	seen := make(map[string]bool)
	for _, adv := range advs {
		id := apkDisplayID(adv)
		key := id + "|" + adv.FixedVersion
		if seen[key] {
			continue
		}
		seen[key] = true
		blocking := adv.FixedEpoch <= highestProven || adv.FixedEpoch == align.BlockedAt
		subject := fmt.Sprintf("%s (%s, fixed in %s)", id, adv.ID, adv.FixedVersion)
		switch adv.Status {
		case apkFirstParty:
			align.FirstParty++
			gp.FirstPartyVulnIDs = append(gp.FirstPartyVulnIDs, id)
			detail := adv.Reason + " - possible first-party vulnerability; needs a patch, not a dependency bump"
			switch {
			case newEpoch >= adv.FixedEpoch:
				detail += fmt.Sprintf("; epoch %d reaches -r%d, so scanners will now treat it as fixed", newEpoch, adv.FixedEpoch)
			case blocking:
				detail += fmt.Sprintf("; holds the epoch below -r%d", adv.FixedEpoch)
			}
			gp.AddAction(ActionPatch, subject, detail)
		case apkUnproven:
			align.Unproven++
			switch {
			case newEpoch >= adv.FixedEpoch:
				k := apkBlockerKey{adv.FixedEpoch, adv.Reason, true}
				if !slices.Contains(blockers[k], id) {
					blockers[k] = append(blockers[k], id)
				}
			case blocking && adv.Reason == apkCauseNoRebuildToolchain:
				noToolchain++
				if noToolchainBelow == 0 || adv.FixedEpoch < noToolchainBelow {
					noToolchainBelow = adv.FixedEpoch
				}
			case blocking:
				k := apkBlockerKey{adv.FixedEpoch, adv.Reason, false}
				if !slices.Contains(blockers[k], id) {
					blockers[k] = append(blockers[k], id)
				}
			}
		default:
			align.Proven++
		}
	}
	for _, k := range slices.SortedFunc(maps.Keys(blockers), func(a, b apkBlockerKey) int {
		return cmp.Or(cmp.Compare(a.epoch, b.epoch), strings.Compare(a.cause, b.cause), cmp.Compare(boolRank(a.reached), boolRank(b.reached)))
	}) {
		ids := blockers[k]
		slices.SortFunc(ids, func(a, b string) int {
			return cmp.Or(cmp.Compare(cveLast(a), cveLast(b)), strings.Compare(a, b))
		})
		list := strings.Join(ids[:min(len(ids), epochCommentMaxIDs)], ", ")
		if len(ids) > epochCommentMaxIDs {
			list += fmt.Sprintf(", +%d more", len(ids)-epochCommentMaxIDs)
		}
		detail := fmt.Sprintf("not proven fixed here (%s) - holds the epoch below -r%d", k.cause, k.epoch)
		if k.reached {
			detail = fmt.Sprintf("not proven fixed here (%s) - epoch %d reaches -r%d anyway, hiding %s from distro-aware scanners",
				k.cause, newEpoch, k.epoch, pluralize(len(ids), "it", "them"))
		}
		gp.AddAction(ActionReview,
			fmt.Sprintf("%d apk %s fixed in -r%d (%s)", len(ids), pluralize(len(ids), "advisory", "advisories"), k.epoch, list), detail)
	}
	if noToolchain > 0 {
		gp.AddAction(ActionRerun, fmt.Sprintf("stdlib rebuild toolchain unavailable (%s)", unresolved),
			fmt.Sprintf("holds the apk epoch below -r%d (%d %s)", noToolchainBelow, noToolchain, pluralize(noToolchain, "advisory", "advisories")))
	}
}

// cveLast ranks CVE IDs ahead of the others (0) for display.
func cveLast(id string) int {
	if strings.HasPrefix(id, "CVE-") {
		return 0
	}
	return 1
}

// apkBlockerKey groups the non-proven advisories holding the epoch (or, when
// reached, that the epoch reaches anyway) into one review action per fix
// epoch and cause.
type apkBlockerKey struct {
	epoch   int64
	cause   string
	reached bool
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// DisplayID is the advisory's report ID (see apkDisplayID).
func (a ApkAdvisory) DisplayID() string { return apkDisplayID(a) }

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
