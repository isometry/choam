package gobump

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"

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
// It records ApkEpochTarget for the epoch stage (see apkNewEpoch), and alerts
// on advisories that match no dependency or stdlib advisory at all (possible
// first-party vulnerabilities, which a dependency bump cannot fix).
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

	// Without a complete dependency analysis every non-stdlib CVE would read
	// as first-party: no evidence, no verdict.
	if !dependencyAnalysisComplete(gp) {
		gp.AddMessage("apk: no complete dependency analysis was performed - skipping apk advisory check")
		return nil
	}

	advs, ev, err := s.classify(ctx, gp)
	if err != nil {
		return cancelledOr(ctx, func() { s.skipWarn(ctx, gp, fmt.Sprintf("apk: advisory check unavailable (%v) - skipping", err)) })
	}
	gp.ApkAdvisories = advs
	gp.ApkEpochTarget = apkEpochTarget(advs)
	reportApk(gp, advs, ev)
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
// classifies each advisory against the evidence this run gathered.
func (s *ApkAdvisoryStage) classify(ctx context.Context, gp *Processor) ([]ApkAdvisory, apkEvidence, error) {
	name, version, epoch := gp.GetPackageName(), gp.GetCurrentVersion(), gp.GetCurrentEpoch()
	pkgs := make([]scan.Package, 0, len(apkEcosystems))
	for _, ecosystem := range apkEcosystems {
		pkgs = append(pkgs, scan.Package{Name: name, Ecosystem: ecosystem, Version: fmt.Sprintf("%s-r%d", version, epoch)})
	}
	records, err := s.advisories.Advisories(ctx, pkgs)
	if err != nil || len(records) == 0 {
		return nil, apkEvidence{}, err
	}

	ev := apkDependencyEvidence(gp)
	advs := make([]ApkAdvisory, 0, len(records))
	for _, rec := range records {
		adv := ApkAdvisory{ID: rec.GetId(), Upstream: slices.Sorted(slices.Values(rec.GetUpstream()))}
		adv.FixedEpoch, _, adv.FixedVersion = apkFixedEpoch(rec, name, version, epoch)
		// ponytail: a stdlib advisory whose upstream lacks its GO- ID reads as
		// first-party - a false alarm, the safe direction; Chainguard records
		// seen so far always carry it.
		if adv.Modules, err = s.upstreamModules(ctx, adv.Upstream, "GO-", &ev); err != nil {
			return nil, apkEvidence{}, err
		}
		advs = append(advs, adv)
	}

	// Stdlib proof: what still affects Go at every recorded rebuild version.
	if len(ev.stdlib) > 0 && len(gp.StdlibRebuildGoVersions) > 0 {
		ev.stdlibRemaining = make(map[string]struct{})
		for _, v := range gp.StdlibRebuildGoVersions {
			vulns, err := scanStdlib(ctx, s.scanner, v)
			if err != nil {
				return nil, apkEvidence{}, err
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
		adv := &advs[i]
		adv.Status = classifyApk(adv.Upstream, ev)
		if adv.Status == apkFirstParty && len(adv.Modules) == 0 {
			if adv.Modules, err = s.upstreamModules(ctx, adv.Upstream, "GHSA-", nil); err != nil {
				return nil, apkEvidence{}, err
			}
		}
	}
	return advs, ev, nil
}

// apkDependencyEvidence gathers the dependency-side evidence: what the
// pristine scans found, what this build fixes and what it leaves unfixed.
// Hygiene-bumped advisories stay unreachable (never security fixes) but are
// fixed for scanners, so they move from unfixed to fixed.
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
	fixed := append(slices.Sorted(maps.Keys(gp.fixedVulnIDs())), slices.Sorted(maps.Keys(hygiene))...)
	var unfixed []string
	for _, r := range append(slices.Clone(gp.Residuals), gp.noFixResiduals()...) {
		unfixed = append(unfixed, r.VulnIDs...)
	}
	for _, id := range gp.UnreachableVulnIDs {
		if _, ok := hygiene[id]; !ok {
			unfixed = append(unfixed, id)
		}
	}
	return apkEvidence{
		pristine: aliasExpand(slices.Sorted(maps.Keys(aliasesOf)), aliasesOf),
		fixed:    aliasExpand(fixed, aliasesOf),
		unfixed:  aliasExpand(unfixed, aliasesOf),
		stdlib:   make(map[string]struct{}),
		modules:  make(map[string]struct{}),
	}
}

// upstreamModules fetches the upstream records with the given ID prefix and
// returns the modules they affect, sorted; when ev is non-nil, each record's
// ID joins ev.stdlib and/or ev.modules by the components it affects. A
// missing record (404) contributes nothing.
func (s *ApkAdvisoryStage) upstreamModules(ctx context.Context, upstream []string, prefix string, ev *apkEvidence) ([]string, error) {
	var modules []string
	for _, id := range upstream {
		if !strings.HasPrefix(id, prefix) {
			continue
		}
		rec, err := s.advisories.Advisory(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, affected := range rec.GetAffected() {
			pkg := affected.GetPackage()
			if pkg.GetName() == "" {
				continue
			}
			modules = append(modules, pkg.GetName())
			switch {
			case ev == nil:
			case pkg.GetEcosystem() == "Go" && (pkg.GetName() == "stdlib" || pkg.GetName() == "toolchain"):
				ev.stdlib[id] = struct{}{}
			default:
				ev.modules[id] = struct{}{}
			}
		}
	}
	slices.Sort(modules)
	return slices.Compact(modules), nil
}

// reportApk renders the classification: first-party ALERTs and the unproven
// advisories the final epoch will hide from distro-aware scanners as notes
// (default verbosity), everything else as messages.
func reportApk(gp *Processor, advs []ApkAdvisory, ev apkEvidence) {
	newEpoch := apkNewEpoch(gp)
	seen := make(map[string]bool)
	for _, adv := range advs {
		id := apkDisplayID(adv)
		// Chainguard publishes one record per ecosystem for the same issue.
		key := id + "|" + adv.FixedVersion
		if seen[key] {
			continue
		}
		seen[key] = true
		fixedIn := "no fix"
		if adv.FixedVersion != "" {
			fixedIn = "fixed in " + adv.FixedVersion
		}
		switch adv.Status {
		case apkFirstParty:
			gp.FirstPartyVulnIDs = append(gp.FirstPartyVulnIDs, id)
			affects := ""
			if len(adv.Modules) > 0 {
				affects = " (affects " + strings.Join(adv.Modules, ", ") + ")"
			}
			note := fmt.Sprintf("ALERT apk: %s (%s, %s) matches no dependency or stdlib advisory - possible first-party vulnerability%s; needs a patch, not a dependency bump",
				id, adv.ID, fixedIn, affects)
			switch {
			case adv.FixedEpoch > 0 && newEpoch >= adv.FixedEpoch:
				note += fmt.Sprintf("; epoch %d reaches -r%d, so scanners will now treat it as fixed", newEpoch, adv.FixedEpoch)
			case adv.FixedEpoch > 0 && slices.ContainsFunc(advs, func(a ApkAdvisory) bool { return a.Status == apkProven && a.FixedEpoch >= adv.FixedEpoch }):
				note += fmt.Sprintf("; epoch held at %d", newEpoch)
			}
			gp.AddNote(note)
		case apkUnproven:
			reason := "no fix recorded here"
			switch {
			case anyIn(adv.Upstream, ev.unfixed):
				reason = "residual or unlinked"
			case anyIn(adv.Upstream, ev.stdlib):
				reason = "stdlib"
			}
			if adv.FixedEpoch > 0 && newEpoch >= adv.FixedEpoch {
				gp.AddNote(fmt.Sprintf("apk: %s (%s) fixed by Chainguard in %s, not proven fixed here (%s) - raising the epoch will hide it from distro-aware scanners",
					id, adv.ID, adv.FixedVersion, reason))
			} else {
				gp.AddMessage(fmt.Sprintf("apk: %s (%s, %s) not proven fixed here (%s)", id, adv.ID, fixedIn, reason))
			}
		default:
			gp.AddMessage(fmt.Sprintf("apk: %s (%s, %s) proven fixed here", id, adv.ID, fixedIn))
		}
	}
}

// apkDisplayID reports an advisory CVE-first, like every other advisory ID.
func apkDisplayID(adv ApkAdvisory) string {
	return scan.PreferredID(&osvschema.Vulnerability{Id: adv.ID, Aliases: adv.Upstream})
}

// skipWarn records a degrade-to-skip in the log and the per-package messages.
func (s *ApkAdvisoryStage) skipWarn(ctx context.Context, gp *Processor, msg string) {
	logging.From(ctx).Warn(msg)
	gp.AddMessage(msg)
}
