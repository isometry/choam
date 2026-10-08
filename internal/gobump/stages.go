package gobump

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/config"
	"github.com/isometry/choam/internal/ecosystem"
	"github.com/isometry/choam/internal/goproxy"
	"github.com/isometry/choam/internal/gorelease"
	"github.com/isometry/choam/internal/goversion"
	"github.com/isometry/choam/internal/logging"
	"github.com/isometry/choam/internal/processor"
	"github.com/isometry/choam/internal/processor/stages"
	"github.com/isometry/choam/internal/scan"
	"github.com/isometry/choam/internal/simulate"
)

// Analyzer holds the shared, ecosystem-agnostic infrastructure - remote
// manifest fetching and OSV vulnerability scanning - used across every
// bump/go-bump pipeline step, regardless of language.
type Analyzer struct {
	fetcher              *ecosystem.Fetcher
	vulnerabilityScanner *scan.VulnerabilityScanner

	// goReleases answers "latest stable Go release (as of T)" queries for
	// the stdlib staleness check; shared across every package in a run so
	// the release list is fetched and memoized once.
	goReleases *gorelease.Index

	// httpClient is the client the fetcher/scanner were built with, retained
	// so the applier's best-effort go-version fallback (see
	// fallbackRequiredGoVersion) shares the same transport and timeouts.
	httpClient *http.Client
}

// NewAnalyzer creates a new analyzer with the provided HTTP client
func NewAnalyzer(httpClient *http.Client) *Analyzer {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &Analyzer{
		fetcher:              ecosystem.NewFetcher(httpClient),
		vulnerabilityScanner: scan.NewVulnerabilityScanner(httpClient),
		goReleases:           gorelease.NewIndex(httpClient),
		httpClient:           httpClient,
	}
}

// VulnerabilityChecker checks for dependency vulnerabilities
type VulnerabilityChecker struct {
	processor.BaseStage
	Analyzer *Analyzer
}

func NewVulnerabilityChecker(analyzer *Analyzer) *VulnerabilityChecker {
	return &VulnerabilityChecker{
		BaseStage: processor.BaseStage{
			StageName:        "vulnerability_check",
			StageDescription: "Check for dependency vulnerabilities",
		},
		Analyzer: analyzer,
	}
}

func (v *VulnerabilityChecker) Check(ctx context.Context, p processor.Processor) error {
	gp, ok := p.(*GoBumpProcessor)
	if !ok {
		return fmt.Errorf("expected GoBumpProcessor, got %T", p)
	}

	analysis, err := v.checkVulnerabilities(ctx, gp)
	if err != nil {
		return fmt.Errorf("checking vulnerabilities: %w", err)
	}

	gp.VulnerabilityAnalysis = analysis

	// Note: SecurityFixes are added by the applier when actual changes are made,
	// not during the check phase. This ensures the count reflects real changes.

	if analysis.VulnerabilitiesFound == 0 {
		gp.AddMessage("No vulnerabilities found")
	} else {
		gp.AddMessage(fmt.Sprintf("Found %d vulnerabilities", analysis.VulnerabilitiesFound))
	}

	return nil
}

// GoBumpApplier applies bump/go-bump pipeline changes
type GoBumpApplier struct {
	processor.BaseStage
	Analyzer *Analyzer

	// goProxyURL is the module proxy the best-effort go-version fallback
	// queries; tests point it at an httptest server.
	goProxyURL string

	// probeDisabled mirrors GOPROXY=off: the best-effort go-version fallback
	// probe is entirely skipped (it would just fail every fetch) and each
	// affected modroot gets one explanatory message instead.
	probeDisabled bool

	// goPrivate/goNoProxy are GOPRIVATE/GONOPROXY captured once at
	// construction (see internal/goproxy.IsPrivate) so the fallback probe
	// never sends a private module's name/version to a public proxy.
	goPrivate string
	goNoProxy string

	// goProxyIsPublic is true when goProxyURL is (or falls back to) the
	// public https://proxy.golang.org - either because GOPROXY named it
	// directly, or because GOPROXY's first entry was unusable ("direct",
	// "off", unset, or garbage) and the probe fell back to it. See
	// skipPrivateModule for why this changes which modules get skipped.
	goProxyIsPublic bool
}

func NewGoBumpApplier(analyzer *Analyzer) *GoBumpApplier {
	proxyURL, ok := goproxy.FirstURL(os.Getenv("GOPROXY"))
	if !ok {
		proxyURL = defaultGoProxyURL
	}
	return &GoBumpApplier{
		BaseStage: processor.BaseStage{
			StageName:        "gobump_apply",
			StageDescription: "Apply bump/go-bump pipeline changes",
		},
		Analyzer:        analyzer,
		goProxyURL:      proxyURL,
		probeDisabled:   goproxy.Disabled(os.Getenv("GOPROXY")),
		goPrivate:       os.Getenv("GOPRIVATE"),
		goNoProxy:       os.Getenv("GONOPROXY"),
		goProxyIsPublic: proxyURL == defaultGoProxyURL,
	}
}

// skipPrivateModule reports whether modulePath is private per the
// applier's captured GOPRIVATE/GONOPROXY - the skip func the best-effort
// go-version fallback probe uses to avoid leaking private module
// names/versions to a public proxy.
//
// When the probe queries the user's own configured proxy, Go's own
// GONOPROXY-precedence rule applies (a non-empty GONOPROXY governs
// exclusively; GOPRIVATE is only consulted as its default) - that precedence
// exists to let a private proxy see modules that are GOPRIVATE-only but not
// GONOPROXY-listed. But when goProxyIsPublic is true there is no private
// proxy in play: the probe is talking to the public proxy.golang.org
// regardless, so applying the same precedence would leak a module that
// matches GOPRIVATE but not a (possibly unrelated, non-empty) GONOPROXY.
// Skip on the UNION of GOPRIVATE and GONOPROXY instead, expressed by
// consulting goproxy.IsPrivate once per pattern list with the other left
// empty.
func (g *GoBumpApplier) skipPrivateModule(modulePath string) bool {
	if g.goProxyIsPublic {
		return goproxy.IsPrivate(modulePath, g.goPrivate, "") || goproxy.IsPrivate(modulePath, "", g.goNoProxy)
	}
	return goproxy.IsPrivate(modulePath, g.goPrivate, g.goNoProxy)
}

// httpClient returns the analyzer's HTTP client, falling back to the default
// client when the applier was built without one (tests).
func (g *GoBumpApplier) httpClient() *http.Client {
	if g.Analyzer != nil && g.Analyzer.httpClient != nil {
		return g.Analyzer.httpClient
	}
	return http.DefaultClient
}

// releaseIndex returns the shared per-run Go release index (nil-safe,
// mirroring httpClient above): the fallback go-version probe and the
// go-package pin floor write both consult it to reject a floor that names no
// real Go release. A nil Analyzer (some unit tests construct GoBumpApplier
// directly) means no index is available - callers treat that as "nothing to
// validate against" rather than an error.
func (g *GoBumpApplier) releaseIndex() *gorelease.Index {
	if g.Analyzer != nil {
		return g.Analyzer.goReleases
	}
	return nil
}

func (g *GoBumpApplier) ShouldRun(ctx context.Context, p processor.Processor) (bool, error) {
	gp, ok := p.(*GoBumpProcessor)
	if !ok {
		return false, fmt.Errorf("expected GoBumpProcessor, got %T", p)
	}

	// Only run if vulnerabilities were found and there are actions to apply
	if gp.VulnerabilityAnalysis == nil {
		return false, nil
	}

	return gp.VulnerabilityAnalysis.VulnerabilitiesFound > 0 &&
		len(gp.VulnerabilityAnalysis.BumpActions) > 0, nil
}

func (g *GoBumpApplier) Apply(ctx context.Context, p processor.Processor) error {
	gp, ok := p.(*GoBumpProcessor)
	if !ok {
		return fmt.Errorf("expected GoBumpProcessor, got %T", p)
	}

	if err := g.applyGoBumpChanges(ctx, gp, gp.VulnerabilityAnalysis); err != nil {
		return err
	}

	if gp.ActualChangesApplied {
		gp.AddMessage("bump changes applied")
	} else {
		gp.AddMessage("no bump changes needed")
	}

	return nil
}

// NewGoBumpPipeline creates the gobump pipeline with the critical fix
func NewGoBumpPipeline(analyzer *Analyzer, opts ProcessorOptions) *processor.Pipeline {
	pipeline := processor.NewPipeline("bump")

	// Add stages in order
	pipeline.AddStages(
		// Check phase
		NewVulnerabilityChecker(analyzer),

		// Validation phase: prove the Go candidate sets resolve and cover
		// every fixable advisory before anything is written (see
		// SimulationStage; skipped and loudly reported when unavailable).
		NewSimulationStage(analyzer, opts),

		// Apply phase
		NewGoBumpApplier(analyzer),

		// Stdlib staleness: does rebuilding with a newer Go toolchain fix
		// stdlib vulnerabilities baked into the last build? Runs even when
		// no dependency changes exist (the pipeline runner evaluates each
		// stage's ShouldRun independently), because the fix IS the rebuild.
		NewStdlibStage(analyzer, opts),

		// Epoch handling - ONLY bump if actual changes were applied
		// This is the critical fix that solves the issue described in the implementation plan
		stages.NewEpochStage(&stages.BumpOnSecurityFixStrategy{
			CheckFunc: func(p processor.Processor) bool {
				if gp, ok := p.(*GoBumpProcessor); ok {
					// Dependency fixes only count when actual changes were
					// applied AND security fixes exist (the critical fix). A
					// stdlib staleness finding justifies a bump on its own -
					// the epoch bump itself is what triggers the fixing
					// rebuild, with zero dependency changes.
					return (gp.ActualChangesApplied && len(gp.SecurityFixes) > 0) || len(gp.StdlibBumps) > 0
				}
				return false
			},
			CommentFunc: func(p processor.Processor) string {
				if gp, ok := p.(*GoBumpProcessor); ok {
					return epochComment(gp)
				}
				return ""
			},
		}),

		// Validate the rewritten YAML before anything touches disk.
		stages.NewValidationStage(false, true),

		// File writing - only writes if there are actual file changes
		// (atomically; backup of the original with --backup-suffix).
		stages.NewFileWriterStage(opts.BackupSuffix != "", opts.BackupSuffix),
	)

	return pipeline
}

// epochCommentMaxIDs caps the fixes list in the epoch intent comment: the
// most critical advisories lead, the rest collapse to "+N more" (the full
// list is always in choam's own output).
const epochCommentMaxIDs = 5

// epochComment composes the inline intent comment the epoch stage writes on
// the epoch line: which action(s) triggered the rebuild ("updated bumps",
// "rebuild with go<V>") and the advisories it fixes, most critical first.
// The clause conditions mirror the epoch CheckFunc exactly, so the comment
// always states why the epoch actually bumped.
func epochComment(gp *GoBumpProcessor) string {
	var clauses []string
	if gp.ActualChangesApplied && len(gp.SecurityFixes) > 0 {
		clauses = append(clauses, "updated bumps")
	}
	if versions := stdlibRebuildVersions(gp.StdlibBumps); len(versions) > 0 {
		clauses = append(clauses, "rebuild with "+strings.Join(versions, ", "))
	}
	if len(clauses) == 0 {
		return ""
	}

	comment := strings.Join(clauses, ", ")
	if list := renderFixList(epochFixedVulnIDs(gp), analysisSeverities(gp)); list != "" {
		comment += "; fixes: " + list
	}
	return comment
}

// stdlibRebuildVersions collects the unique "go<version>" rebuild targets
// across the stdlib bumps, sorted.
func stdlibRebuildVersions(bumps []StdlibBump) []string {
	seen := make(map[string]struct{}, len(bumps))
	var versions []string
	for _, bump := range bumps {
		if bump.RebuildGoVersion == "" {
			continue
		}
		name := "go" + bump.RebuildGoVersion
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		versions = append(versions, name)
	}
	sort.Strings(versions)
	return versions
}

// epochFixedVulnIDs derives the advisory IDs this epoch bump fixes. For
// validated dependency bumps that is the proven set: everything the analysis
// scan found, minus residuals, minus advisories in unlinked code (the same
// arithmetic ToResult counts with). Unvalidated bumps fall back to the IDs
// recorded on the SecurityFixes (skipping the "security vulnerability"
// placeholder used when no OSV ID was matched). Stdlib rebuild fixes are
// always included.
func epochFixedVulnIDs(gp *GoBumpProcessor) []string {
	ids := make(map[string]struct{})
	if gp.ActualChangesApplied && len(gp.SecurityFixes) > 0 {
		ids = gp.fixedVulnIDs()
	}
	for _, bump := range gp.StdlibBumps {
		for _, id := range bump.VulnIDs {
			ids[id] = struct{}{}
		}
	}
	return slices.Collect(maps.Keys(ids))
}

// analysisSeverities maps every advisory ID the analysis scan found to its
// most critical observed severity.
func analysisSeverities(gp *GoBumpProcessor) map[string]string {
	severities := make(map[string]string)
	if gp.VulnerabilityAnalysis == nil {
		return severities
	}
	for _, lang := range gp.VulnerabilityAnalysis.ByLanguage {
		for _, modroot := range lang.ByModroot {
			if modroot.ScanResult == nil {
				continue
			}
			for _, vuln := range modroot.ScanResult.Vulnerabilities {
				if existing, ok := severities[vuln.ID]; !ok || scan.SeverityRank(vuln.Severity) < scan.SeverityRank(existing) {
					severities[vuln.ID] = vuln.Severity
				}
			}
		}
	}
	return severities
}

// renderFixList renders advisory IDs most-critical-first (alphabetical
// within a severity tier; IDs without a known severity - including stdlib
// GO-* records, which carry none - rank last), truncated to
// epochCommentMaxIDs with a "+N more" tail.
func renderFixList(ids []string, severities map[string]string) string {
	if len(ids) == 0 {
		return ""
	}
	sort.Slice(ids, func(i, j int) bool {
		ri, rj := scan.SeverityRank(severities[ids[i]]), scan.SeverityRank(severities[ids[j]])
		if ri != rj {
			return ri < rj
		}
		return ids[i] < ids[j]
	})
	if len(ids) > epochCommentMaxIDs {
		return fmt.Sprintf("%s, +%d more",
			strings.Join(ids[:epochCommentMaxIDs], ", "), len(ids)-epochCommentMaxIDs)
	}
	return strings.Join(ids, ", ")
}

// checkVulnerabilities performs real vulnerability analysis across every
// language and module root discovered for this package (see
// discoverAnalysisUnits) - a package may have more than one language.
func (v *VulnerabilityChecker) checkVulnerabilities(ctx context.Context, gp *GoBumpProcessor) (*VulnerabilityAnalysis, error) {
	logging.From(ctx).Debug("checking vulnerabilities")

	loader := newMelangeLoader()

	bumpSteps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	if err != nil {
		return nil, fmt.Errorf("finding bump pipelines: %w", err)
	}

	// Migration is decided before simulation so the simulated engine is the
	// one the written step will run (see planMigration).
	var releases *gorelease.Index
	if v.Analyzer != nil {
		releases = v.Analyzer.goReleases
	}
	units := discoverAnalysisUnits(ctx, gp.Config, bumpSteps, planMigrations(ctx, gp.GetCurrentYAML(), bumpSteps, releases))
	if len(units) == 0 {
		logging.From(ctx).Debug("not a bumpable project")
		gp.AddMessage("Not a bumpable project - skipping dependency analysis")
		return &VulnerabilityAnalysis{}, nil
	}

	// Anything that prevents fetching the source's manifests skips the file
	// (a distinct SKIPPED status, never clean): no git-checkout step (a
	// fetch:-based source), an unresolvable repository/tag, or a repository
	// host manifests cannot be fetched from.
	repoURL, tag, expectedCommit, err := extractRepositoryFromYAML(gp.GetCurrentYAML(), gp.Config, gp.GetCurrentVersion())
	if err == nil {
		err = ecosystem.CheckRepository(repoURL)
	}
	if err != nil {
		gp.Skip(ctx, fmt.Sprintf("cannot fetch dependency manifests: %v", err))
		return &VulnerabilityAnalysis{}, nil
	}
	// Fetch what melange builds: the expected commit when pinned (a tag can
	// move), else the tag.
	ref := cmp.Or(expectedCommit, tag)

	languages := make([]string, 0, len(units))
	for language := range units {
		languages = append(languages, language)
	}
	sort.Strings(languages)

	analysis := &VulnerabilityAnalysis{
		RepoURL:        repoURL,
		Tag:            tag,
		ExpectedCommit: expectedCommit,
	}
	uniqueVulns := make(map[string]scan.Vulnerability)
	var rawBumpsSeen []string

	for _, language := range languages {
		// Shadowed for the rest of this iteration: every log emitted while
		// analyzing this language - including deep inside performAnalysis -
		// now carries it.
		ctx := logging.With(ctx, "language", language)

		langUnits := units[language] // already sorted by modroot
		modroots := unitRoots(langUnits)

		eco, err := ecosystem.New(language)
		if err != nil {
			// A language detected via annotation/build-signal but not (yet)
			// implemented (e.g. gradle): skipped, and reported as such.
			gp.Skip(ctx, fmt.Sprintf("%s: %v", language, err))
			continue
		}

		logging.From(ctx).Debug("analyzing language", "repository", repoURL, "ref", ref, "modroots", modroots)
		gp.AddMessage(fmt.Sprintf("Analyzing %s dependencies from %s @ %s (modroots: %s)", language, repoURL, ref, strings.Join(modroots, ", ")))

		result, err := v.performAnalysis(ctx, eco, language, repoURL, ref, langUnits, bumpSteps, gp)
		if err != nil {
			return nil, fmt.Errorf("performing %s dependency analysis: %w", language, err)
		}

		analysis.ByLanguage = append(analysis.ByLanguage, result.Analysis)
		analysis.BumpActions = append(analysis.BumpActions, result.Actions...)
		rawBumpsSeen = append(rawBumpsSeen, result.RawBumps...)
		maps.Copy(uniqueVulns, result.Vulns)

		gp.AddMessage(fmt.Sprintf("%s analysis complete: %d modroot(s), %d action(s) needed", language, len(modroots), len(result.Actions)))
	}

	analysis.VulnerabilitiesFound = len(uniqueVulns)
	for _, vuln := range uniqueVulns {
		switch vuln.Severity {
		case "CRITICAL":
			analysis.CriticalCount++
		case "HIGH":
			analysis.HighCount++
		}
	}
	analysis.SecurityBumps = dedupeSorted(rawBumpsSeen)

	gp.AddMessage(fmt.Sprintf("Analysis complete: %d language(s), %d vulnerabilities, %d action(s) needed",
		len(analysis.ByLanguage), analysis.VulnerabilitiesFound, len(analysis.BumpActions)))

	return analysis, nil
}

// languageResult holds one language's per-modroot analysis, plus its
// contribution to the overall multi-language aggregate: unique
// vulnerabilities found (keyed by ID, so checkVulnerabilities can dedupe
// across languages), bump actions, and the raw OSV-recommended bump strings
// (for the human-readable SecurityBumps summary).
type languageResult struct {
	Analysis LanguageAnalysis
	Vulns    map[string]scan.Vulnerability
	Actions  []BumpAction
	RawBumps []string
}

// performAnalysis analyzes each module root independently: fetching its
// manifest files at ref (fail closed: any fetch failure other than a
// confirmed 404 on an optional manifest, and any unanalyzable manifest, is an
// error for the file - never a silently clean modroot), scanning for
// vulnerabilities, and determining the desired
// dependency set for that root by filtering candidate bumps (its existing
// declared deps plus any new security bumps) against its own manifest. This
// per-root filtering applies to deps entries only: omnibump go-gets an
// absent dep, and the final tidy prunes it back out (warn-skipped), so a
// deps entry must never be declared for a root that doesn't actually depend
// on it. Replaces entries are exempt - omnibump's workspace path re-adds a
// replace pin for a module absent from a sub-module's go.mod (AUTO-954; the
// single-module path always applies replaces unconditionally), because a replace directive, unlike a bare require,
// survives go mod tidy. That's why replaces pass through unfiltered here.
func (v *VulnerabilityChecker) performAnalysis(ctx context.Context, eco ecosystem.Ecosystem, language, repoURL, ref string, langUnits []analysisUnit, bumpSteps []config.BumpStep, gp *GoBumpProcessor) (*languageResult, error) {
	fetcher := v.Analyzer.fetcher
	scanner := v.Analyzer.vulnerabilityScanner

	modroots := unitRoots(langUnits)
	existingDepsByRoot := existingDepsForModroots(modroots, bumpSteps)
	existingReplacesByRoot := existingReplacesForModroots(modroots, bumpSteps)
	// go-version is a Go-only (go/bump) pipeline input - other languages'
	// analyses never carry one.
	existingGoVersionByRoot := make(map[string]string)
	if language == "go" {
		existingGoVersionByRoot = existingGoVersionsForModroots(modroots, bumpSteps)
	}
	required, optional := eco.ManifestFiles()

	result := &languageResult{
		Vulns: make(map[string]scan.Vulnerability),
	}
	result.Analysis.Language = language
	result.Analysis.ByModroot = make([]ModrootAnalysis, 0, len(modroots))

	for _, unit := range langUnits {
		root := unit.Modroot
		// Shadowed for the rest of this iteration - see the language-level
		// shadow above.
		ctx := logging.With(ctx, "modroot", root)

		files := make(map[string][]byte, len(required)+len(optional))
		for _, name := range append(slices.Clone(required), optional...) {
			content, err := fetcher.FetchFile(ctx, repoURL, ref, modrootPath(root, name))
			if errors.Is(err, ecosystem.ErrNotFound) && slices.Contains(optional, name) {
				logging.From(ctx).Debug("optional manifest file absent", "manifest", name)
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("modroot %s: %w", root, err)
			}
			files[name] = content
		}

		deps, err := eco.Analyze(ctx, files)
		if err != nil {
			return nil, fmt.Errorf("modroot %s: analyzing dependencies: %w", root, err)
		}

		pkgs := eco.ScanPackages(ctx, deps)
		scanResult, err := scanner.ScanPackages(ctx, pkgs)
		if err != nil {
			return nil, fmt.Errorf("modroot %s: scanning dependencies for vulnerabilities: %w", root, err)
		}
		if scanResult.Error != "" {
			return nil, fmt.Errorf("modroot %s: security scan error: %s", root, scanResult.Error)
		}

		for _, vuln := range scanResult.Vulnerabilities {
			result.Vulns[vuln.ID] = vuln
		}

		existingDeps := existingDepsByRoot[root]
		existingReplaces := existingReplacesByRoot[root]
		desiredDeps, held := eco.FilterBumps(ctx, existingDeps, scanResult.SecurityBumps, deps)
		heldResiduals := make([]simulate.Residual, 0, len(held))
		for _, h := range held {
			heldResiduals = append(heldResiduals, simulate.Residual{
				Module:          h.Bump.Name,
				ResolvedVersion: h.Bump.CurrentVersion,
				FixedVersion:    h.Bump.FixedVersion,
				VulnIDs:         h.Bump.VulnIDs,
				Reason:          h.Reason,
			})
			logging.From(ctx).Warn("fix held back", "module", h.Bump.Name, "fix", h.Bump.FixedVersion, "reason", h.Reason)
		}
		gp.AddResiduals(heldResiduals)

		for _, bump := range scanResult.SecurityBumps {
			result.RawBumps = append(result.RawBumps, fmt.Sprintf("%s@%s", bump.Name, bump.FixedVersion))
		}

		// Coordinates in this modroot's rendered dep grammar (not OSV's own
		// naming - see Ecosystem.BumpCoords), so they compare directly
		// against splitCoordVersion output downstream.
		bumpCoords := eco.BumpCoords(ctx, scanResult.SecurityBumps, deps)
		securityBumpModules := make([]string, 0, len(bumpCoords))
		for coord := range bumpCoords {
			securityBumpModules = append(securityBumpModules, coord)
		}
		sort.Strings(securityBumpModules)

		result.Analysis.ByModroot = append(result.Analysis.ByModroot, ModrootAnalysis{
			Modroot:        root,
			BuildPackages:  unit.Packages,
			BuildTags:      unit.Tags,
			BumpEngine:     unit.Engine,
			BumpMigrating:  unit.Migrating,
			BumpNoTidy:     unit.NoTidy,
			GoPackageMinor: unit.GoMinor,
			Deps:           deps,
			ScanResult:     scanResult,
			ExistingDeps:   existingDeps,
			DesiredDeps:    desiredDeps,
			// Analysis never invents replaces - it carries existing ones
			// forward (the simulation may raise or retire them, never add
			// any). This also keeps the --no-validate degrade path a
			// pass-through.
			ExistingReplaces:     existingReplaces,
			DesiredReplaces:      existingReplaces,
			ExistingGoVersion:    existingGoVersionByRoot[root],
			SecurityBumpModules:  securityBumpModules,
			SecurityBumpsByCoord: bumpCoords,
			Residuals:            heldResiduals,
		})

		if haveDepsChanged(existingDeps, desiredDeps) {
			added := newlyAddedDeps(existingDeps, desiredDeps)
			result.Actions = append(result.Actions, BumpAction{
				Action:       "needs_bump",
				Language:     language,
				Modroots:     []string{root},
				Dependencies: added,
				Reason:       fmt.Sprintf("dependency changes needed for modroot %s", root),
			})
		}
	}

	return result, nil
}

// existingDepsForModroots returns, for each modroot, the deduplicated union
// of deps declared by every existing bump/go-bump step that covers it.
func existingDepsForModroots(modroots []string, bumpSteps []config.BumpStep) map[string][]string {
	return existingEntriesForModroots(modroots, bumpSteps, func(step config.BumpStep) []string { return step.Deps })
}

// existingReplacesForModroots is the replaces-field analogue of
// existingDepsForModroots.
func existingReplacesForModroots(modroots []string, bumpSteps []config.BumpStep) map[string][]string {
	return existingEntriesForModroots(modroots, bumpSteps, func(step config.BumpStep) []string { return step.Replaces })
}

// existingGoVersionsForModroots returns, for each modroot, the highest
// with.go-version carried by any existing go/bump step that covers it (""
// when none). It mirrors existingDepsForModroots' matching semantics (a step
// covers a root when its modroot list contains it), but only go/bump steps
// count: go-version is a gobump input, and the `uses: bump` pipeline has no
// such input (omnibump never sees it). Values goversion can't order
// (templated expressions) are ignored here; the reconciler warns about them
// instead of editing (see fastPathGoVersion). Only go/bump steps that are not
// migrated to `uses: bump` keep and raise their go-version.
func existingGoVersionsForModroots(modroots []string, bumpSteps []config.BumpStep) map[string]string {
	result := make(map[string]string, len(modroots))
	for _, root := range modroots {
		var highest string
		for _, step := range bumpSteps {
			if step.Action != "go/bump" || step.GoVersion == "" || !slices.Contains(step.Modroots, root) {
				continue
			}
			highest = goversion.Max(highest, step.GoVersion)
		}
		result[root] = highest
	}
	return result
}

func existingEntriesForModroots(modroots []string, bumpSteps []config.BumpStep, entries func(config.BumpStep) []string) map[string][]string {
	result := make(map[string][]string, len(modroots))
	for _, root := range modroots {
		var collected []string
		seen := make(map[string]struct{})
		for _, step := range bumpSteps {
			if !slices.Contains(step.Modroots, root) {
				continue
			}
			for _, entry := range entries(step) {
				if _, ok := seen[entry]; !ok {
					seen[entry] = struct{}{}
					collected = append(collected, entry)
				}
			}
		}
		result[root] = collected
	}
	return result
}

// modrootPath joins a modroot with a filename, treating "." (and "") as the repository root.
func modrootPath(root, file string) string {
	if root == "" || root == "." {
		return file
	}
	return strings.TrimSuffix(root, "/") + "/" + file
}

// newlyAddedDeps returns the entries in desired that are new or changed
// relative to existing, by coordinate (see splitCoordVersion).
func newlyAddedDeps(existing, desired []string) []string {
	existingByCoord := make(map[string]string, len(existing))
	for _, dep := range existing {
		if coord, version, ok := splitCoordVersion(dep); ok {
			existingByCoord[coord] = version
		}
	}

	var added []string
	for _, dep := range desired {
		coord, version, ok := splitCoordVersion(dep)
		if !ok {
			continue
		}
		if existingByCoord[coord] != version {
			added = append(added, dep)
		}
	}
	return added
}

// splitCoordVersion splits a rendered dep entry into its coordinate and
// trailing version, splitting on the LAST "@" so multi-@ grammars (Maven's
// "groupId@artifactId@version") are handled the same as simpler ones (Go's
// "module@version", Rust's "crate@version").
func splitCoordVersion(dep string) (coord, version string, ok bool) {
	idx := strings.LastIndex(dep, "@")
	if idx < 0 {
		return "", "", false
	}
	return dep[:idx], dep[idx+1:], true
}

// haveDepsChanged compares two dependency lists (order-independent, after
// trimming whitespace and dropping empties) to determine if they're different.
func haveDepsChanged(existing, desired []string) bool {
	normalize := func(deps []string) []string {
		var normalized []string
		for _, dep := range deps {
			dep = strings.TrimSpace(dep)
			if dep != "" {
				normalized = append(normalized, dep)
			}
		}
		slices.Sort(normalized)
		return normalized
	}
	return !slices.Equal(normalize(existing), normalize(desired))
}

// dedupeSorted deduplicates and sorts a list of strings, returning nil for an empty input.
func dedupeSorted(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}
	sort.Strings(result)
	return result
}

// applyGoBumpChanges reconciles the package's bump/go-bump pipeline steps
// with the desired per-modroot dependency sets computed during the check phase.
func (g *GoBumpApplier) applyGoBumpChanges(ctx context.Context, gp *GoBumpProcessor, analysis *VulnerabilityAnalysis) error {
	if len(analysis.BumpActions) == 0 {
		logging.From(ctx).Debug("skipping apply - no actions to apply")
		return nil
	}

	// Best-effort go-version computation for modroots the simulation didn't
	// prove (--no-validate, degrade, or per-root skips) - must run before
	// reconciliation so the value feeds step emission and the pin floor.
	if err := g.fallbackGoVersions(ctx, gp, analysis); err != nil {
		return err
	}

	loader := newMelangeLoader()

	if err := g.reconcileBumpSteps(ctx, gp, analysis, loader); err != nil {
		return fmt.Errorf("reconciling bump steps: %w", err)
	}

	if err := g.reconcileGoPackagePins(ctx, gp, goPinFloors(analysis)); err != nil {
		return fmt.Errorf("reconciling go-package pins: %w", err)
	}

	return nil
}

// fallbackGoVersions populates RequiredGoVersion for go modroots the
// simulation didn't cover, from the best-effort proxy probe (see
// fallbackRequiredGoVersion), gated against the pristine baseline exactly
// like the simulation path. Fail-open throughout: any failure just leaves
// RequiredGoVersion empty (with a warning), never blocks the apply - except
// a cancellation, which is returned. When GOPROXY=off (probeDisabled), the
// probe is skipped entirely - it would only fail every fetch - and each
// affected modroot gets one message instead.
func (g *GoBumpApplier) fallbackGoVersions(ctx context.Context, gp *GoBumpProcessor, analysis *VulnerabilityAnalysis) error {
	for li := range analysis.ByLanguage {
		lang := &analysis.ByLanguage[li]
		if lang.Language != "go" {
			continue
		}
		for mi := range lang.ByModroot {
			m := &lang.ByModroot[mi]
			if m.Simulated || m.RequiredGoVersion != "" {
				continue
			}
			if len(m.DesiredDeps) == 0 && len(m.DesiredReplaces) == 0 {
				continue
			}
			if g.probeDisabled {
				logging.From(ctx).Debug("go-version fallback: probe disabled (GOPROXY=off) - skipping", "modroot", m.Modroot)
				gp.AddMessage(fmt.Sprintf("modroot %s: GOPROXY=off - skipping best-effort Go version probe", m.Modroot))
				continue
			}
			required, unfetched, err := fallbackRequiredGoVersion(ctx, g.httpClient(), g.goProxyURL, m, g.skipPrivateModule)
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			if err == nil && unfetched > 0 {
				logging.From(ctx).Warn("best-effort Go version probe incomplete - the required Go version may be higher",
					"modroot", m.Modroot, "unfetched", unfetched)
				gp.AddMessage(fmt.Sprintf("modroot %s: best-effort Go version probe incomplete (%d candidate go.mod file(s) could not be fetched) - the required Go version may be higher", m.Modroot, unfetched))
			}
			if err != nil {
				logging.From(ctx).Warn("could not determine required Go version (best-effort probe failed)",
					"modroot", m.Modroot, "error", err)
				gp.AddMessage(fmt.Sprintf("modroot %s: could not determine required Go version (best-effort probe failed): %v", m.Modroot, err))
				continue
			}
			if required == "" || goversion.Compare(required, pristineGoBaseline(m)) <= 0 {
				continue
			}

			// The probed floor is unvalidated external input (a remote
			// go.mod's go directive): before it can become RequiredGoVersion
			// - which feeds both the go-version field and the go-package pin
			// floor - confirm it names a real Go release.
			valid, offlineErr := validateGoVersionFloor(ctx, g.releaseIndex(), goversion.Minor(required))
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			if offlineErr != nil {
				logging.From(ctx).Warn("could not validate required Go version against known releases (index unavailable) - proceeding",
					"modroot", m.Modroot, "version", required, "error", offlineErr)
				gp.AddMessage(fmt.Sprintf("modroot %s: could not validate required Go %s against known releases (index unavailable) - proceeding without validation: %v",
					m.Modroot, required, offlineErr))
			}
			if !valid {
				logging.From(ctx).Warn("candidate dependencies claim to require an unknown Go release - ignoring",
					"modroot", m.Modroot, "version", required)
				gp.AddMessage(fmt.Sprintf("modroot %s: candidate dependencies claim to require Go %s, which is not a known Go release — ignoring (check the dependency's go.mod)",
					m.Modroot, required))
				continue
			}

			m.RequiredGoVersion = required
			gp.AddMessage(fmt.Sprintf("modroot %s: candidate dependencies require Go %s (module baseline %s) - best-effort (direct candidates only); run with simulation for a proven result",
				m.Modroot, required, baselineWord(pristineGoBaseline(m))))
		}
	}
	return nil
}

// reconcileBumpSteps writes the desired per-modroot dependency sets back into
// the package's bump/go-bump pipeline steps, one language at a time (see
// reconcileLanguageBumpSteps).
func (g *GoBumpApplier) reconcileBumpSteps(ctx context.Context, gp *GoBumpProcessor, analysis *VulnerabilityAnalysis, loader *config.Loader) error {
	for _, langAnalysis := range analysis.ByLanguage {
		if len(langAnalysis.ByModroot) == 0 {
			continue
		}
		if err := g.reconcileLanguageBumpSteps(ctx, gp, langAnalysis, loader); err != nil {
			return fmt.Errorf("reconciling %s bump steps: %w", langAnalysis.Language, err)
		}
	}
	return nil
}

// stepEdit is one existing bump step's reconciliation: the modroots it owns
// (it is the first step covering them) grouped by identical desired
// deps/replaces.
type stepEdit struct {
	step    config.BumpStep
	groups  []modrootGroup
	owned   []*ModrootAnalysis
	changed bool
}

// reconcileLanguageBumpSteps writes one language's desired per-modroot
// dependency sets back into its own bump/go-bump pipeline steps, leaving
// every other language's steps untouched.
//
// Existing steps are edited IN PLACE: each keeps its position, its comments
// and every `with:` option choam does not manage (tidy, tidy-compat, work,
// show-diff, name, if, ...); only deps/replaces (and, for a migrated go/bump
// step, uses/language/go-version - see migrateStep) change. A step is only
// touched when its own content changes. Each analyzed modroot belongs to the
// first step covering it; a multi-modroot step whose roots now diverge keeps
// the first group and gets a clone (same options) per further group directly
// after it; roots left with nothing to declare leave the step's modroot list,
// and a step left with nothing at all is removed. Existing steps are never
// merged. Modroots no step covers get fresh `uses: bump` steps (coalesced by
// identical sets) after the first git-checkout. Deps are written in the
// order the simulation applied them (see simulate.ModrootResult.FinalDeps).
func (g *GoBumpApplier) reconcileLanguageBumpSteps(ctx context.Context, gp *GoBumpProcessor, langAnalysis LanguageAnalysis, loader *config.Loader) error {
	yamlContent := gp.GetCurrentYAML()
	allSteps, err := loader.FindBumpSteps(yamlContent)
	if err != nil {
		return fmt.Errorf("finding existing bump steps: %w", err)
	}

	var existingSteps []config.BumpStep
	for _, step := range allSteps {
		stepLanguage := step.Language
		if stepLanguage == "" {
			stepLanguage = "go"
		}
		if stepLanguage == langAnalysis.Language {
			existingSteps = append(existingSteps, step)
		}
	}

	byRoot := make(map[string]*ModrootAnalysis, len(langAnalysis.ByModroot))
	for i := range langAnalysis.ByModroot {
		byRoot[langAnalysis.ByModroot[i].Modroot] = &langAnalysis.ByModroot[i]
	}
	owner := make(map[string]int)
	for i, step := range existingSteps {
		for _, root := range step.Modroots {
			if _, ok := owner[root]; !ok {
				owner[root] = i
			}
		}
	}

	edits := make([]stepEdit, 0, len(existingSteps))
	for i, step := range existingSteps {
		edit := stepEdit{step: step}
		analyzed := false
		for _, root := range step.Modroots {
			if owner[root] != i {
				continue
			}
			m, ok := byRoot[root]
			if !ok {
				// Not analyzed (its manifest could not be fetched or
				// parsed): it keeps exactly what the step declares today.
				m = &ModrootAnalysis{Modroot: root, ExistingDeps: step.Deps, DesiredDeps: step.Deps,
					ExistingReplaces: step.Replaces, DesiredReplaces: step.Replaces}
			} else {
				analyzed = true
			}
			edit.owned = append(edit.owned, m)
		}
		if !analyzed {
			continue
		}
		ownedAnalyses := make([]ModrootAnalysis, len(edit.owned))
		for j, m := range edit.owned {
			ownedAnalyses[j] = *m
		}
		edit.groups = coalesceModroots(ownedAnalyses)
		switch len(edit.groups) {
		case 0:
			edit.changed = len(step.Deps) > 0 || len(step.Replaces) > 0
		case 1:
			group := edit.groups[0]
			edit.changed = !sameRootSet(group.Modroots, step.Modroots) ||
				haveDepsChanged(step.Deps, group.Deps) || haveDepsChanged(step.Replaces, group.Replaces)
		default:
			edit.changed = true
		}
		edits = append(edits, edit)
	}

	// Edit from the last step backwards: removals and clones only shift the
	// indices of steps already handled.
	sort.Slice(edits, func(i, j int) bool { return edits[i].step.Index > edits[j].step.Index })
	hasBlankLines := loader.HasBlankLinesBetweenPipelineSteps(yamlContent)
	changed := false
	for _, edit := range edits {
		if !edit.changed {
			continue
		}
		updated, err := g.rewriteStep(ctx, gp, yamlContent, edit, hasBlankLines)
		if err != nil {
			return err
		}
		yamlContent = updated
		changed = true
	}

	var unowned []ModrootAnalysis
	for _, m := range langAnalysis.ByModroot {
		if _, ok := owner[m.Modroot]; !ok {
			unowned = append(unowned, m)
		}
	}
	if groups := coalesceModroots(unowned); len(groups) > 0 {
		gitCheckoutIndices, err := loader.FindPipelinesByUse(yamlContent, "git-checkout")
		if err != nil {
			return fmt.Errorf("finding git-checkout pipeline: %w", err)
		}
		insertPos := 0
		if len(gitCheckoutIndices) > 0 {
			insertPos = gitCheckoutIndices[0] + 1
		}
		for _, group := range groups {
			spec := config.BumpStepSpec{
				Action:   "bump",
				Language: langAnalysis.Language,
				Modroots: group.Modroots,
				Deps:     group.Deps,
				Replaces: group.Replaces,
			}
			updated, err := loader.InsertBumpPipelineStep(yamlContent, insertPos, spec, hasBlankLines)
			if err != nil {
				return fmt.Errorf("inserting bump step: %w", err)
			}
			yamlContent = updated
			gp.AddMessage(fmt.Sprintf("Added %s bump step pipeline[%d] for modroot(s) %s with %d dependencies and %d replaces",
				langAnalysis.Language, insertPos, strings.Join(group.Modroots, ", "), len(group.Deps), len(group.Replaces)))
			insertPos++
			changed = true
		}
	}

	if !changed {
		return nil
	}
	gp.SetCurrentYAML(yamlContent)
	gp.MarkActualChangesApplied()
	g.recordSecurityFixes(gp, langAnalysis, addedAcrossRoots(langAnalysis.ByModroot))
	return nil
}

// rewriteStep applies one changed stepEdit in place (see
// reconcileLanguageBumpSteps): removal when nothing is left, else the first
// group's deps/replaces/modroot on the step itself - migrating a go/bump
// step when it can (see migrationFor) - and one clone per further group.
func (g *GoBumpApplier) rewriteStep(ctx context.Context, gp *GoBumpProcessor, yamlContent []byte, edit stepEdit, hasBlankLines bool) ([]byte, error) {
	loader := config.NewLoader()
	step := edit.step
	if len(edit.groups) == 0 {
		updated, err := loader.RemovePipelineStep(yamlContent, step.Index)
		if err != nil {
			return nil, fmt.Errorf("removing %s pipeline[%d]: %w", step.Action, step.Index, err)
		}
		gp.AddMessage(fmt.Sprintf("Removed %s pipeline[%d]: no dependencies or replaces left to declare", step.Action, step.Index))
		return updated, nil
	}

	migrate, plan := g.migrationFor(ctx, gp, yamlContent, edit)
	first := edit.groups[0]
	var goVersion string
	if step.Action == "go/bump" && !migrate {
		goVersion = g.fastPathGoVersion(gp, step, maxEffectiveGoVersion(edit.owned))
	}
	updated, err := loader.UpdateGoBumpStep(yamlContent, step.Index, first.Deps, first.Replaces, goVersion)
	if err != nil {
		return nil, fmt.Errorf("updating %s pipeline[%d]: %w", step.Action, step.Index, err)
	}
	if !sameRootSet(first.Modroots, step.Modroots) {
		if updated, err = loader.SetBumpModroots(updated, step.Index, first.Modroots); err != nil {
			return nil, fmt.Errorf("updating modroot of %s pipeline[%d]: %w", step.Action, step.Index, err)
		}
	}
	switch {
	case migrate:
		if updated, err = migrateStep(gp, updated, step, plan); err != nil {
			return nil, fmt.Errorf("migrating go/bump pipeline[%d]: %w", step.Index, err)
		}
		if step.NoTidy && anyBaselineTidies(edit.owned) {
			gp.AddMessage(fmt.Sprintf("pipeline[%d]: tidy: false may no longer be needed (omnibump tidies without -go; the upstream module tidies under omnibump) - left as written", step.Index))
		}
	case step.Action != "go/bump" && step.GoVersion != "":
		// The bump pipeline has no go-version input: drop a stale one.
		if updated, err = loader.RemovePipelineWithFieldLines(updated, step.Index, "go-version"); err != nil {
			return nil, fmt.Errorf("removing go-version from %s pipeline[%d]: %w", step.Action, step.Index, err)
		}
	}
	gp.AddMessage(fmt.Sprintf("Updated %s pipeline[%d] in place with %d dependencies and %d replaces", step.Action, step.Index, len(first.Deps), len(first.Replaces)))

	// Further groups: clones of the rewritten step, in group order.
	for gi := len(edit.groups) - 1; gi >= 1; gi-- {
		group := edit.groups[gi]
		if updated, err = loader.ClonePipelineStepAfter(updated, step.Index, hasBlankLines); err != nil {
			return nil, fmt.Errorf("splitting pipeline[%d]: %w", step.Index, err)
		}
		clone := step.Index + 1
		if updated, err = loader.UpdateGoBumpStep(updated, clone, group.Deps, group.Replaces, ""); err != nil {
			return nil, fmt.Errorf("updating split of pipeline[%d]: %w", step.Index, err)
		}
		if updated, err = loader.SetBumpModroots(updated, clone, group.Modroots); err != nil {
			return nil, fmt.Errorf("updating modroot of split of pipeline[%d]: %w", step.Index, err)
		}
		gp.AddMessage(fmt.Sprintf("Split pipeline[%d]: modroot(s) %s now diverge, written to a copy of the step with %d dependencies and %d replaces",
			step.Index, strings.Join(group.Modroots, ", "), len(group.Deps), len(group.Replaces)))
	}
	return updated, nil
}

// migrationFor decides whether a go/bump step being rewritten migrates to
// `uses: bump`: its plan allows it (see planMigration) AND every modroot it
// owns was simulated with the omnibump engine - so what is written is what
// was validated. A step that does not migrate gets a message saying why.
func (g *GoBumpApplier) migrationFor(ctx context.Context, gp *GoBumpProcessor, yamlContent []byte, edit stepEdit) (bool, migrationPlan) {
	step := edit.step
	if step.Action != "go/bump" {
		return false, migrationPlan{}
	}
	plan := planMigration(ctx, yamlContent, step, g.releaseIndex())
	if !plan.ok {
		gp.AddMessage(fmt.Sprintf("go/bump pipeline[%d] not migrated to uses: bump: %s", step.Index, plan.reason))
		return false, plan
	}
	for _, m := range edit.owned {
		if !m.Simulated || m.BumpEngine != simulate.EngineOmnibump {
			gp.AddMessage(fmt.Sprintf("go/bump pipeline[%d] not migrated to uses: bump: modroot %s was not validated with the omnibump engine", step.Index, m.Modroot))
			return false, plan
		}
	}
	return true, plan
}

// anyBaselineTidies reports whether any of the modroots tidies under omnibump.
func anyBaselineTidies(roots []*ModrootAnalysis) bool {
	for _, m := range roots {
		if m.BaselineTidies {
			return true
		}
	}
	return false
}

// fastPathGoVersion decides the go-version argument for the in-place update
// of a go/bump step that is not migrated: the group's effective value when
// it genuinely raises the step's current one, "" (leave the field untouched,
// byte-for-byte) when the step already carries an equal-or-higher value - so
// re-running the applier on already-updated YAML never churns it, and an
// existing value is NEVER lowered. A step value goversion can't order
// (templated expression) is warned about, never overwritten.
func (g *GoBumpApplier) fastPathGoVersion(gp *GoBumpProcessor, step config.BumpStep, effective string) string {
	if effective == "" {
		return ""
	}
	switch {
	case step.GoVersion == "":
		return effective
	case !goversion.IsValid(step.GoVersion):
		gp.AddMessage(fmt.Sprintf("%s pipeline[%d] go-version %q is not a plain version (templated?); required Go %s - not rewritten, update it manually",
			step.Action, step.Index, step.GoVersion, effective))
		return ""
	case goversion.Compare(effective, step.GoVersion) > 0:
		return effective
	default:
		return ""
	}
}

// modrootGroup is a set of modroots that share identical desired dependency
// and replace sets.
type modrootGroup struct {
	Modroots []string
	Deps     []string
	Replaces []string
}

// coalesceModroots groups modroots that end up with identical desired
// dependency AND replace sets (compared as sets) into a single step, in
// first-seen order. A group's lists keep its first modroot's order (the
// order the simulation applied them in). Roots with neither desired deps nor
// replaces are omitted entirely.
func coalesceModroots(byModroot []ModrootAnalysis) []modrootGroup {
	var order []string
	byKey := make(map[string]*modrootGroup)

	for _, m := range byModroot {
		if len(m.DesiredDeps) == 0 && len(m.DesiredReplaces) == 0 {
			continue
		}
		key := groupKey(m.DesiredDeps) + "\x00" + groupKey(m.DesiredReplaces)
		group, ok := byKey[key]
		if !ok {
			group = &modrootGroup{Deps: slices.Clone(m.DesiredDeps), Replaces: slices.Clone(m.DesiredReplaces)}
			byKey[key] = group
			order = append(order, key)
		}
		group.Modroots = append(group.Modroots, m.Modroot)
	}

	groups := make([]modrootGroup, 0, len(order))
	for _, key := range order {
		groups = append(groups, *byKey[key])
	}
	return groups
}

// groupKey returns an order-independent key for a set of rendered dep entries.
func groupKey(deps []string) string {
	return strings.Join(sortedCopy(deps), "\n")
}

func sortedCopy(s []string) []string {
	out := make([]string, len(s))
	copy(out, s)
	sort.Strings(out)
	return out
}

// sameRootSet reports whether two modroot lists contain the same set of roots (order-independent).
func sameRootSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	return slices.Equal(sortedCopy(a), sortedCopy(b))
}

// effectiveGoVersion is the go-version a modroot's go/bump step should end
// up carrying: the max of what its existing steps already declare and what
// the proven/probed candidate set requires. Max never picks the lower of two
// valid values, so an existing value is never lowered. "" for non-Go
// modroots (both fields are Go-only) and when neither side has a value.
func effectiveGoVersion(m ModrootAnalysis) string {
	return goversion.Max(m.ExistingGoVersion, m.RequiredGoVersion)
}

// maxEffectiveGoVersion returns the highest effective go-version
// (effectiveGoVersion) across the given modroots, "" if none has one: a step
// covering several roots must satisfy all of them, and go-version is a floor,
// so raising to the maximum is always safe - fastPathGoVersion still
// enforces never-lower against the step's current value on top of this.
func maxEffectiveGoVersion(roots []*ModrootAnalysis) string {
	var max string
	for _, m := range roots {
		max = goversion.Max(max, effectiveGoVersion(*m))
	}
	return max
}

// addedAcrossRoots returns the deduplicated union, across all modroots, of
// dependencies that are new or changed relative to what was previously
// declared AND actually fix a flagged vulnerability (see
// ModrootAnalysis.SecurityBumpModules) - used only to feed
// recordSecurityFixes, so a coherence-only entry (added purely to keep the
// module graph consistent, fixing no CVE) never counts as a security fix.
func addedAcrossRoots(byModroot []ModrootAnalysis) []string {
	seen := make(map[string]struct{})
	var added []string
	for _, m := range byModroot {
		securityModules := make(map[string]struct{}, len(m.SecurityBumpModules))
		for _, module := range m.SecurityBumpModules {
			securityModules[module] = struct{}{}
		}
		isSecurityModule := func(module string) bool {
			if _, ok := securityModules[module]; ok {
				return true
			}
			_, ok := securityModules[trimMajorSuffix(module)]
			return ok
		}

		for _, dep := range newlyAddedDeps(m.ExistingDeps, m.DesiredDeps) {
			coord, _, ok := splitCoordVersion(dep)
			if !ok {
				coord = dep
			}
			if !isSecurityModule(coord) {
				continue
			}
			if _, ok := seen[dep]; !ok {
				seen[dep] = struct{}{}
				added = append(added, dep)
			}
		}

		// A changed replace directive that fixes a CVE counts as a
		// security fix too - raised replaces must feed epoch accounting. The
		// module coordinate is the directive's new path ("old=new@version").
		for _, replace := range newlyAddedDeps(m.ExistingReplaces, m.DesiredReplaces) {
			coord, version, ok := splitCoordVersion(replace)
			if !ok {
				continue
			}
			if _, newPath, found := strings.Cut(coord, "="); found {
				coord = newPath
			}
			if !isSecurityModule(coord) {
				continue
			}
			entry := coord + "@" + version
			if _, ok := seen[entry]; !ok {
				seen[entry] = struct{}{}
				added = append(added, entry)
			}
		}
	}
	sort.Strings(added)
	return added
}

// recordSecurityFixes records security fixes in the processor for reporting.
// Creates one SecurityFix per dependency so len(SecurityFixes) accurately
// reflects the count. Advisory IDs and prior versions come from the scan's
// SecurityBumps when available.
func (g *GoBumpApplier) recordSecurityFixes(gp *GoBumpProcessor, langAnalysis LanguageAnalysis, dependencies []string) {
	type bumpDetail struct {
		vulnIDs    []string
		oldVersion string
	}
	byModule := make(map[string]bumpDetail)
	for _, m := range langAnalysis.ByModroot {
		// Rendered-coordinate mapping first (see Ecosystem.BumpCoords) -
		// this is what actually matches splitCoordVersion output for Maven
		// ("groupId@artifactId") and v2+-normalized Go module paths.
		for coord, bump := range m.SecurityBumpsByCoord {
			byModule[coord] = bumpDetail{vulnIDs: bump.VulnIDs, oldVersion: bump.CurrentVersion}
		}
		if m.ScanResult == nil {
			continue
		}
		// Legacy OSV-name fallback, for coordinates the map lacks (hand-built
		// fixtures, or entries the simulation added after analysis).
		for _, bump := range m.ScanResult.SecurityBumps {
			if _, ok := byModule[bump.Name]; !ok {
				byModule[bump.Name] = bumpDetail{vulnIDs: bump.VulnIDs, oldVersion: bump.CurrentVersion}
			}
		}
	}

	for _, dep := range dependencies {
		module, version, ok := splitCoordVersion(dep)
		if !ok {
			module = dep
			version = "unknown"
		}

		detail, found := byModule[module]
		if !found {
			// OSV names v2+ Go modules without the /vN path suffix.
			detail = byModule[trimMajorSuffix(module)]
		}
		vulnerability := "security vulnerability"
		if len(detail.vulnIDs) > 0 {
			vulnerability = strings.Join(detail.vulnIDs, ", ")
		}
		oldVersion := "vulnerable"
		if detail.oldVersion != "" {
			oldVersion = detail.oldVersion
		}

		gp.AddSecurityFix(SecurityFix{
			Module:        module,
			Vulnerability: vulnerability,
			OldVersion:    oldVersion,
			NewVersion:    version,
			Severity:      "varies",
		})
	}
}

// Helper functions

// newMelangeLoader creates a new melange configuration loader
func newMelangeLoader() *config.Loader {
	return config.NewLoader()
}

// extractRepositoryFromYAML extracts the repository URL, tag, and
// expected-commit from the melange YAML's first git-checkout step.
func extractRepositoryFromYAML(yamlContent []byte, cfg *melange.Configuration, latestVersion string) (string, string, string, error) {
	loader := newMelangeLoader()

	// Find git-checkout pipelines
	gitCheckoutIndices, err := loader.FindPipelinesByUse(yamlContent, "git-checkout")
	if err != nil {
		return "", "", "", fmt.Errorf("finding git-checkout pipelines: %w", err)
	}

	if len(gitCheckoutIndices) == 0 {
		return "", "", "", fmt.Errorf("no git-checkout pipeline found")
	}

	// Get the first git-checkout pipeline fields
	withFields, err := loader.GetPipelineWithField(yamlContent, gitCheckoutIndices[0])
	if err != nil {
		return "", "", "", fmt.Errorf("getting git-checkout pipeline fields: %w", err)
	}

	repoURL, hasRepo := withFields["repository"]
	tag, hasTag := withFields["tag"]
	expectedCommit := withFields["expected-commit"]

	if !hasRepo || repoURL == "" {
		return "", "", "", fmt.Errorf("no repository URL found in git-checkout pipeline")
	}

	if !hasTag || tag == "" {
		// Use the latest version as tag if no tag specified
		tag = latestVersion
	}

	// Resolve template variables in repoURL and tag using the Renderer
	renderer, err := config.NewRenderer(cfg)
	if err != nil {
		return "", "", "", fmt.Errorf("creating template renderer: %w", err)
	}

	// Resolve repository URL template variables
	resolvedRepoURL, err := renderer.RenderString(repoURL)
	if err != nil {
		return "", "", "", fmt.Errorf("resolving repository URL template %q: %w", repoURL, err)
	}

	// Resolve tag template variables
	resolvedTag, err := renderer.RenderString(tag)
	if err != nil {
		return "", "", "", fmt.Errorf("resolving tag template %q: %w", tag, err)
	}

	resolvedCommit, err := renderer.RenderString(expectedCommit)
	if err != nil {
		return "", "", "", fmt.Errorf("resolving expected-commit template %q: %w", expectedCommit, err)
	}

	return resolvedRepoURL, resolvedTag, resolvedCommit, nil
}
