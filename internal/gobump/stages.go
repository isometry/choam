package gobump

import (
	"context"
	"fmt"
	"log/slog"
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
	"github.com/isometry/choam/internal/processor"
	"github.com/isometry/choam/internal/processor/stages"
	"github.com/isometry/choam/internal/scan"
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

		// File writing - only writes if there are actual file changes
		stages.NewFileWriterStage(false, ""),

		// Final validation
		stages.NewValidationStage(false, true),
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
		if gp.Validated {
			for id := range analysisSeverities(gp) {
				ids[id] = struct{}{}
			}
			for _, residual := range gp.Residuals {
				for _, id := range residual.VulnIDs {
					delete(ids, id)
				}
			}
			for _, id := range gp.UnreachableVulnIDs {
				delete(ids, id)
			}
		} else {
			for _, fix := range gp.SecurityFixes {
				for _, id := range strings.Split(fix.Vulnerability, ",") {
					id = strings.TrimSpace(id)
					if id == "" || strings.ContainsRune(id, ' ') {
						continue // free-text placeholder, not an advisory ID
					}
					ids[id] = struct{}{}
				}
			}
		}
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
	slog.Debug("checking vulnerabilities", "file", gp.GetFilePath())

	loader := newMelangeLoader()

	bumpSteps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	if err != nil {
		return nil, fmt.Errorf("finding bump pipelines: %w", err)
	}

	units := discoverAnalysisUnits(gp.Config, bumpSteps)
	if len(units) == 0 {
		slog.Debug("not a bumpable project", "file", gp.GetFilePath())
		gp.AddMessage("Not a bumpable project - skipping dependency analysis")
		return &VulnerabilityAnalysis{}, nil
	}

	repoURL, tag, expectedCommit, err := extractRepositoryFromYAML(gp.GetCurrentYAML(), gp.Config, gp.GetCurrentVersion())
	if err != nil {
		slog.Debug("could not extract repository info", "file", gp.GetFilePath(), "error", err)
		gp.AddMessage(fmt.Sprintf("Could not extract repository info - skipping: %v", err))
		return &VulnerabilityAnalysis{}, nil
	}

	if repoURL == "" {
		gp.AddMessage("No repository URL found - skipping dependency analysis")
		return &VulnerabilityAnalysis{}, nil
	}

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
		langUnits := units[language] // already sorted by modroot
		modroots := unitRoots(langUnits)

		eco, err := ecosystem.New(language)
		if err != nil {
			// A language detected via annotation/build-signal but not (yet)
			// implemented (e.g. gradle) - surface it, don't fail the run.
			gp.AddMessage(fmt.Sprintf("%s: %v - skipping", language, err))
			continue
		}

		slog.Debug("analyzing language", "language", language, "repository", repoURL, "tag", tag, "modroots", modroots)
		gp.AddMessage(fmt.Sprintf("Analyzing %s dependencies from %s @ %s (modroots: %s)", language, repoURL, tag, strings.Join(modroots, ", ")))

		result, err := v.performAnalysis(ctx, eco, language, repoURL, tag, langUnits, bumpSteps, gp)
		if err != nil {
			return nil, fmt.Errorf("performing %s dependency analysis: %w", language, err)
		}

		analysis.ByLanguage = append(analysis.ByLanguage, result.Analysis)
		analysis.BumpActions = append(analysis.BumpActions, result.Actions...)
		rawBumpsSeen = append(rawBumpsSeen, result.RawBumps...)
		for id, vuln := range result.Vulns {
			uniqueVulns[id] = vuln
		}

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
// manifest files, scanning for vulnerabilities, and determining the desired
// dependency set for that root by filtering candidate bumps (its existing
// declared deps plus any new security bumps) against its own manifest. This
// per-root filtering applies to deps entries only: omnibump go-gets an
// absent dep, and the final tidy prunes it back out (warn-skipped), so a
// deps entry must never be declared for a root that doesn't actually depend
// on it. Replaces entries are exempt - since omnibump v0.23.1 (AUTO-954) the
// workspace path re-adds a replace pin for a module absent from a
// sub-module's go.mod (the single-module path always applied replaces
// unconditionally), because a replace directive, unlike a bare require,
// survives go mod tidy. That's why replaces pass through unfiltered here.
func (v *VulnerabilityChecker) performAnalysis(ctx context.Context, eco ecosystem.Ecosystem, language, repoURL, tag string, langUnits []analysisUnit, bumpSteps []config.BumpStep, gp *GoBumpProcessor) (*languageResult, error) {
	fetcher := v.Analyzer.fetcher
	scanner := v.Analyzer.vulnerabilityScanner

	modroots := unitRoots(langUnits)
	existingDepsByRoot := existingDepsForModroots(modroots, bumpSteps)
	existingReplacesByRoot := existingReplacesForModroots(modroots, bumpSteps)
	// go-version is a Go-only pipeline input - other languages' analyses must
	// never carry one (the coalesce key includes it; a stray value would
	// split their groups).
	existingGoVersionByRoot := make(map[string]string)
	if language == "go" {
		existingGoVersionByRoot = existingGoVersionsForModroots(modroots, bumpSteps)
	}
	manifestFiles := eco.ManifestFiles()

	result := &languageResult{
		Vulns: make(map[string]scan.Vulnerability),
	}
	result.Analysis.Language = language
	result.Analysis.ByModroot = make([]ModrootAnalysis, 0, len(modroots))

	for _, unit := range langUnits {
		root := unit.Modroot
		files := make(map[string][]byte, len(manifestFiles))
		for _, name := range manifestFiles {
			content, err := fetcher.FetchFile(ctx, repoURL, tag, modrootPath(root, name))
			if err != nil {
				slog.Debug("could not fetch manifest file", "modroot", root, "file", name, "error", err)
				continue
			}
			files[name] = content
		}

		deps, err := eco.Analyze(ctx, files)
		if err != nil {
			slog.Debug("could not analyze modroot", "modroot", root, "error", err)
			gp.AddMessage(fmt.Sprintf("modroot %s: could not analyze dependencies (%v) - skipping", root, err))
			continue
		}

		pkgs := eco.ScanPackages(deps)
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
		desiredDeps := eco.FilterBumps(ctx, existingDeps, scanResult.SecurityBumps, deps)

		for _, bump := range scanResult.SecurityBumps {
			result.RawBumps = append(result.RawBumps, fmt.Sprintf("%s@%s", bump.Name, bump.FixedVersion))
		}

		// Coordinates in this modroot's rendered dep grammar (not OSV's own
		// naming - see Ecosystem.BumpCoords), so they compare directly
		// against splitCoordVersion output downstream.
		bumpCoords := eco.BumpCoords(scanResult.SecurityBumps, deps)
		securityBumpModules := make([]string, 0, len(bumpCoords))
		for coord := range bumpCoords {
			securityBumpModules = append(securityBumpModules, coord)
		}
		sort.Strings(securityBumpModules)

		result.Analysis.ByModroot = append(result.Analysis.ByModroot, ModrootAnalysis{
			Modroot:       root,
			BuildPackages: unit.Packages,
			Deps:          deps,
			ScanResult:    scanResult,
			ExistingDeps:  existingDeps,
			DesiredDeps:   desiredDeps,
			// Analysis never invents replaces - it carries existing ones
			// forward; only the simulation promotes pins into this channel.
			// This also keeps the --no-validate degrade path a pass-through.
			ExistingReplaces:     existingReplaces,
			DesiredReplaces:      existingReplaces,
			ExistingGoVersion:    existingGoVersionByRoot[root],
			SecurityBumpModules:  securityBumpModules,
			SecurityBumpsByCoord: bumpCoords,
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
// with.go-version carried by any existing go-language bump/go-bump step that
// covers it ("" when none). It mirrors existingDepsForModroots' matching
// semantics (a step covers a root when its modroot list contains it), but is
// additionally filtered to go-language steps - go-version is meaningless
// elsewhere. Values goversion can't order (templated expressions) are ignored
// here; the fast-path reconciler warns about them instead of editing.
func existingGoVersionsForModroots(modroots []string, bumpSteps []config.BumpStep) map[string]string {
	result := make(map[string]string, len(modroots))
	for _, root := range modroots {
		var highest string
		for _, step := range bumpSteps {
			if step.GoVersion == "" || !slices.Contains(step.Modroots, root) {
				continue
			}
			if stepLanguage := step.Language; stepLanguage != "" && stepLanguage != "go" {
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
		slog.Debug("skipping apply - no actions to apply")
		return nil
	}

	// Best-effort go-version computation for modroots the simulation didn't
	// prove (--no-validate, degrade, or per-root skips) - must run before
	// reconciliation so the value feeds step emission and the pin floor.
	g.fallbackGoVersions(ctx, gp, analysis)

	loader := newMelangeLoader()

	if err := g.reconcileBumpSteps(gp, analysis, loader); err != nil {
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
// RequiredGoVersion empty (with a warning), never blocks the apply. When
// GOPROXY=off (probeDisabled), the probe is skipped entirely - it would
// only fail every fetch - and each affected modroot gets one message
// instead.
func (g *GoBumpApplier) fallbackGoVersions(ctx context.Context, gp *GoBumpProcessor, analysis *VulnerabilityAnalysis) {
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
				slog.Debug("go-version fallback: probe disabled (GOPROXY=off) - skipping", "modroot", m.Modroot)
				gp.AddMessage(fmt.Sprintf("modroot %s: GOPROXY=off - skipping best-effort Go version probe", m.Modroot))
				continue
			}
			required, err := fallbackRequiredGoVersion(ctx, g.httpClient(), g.goProxyURL, m, g.skipPrivateModule)
			if err != nil {
				slog.Warn("could not determine required Go version (best-effort probe failed)",
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
			if offlineErr != nil {
				slog.Warn("could not validate required Go version against known releases (index unavailable) - proceeding",
					"modroot", m.Modroot, "version", required, "error", offlineErr)
				gp.AddMessage(fmt.Sprintf("modroot %s: could not validate required Go %s against known releases (index unavailable) - proceeding without validation: %v",
					m.Modroot, required, offlineErr))
			}
			if !valid {
				slog.Warn("candidate dependencies claim to require an unknown Go release - ignoring",
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
}

// reconcileBumpSteps writes the desired per-modroot dependency sets back into
// the package's bump/go-bump pipeline steps.
//
// Fast path: when a single existing step already covers exactly the analyzed
// modroot set and every one of those roots desires an identical dependency
// set, its deps are updated in place, preserving its action (bump or
// go/bump), modroot list, and language.
//
// General path: otherwise, all existing bump/go-bump steps are removed and
// replaced with freshly coalesced "bump" steps - one per distinct desired
// dependency set, each covering every modroot that shares it, with an
// explicit with.language. This is what produces cert-manager-style
// multi-step output when modroots genuinely diverge, while collapsing to a
// single step when they agree.
func (g *GoBumpApplier) reconcileBumpSteps(gp *GoBumpProcessor, analysis *VulnerabilityAnalysis, loader *config.Loader) error {
	for _, langAnalysis := range analysis.ByLanguage {
		if len(langAnalysis.ByModroot) == 0 {
			continue
		}
		if err := g.reconcileLanguageBumpSteps(gp, langAnalysis, loader); err != nil {
			return fmt.Errorf("reconciling %s bump steps: %w", langAnalysis.Language, err)
		}
	}
	return nil
}

// reconcileLanguageBumpSteps writes one language's desired per-modroot
// dependency sets back into its own bump/go-bump pipeline steps, leaving
// every other language's steps untouched (existing steps are filtered to
// this language before any fast-path/rebuild decision is made).
//
// Fast path: when a single existing step of this language already covers
// exactly its analyzed modroot set and every one of those roots desires an
// identical dependency set and replace set, its deps/replaces are updated in
// place, preserving its action (bump or go/bump), modroot list, and
// language. Per-root effective go-versions are NOT required to match to take
// this path: go-version is a floor (never-lowered downstream by
// fastPathGoVersion), so the single step is simply raised to the highest
// effective go-version across all covered roots (maxEffectiveGoVersion),
// which safely satisfies the most demanding root even when roots diverge.
// Forcing a rebuild over a go-version mismatch alone would destroy the
// step's comments for no safety benefit.
//
// General path: otherwise, all of this language's existing steps are
// removed and replaced with freshly coalesced "bump" steps - one per
// distinct desired dependency set (deps, replaces, AND effective
// go-version), each covering every modroot that shares it, with an explicit
// with.language. This is what produces cert-manager-style multi-step output
// when modroots genuinely diverge, while collapsing to a single step when
// they agree.
func (g *GoBumpApplier) reconcileLanguageBumpSteps(gp *GoBumpProcessor, langAnalysis LanguageAnalysis, loader *config.Loader) error {
	allSteps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
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

	if len(existingSteps) == 1 &&
		sameRootSet(existingSteps[0].Modroots, allModroots(langAnalysis.ByModroot)) &&
		allRootsShareDeps(langAnalysis.ByModroot) &&
		allRootsShareReplaces(langAnalysis.ByModroot) {
		step := existingSteps[0]
		desired := desiredDepsForSingleGroup(langAnalysis.ByModroot)
		desiredReplaces := desiredReplacesForSingleGroup(langAnalysis.ByModroot)
		goVersion := g.fastPathGoVersion(gp, step, maxEffectiveGoVersion(langAnalysis.ByModroot))

		updated, err := loader.UpdateGoBumpStep(gp.GetCurrentYAML(), step.Index, desired, desiredReplaces, goVersion)
		if err != nil {
			return fmt.Errorf("updating %s pipeline[%d]: %w", step.Action, step.Index, err)
		}

		gp.SetCurrentYAML(updated)
		gp.MarkActualChangesApplied()
		gp.AddMessage(fmt.Sprintf("Updated %s pipeline[%d] with %d dependencies and %d replaces", step.Action, step.Index, len(desired), len(desiredReplaces)))
		g.recordSecurityFixes(gp, langAnalysis, addedAcrossRoots(langAnalysis.ByModroot))
		return nil
	}

	// A step carrying a templated/unorderable go-version cannot be preserved
	// through this rebuild: InsertBumpPipelineStep only accepts plain version
	// characters ([0-9A-Za-z._+-]), so the raw templated value can never be
	// re-emitted (existingGoVersionsForModroots above already silently drops
	// it from the effective-go-version computation). Warn loudly instead of
	// letting it vanish.
	for _, step := range existingSteps {
		if step.GoVersion != "" && !goversion.IsValid(step.GoVersion) {
			msg := fmt.Sprintf("%s pipeline[%d] go-version %q is not a plain version (templated?) and could not be preserved across the bump pipeline rebuild (modroots: %s) - reapply it manually",
				step.Action, step.Index, step.GoVersion, strings.Join(step.Modroots, ", "))
			gp.AddMessage(msg)
			slog.Warn("go-version could not be preserved across bump pipeline rebuild",
				"action", step.Action, "index", step.Index, "go_version", step.GoVersion, "modroots", step.Modroots)
		}
	}

	groups := coalesceModroots(langAnalysis.ByModroot)

	indices := make([]int, len(existingSteps))
	for i, step := range existingSteps {
		indices[i] = step.Index
	}
	sort.Sort(sort.Reverse(sort.IntSlice(indices)))

	yamlContent := gp.GetCurrentYAML()

	// Capture the file's step-separation convention BEFORE stripping steps -
	// a pipeline reduced to a lone git-checkout has nothing left to detect it from.
	hasBlankLines := loader.HasBlankLinesBetweenPipelineSteps(yamlContent)

	for _, idx := range indices {
		updated, err := loader.RemovePipelineStep(yamlContent, idx)
		if err != nil {
			return fmt.Errorf("removing bump step[%d]: %w", idx, err)
		}
		yamlContent = updated
	}

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
			Action:    "bump",
			Language:  langAnalysis.Language,
			GoVersion: group.GoVersion,
			Modroots:  group.Modroots,
			Deps:      group.Deps,
			Replaces:  group.Replaces,
		}
		updated, err := loader.InsertBumpPipelineStep(yamlContent, insertPos, spec, hasBlankLines)
		if err != nil {
			return fmt.Errorf("inserting bump step: %w", err)
		}
		yamlContent = updated
		insertPos++
	}

	gp.SetCurrentYAML(yamlContent)
	gp.MarkActualChangesApplied()
	gp.AddMessage(fmt.Sprintf("Rebuilt %s bump pipeline into %d step(s) across %d modroot(s)", langAnalysis.Language, len(groups), len(langAnalysis.ByModroot)))
	g.recordSecurityFixes(gp, langAnalysis, addedAcrossRoots(langAnalysis.ByModroot))

	return nil
}

// fastPathGoVersion decides the go-version argument for a fast-path in-place
// update of step: the group's effective value when it genuinely raises the
// step's current one, "" (leave the field untouched, byte-for-byte) when the
// step already carries an equal-or-higher value - so re-running the applier
// on already-updated YAML never churns it, and an existing value is NEVER
// lowered. A step value goversion can't order (templated expression) is
// warned about, never overwritten.
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
// and replace sets and (for Go) an identical effective go-version.
type modrootGroup struct {
	Modroots  []string
	Deps      []string
	Replaces  []string
	GoVersion string // effective go-version shared by the group; "" for none (and always for non-Go languages)
}

// coalesceModroots groups modroots that end up with identical desired
// dependency AND replace sets AND effective go-version into a single step, in
// first-seen order. Roots with neither desired deps nor replaces are omitted
// entirely. The go-version key component is only ever non-empty for Go
// modroots (RequiredGoVersion/ExistingGoVersion are Go-only fields), so other
// languages' grouping is unaffected; empty values group together as before.
func coalesceModroots(byModroot []ModrootAnalysis) []modrootGroup {
	var order []string
	byKey := make(map[string]*modrootGroup)

	for _, m := range byModroot {
		if len(m.DesiredDeps) == 0 && len(m.DesiredReplaces) == 0 {
			continue
		}
		goVersion := effectiveGoVersion(m)
		key := groupKey(m.DesiredDeps) + "\x00" + groupKey(m.DesiredReplaces) + "\x00" + goVersion
		group, ok := byKey[key]
		if !ok {
			group = &modrootGroup{Deps: sortedCopy(m.DesiredDeps), Replaces: sortedCopy(m.DesiredReplaces), GoVersion: goVersion}
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

func allModroots(byModroot []ModrootAnalysis) []string {
	roots := make([]string, len(byModroot))
	for i, m := range byModroot {
		roots[i] = m.Modroot
	}
	return roots
}

// allRootsShareDeps reports whether every analyzed modroot desires an identical dependency set.
func allRootsShareDeps(byModroot []ModrootAnalysis) bool {
	if len(byModroot) <= 1 {
		return true
	}
	key := groupKey(byModroot[0].DesiredDeps)
	for _, m := range byModroot[1:] {
		if groupKey(m.DesiredDeps) != key {
			return false
		}
	}
	return true
}

// allRootsShareReplaces reports whether every analyzed modroot desires an
// identical replace-directive set.
func allRootsShareReplaces(byModroot []ModrootAnalysis) bool {
	if len(byModroot) <= 1 {
		return true
	}
	key := groupKey(byModroot[0].DesiredReplaces)
	for _, m := range byModroot[1:] {
		if groupKey(m.DesiredReplaces) != key {
			return false
		}
	}
	return true
}

// effectiveGoVersion is the go-version a modroot's bump step should end up
// carrying: the max of what its existing steps already declare and what the
// proven/probed candidate set requires. Max never picks the lower of two
// valid values, so an existing value is never lowered. "" for non-Go
// modroots (both fields are Go-only) and when neither side has a value.
func effectiveGoVersion(m ModrootAnalysis) string {
	return goversion.Max(m.ExistingGoVersion, m.RequiredGoVersion)
}

// maxEffectiveGoVersion returns the highest effective go-version
// (effectiveGoVersion) across all analyzed modroots, "" if none has one. Used
// by the fast path, whose single step must satisfy every covered root at
// once: go-version is a floor, not an exact requirement, so raising to the
// maximum is always safe even when roots' effective versions diverge -
// fastPathGoVersion still enforces never-lower against the step's current
// value on top of this.
func maxEffectiveGoVersion(byModroot []ModrootAnalysis) string {
	var max string
	for _, m := range byModroot {
		max = goversion.Max(max, effectiveGoVersion(m))
	}
	return max
}

// desiredDepsForSingleGroup returns the desired deps shared by every
// analyzed modroot (only valid when allRootsShareDeps is true).
func desiredDepsForSingleGroup(byModroot []ModrootAnalysis) []string {
	if len(byModroot) == 0 {
		return nil
	}
	return byModroot[0].DesiredDeps
}

// desiredReplacesForSingleGroup returns the desired replaces shared by every
// analyzed modroot (only valid when allRootsShareReplaces is true).
func desiredReplacesForSingleGroup(byModroot []ModrootAnalysis) []string {
	if len(byModroot) == 0 {
		return nil
	}
	return byModroot[0].DesiredReplaces
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

		// A new/changed replace directive that fixes a CVE counts as a
		// security fix too - promotions must feed epoch accounting. The
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

	return resolvedRepoURL, resolvedTag, expectedCommit, nil
}
