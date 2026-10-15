package gobump

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strings"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/config"
	"github.com/isometry/choam/internal/ecosystem"
	ecogolang "github.com/isometry/choam/internal/ecosystem/golang"
	"github.com/isometry/choam/internal/gorelease"
	"github.com/isometry/choam/internal/logging"
	"github.com/isometry/choam/internal/processor"
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
	// so the best-effort go-version fallback stage (see
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

// releaseIndex returns the shared per-run Go release index: the fallback
// go-version probe, the go-package pin floor write and go/bump migration
// planning consult it to reject a version that names no real Go release. A
// nil Analyzer (some unit tests construct stages directly) means no index is
// available - callers treat that as "nothing to validate against" rather
// than an error.
func (a *Analyzer) releaseIndex() *gorelease.Index {
	if a == nil {
		return nil
	}
	return a.goReleases
}

// client returns the analyzer's HTTP client, falling back to the default
// client when a stage was built without an analyzer (tests).
func (a *Analyzer) client() *http.Client {
	if a != nil && a.httpClient != nil {
		return a.httpClient
	}
	return http.DefaultClient
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

// ShouldRun skips analysis for a package excluded by annotation; leaving
// VulnerabilityAnalysis nil turns off every stage gated on it.
func (v *VulnerabilityChecker) ShouldRun(ctx context.Context, p processor.Processor) (bool, error) {
	gp, err := asBump(p)
	if err != nil {
		return false, err
	}
	return gp.ExcludedReason == "", nil
}

func (v *VulnerabilityChecker) Check(ctx context.Context, p processor.Processor) error {
	gp, err := asBump(p)
	if err != nil {
		return err
	}

	analysis, err := v.checkVulnerabilities(ctx, gp)
	if err != nil {
		return fmt.Errorf("checking vulnerabilities: %w", err)
	}

	gp.VulnerabilityAnalysis = analysis

	// Note: SecurityFixes are added by the applier when actual changes are made,
	// not during the check phase. This ensures the count reflects real changes.

	logging.From(ctx).Debug("vulnerability analysis complete", "vulnerabilities", analysis.VulnerabilitiesFound)
	return nil
}

// checkVulnerabilities performs real vulnerability analysis across every
// language and module root discovered for this package (see
// discoverAnalysisUnits) - a package may have more than one language.
func (v *VulnerabilityChecker) checkVulnerabilities(ctx context.Context, gp *Processor) (*VulnerabilityAnalysis, error) {
	logging.From(ctx).Debug("checking vulnerabilities")

	loader := newMelangeLoader()

	bumpSteps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	if err != nil {
		return nil, fmt.Errorf("finding bump pipelines: %w", err)
	}

	// Migration is decided before simulation so the simulated engine is the
	// one the written step will run (see planMigration).
	units, notes := discoverAnalysisUnits(ctx, gp.Config, bumpSteps, planMigrations(ctx, gp.GetCurrentYAML(), bumpSteps, v.Analyzer.releaseIndex()))
	for _, note := range notes {
		gp.AddMessage("build: " + note)
	}
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

		result, err := v.performAnalysis(ctx, eco, language, repoURL, ref, langUnits, bumpSteps, gp)
		if err != nil {
			return nil, fmt.Errorf("performing %s dependency analysis: %w", language, err)
		}

		analysis.ByLanguage = append(analysis.ByLanguage, result.Analysis)
		analysis.BumpActions = append(analysis.BumpActions, result.Actions...)
		maps.Copy(uniqueVulns, result.Vulns)
		logging.From(ctx).Debug("language analysis complete", "modroots", len(modroots), "actions", len(result.Actions))
	}

	analysis.VulnerabilitiesFound = len(uniqueVulns)

	logging.From(ctx).Debug("analysis complete", "languages", len(analysis.ByLanguage), "vulnerabilities", analysis.VulnerabilitiesFound, "actions", len(analysis.BumpActions))

	return analysis, nil
}

// languageResult holds one language's per-modroot analysis, plus its
// contribution to the overall multi-language aggregate: unique
// vulnerabilities found (keyed by ID, so checkVulnerabilities can dedupe
// across languages) and bump actions.
type languageResult struct {
	Analysis LanguageAnalysis
	Vulns    map[string]scan.Vulnerability
	Actions  []BumpAction
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
func (v *VulnerabilityChecker) performAnalysis(ctx context.Context, eco ecosystem.Ecosystem, language, repoURL, ref string, langUnits []analysisUnit, bumpSteps []config.BumpStep, gp *Processor) (*languageResult, error) {
	modroots := unitRoots(langUnits)
	existing := modrootExisting{
		deps:     existingDepsForModroots(modroots, bumpSteps),
		replaces: existingReplacesForModroots(modroots, bumpSteps),
		// go-version is a Go-only (go/bump) pipeline input - other languages'
		// analyses never carry one.
		goVersions: make(map[string]string),
	}
	if language == "go" {
		existing.goVersions = existingGoVersionsForModroots(modroots, bumpSteps)
	}

	result := &languageResult{
		Vulns: make(map[string]scan.Vulnerability),
	}
	result.Analysis.Language = language
	result.Analysis.ByModroot = make([]ModrootAnalysis, 0, len(modroots))

	for _, unit := range langUnits {
		root := unit.Modroot
		// Shadowed for the rest of this iteration - see the language-level
		// shadow in checkVulnerabilities.
		ctx := logging.With(ctx, "modroot", root)

		m, err := v.analyzeModroot(ctx, eco, repoURL, ref, unit, existing, gp)
		if err != nil {
			return nil, err
		}
		for _, vuln := range m.ScanResult.Vulnerabilities {
			result.Vulns[vuln.ID] = vuln
		}
		result.Analysis.ByModroot = append(result.Analysis.ByModroot, m)

		if haveDepsChanged(m.ExistingDeps, m.DesiredDeps) {
			added := newlyAddedDeps(m.ExistingDeps, m.DesiredDeps)
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

// modrootExisting is what a language's existing bump steps already declare,
// per modroot.
type modrootExisting struct {
	deps       map[string][]string
	replaces   map[string][]string
	goVersions map[string]string
}

// analyzeModroot fetches, analyzes and scans one module root, and filters
// its candidate bumps against its own manifest (see performAnalysis). Fix
// bumps the ecosystem holds back are recorded as residuals on gp.
func (v *VulnerabilityChecker) analyzeModroot(ctx context.Context, eco ecosystem.Ecosystem, repoURL, ref string, unit analysisUnit, existing modrootExisting, gp *Processor) (ModrootAnalysis, error) {
	root := unit.Modroot
	files, err := v.fetchManifests(ctx, eco, repoURL, ref, root)
	if err != nil {
		return ModrootAnalysis{}, err
	}

	deps, err := eco.Analyze(ctx, files)
	if err != nil {
		return ModrootAnalysis{}, fmt.Errorf("modroot %s: analyzing dependencies: %w", root, err)
	}

	pkgs := eco.ScanPackages(ctx, deps)
	scanResult, err := v.Analyzer.vulnerabilityScanner.ScanPackages(ctx, pkgs)
	if err != nil {
		return ModrootAnalysis{}, fmt.Errorf("modroot %s: scanning dependencies for vulnerabilities: %w", root, err)
	}
	if scanResult.Error != "" {
		return ModrootAnalysis{}, fmt.Errorf("modroot %s: security scan error: %s", root, scanResult.Error)
	}

	existingDeps := existing.deps[root]
	existingReplaces := existing.replaces[root]
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
		logging.From(ctx).Debug("fix held back", "module", h.Bump.Name, "fix", h.Bump.FixedVersion, "reason", h.Reason)
	}
	gp.AddResiduals(heldResiduals)

	// Coordinates in this modroot's rendered dep grammar (not OSV's own
	// naming - see Ecosystem.BumpCoords), so they compare directly
	// against splitCoordVersion output downstream.
	bumpCoords := eco.BumpCoords(ctx, scanResult.SecurityBumps, deps)
	securityBumpModules := make([]string, 0, len(bumpCoords))
	for coord := range bumpCoords {
		securityBumpModules = append(securityBumpModules, coord)
	}
	sort.Strings(securityBumpModules)

	return ModrootAnalysis{
		Modroot:         root,
		BuildPackages:   unit.Packages,
		BuildTags:       unit.Tags,
		BuildArches:     unit.Arches,
		BuildEnv:        unit.Env,
		BumpEngine:      unit.Engine,
		BumpMigrating:   unit.Migrating,
		BumpNoTidy:      unit.NoTidy,
		GoPackageMinor:  unit.GoMinor,
		Deps:            deps,
		ScannedPackages: pkgs,
		ScanResult:      scanResult,
		ExistingDeps:    existingDeps,
		DesiredDeps:     desiredDeps,
		// Analysis never invents replaces - it carries existing ones
		// forward (the simulation may raise or retire them, never add
		// any). This also keeps the --no-validate degrade path a
		// pass-through.
		ExistingReplaces:     existingReplaces,
		DesiredReplaces:      existingReplaces,
		ExistingGoVersion:    existing.goVersions[root],
		SecurityBumpModules:  securityBumpModules,
		SecurityBumpsByCoord: bumpCoords,
		Residuals:            heldResiduals,
	}, nil
}

// fetchManifests fetches a modroot's required and optional manifest files
// at ref; only a confirmed 404 on an optional manifest is tolerated (fail
// closed).
func (v *VulnerabilityChecker) fetchManifests(ctx context.Context, eco ecosystem.Ecosystem, repoURL, ref, root string) (map[string][]byte, error) {
	required, optional := eco.ManifestFiles()
	files := make(map[string][]byte, len(required)+len(optional))
	for _, name := range append(slices.Clone(required), optional...) {
		content, err := v.Analyzer.fetcher.FetchFile(ctx, repoURL, ref, modrootPath(root, name))
		if errors.Is(err, ecosystem.ErrNotFound) && slices.Contains(optional, name) {
			logging.From(ctx).Debug("optional manifest file absent", "manifest", name)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("modroot %s: %w", root, err)
		}
		files[name] = content
	}
	return files, nil
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
			_, ok := lookupModule(securityModules, module)
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
			if _, newPath, _, isReplace := ecogolang.ParseReplace(replace); isReplace {
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
func (g *Applier) recordSecurityFixes(gp *Processor, langAnalysis LanguageAnalysis, dependencies []string) {
	bumps := analysisBumps(langAnalysis)
	for _, dep := range dependencies {
		module, version, ok := splitCoordVersion(dep)
		if !ok {
			module = dep
			version = "unknown"
		}

		bump, _ := lookupModule(bumps, module)
		vulnerability := "security vulnerability"
		if len(bump.VulnIDs) > 0 {
			vulnerability = strings.Join(bump.VulnIDs, ", ")
		}

		gp.AddSecurityFix(SecurityFix{
			Module:        module,
			Vulnerability: vulnerability,
			OldVersion:    cmp.Or(bump.CurrentVersion, "vulnerable"),
			NewVersion:    version,
			Severity:      cmp.Or(bump.Severity, "varies"),
		})
	}
}

// analysisBumps indexes a language's analysis bumps for lookupModule:
// rendered coordinates first (see Ecosystem.BumpCoords - this is what
// matches splitCoordVersion output for Maven "groupId@artifactId" and
// v2+-normalized Go module paths), then OSV names for coordinates the map
// lacks (hand-built fixtures, or entries the simulation added after
// analysis).
func analysisBumps(langAnalysis LanguageAnalysis) map[string]scan.SecurityBump {
	byModule := make(map[string]scan.SecurityBump)
	for _, m := range langAnalysis.ByModroot {
		maps.Copy(byModule, m.SecurityBumpsByCoord)
		if m.ScanResult == nil {
			continue
		}
		for _, bump := range m.ScanResult.SecurityBumps {
			if _, ok := byModule[bump.Name]; !ok {
				byModule[bump.Name] = bump
			}
		}
	}
	return byModule
}

// lookupModule finds a module by its exact key, then by its path without the
// /vN major suffix: OSV names v2+ Go modules without the suffix that
// FilterBumps and Ecosystem.BumpCoords normalize in.
func lookupModule[V any](byModule map[string]V, module string) (V, bool) {
	if v, ok := byModule[module]; ok {
		return v, true
	}
	v, ok := byModule[ecogolang.TrimMajorSuffix(module)]
	return v, ok
}

// recordHygieneBumps records the scanner-hygiene entries (see
// ModrootAnalysis.HygieneModules) this write adds or changes, once per
// module@version across modroots - apart from the security fixes, so they
// are never counted as one.
func recordHygieneBumps(gp *Processor, langAnalysis LanguageAnalysis) {
	bumps := analysisBumps(langAnalysis)
	severities := analysisSeverities(gp)
	seen := make(map[string]struct{})
	for _, m := range langAnalysis.ByModroot {
		hygiene := make(map[string]simulate.HygieneModule, len(m.HygieneModules))
		for _, h := range m.HygieneModules {
			hygiene[h.Module+"@"+h.Version] = h
		}
		for _, dep := range newlyAddedDeps(m.ExistingDeps, m.DesiredDeps) {
			h, ok := hygiene[dep]
			if _, dup := seen[dep]; !ok || dup {
				continue
			}
			seen[dep] = struct{}{}
			bump, _ := lookupModule(bumps, h.Module)
			severity := ""
			for _, id := range h.VulnIDs {
				if sev := severities[id]; sev != "" && (severity == "" || scan.SeverityRank(sev) < scan.SeverityRank(severity)) {
					severity = sev
				}
			}
			gp.AddHygieneBump(SecurityFix{
				Module:        h.Module,
				Vulnerability: strings.Join(h.VulnIDs, ", "),
				OldVersion:    cmp.Or(bump.CurrentVersion, "flagged"),
				NewVersion:    h.Version,
				Severity:      cmp.Or(severity, "varies"),
			})
		}
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
