package golang

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/isometry/choam/internal/logging"
	"github.com/isometry/choam/internal/scan"
	"github.com/isometry/choam/internal/utils"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// analyzer applies Go-specific bump decisioning: version comparison,
// v2+ module path normalization, and replace-directive resolution.
type analyzer struct{}

func newAnalyzer() *analyzer {
	return &analyzer{}
}

// analyzeBumps analyzes each candidate bump and determines whether to keep or remove it.
//
// Debug trace: one "analyzing bumps" header after dedup, one "bump decision"
// per unique module (in sorted module order) and the closing summary.
func (a *analyzer) analyzeBumps(ctx context.Context, deps []string, goModInfo *GoModInfo) ([]bumpAnalysis, []string) {
	var analysis []bumpAnalysis

	// First, deduplicate and keep only the latest version per module
	latestVersions := make(map[string]string)

	for _, dep := range deps {
		dep = strings.TrimSpace(dep)
		if dep == "" {
			continue
		}

		// Parse module@version
		parts := strings.Split(dep, "@")
		if len(parts) != 2 {
			// Malformed dep, keep it as is (but still dedupe)
			if _, exists := latestVersions[dep]; !exists {
				latestVersions[dep] = ""
			}
			continue
		}

		module := parts[0]
		bumpVersion := parts[1]

		// Keep only the latest version for each module
		if existing, exists := latestVersions[module]; exists {
			if existing == "" {
				// Previous was malformed, this one is valid
				latestVersions[module] = bumpVersion
			} else if semver.Compare(bumpVersion, existing) == 0 {
				// Two spellings of one version (v2.8.2, v2.8.2+incompatible):
				// keep the canonical one whichever came first.
				latestVersions[module] = scan.PreferVersion(existing, bumpVersion)
			} else if semver.Compare(bumpVersion, existing) > 0 {
				// This version is newer
				latestVersions[module] = bumpVersion
			}
			// Otherwise keep existing
		} else {
			latestVersions[module] = bumpVersion
		}
	}

	// Sorted iteration makes the decision trace deterministic.
	modules := slices.Sorted(maps.Keys(latestVersions))
	bumps := make([]string, 0, len(modules))
	for _, module := range modules {
		if v := latestVersions[module]; v != "" {
			bumps = append(bumps, module+"@"+v)
		} else {
			bumps = append(bumps, module)
		}
	}
	logging.From(ctx).Debug("analyzing bumps",
		"input_count", len(deps),
		"unique", len(modules),
		"bumps", strings.Join(bumps, " "))

	// decide records one analysis entry and its single "bump decision" line.
	// normalized/effective are set only when they apply.
	decide := func(module, normalized string, an bumpAnalysis, replaced bool) {
		analysis = append(analysis, an)
		attrs := []any{"module", module, "bump", an.BumpVersion}
		if an.GoModVersion != "" {
			attrs = append(attrs, "effective", an.GoModVersion)
		}
		if normalized != "" && normalized != module {
			attrs = append(attrs, "normalized", normalized)
		}
		attrs = append(attrs, "replaced", replaced, "action", an.Action, "reason", an.Reason)
		logging.From(ctx).Debug("bump decision", attrs...)
	}

	// Now analyze the deduplicated dependencies
	var filteredDeps []string

	for _, module := range modules {
		bumpVersion := latestVersions[module]

		if bumpVersion == "" {
			// Malformed dep, keep it as is
			filteredDeps = append(filteredDeps, module)
			decide(module, "", bumpAnalysis{
				Module:       module,
				BumpVersion:  "",
				GoModVersion: "",
				Action:       "keep",
				Reason:       "malformed dependency, keeping as-is",
			}, false)
			continue
		}

		// Normalize module path for v2+ modules (adds /vN suffix if needed)
		normalizedModule, exists := a.normalizeModulePath(ctx, module, bumpVersion, goModInfo)
		if !exists {
			// Module not found even with path correction
			decide(module, "", bumpAnalysis{
				Module:       module,
				BumpVersion:  bumpVersion,
				GoModVersion: "(missing)",
				Action:       "remove-missing",
				Reason:       "module not found in go.mod/go.sum",
			}, false)
			continue
		}

		// OSV fix versions omit +incompatible; the module path decides it.
		bumpVersion = scan.CanonicalModuleVersion(normalizedModule, bumpVersion)

		// Get the version from go.mod using normalized path
		goModVersion := goModInfo.AllRequirements[normalizedModule]

		// Check for replace directives that affect this module
		effectiveVersion := a.getEffectiveVersion(ctx, normalizedModule, goModVersion, goModInfo.Replacements)
		replaced := effectiveVersion != goModVersion

		// Compare versions using semantic versioning
		comparison := semver.Compare(bumpVersion, effectiveVersion)

		an := bumpAnalysis{
			Module:       normalizedModule,
			BumpVersion:  bumpVersion,
			GoModVersion: effectiveVersion,
		}
		switch {
		case comparison > 0:
			// Bump version is ahead of go.mod version - keep it
			// Use normalized module path in output
			filteredDeps = append(filteredDeps, fmt.Sprintf("%s@%s", normalizedModule, bumpVersion))
			an.Action, an.Reason = "keep", "bump version is newer than effective version"
		case comparison == 0:
			// Versions are equal - remove as no-op
			an.Action, an.Reason = "remove-noop", "bump version matches effective version"
		default:
			// Bump version is behind go.mod version - remove as downgrade
			an.Action, an.Reason = "remove-downgrade", "bump version is older than effective version"
		}
		decide(module, normalizedModule, an, replaced)
	}

	// Smart ordering: group by dependency type, then sort alphabetically within groups
	// This helps prevent later bumps from downgrading earlier ones via transitive deps
	indirectDeps := make([]string, 0)
	directDeps := make([]string, 0)
	newDeps := make([]string, 0)

	for _, dep := range filteredDeps {
		// Extract module name (before @version)
		parts := strings.Split(dep, "@")
		if len(parts) != 2 {
			// Malformed, put in new deps
			newDeps = append(newDeps, dep)
			continue
		}
		module := parts[0]

		// Classify based on presence in go.mod
		if _, isRequired := goModInfo.Requirements[module]; isRequired {
			// Direct dependency (explicitly in project's go.mod)
			directDeps = append(directDeps, dep)
		} else if _, isTransitive := goModInfo.AllRequirements[module]; isTransitive {
			// Indirect dependency (transitive, not directly required)
			indirectDeps = append(indirectDeps, dep)
		} else {
			// New dependency (not currently in go.mod at all)
			newDeps = append(newDeps, dep)
		}
	}

	// Sort each group alphabetically for stability and reproducibility
	slices.Sort(indirectDeps)
	slices.Sort(directDeps)
	slices.Sort(newDeps)

	// Combine in order: indirect → direct → new
	// Rationale: indirect deps are "leaves", direct deps are "roots" that depend on them
	// Applying indirect first establishes baseline before direct deps potentially override
	filteredDeps = make([]string, 0, len(indirectDeps)+len(directDeps)+len(newDeps))
	filteredDeps = append(filteredDeps, indirectDeps...)
	filteredDeps = append(filteredDeps, directDeps...)
	filteredDeps = append(filteredDeps, newDeps...)

	// Count actions for summary
	kept, removedMissing, removedNoop, removedDowngrade := 0, 0, 0, 0
	for _, a := range analysis {
		switch a.Action {
		case "keep":
			kept++
		case "remove-missing":
			removedMissing++
		case "remove-noop":
			removedNoop++
		case "remove-downgrade":
			removedDowngrade++
		}
	}

	logging.From(ctx).Debug("analysis phase complete",
		"total_analyzed", len(analysis),
		"kept", kept,
		"removed_missing", removedMissing,
		"removed_noop", removedNoop,
		"removed_downgrade", removedDowngrade,
		"final_deps", filteredDeps)

	return analysis, filteredDeps
}

// normalizeModulePath corrects module paths for v2+ modules by adding version suffix.
// Go modules v2+ require /vN suffix in import path (e.g., github.com/foo/bar/v2).
// OSV often returns paths without this suffix, so we need to correct them against go.mod.
// Returns the normalized module path and whether it was found in go.mod with compatible major version.
// It is called from several paths (analysis, BumpCoords), so it does not log;
// analyzeBumps reports the outcome once per module.
func (a *analyzer) normalizeModulePath(_ context.Context, module, version string, goModInfo *GoModInfo) (string, bool) {
	bumpMajor := semver.Major(version)

	// Try module as-is first
	if existingVersion, exists := goModInfo.AllRequirements[module]; exists {
		// Only an exact major match is a compatible raise: v0 -> v1 needs no
		// import path change, but it is still a major (breaking) change -
		// v0 promises no compatibility. v2+ additionally needs /vN. A major
		// version change (v0 -> v1 included) is not a compatible raise a
		// deps entry can express.
		return module, bumpMajor == semver.Major(existingVersion)
	}

	// If not found, try with version suffix for v2+
	if bumpMajor == "" || bumpMajor == "v0" || bumpMajor == "v1" {
		// v0 and v1 modules don't use version suffix, and we already checked above
		return module, false
	}

	// Check if path already has the suffix (and was not found above)
	suffix := "/" + bumpMajor
	if strings.HasSuffix(module, suffix) {
		return module, false
	}

	// Try with version suffix (e.g., github.com/cli/go-gh -> github.com/cli/go-gh/v2)
	correctedPath := module + suffix
	if existingVersion, exists := goModInfo.AllRequirements[correctedPath]; exists {
		return correctedPath, bumpMajor == semver.Major(existingVersion)
	}

	// Not found even with correction
	return module, false
}

// getEffectiveVersion returns the effective version considering replace directives.
// Silent for the same reason as normalizeModulePath.
func (a *analyzer) getEffectiveVersion(_ context.Context, module, originalVersion string, replacements map[string]*modfile.Replace) string {
	// Check for exact version replacement first (module@version), then a
	// module-level replacement (all versions).
	for _, key := range []string{module + "@" + originalVersion, module} {
		replace, ok := replacements[key]
		if !ok {
			continue
		}
		if utils.IsLocalPath(replace.New.Path) {
			// Local replacement - treat as effectively very new version
			return "v999.999.999" // This ensures bumps are considered downgrades
		}
		if replace.New.Version != "" {
			return replace.New.Version
		}
	}

	// No replacement, use original version
	return originalVersion
}
