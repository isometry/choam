package gobump

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/isometry/choam/internal/scan"
	"github.com/isometry/choam/internal/utils"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// Analyzer handles vulnerability analysis and bump logic for Go dependencies
type Analyzer struct {
	fetcher              *Fetcher
	parser               *Parser
	vulnerabilityScanner *scan.VulnerabilityScanner
}

// NewAnalyzer creates a new analyzer with the provided HTTP client
func NewAnalyzer(httpClient *http.Client) *Analyzer {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &Analyzer{
		fetcher:              NewFetcher(httpClient),
		parser:               NewParser(),
		vulnerabilityScanner: scan.NewVulnerabilityScanner(httpClient),
	}
}

// AnalyzeBumps analyzes each bump and determines whether to keep or remove it
func (a *Analyzer) AnalyzeBumps(deps []string, goModInfo *GoModInfo) ([]BumpAnalysis, []string) {
	var analysis []BumpAnalysis

	slog.Debug("analyzing bumps",
		"input_count", len(deps),
		"deps", deps)

	// First, deduplicate and keep only the latest version per module
	latestVersions := make(map[string]string)

	slog.Debug("deduplication phase started", "raw_deps", len(deps))

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
				slog.Debug("malformed dependency detected",
					"dep", dep,
					"reason", "missing @ separator")
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
				slog.Debug("duplicate module - replacing malformed with valid",
					"module", module,
					"new_version", bumpVersion)
			} else if semver.Compare(bumpVersion, existing) > 0 {
				// This version is newer
				slog.Debug("duplicate module detected - keeping newer",
					"module", module,
					"old_version", existing,
					"new_version", bumpVersion,
					"comparison", "newer")
				latestVersions[module] = bumpVersion
			} else {
				slog.Debug("duplicate module detected - keeping existing",
					"module", module,
					"existing_version", existing,
					"rejected_version", bumpVersion,
					"comparison", "older_or_equal")
			}
			// Otherwise keep existing
		} else {
			latestVersions[module] = bumpVersion
		}
	}

	slog.Debug("deduplication phase complete",
		"unique_modules", len(latestVersions))

	// Now analyze the deduplicated dependencies
	var filteredDeps []string

	slog.Debug("analysis phase started", "modules_to_analyze", len(latestVersions))

	for module, bumpVersion := range latestVersions {
		slog.Debug("analyzing module",
			"module", module,
			"bump_version", bumpVersion)

		if bumpVersion == "" {
			// Malformed dep, keep it as is
			filteredDeps = append(filteredDeps, module)
			analysis = append(analysis, BumpAnalysis{
				Module:       module,
				BumpVersion:  "",
				GoModVersion: "",
				Action:       "keep",
				Reason:       "malformed dependency, keeping as-is",
			})
			slog.Debug("analysis decision",
				"module", module,
				"action", "keep",
				"reason", "malformed dependency")
			continue
		}

		// Normalize module path for v2+ modules (adds /vN suffix if needed)
		normalizedModule, exists := a.normalizeModulePath(module, bumpVersion, goModInfo)
		if !exists {
			// Module not found even with path correction
			analysis = append(analysis, BumpAnalysis{
				Module:       module,
				BumpVersion:  bumpVersion,
				GoModVersion: "(missing)",
				Action:       "remove-missing",
				Reason:       "module not found in go.mod/go.sum",
			})
			slog.Debug("analysis decision",
				"module", module,
				"bump_version", bumpVersion,
				"action", "remove-missing",
				"reason", "module not found or incompatible major version")
			continue
		}

		// Get the version from go.mod using normalized path
		goModVersion := goModInfo.AllRequirements[normalizedModule]

		slog.Debug("go.mod lookup",
			"normalized_module", normalizedModule,
			"current_version", goModVersion)

		// Check for replace directives that affect this module
		effectiveVersion := a.getEffectiveVersion(normalizedModule, goModVersion, goModInfo.Replacements)

		// Compare versions using semantic versioning
		comparison := semver.Compare(bumpVersion, effectiveVersion)

		slog.Debug("version comparison",
			"module", normalizedModule,
			"bump_version", bumpVersion,
			"effective_version", effectiveVersion,
			"result", func() string {
				if comparison > 0 {
					return "newer"
				} else if comparison == 0 {
					return "equal"
				}
				return "older"
			}())

		if comparison > 0 {
			// Bump version is ahead of go.mod version - keep it
			// Use normalized module path in output
			dep := fmt.Sprintf("%s@%s", normalizedModule, bumpVersion)
			filteredDeps = append(filteredDeps, dep)
			analysis = append(analysis, BumpAnalysis{
				Module:       normalizedModule,
				BumpVersion:  bumpVersion,
				GoModVersion: effectiveVersion,
				Action:       "keep",
				Reason:       "bump version is newer than effective version",
			})
			slog.Debug("analysis decision",
				"module", normalizedModule,
				"action", "keep",
				"reason", "bump version is newer")
		} else if comparison == 0 {
			// Versions are equal - remove as no-op
			analysis = append(analysis, BumpAnalysis{
				Module:       normalizedModule,
				BumpVersion:  bumpVersion,
				GoModVersion: effectiveVersion,
				Action:       "remove-noop",
				Reason:       "bump version matches effective version",
			})
			slog.Debug("analysis decision",
				"module", normalizedModule,
				"action", "remove-noop",
				"reason", "versions match")
		} else {
			// Bump version is behind go.mod version - remove as downgrade
			analysis = append(analysis, BumpAnalysis{
				Module:       normalizedModule,
				BumpVersion:  bumpVersion,
				GoModVersion: effectiveVersion,
				Action:       "remove-downgrade",
				Reason:       "bump version is older than effective version",
			})
			slog.Debug("analysis decision",
				"module", normalizedModule,
				"action", "remove-downgrade",
				"reason", "bump would downgrade")
		}
	}

	// Smart ordering: group by dependency type, then sort alphabetically within groups
	// This helps prevent later bumps from downgrading earlier ones via transitive deps
	indirectDeps := make([]string, 0)
	directDeps := make([]string, 0)
	newDeps := make([]string, 0)

	slog.Debug("classifying dependencies for smart ordering",
		"total_deps", len(filteredDeps))

	for _, dep := range filteredDeps {
		// Extract module name (before @version)
		parts := strings.Split(dep, "@")
		if len(parts) != 2 {
			// Malformed, put in new deps
			newDeps = append(newDeps, dep)
			slog.Debug("malformed dep - classifying as new",
				"dep", dep)
			continue
		}
		module := parts[0]

		// Classify based on presence in go.mod
		if _, isRequired := goModInfo.Requirements[module]; isRequired {
			// Direct dependency (explicitly in project's go.mod)
			directDeps = append(directDeps, dep)
			slog.Debug("classified as direct dependency",
				"module", module,
				"reason", "found in Requirements")
		} else if _, isTransitive := goModInfo.AllRequirements[module]; isTransitive {
			// Indirect dependency (transitive, not directly required)
			indirectDeps = append(indirectDeps, dep)
			slog.Debug("classified as indirect dependency",
				"module", module,
				"reason", "found in AllRequirements but not Requirements")
		} else {
			// New dependency (not currently in go.mod at all)
			newDeps = append(newDeps, dep)
			slog.Debug("classified as new dependency",
				"module", module,
				"reason", "not found in go.mod")
		}
	}

	// Sort each group alphabetically for stability and reproducibility
	slices.Sort(indirectDeps)
	slices.Sort(directDeps)
	slices.Sort(newDeps)

	slog.Debug("dependency groups sorted alphabetically",
		"indirect_count", len(indirectDeps),
		"direct_count", len(directDeps),
		"new_count", len(newDeps))

	// Combine in order: indirect → direct → new
	// Rationale: indirect deps are "leaves", direct deps are "roots" that depend on them
	// Applying indirect first establishes baseline before direct deps potentially override
	filteredDeps = make([]string, 0, len(indirectDeps)+len(directDeps)+len(newDeps))
	filteredDeps = append(filteredDeps, indirectDeps...)
	filteredDeps = append(filteredDeps, directDeps...)
	filteredDeps = append(filteredDeps, newDeps...)

	slog.Debug("smart ordering applied",
		"order", "indirect→direct→new",
		"final_list", filteredDeps)

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

	slog.Debug("analysis phase complete",
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
func (a *Analyzer) normalizeModulePath(module, version string, goModInfo *GoModInfo) (string, bool) {
	// Extract major version from the bump version
	bumpMajor := semver.Major(version)

	slog.Debug("normalizing module path",
		"module", module,
		"version", version,
		"bump_major", bumpMajor)

	// Try module as-is first
	if existingVersion, exists := goModInfo.AllRequirements[module]; exists {
		slog.Debug("module found as-is",
			"module", module,
			"existing_version", existingVersion)

		// Check if major versions are compatible
		existingMajor := semver.Major(existingVersion)

		slog.Debug("checking major version compatibility",
			"bump_major", bumpMajor,
			"existing_major", existingMajor)

		// v0 and v1 are compatible (v0→v1 doesn't require import path changes)
		// v2+ requires /vN suffix and major version must match exactly
		if bumpMajor == existingMajor {
			// Major versions match exactly
			slog.Debug("major versions match - compatible",
				"module", module,
				"major_version", bumpMajor,
				"result", "found")
			return module, true
		}
		if (bumpMajor == "v0" || bumpMajor == "v1") && (existingMajor == "v0" || existingMajor == "v1") {
			// v0↔v1 transitions don't require path changes
			slog.Debug("v0↔v1 transition - compatible",
				"module", module,
				"bump_major", bumpMajor,
				"existing_major", existingMajor,
				"result", "found")
			return module, true
		}
		// Major versions don't match and require import path changes (/v2, /v3, etc.)
		// This is not compatible with simple go/bump updates
		slog.Debug("major version incompatibility detected",
			"module", module,
			"bump_major", bumpMajor,
			"existing_major", existingMajor,
			"reason", "major version upgrade requires import path changes",
			"result", "not_found")
		return module, false
	}

	slog.Debug("module not found as-is, trying with suffix",
		"module", module)

	// If not found, try with version suffix for v2+
	if bumpMajor == "" || bumpMajor == "v0" || bumpMajor == "v1" {
		// v0 and v1 modules don't use version suffix, and we already checked above
		slog.Debug("v0/v1 module not found",
			"module", module,
			"reason", "v0/v1 modules don't use version suffix",
			"result", "not_found")
		return module, false
	}

	// Check if path already has the suffix
	suffix := "/" + bumpMajor
	if strings.HasSuffix(module, suffix) {
		slog.Debug("module already has version suffix",
			"module", module,
			"suffix", suffix)

		// Already has suffix, check if it exists with compatible version
		if existingVersion, exists := goModInfo.AllRequirements[module]; exists {
			existingMajor := semver.Major(existingVersion)

			slog.Debug("module with suffix found",
				"module", module,
				"existing_version", existingVersion,
				"existing_major", existingMajor)

			if bumpMajor == existingMajor {
				slog.Debug("major versions match with suffix",
					"module", module,
					"result", "found")
				return module, true
			}
			// v0 and v1 are compatible
			if (bumpMajor == "v0" || bumpMajor == "v1") && (existingMajor == "v0" || existingMajor == "v1") {
				slog.Debug("v0↔v1 transition with suffix",
					"module", module,
					"result", "found")
				return module, true
			}
			slog.Debug("major version mismatch with suffix",
				"module", module,
				"result", "not_found")
			return module, false
		}
		slog.Debug("module with suffix not found in go.mod",
			"module", module,
			"result", "not_found")
		return module, false
	}

	// Try with version suffix (e.g., github.com/cli/go-gh -> github.com/cli/go-gh/v2)
	correctedPath := module + suffix
	slog.Debug("trying with corrected path",
		"original", module,
		"corrected", correctedPath)

	if existingVersion, exists := goModInfo.AllRequirements[correctedPath]; exists {
		slog.Debug("corrected path found",
			"corrected_path", correctedPath,
			"existing_version", existingVersion)

		// Verify major version compatibility
		existingMajor := semver.Major(existingVersion)

		if bumpMajor == existingMajor {
			slog.Debug("major versions match with corrected path",
				"corrected_path", correctedPath,
				"result", "found")
			return correctedPath, true
		}
		// v0 and v1 are compatible
		if (bumpMajor == "v0" || bumpMajor == "v1") && (existingMajor == "v0" || existingMajor == "v1") {
			slog.Debug("v0↔v1 transition with corrected path",
				"corrected_path", correctedPath,
				"result", "found")
			return correctedPath, true
		}
		slog.Debug("major version mismatch with corrected path",
			"corrected_path", correctedPath,
			"bump_major", bumpMajor,
			"existing_major", existingMajor,
			"result", "not_found")
		return correctedPath, false
	}

	// Not found even with correction
	slog.Debug("module not found even with path correction",
		"original", module,
		"corrected", correctedPath,
		"result", "not_found")
	return module, false
}

// getEffectiveVersion returns the effective version considering replace directives
func (a *Analyzer) getEffectiveVersion(module, originalVersion string, replacements map[string]*modfile.Replace) string {
	slog.Debug("checking effective version",
		"module", module,
		"original_version", originalVersion)

	// Check for exact version replacement first (module@version)
	exactKey := module + "@" + originalVersion
	if replace, ok := replacements[exactKey]; ok {
		if utils.IsLocalPath(replace.New.Path) {
			// Local replacement - treat as effectively very new version
			slog.Debug("exact version replacement with local path",
				"module", module,
				"local_path", replace.New.Path,
				"effective_version", "v999.999.999")
			return "v999.999.999" // This ensures bumps are considered downgrades
		}
		if replace.New.Version != "" {
			slog.Debug("exact version replacement",
				"module", module,
				"original_version", originalVersion,
				"effective_version", replace.New.Version)
			return replace.New.Version
		}
	}

	// Check for module-level replacement (all versions)
	if replace, ok := replacements[module]; ok {
		if utils.IsLocalPath(replace.New.Path) {
			// Local replacement - treat as effectively very new version
			slog.Debug("module-level replacement with local path",
				"module", module,
				"local_path", replace.New.Path,
				"effective_version", "v999.999.999")
			return "v999.999.999" // This ensures bumps are considered downgrades
		}
		if replace.New.Version != "" {
			slog.Debug("module-level replacement",
				"module", module,
				"original_version", originalVersion,
				"effective_version", replace.New.Version)
			return replace.New.Version
		}
	}

	// No replacement, use original version
	slog.Debug("no replacement directive",
		"module", module,
		"effective_version", originalVersion)
	return originalVersion
}

// HaveDepsChanged compares two dependency lists to determine if they're different
func (a *Analyzer) HaveDepsChanged(existing, merged []string) bool {
	// Normalize both slices for comparison
	normalizeDepList := func(deps []string) []string {
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

	normalizedExisting := normalizeDepList(existing)
	normalizedMerged := normalizeDepList(merged)

	return !slices.Equal(normalizedExisting, normalizedMerged)
}

// GetVulnerabilityScanner returns the vulnerability scanner for external use
func (a *Analyzer) GetVulnerabilityScanner() *scan.VulnerabilityScanner {
	return a.vulnerabilityScanner
}

// GetFetcher returns the fetcher for external use
func (a *Analyzer) GetFetcher() *Fetcher {
	return a.fetcher
}

// GetParser returns the parser for external use
func (a *Analyzer) GetParser() *Parser {
	return a.parser
}
