package gobump

import (
	"fmt"
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
			} else if semver.Compare(bumpVersion, existing) > 0 {
				// This version is newer
				latestVersions[module] = bumpVersion
			}
			// Otherwise keep existing
		} else {
			latestVersions[module] = bumpVersion
		}
	}

	// Now analyze the deduplicated dependencies
	var filteredDeps []string

	for module, bumpVersion := range latestVersions {
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
			continue
		}

		// Check if this module exists in go.mod requirements (including indirect)
		goModVersion, exists := goModInfo.AllRequirements[module]
		if !exists {
			// Module not found in go.mod/go.sum - remove it
			analysis = append(analysis, BumpAnalysis{
				Module:       module,
				BumpVersion:  bumpVersion,
				GoModVersion: "(missing)",
				Action:       "remove-missing",
				Reason:       "module not found in go.mod/go.sum",
			})
			continue
		}

		// Check for replace directives that affect this module
		effectiveVersion := a.getEffectiveVersion(module, goModVersion, goModInfo.Replacements)

		// Compare versions using semantic versioning
		comparison := semver.Compare(bumpVersion, effectiveVersion)

		if comparison > 0 {
			// Bump version is ahead of go.mod version - keep it
			dep := fmt.Sprintf("%s@%s", module, bumpVersion)
			filteredDeps = append(filteredDeps, dep)
			analysis = append(analysis, BumpAnalysis{
				Module:       module,
				BumpVersion:  bumpVersion,
				GoModVersion: effectiveVersion,
				Action:       "keep",
				Reason:       "bump version is newer than effective version",
			})
		} else if comparison == 0 {
			// Versions are equal - remove as no-op
			analysis = append(analysis, BumpAnalysis{
				Module:       module,
				BumpVersion:  bumpVersion,
				GoModVersion: effectiveVersion,
				Action:       "remove-noop",
				Reason:       "bump version matches effective version",
			})
		} else {
			// Bump version is behind go.mod version - remove as downgrade
			analysis = append(analysis, BumpAnalysis{
				Module:       module,
				BumpVersion:  bumpVersion,
				GoModVersion: effectiveVersion,
				Action:       "remove-downgrade",
				Reason:       "bump version is older than effective version",
			})
		}
	}

	// Sort the filtered deps lexicographically for stability
	slices.Sort(filteredDeps)

	return analysis, filteredDeps
}

// getEffectiveVersion returns the effective version considering replace directives
func (a *Analyzer) getEffectiveVersion(module, originalVersion string, replacements map[string]*modfile.Replace) string {
	// Check for exact version replacement first (module@version)
	exactKey := module + "@" + originalVersion
	if replace, ok := replacements[exactKey]; ok {
		if utils.IsLocalPath(replace.New.Path) {
			// Local replacement - treat as effectively very new version
			return "v999.999.999" // This ensures bumps are considered downgrades
		}
		if replace.New.Version != "" {
			return replace.New.Version
		}
	}

	// Check for module-level replacement (all versions)
	if replace, ok := replacements[module]; ok {
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
